#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from argparse import ArgumentTypeError
from datetime import datetime
import json
import sys
from ipahealthcheck.core.constants import _nameToLevel, SUCCESS
from ipahealthcheck.core.plugin import Registry


class OutputRegistry(Registry):
    pass


output_registry = OutputRegistry()


class Int:
    def __init__(self, minimum=0, maximum=100):
        self.minimum = minimum
        self.maximum = maximum

    def __call__(self, arg):
        try:
            value = int(arg)
        except ValueError:
            raise ArgumentTypeError("'%s' is not an integer" % arg)

        if (value < self.minimum) or (value > self.maximum):
            raise ArgumentTypeError(
                "'%s' is not in the range %s-%s"
                % (value, self.minimum, self.maximum)
            )

        return value


class Output:
    """Base class for writing/displaying the output of results

       options is a tuple of argparse options that can add
       class-specific options for output.

       Output will be typically generated like:
       >>> output = JSON(options)
       >>> output.render(results)

       render() will:
       1. Strip out any SUCCESS if requested (strip_output)
       2. Generate a string to be written (generate)
       3. Write to the requested file or stdout (write_file)

       stdout == sys.stdout by default.

       An Output class only needs to implement the generate() method
       which will render the results into a string for writing.
    """
    def __init__(self, options):
        self.filename = options.output_file

        # Non-required options in the framework, set logical defaults to
        # pre 0.6 behavior with everything reported.
        self.severity = None
        self.failures_only = False
        self.all = True

        if 'failures_only' in options:
            self.failures_only = options.failures_only
        if 'all' in options:
            self.all = options.all
        if 'severity' in options:
            self.severity = options.severity

    def render(self, results):
        """Process the results into output"""
        output = self.strip_output(results)
        output = self.generate(output)
        self.write_file(output)

    def write_file(self, output):
        """Write the output to a file or sys.stdout"""
        if self.filename:
            with open(self.filename, 'w') as fd:
                fd.write(output)
        else:
            sys.stdout.write(output)

    def strip_output(self, results):
        """Strip out SUCCESS results if --failures-only or
           --severity was used

           Returns a list of result values.
        """
        output = []
        for line in results.output():
            result = line.get('result')
            if _nameToLevel.get(result) == SUCCESS:
                if self.failures_only:
                    continue
                if (not self.all and
                    self.filename is None and
                    not (self.failures_only is False and
                         not sys.stdin.isatty())):
                    continue
            if self.severity is not None and result not in self.severity:
                continue
            output.append(line)

        return output

    def generate(self, data):
        """Convert the output to the desired format, ready for writing

           This is the only method an output plugin is required to
           provide. The return value should be in ready-to-write format.

           Returns a string.
        """
        raise NotImplementedError


@output_registry
class JSON(Output):
    """Output information in JSON format"""

    options = (
        ('--indent', dict(dest='indent', type=Int(0, 32), default=2,
         help='Indention level of JSON output')),
    )

    def __init__(self, options):
        super().__init__(options)
        self.indent = options.indent

    def generate(self, data):
        output = json.dumps(data, indent=self.indent)
        if self.filename is None:
            output += '\n'

        return output


@output_registry
class Human(Output):
    """Display output in a more human-friendly way"""
    options = ()

    def generate(self, data):
        if not data:
            return "No issues found.\n"
        output = ''
        for line in data:
            kw = line.get('kw')
            result = line.get('result')
            source = line.get('source')
            check = line.get('check')
            outline = '%s: %s.%s' % (result, source, check)
            if 'key' in kw:
                outline += '.%s' % kw.get('key')
            if 'msg' in kw:
                msg = kw.get('msg')
                err = msg.format(**kw)
                outline += ': %s' % err
            elif 'exception' in kw:
                outline += ': %s' % kw.get('exception')
            output += outline + '\n'

        return output


@output_registry
class Prometheus(Output):
    """Render results as Prometheus text metric exposition format"""

    class Renderer:
        """Line-based Metrics Exposition Format renderer"""

        def __init__(self, metric_prefix=""):
            self.metric_prefix = metric_prefix
            self.output = []

        def add_info(self, metric_name, metric_type=None, help=None):
            if help is not None:
                line = '# HELP %s_%s %s' % (
                    self.metric_prefix, metric_name, help,
                )
                self.output.append(line)

            if metric_type is not None:
                line = '# TYPE %s_%s %s' % (
                    self.metric_prefix, metric_name, metric_type,
                )
                self.output.append(line)

        def add_data(self, metric_name, value, format='%.1f', **labels):
            lbls = ','.join(
                '{}="{}"'.format(key, value) for key, value in labels.items()
            )
            fmt = '%s_%s{%s} ' + format
            line = fmt % (self.metric_prefix, metric_name, lbls, value)

            self.output.append(line)

        def reset(self):
            self.output = []

        def render(self):
            self.output.append('')

            return '\n'.join(self.output)

    options = (
        ('--metric-prefix', dict(dest='metric_prefix', default='ipa',
         help='Metric name prefix')),
    )

    def __init__(self, options):
        super().__init__(options)
        self.metric_prefix = options.metric_prefix

    def generate(self, data):
        if not data:
            return '\n'

        crt = {}
        svc = {}
        chk = {}
        for line in data:
            kw = line.get('kw')
            result = line.get('result')
            source = line.get('source')
            check = line.get('check')

            if result in chk:
                chk[result] += 1
            else:
                chk[result] = 1

            if source == 'ipahealthcheck.meta.services':
                state = 1.0 if _nameToLevel.get(result) == SUCCESS else 0.0
                svc[check] = state
            elif (source == 'ipahealthcheck.ipa.certs' and
                  check == "IPACertmongerExpirationCheck"):

                # only unsuccessful checks carry the expiration information
                if 'key' in kw and 'expiration_date' in kw:
                    expiration = datetime.strptime(kw['expiration_date'],
                                                   '%Y%m%d%H%M%SZ')
                    crt[kw['key']] = expiration.timestamp()

        metrics = Prometheus.Renderer(self.metric_prefix)
        self.generate_check_metrics(metrics, chk)
        self.generate_service_metrics(metrics, svc)
        self.generate_certificate_metrics(metrics, crt)

        return metrics.render()

    def generate_check_metrics(self, out, data):
        if not data:
            return

        metric_name = 'healthcheck'
        out.add_info(
            metric_name, 'gauge',
            'Number of healthchecks with a certain result',
        )
        for check, quantity in data.items():
            out.add_data(metric_name, quantity, '%.1f', result=check)

    def generate_service_metrics(self, out, data):
        if not data:
            return

        metric_name = 'service_state'
        out.add_info(
            metric_name, 'gauge',
            'State of the services monitored by IPA healthcheck',
        )
        for service, state in data.items():
            out.add_data(metric_name, state, '%.1f', service=service)

    def generate_certificate_metrics(self, out, data):
        if not data:
            return

        metric_name = 'cert_expiration'
        out.add_info(
            metric_name,
            'gauge',
            'Expiration date of certificates in warning/error state',
        )
        for certificate, timestamp in data.items():
            out.add_data(
                metric_name, timestamp, '%.9e',
                certificate_request_id=certificate,
            )
