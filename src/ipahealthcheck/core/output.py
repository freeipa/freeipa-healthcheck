#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import json
import sys
from ipahealthcheck.core.constants import _nameToLevel, SUCCESS
from ipahealthcheck.core.plugin import Registry


class OutputRegistry(Registry):
    pass


output_registry = OutputRegistry()


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
        self.filename = options.outfile

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


@output_registry
class JSON(Output):
    """Output information in JSON format"""

    options = (
        ('--indent', dict(dest='indent', type=int, default=2,
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
