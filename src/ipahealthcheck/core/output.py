#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import json
from ipahealthcheck.core.constants import getLevelName, _nameToLevel, SUCCESS
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

       stdout == /dev/tty in this case. By using /dev/tty instead
       of sys.stdout we avoid worrying about closing the fd.

       An Output class only needs to implement the generate() method
       which will render the results into a string for writing.
    """
    def __init__(self, options):
        self.filename = options.outfile
        self.failures_only = options.failures_only
        self.severity = options.severity

    def render(self, results):
        """Process the results into output"""
        output = self.strip_output(results)
        output = self.generate(output)
        self.write_file(output)

    def write_file(self, output):
        """Write the output to a file or /dev/tty"""
        with open(self.filename, 'w') as fd:
            fd.write(output)

    def strip_output(self, results):
        """Strip out SUCCESS results if --failures-only or
           --severity was used

           Returns a list of result values.
        """
        output = []
        for line in results.output():
            result = line.get('result')
            if self.failures_only and _nameToLevel.get(result) == SUCCESS:
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
        pass


@output_registry
class JSON(Output):
    """Output information in JSON format"""

    options = (
        ('--indent', dict(dest='indent', type=int, default=2,
         help='Indention level of JSON output')),
    )

    def __init__(self, options):
        super(JSON, self).__init__(options)
        self.indent = options.indent

    def generate(self, data):
        output = json.dumps(data, indent=self.indent)
        if self.filename == '/dev/tty':
            output += '\n'

        return output


@output_registry
class Human(Output):
    """Display output in a more human-friendly way"""
    options = ()

    def __init__(self, options):
        super(Human, self).__init__(options)

    def generate(self, data):
        output = ''
        for line in data:
            kw = line.get('kw')
            result = line.get('result')
            source = line.get('source')
            check = line.get('check')
            outline = '%s: %s.%s' % (getLevelName(result), source, check)
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
