import json
import sys
from idmcheck.core.constants import getLevelName
from idmcheck.core.plugin import Registry, json_to_results


class OutputRegistry(Registry):
    pass


output_registry = OutputRegistry()


class Output:
    def __init__(self, options):
        self.output_only = False

    def render(self, data):
        pass


@output_registry
class JSON(Output):
    """Output information in JSON format"""

    options = (
        ('--output-file', dict(dest='filename', help='File to store output')),
        ('--indent', dict(dest='indent', type=int, default=None,
         help='Indention level of JSON output')),
    )

    def __init__(self, options):
        super(JSON, self).__init__(options)
        self.filename = options.filename
        self.indent = options.indent

    def render(self, data):
        if self.filename:
            f = open(self.filename, 'w')
        else:
            f = sys.stdout

        output = [x for x in data.output()]
        f.write(json.dumps(output, indent=self.indent))

        # Ok, hacky, but using with and stdout will close stdout
        # which could be bad.
        if self.filename:
            f.close()


@output_registry
class Human(Output):
    """Display output in a more human-friendly way

    TODO: Use the logging module

    """
    options = (
        ('--input-file', dict(dest='infile', help='File to translate')),
    )

    def __init__(self, options):
        super(Human, self).__init__(options)
        self.filename = options.infile
        if self.filename:
            self.output_only = True

    def render(self, data):

        if self.filename:
            with open(self.filename, 'r') as f:
                raw_data = f.read()

            # caller catches exception
            json_data = json.loads(raw_data)
            data = json_to_results(json_data)

        for line in data.output():
            kw = line.get('kw')
            severity = line.get('severity')
            source = line.get('source')
            check = line.get('check')
            print('%s: %s.%s' % (getLevelName(severity), source, check),
                  end='')
            if 'key' in kw:
                print('.%s' % kw.get('key'), end='')
            if 'msg' in kw:
                print(': ', end='')
                msg = kw.get('msg')
                err = msg.format(**kw)
                print(err)
            elif 'exception' in kw:
                print(': ', end='')
                print('%s' % kw.get('exception'))
            else:
                print()
