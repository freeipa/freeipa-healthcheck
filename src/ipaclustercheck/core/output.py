#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import json
from ipahealthcheck.core.output import OutputRegistry, Output


output_registry = OutputRegistry()

class ClusterOutput(Output):
    """Base class for writing/display output of cluster results

       severity doesn't apply in this case so exclude those.
    """
    def __init__(self, options):
        self.filename = options.outfile

    def strip_output(self, results):
        """Nothing to strip out"""
        return [result for result in results.output()]


@output_registry
class Ansible(ClusterOutput):
    """Output information JSON format for consumption by Ansible

       Required keywords in a Result:
       name - unique identifier for the return value

       One of these is required:
       value - the return value. Type? I dunno yet
       error - if an error was returned
    """

    options = (
        ('--indent', dict(dest='indent', type=int, default=2,
         help='Indention level of JSON output')),
    )

    def __init__(self, options):
        super().__init__(options)
        self.indent = options.indent

    def generate(self, data):
        output = []
        for line in data:
            kw = line.get('kw')
            name = kw.get('name')
            value = kw.get('value')
            error = kw.get('error')

            if value and error:
                value = '%s: %s' % (error, value)
            elif error:
                value = error

            rval = {'%s' % name: value}
            output.append(rval)
            
        output = json.dumps(output, indent=self.indent)
        if self.filename is None:
            output += '\n'

        return output
