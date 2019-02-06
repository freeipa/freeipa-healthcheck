from idmcheck.core.plugin import Plugin, Result
from idmcheck.dogtag.plugin import registry

@registry
class DogtagExample(Plugin):
    def check(self):
        print('Called check on', self)
        return Result(self, 0)
