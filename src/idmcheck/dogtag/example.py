from idmcheck.core.plugin import Plugin
from idmcheck.dogtag.plugin import registry

@registry
class DogtagExample(Plugin):
    def check(self):
        print('Called check on', self)

