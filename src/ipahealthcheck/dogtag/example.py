from ipahealthcheck.core.plugin import Plugin, Result
from ipahealthcheck.dogtag.plugin import registry


@registry
class DogtagExample(Plugin):
    def __init__(self, registry):
        super(DogtagExample, self).__init__(registry)
        self.requires = ('foo', 'bar')

    def check(self):
        return Result(self, 0)
