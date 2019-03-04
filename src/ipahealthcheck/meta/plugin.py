from ipahealthcheck.core.plugin import Plugin, Registry


class MetaPlugin(Plugin):
    pass


class MetaRegistry(Registry):
    pass


registry = MetaRegistry()
