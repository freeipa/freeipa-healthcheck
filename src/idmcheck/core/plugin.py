class Registry:
    def __init__(self):
        self.plugins = []
        self.framework = None

    def initialize(self, framework):
        self.framework = framework

    def __call__(self, cls):
        self.plugins.append(cls)
        return cls

    def get_plugins(self):
        for plugincls in self.plugins:
            yield plugincls(self)


class Plugin:
    def __init__(self, registry):
        self.registry = registry
