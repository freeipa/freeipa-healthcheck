import pkg_resources

def find_registries():
    return {
        ep.name: ep.resolve()
        for ep in pkg_resources.iter_entry_points('idmcheck.registry')
    }


def find_plugins(name, registry):
    for ep in pkg_resources.iter_entry_points(name):
        # load module
        ep.load()
    return registry.get_plugins()

def main():
    framework = object()
    plugins = []

    for name, registry in find_registries().items():
        registry.initialize(framework)
        for plugin in find_plugins(name, registry):
            plugins.append(plugin)

    for plugin in plugins:
        plugin.check()
