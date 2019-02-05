import pkg_resources
from idmcheck.core.plugin import Result, Results, JSON
from pprint import pprint

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
    results = Results()

    for name, registry in find_registries().items():
        registry.initialize(framework)
        print(name, registry)
        for plugin in find_plugins(name, registry):
            plugins.append(plugin)

    for plugin in plugins:
        try:
            result = plugin.check()
            if not isinstance(result, Result):
                # Treat no result as success
                result = Result(0)
            result.check = plugin.__class__.__name__
            result.source = plugin.__class__.__module__
            results.add(result)
        except Exception as e:
            print('Exception raised: %s', e)

    output = JSON()
    output.render(results)
