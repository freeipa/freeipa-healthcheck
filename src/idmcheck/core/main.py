import pkg_resources
from idmcheck.core.plugin import Result, Results, JSON
from idmcheck.core import constants
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
            if type(result) not in (Result, Results):
                # Treat no result as success
                result = Result(plugin, constants.SUCCESS)
        except Exception as e:
            print('Exception raised: %s', e)
            result = Result(plugin, constants.CRITICAL, exception=str(e))

        if isinstance(result, Result):
            results.add(result)
        elif isinstance(result, Results):
            results.extend(result)

    output = JSON()
    output.render(results)
