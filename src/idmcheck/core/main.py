import argparse
import pkg_resources
from idmcheck.core.plugin import Result, Results
from idmcheck.core.output import output_registry, JSON, Human
from idmcheck.core import constants
from idmcheck.meta.services import ServiceCheck


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


def run_plugin(plugin, available=()):
    try:
        result = plugin.check()
        if type(result) not in (Result, Results):
            # Treat no result as success
            result = Result(plugin, constants.SUCCESS)
    except Exception as e:
        print('Exception raised: %s', e)
        result = Result(plugin, constants.CRITICAL, exception=str(e))

    return result


def run_service_plugins(plugins):
    results = Results()
    available = []

    for plugin in plugins:
        if not isinstance(plugin, ServiceCheck):
            continue

        result = run_plugin(plugin)

        if result.severity == constants.SUCCESS:
            available.append(plugin.service_name)

        if isinstance(result, Result):
            results.add(result)
        elif isinstance(result, Results):
            results.extend(result)

    return results, set(available)


def run_plugins(plugins, available):
    results = Results()

    for plugin in plugins:
        if isinstance(plugin, ServiceCheck):
            continue

        # TODO: make this not the default
        if not set(plugin.requires).issubset(available):
            result = Result(plugin, constants.ERROR,
                            msg='%s service(s) not running' %
                            (', '.join(set(plugin.requires) - available)))
        else:
            result = run_plugin(plugin, available)

        if isinstance(result, Result):
            results.add(result)
        elif isinstance(result, Results):
            results.extend(result)

    return results


def parse_options(output_registry):
    output_names = [plugin.__name__.lower() for
                    plugin in output_registry.plugins]
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-type', dest='output', choices=output_names,
                        default='json', help='Output method')
    parser.add_argument('--no-success', dest='success', action='store_true',
                        default=False,
                        help='Include SUCCESS level on output')
    for plugin in output_registry.plugins:
        onelinedoc = plugin.__doc__.split('\n\n', 1)[0].strip()
        group = parser.add_argument_group(plugin.__name__.lower(),
                                          onelinedoc)
        for option in plugin.options:
            group.add_argument(option[0], **option[1])

    options = parser.parse_args()

    return options


def main():
    framework = object()
    plugins = []

    output_names = [plugin.__name__.lower() for
                    plugin in output_registry.plugins]
    options = parse_options(output_registry)

    for name, registry in find_registries().items():
        registry.initialize(framework)
        print(name, registry)
        for plugin in find_plugins(name, registry):
            plugins.append(plugin)

    results, available = run_service_plugins(plugins)
    results.extend(run_plugins(plugins, available))

    for out in output_registry.plugins:
        if out.__name__.lower() == options.output:
            output = out(options)
            output.render(results)
