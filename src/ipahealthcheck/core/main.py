#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import argparse
import json
import logging
from os import environ
import pkg_resources
import sys

from datetime import datetime

from ipahealthcheck.core.config import read_config
from ipahealthcheck.core.plugin import Result, Results, json_to_results
from ipahealthcheck.core.output import output_registry
from ipahealthcheck.core import constants

logging.basicConfig(format='%(message)s')
logger = logging.getLogger()

try:
    from ipaserver.install.installutils import is_ipa_configured
except ImportError:
    logging.error("IPA server packages are not installed on this system.")
    sys.exit(1)
else:
    from ipahealthcheck.meta.services import ServiceCheck


def find_registries():
    return {
        ep.name: ep.resolve()
        for ep in pkg_resources.iter_entry_points('ipahealthcheck.registry')
    }


def find_plugins(name, registry):
    for ep in pkg_resources.iter_entry_points(name):
        # load module
        ep.load()
    return registry.get_plugins()


def run_plugin(plugin, available=()):
    # manually calculate duration when we create results of our own
    start = datetime.utcnow()
    try:
        for result in plugin.check():
            if result is None:
                # Treat no result as success, fudge start time
                result = Result(plugin, constants.SUCCESS, start=start)
            yield result
    except Exception as e:
        logger.debug('Exception raised: %s', e)
        yield Result(plugin, constants.CRITICAL, exception=str(e),
                     start=start)


def source_or_check_matches(plugin, source, check):
    """Determine whether a given a plugin matches if a source
       and optional check are provided.
    """
    if source is not None and plugin.__module__ != source:
        return False

    if check and plugin.__class__.__name__ != check:
        return False

    return True


def run_service_plugins(plugins, config, source, check):
    """Execute plugins with the base class of ServiceCheck

       This is a specialized check to use systemd to determine
       if a service is running or not.
    """
    results = Results()
    available = []

    for plugin in plugins:
        if not isinstance(plugin, ServiceCheck):
            continue

        logger.debug('Calling check %s', plugin)
        for result in plugin.check():
            # always run the service checks so dependencies work
            if result is not None and result.result == constants.SUCCESS:
                available.append(plugin.service.service_name)
            if not source_or_check_matches(plugin, source, check):
                continue
            if result is not None:
                results.add(result)

    return results, set(available)


def run_plugins(plugins, config, available, source, check):
    """Execute plugins without the base class of ServiceCheck

       These are the remaining, non-service checking checks
       that do validation for various parts of a system.
    """
    results = Results()

    for plugin in plugins:
        if isinstance(plugin, ServiceCheck):
            continue

        if not source_or_check_matches(plugin, source, check):
            continue

        logger.debug('Calling check %s' % plugin)
        plugin.config = config
        if not set(plugin.requires).issubset(available):
            logger.debug('Skipping %s:%s because %s service(s) not running',
                         plugin.__class__.__module__,
                         plugin.__class__.__name__,
                         ', '.join(set(plugin.requires) - available))
            # Not providing a Result in this case because if a required
            # service isn't available then this could generate a lot of
            # false positives.
        else:
            for result in run_plugin(plugin, available):
                results.add(result)

    return results


def list_sources(plugins):
    """Print list of all sources and checks"""
    source = None
    for plugin in plugins:
        if source != plugin.__class__.__module__:
            print(plugin.__class__.__module__)
            source = plugin.__class__.__module__
        print("  ", plugin.__class__.__name__)

    return 0


def parse_options(output_registry):
    output_names = [plugin.__name__.lower() for
                    plugin in output_registry.plugins]
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', dest='debug', action='store_true',
                        default=False, help='Include debug output')
    parser.add_argument('--list-sources', dest='list_sources',
                        action='store_true', default=False,
                        help='List all available sources')
    parser.add_argument('--source', dest='source',
                        default=None,
                        help='Source of checks, e.g. ipahealthcheck.foo.bar')
    parser.add_argument('--check', dest='check',
                        default=None,
                        help='Check to execute, e.g. BazCheck')
    parser.add_argument('--output-type', dest='output', choices=output_names,
                        default='json', help='Output method')
    parser.add_argument('--output-file', dest='outfile', default='/dev/tty',
                        help='File to store output')
    parser.add_argument('--input-file', dest='infile',
                        help='File to read as input')
    parser.add_argument('--failures-only', dest='failures_only',
                        action='store_true', default=False,
                        help='Exclude SUCCESS result on output')
    for plugin in output_registry.plugins:
        onelinedoc = plugin.__doc__.split('\n\n', 1)[0].strip()
        group = parser.add_argument_group(plugin.__name__.lower(),
                                          onelinedoc)
        for option in plugin.options:
            group.add_argument(option[0], **option[1])

    options = parser.parse_args()

    # Validation
    if options.check and not options.source:
        print("--source is required when --check is used")
        sys.exit(1)

    return options


def limit_results(results, source, check):
    """Return ony those results which match source and/or check"""
    new_results = Results()
    for result in results.results:
        if result.source == source:
            if check is None or result.check == check:
                new_results.add(result)
    return new_results


def main():
    environ["KRB5_CLIENT_KTNAME"] = "/etc/krb5.keytab"
    environ["KRB5CCNAME"] = "MEMORY:"
    framework = object()
    plugins = []
    output = constants.DEFAULT_OUTPUT

    logger.setLevel(logging.INFO)

    options = parse_options(output_registry)

    if options.debug:
        logger.setLevel(logging.DEBUG)

    config = read_config()
    if config is None:
        sys.exit(1)

    if not (
        options.source or options.list_sources
    ) and not is_ipa_configured():
        logging.error("IPA is not configured on this system.")
        sys.exit(1)

    for name, registry in find_registries().items():
        try:
            registry.initialize(framework)
        except Exception as e:
            print("Unable to initialize %s: %s" % (name, e))
            sys.exit(1)
        for plugin in find_plugins(name, registry):
            plugins.append(plugin)

    for out in output_registry.plugins:
        if out.__name__.lower() == options.output:
            output = out(options)

    if options.list_sources:
        return list_sources(plugins)

    if options.infile:
        try:
            with open(options.infile, 'r') as f:
                raw_data = f.read()

            json_data = json.loads(raw_data)
            results = json_to_results(json_data)
            available = ()
        except Exception as e:
            print("Unable to import '%s': %s" % (options.infile, e))
            sys.exit(1)
        if options.source:
            results = limit_results(results, options.source, options.check)
    else:
        results, available = run_service_plugins(plugins, config,
                                                 options.source,
                                                 options.check)
        results.extend(run_plugins(plugins, config, available,
                                   options.source, options.check))

    if options.source and len(results.results) == 0:
        if options.check:
            print("Check '%s' not found in Source '%s'" %
                  (options.check, options.source))
        else:
            print("Source '%s' not found" % options.source)
        sys.exit(1)

    try:
        output.render(results)
    except Exception as e:
        logger.error('Output raised %s: %s', e.__class__.__name__, e)

    return_value = 0
    for result in results.results:
        if result.result != constants.SUCCESS:
            return_value = 1
            break

    sys.exit(return_value)
