#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import argparse
import json
import logging
import pkg_resources
import signal
import warnings
import traceback

from datetime import datetime

from ipahealthcheck.core.config import read_config
from ipahealthcheck.core.exceptions import TimeoutError
from ipahealthcheck.core.plugin import Result, Results, json_to_results
from ipahealthcheck.core.output import output_registry
from ipahealthcheck.core import constants
from ipahealthcheck.core.service import ServiceCheck

logging.basicConfig(format='%(message)s')
logger = logging.getLogger()


def find_registries(entry_points):
    # Loading the resources may reset the log level, save it.
    log_level = logger.level
    registries = {}
    for entry_point in entry_points:
        registries.update({
            ep.name: ep.resolve()
            for ep in pkg_resources.iter_entry_points(entry_point)
        })
    logger.setLevel(log_level)
    return registries


def find_plugins(name, registry):
    for ep in pkg_resources.iter_entry_points(name):
        # load module
        ep.load()
    return registry.get_plugins()


def run_plugin(plugin, available=(), timeout=constants.DEFAULT_TIMEOUT):
    def signal_handler(signum, frame):
        raise TimeoutError('Request timed out')

    # manually calculate duration when we create results of our own
    start = datetime.utcnow()
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(timeout)
    try:
        for result in plugin.check():
            if result is None:
                # Treat no result as success, fudge start time
                result = Result(plugin, constants.SUCCESS, start=start)
            yield result
    except TimeoutError as e:
        yield Result(plugin, constants.ERROR, exception=str(e),
                     start=start)
    except Exception as e:
        logger.debug('Exception raised: %s', e)
        logger.debug(traceback.format_exc())
        yield Result(plugin, constants.CRITICAL, exception=str(e),
                     traceback=traceback.format_exc(),
                     start=start)
    finally:
        signal.alarm(0)


def source_or_check_matches(plugin, source, check):
    """Determine whether a given a plugin matches if a source
       and optional check are provided.
    """
    if (
        source is not None and
        not _is_prefix_of_source(source, plugin.__module__)
    ):
        return False

    if check and plugin.__class__.__name__ != check:
        return False

    return True


def exclude_source_or_check(source, check, config):
    """Return True if a source or check should be excluded, otherwise False"""
    exclude_source = []
    exclude_check = []

    if 'excludes_source' in config:
        exclude_source = config.excludes_source
    if 'excludes_check' in config:
        exclude_check = config.excludes_check

    for exclude in exclude_source:
        if _is_prefix_of_source(exclude, source):
            return True

    for exclude in exclude_check:
        if exclude == check:
            return True

    return False


def run_service_plugins(plugins, source, check):
    """Execute plugins with the base class of ServiceCheck

       This is a specialized check to use systemd to determine
       if a service is running or not.
    """
    results = Results()
    available = []

    for plugin in plugins:
        if not isinstance(plugin, ServiceCheck):
            continue

        # Try to save some time to not check dependent services if the
        # parent is down.
        if not set(plugin.requires).issubset(available):
            # A required service is not available. Either it hasn't been
            # checked yet or it isn't running. If not running break.
            running = True
            for result in results.results:
                if result.check in plugin.requires:
                    # if not in available but in results the service failed
                    running = False
                    break
            if not running:
                logger.debug(
                    'Skipping %s:%s because %s service(s) not running',
                    plugin.__class__.__module__,
                    plugin.__class__.__name__,
                    ', '.join(set(plugin.requires) - set(available))
                )
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


def run_plugins(plugins, available, source, check,
                config, timeout=constants.DEFAULT_TIMEOUT):
    """Execute plugins without the base class of ServiceCheck

       These are the remaining, non-service checking checks
       that do validation for various parts of a system.
    """
    results = Results()

    for plugin in plugins:
        if isinstance(plugin, ServiceCheck):
            continue

        if exclude_source_or_check(
            plugin.__module__, plugin.__class__.__name__, config
        ):
            logger.debug("Excluding %s::%s per config",
                         plugin.__module__, plugin.__class__.__name__)
            continue
        if not source_or_check_matches(plugin, source, check):
            continue

        logger.debug("Calling check %s", plugin)
        if not set(plugin.requires).issubset(available):
            logger.debug('Skipping %s:%s because %s service(s) not running',
                         plugin.__class__.__module__,
                         plugin.__class__.__name__,
                         ', '.join(set(plugin.requires) - available))
            # Not providing a Result in this case because if a required
            # service isn't available then this could generate a lot of
            # false positives.
        else:
            for result in run_plugin(plugin, available, timeout):
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


def add_default_options(parser, output_registry, default_output):
    output_names = [plugin.__name__.lower() for
                    plugin in output_registry.plugins]
    parser.add_argument('--config', dest='config',
                        default=None, help='Config file to load')
    parser.add_argument('--verbose', dest='verbose', action='store_true',
                        default=False, help='Run in verbose mode')
    parser.add_argument('--debug', dest='debug', action='store_true',
                        default=False, help='Include debug output')
    parser.add_argument('--list-sources', dest='list_sources',
                        action='store_true', default=False,
                        help='List all available sources')
    parser.add_argument('--source', dest='source',
                        default=None,
                        help='Source of checks, e.g. foo.bar.baz')
    parser.add_argument('--check', dest='check',
                        default=None,
                        help='Check to execute, e.g. BazCheck')
    parser.add_argument('--output-type', dest='output_type',
                        choices=output_names,
                        default=default_output, help='Output method')
    parser.add_argument('--output-file', dest='output_file', default=None,
                        help='File to store output')
    parser.add_argument('--version', dest='version', action='store_true',
                        help='Report the version number and exit')


def add_output_options(parser, output_registry):
    for plugin in output_registry.plugins:
        onelinedoc = plugin.__doc__.split('\n\n', 1)[0].strip()
        group = parser.add_argument_group(plugin.__name__.lower(),
                                          onelinedoc)
        for option in plugin.options:
            group.add_argument(option[0], **option[1])


def parse_options(parser):
    options = parser.parse_args()

    # Validation
    if options.check and not options.source:
        print("--source is required when --check is used")
        return 1

    return options


def limit_results(results, source, check):
    """Return ony those results which match source and/or check"""
    new_results = Results()
    for result in results.results:
        if check is None:
            # treat 'source' as prefix
            if _is_prefix_of_source(source, result.source):
                new_results.add(result)
        else:
            # when 'check' is given, match source fully
            if result.source == source and result.check == check:
                new_results.add(result)
    return new_results


def exclude_keys(config, results):
    """Generate a new result, excluding unwanted keys"""
    new_results = Results()

    for result in results.results:
        if (
            'excludes_key' in config and
            result.kw.get("key") in config.excludes_key
        ):
            logger.debug("Excluding %s::%s::%s per config",
                         result.source, result.check, result.kw.get('key'))
        else:
            new_results.add(result)

    return new_results


def _is_prefix_of_source(prefix, source):
    prefix_parts = prefix.split('.')
    source_parts = source.split('.')
    return source_parts[:len(prefix_parts)] == prefix_parts


class RunChecks:
    def __init__(self, entry_points, configfile,
                 output_registry=output_registry,
                 default_output='json'):
        """Initialize class variables

          entry_points: A list of entry points to find plugins
          configfile: full path to the config file
          output_registry: registry containing the set of output
                           plugins to register.
          default_output: default output class
        """
        self.entry_points = entry_points
        self.configfile = configfile
        self.output_registry = output_registry
        self.default_output = default_output
        self.parser = argparse.ArgumentParser()
        self.options = None

    def pre_check(self):
        return None

    def add_options(self):
        """Add custom options for this check program"""

    def validate_options(self):
        """Validate options other than source and check"""
        return None

    def run_healthcheck(self):
        framework = object()
        plugins = []
        output = None

        logger.setLevel(logging.WARNING)

        add_default_options(self.parser, self.output_registry,
                            self.default_output)
        add_output_options(self.parser, self.output_registry)
        self.add_options()
        options = parse_options(self.parser)

        if options.version:
            for registry in self.entry_points:
                name = registry.split('.')[0]
                try:
                    version = pkg_resources.get_distribution(name).version
                except pkg_resources.DistributionNotFound:
                    continue
                print('%s: %s' % (name, version))
            return 0

        # pylint: disable=assignment-from-none
        rval = self.validate_options()
        # pylint: enable=assignment-from-none
        if rval is not None:
            return rval

        if options.config is not None:
            config = read_config(options.config)
        else:
            config = read_config(self.configfile)
        if config is None:
            return 1

        # Unify config and options. One of these variables will be
        # eventually deprecated in the future. This way all cli
        # options can be set in config instead.
        config.merge(vars(options))
        self.options = config
        options = config

        if options.verbose:
            logger.setLevel(logging.INFO)

        if options.debug:
            logger.setLevel(logging.DEBUG)

        # pylint: disable=assignment-from-none
        rval = self.pre_check()
        # pylint: enable=assignment-from-none
        if rval is not None:
            return rval

        # The pki checks are noisy if a CA is not configured so we
        # want to suppress that for IPA.
        #
        # There are 3 possible states:
        # 1. IPA is configured with a CA
        # 2. IPA is configured without a CA
        # 3. IPA is not configured
        #
        # If we have IPA configured without a CA then we want to skip
        # the pkihealthcheck plugins
        #
        # The IPA registry will set ca_configured in its registry to True
        # or False. We will skip the pkihealthcheck plugins only if
        # ca_configured is False which means that it was set by IPA. So
        # we initialize ca_configured to None so that the pki checks
        # will always be executed with pki-healthcheck.
        ca_configured = None
        for name, registry in find_registries(self.entry_points).items():
            try:
                registry.initialize(framework, config, options)
            except Exception as e:
                warnings.warn("Trying deprecated initialization API: %s" % e,
                              DeprecationWarning)
                try:
                    registry.initialize(framework, config)
                except Exception as e:
                    logger.error("Unable to initialize %s: %s", name, e)
                    continue
            if hasattr(registry, 'ca_configured'):
                ca_configured = registry.ca_configured
        for name, registry in find_registries(self.entry_points).items():
            if 'pkihealthcheck' in name and ca_configured is False:
                logger.debug('IPA CA is not configured, skipping %s', name)
                continue
            for plugin in find_plugins(name, registry):
                plugins.append(plugin)

        for out in self.output_registry.plugins:
            if out.__name__.lower() == options.output_type:
                output = out(options)
                break
        if output is None:
            print(f"Unknown output-type '{options.output_type}'")
            return 1

        if options.list_sources:
            return list_sources(plugins)

        if 'infile' in options and options.infile:
            try:
                with open(options.infile, 'r') as f:
                    raw_data = f.read()

                json_data = json.loads(raw_data)
                results = json_to_results(json_data)
                available = ()
            except Exception as e:
                print("Unable to import '%s': %s" % (options.infile, e))
                return 1
            if options.source:
                results = limit_results(results, options.source, options.check)
        else:
            results, available = run_service_plugins(plugins,
                                                     options.source,
                                                     options.check)
            results.extend(run_plugins(plugins, available,
                                       options.source, options.check, config,
                                       int(config.timeout)))

        if options.source and len(results.results) == 0:
            for plugin in plugins:
                if not source_or_check_matches(plugin, options.source,
                                               options.check):
                    continue

                if not set(plugin.requires).issubset(available):
                    print("Source '%s' is missing one or more requirements "
                          "'%s'" %
                          (options.source, ', '.join(plugin.requires)))
                    return 1

            if options.check:
                print("Check '%s' not found in Source '%s'" %
                      (options.check, options.source))
            else:
                print("Source '%s' not found" % options.source)
            return 1

        results = exclude_keys(config, results)

        try:
            output.render(results)
        except Exception as e:
            logger.error('Output raised %s: %s', e.__class__.__name__, e)

        return_value = 0
        for result in results.results:
            if result.result != constants.SUCCESS:
                return_value = 1
                break

        return return_value
