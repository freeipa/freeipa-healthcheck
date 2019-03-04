#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.constants import getLevelName


class Registry:
    """
    A decorator that makes plugins available to the API

    Usage::

        register = Registry()

        @register()
        class some_plugin(...):
            ...
    """
    def __init__(self):
        self.plugins = []
        self.framework = None

    def initialize(self, framework):
        self.framework = framework

    def __call__(self, cls):
        if not callable(cls):
            raise TypeError('plugin must be callable; got %r' % cls)
        self.plugins.append(cls)
        return cls

    def get_plugins(self):
        for plugincls in self.plugins:
            yield plugincls(self)


class Plugin:
    """
    Base class for all plugins.

    registry defines where the plugin was registered, normally via
    a pkg_resource.

    requires is a set of strings that define pre-requisites for
    execution. Some output formats allow plugins that do not have
    these requirements met to skip them (JSON does NOT, all plugins
    are always executed and reported).

    Each Plugin should define a check() method that contains as
    simple a test as possible on the status a unique potential issue.

    A Plugin may return either Result for a single result or
    Results if multiple issues are discovered.

    It is strongly recommended to keep each Plugin as discrete as
    possible. This is not always possible or practical, for example
    to avoid hundreds of plugins that test nearly the same thing.

    Usage::

        register = Registry()

        @register()
        tmp_exists_check(Plugin)
            def check(self):
                if os.path.exists('/tmp'):
                    result = Result(self, SUCCESS)
                else:
                    result = Result(self, CRITICAL, path='/tmp',
                                    msg='Temporary directory is missing')

                return result

    """
    def __init__(self, registry):
        self.registry = registry
        self.requires = set()


class Result:
    """
    The result of a check.

    :param plugin: The plugin which generated the result.
    :param severity: A severity constant representing the level of error.
    :param source: If no plugin is passed then the name of the source
                   can be provided directly.
    :param check: If no plugin is passed then the name of the check
                   can be provided directly.
    :param kw: A dictionary of items providing insight in the error.

    Either both check and source need to be provided or plugin needs
    to be provided.

    kw is meant to provide some level of flexibility to check authors
    but the following is a set of pre-defined keys that may be present:

        key: some checks can have multiple tests. This
             provides for uniqueuess.
        msg: A message that can take other keywords as input
        exception: used when a check raises an exception
    """
    def __init__(self, plugin, severity, source=None, check=None, **kw):
        self.severity = severity
        self.kw = kw
        if None not in (check, source):
            self.check = check
            self.source = source
        else:
            if plugin is None:
                raise TypeError('source and check or plugin must be provided')
            self.check = plugin.__class__.__name__
            self.source = plugin.__class__.__module__

        assert getLevelName(severity) is not None

    def __repr__(self):
        return "%s.%s(%s): %s" % (self.source, self.check, self.kw,
                                  self.severity)


class Results:
    """
    A list-like collection of Result values.

    Provides a very limited subset of list operations.

    Usage::

        results = Results()

        result = Result(plugin, SUCCESS, **kw)
        results.add(result)
    """
    def __init__(self):
        self.results = []

    def __len__(self):
        return len(self.results)

    def add(self, result):
        assert isinstance(result, Result)
        self.results.append(result)

    def extend(self, results):
        assert isinstance(results, Results)
        self.results.extend(results.results)

    def output(self):
        for result in self.results:
            yield dict(source=result.source,
                       check=result.check,
                       severity=result.severity,
                       kw=result.kw)


def json_to_results(data):
    """
    Convert JSON data into a Results object.

    :param data: valid JSON input
    :returns: a Results object representing the JSON input
    """

    results = Results()

    for line in data:
        severity = line.pop('severity')
        source = line.pop('source')
        check = line.pop('check')
        result = Result(None, severity, source, check, **line)
        results.add(result)

    return results
