#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import uuid
from datetime import datetime
from functools import wraps

from ipahealthcheck.core.constants import getLevelName


def duration(f):
    """Compute the duration of execution"""
    @wraps(f)
    def wrapper(*args, **kwds):
        start = datetime.utcnow()
        end = None
        for result in f(*args, **kwds):
            end = datetime.utcnow()
            dur = end - start
            result.duration = '%6.6f' % dur.total_seconds()
            yield result
        if end is None:
            # no results, yield None so a SUCCESS result will be created
            yield None
    return wrapper


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
        self.config = dict()
        self.options = None

    def initialize(self, framework, config, options=None):
        self.framework = framework
        self.config = config
        self.options = options

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

    requires is a tuple of strings that define pre-requisites for
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
    requires = ()

    def __init__(self, registry):
        self.registry = registry
        self.config = registry.config


class Result:
    """
    The result of a check.

    :param plugin: The plugin which generated the result.
    :param result: A result constant representing the level of error.
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
    def __init__(self, plugin, result, source=None, check=None,
                 start=None, duration=None, when=None, **kw):
        self.result = result
        self.kw = kw
        self.when = when or generalized_time(datetime.utcnow())
        self.duration = duration
        self.uuid = str(uuid.uuid4())
        if None not in (check, source):
            self.check = check
            self.source = source
        else:
            if plugin is None:
                raise TypeError('source and check or plugin must be provided')
            self.check = plugin.__class__.__name__
            self.source = plugin.__class__.__module__
        if start is not None:
            dur = datetime.utcnow() - start
            self.duration = '%6.6f' % dur.total_seconds()

        assert getLevelName(result) is not None

    def __repr__(self):
        return "%s.%s(%s): %s" % (self.source, self.check, self.kw,
                                  self.result)


class Results:
    """
    A list-like collection of Result values.

    Provides a very limited subset of list operations. Is intended for
    internal-use only and not by check functions.

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
                       result=getLevelName(result.result),
                       uuid=result.uuid,
                       when=result.when,
                       duration=result.duration,
                       kw=result.kw)


def json_to_results(data):
    """
    Convert JSON data into a Results object.

    :param data: valid JSON input
    :returns: a Results object representing the JSON input
    """

    results = Results()

    for line in data:
        result = line.pop('result')
        source = line.pop('source')
        check = line.pop('check')
        duration = line.pop('duration')
        when = line.pop('when')
        kw = line.pop('kw')
        result = Result(None, result, source, check, duration=duration,
                        when=when, **kw)
        results.add(result)

    return results


def generalized_time(intime):
    """Convert a datetime.datetime object to LDAP generalized time format

       :param intime: a datetime.datetime object
    """
    assert isinstance(intime, datetime)
    return intime.strftime('%Y%m%d%H%M%SZ')
