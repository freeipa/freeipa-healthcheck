import json
import sys
from idmcheck.core.constants import getLevelName


class Registry:
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
    def __init__(self, registry):
        self.registry = registry
        self.requires = set()


class Result:
    """
    The result of a check.

    kw is meant to provide some level of flexibility to check authors
    but the following is a set of pre-defined keys that may be present:

        key: some checks can have multiple tests. This
             provides for uniqueuess.
        msg: A message that can take other keywords as input
        exception: used when a check raises an exception
    """
    def __init__(self, plugin, severity, **kw):
        self.severity = severity
        self.kw = kw
        self.check = plugin.__class__.__name__
        self.source = plugin.__class__.__module__

        assert getLevelName(severity) is not None

    def __repr__(self):
        return "%s.%s(%s): %s" % (self.source, self.check, self.kw,
                                  self.severity)


class Results:
    def __init__(self):
        self.results = []

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


class Output:
    def __init__(self):
        pass

    def render(self, data):
        pass


class JSON(Output):

    def __init__(self, filename=None):
        self.filename = filename

    def render(self, data):
        if self.filename:
            f = open(self.filename, 'w')
        else:
            f = sys.stdout

        output = [x for x in data.output()]
        f.write(json.dumps(output, indent=2))

        # Ok, hacky, but using with and stdout will close stdout
        # which could be bad.
        if self.filename:
            f.close()


class Human(Output):
    """Display output in a more human-friendly way

    TODO: Use the logging module

    """

    def render(self, data):

        for line in data.output():
            kw = line.get('kw')
            severity = line.get('severity')
            source = line.get('source')
            check = line.get('check')
            print('%s: %s.%s' % (getLevelName(severity), source, check),
                  end='')
            if 'key' in kw:
                print('.%s' % kw.get('key'), end='')
            if 'msg' in kw:
                print(': ', end='')
                msg = kw.get('msg')
                err = msg.format(**kw)
                print(err)
            elif 'exception' in kw:
                print(': ', end='')
                print('%s' % kw.get('exception'))
            else:
                print()
