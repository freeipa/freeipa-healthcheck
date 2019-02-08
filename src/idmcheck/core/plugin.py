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


class Result:
    def __init__(self, plugin, severity, **kw):
        self.severity = severity
        self.kw = kw
        self.check = plugin.__class__.__name__
        self.source = plugin.__class__.__module__


    def __repr__(self):
        return "%s.%s(%s): %s" % (self.source, self.check, self.kw, self.severity)


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


import json
import sys

class JSON(Output):

    def __init__(self, filename = None):
        self.filename = filename

    def render(self, data):
        if self.filename:
           f = open(self.filename, 'w')
        else:
           f = sys.stdout

        output =  [x for x in data.output()]
        f.write(json.dumps(output, indent=2))

        # Ok, hacky, but using with and stdout will close stdout
        # which could be bad.
        if self.filename:
            f.close()
