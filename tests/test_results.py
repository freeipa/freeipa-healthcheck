from util import raises
from idmcheck.core.plugin import Registry, Plugin, Result, Results
from idmcheck.core import constants


def test_Result():
    """
    Test the `idmcheck.plugin.Result` class
    """

    registry = Registry()
    p = Plugin(registry)

    # Standard case of passing plugin to Result
    r = Result(p, constants.SUCCESS)

    kw = dict(key='value')
    r = Result(p, constants.SUCCESS, **kw)

    e = raises(TypeError, Result)
    assert str(e) == "__init__() missing 2 required positional arguments: " \
                     "'plugin' and 'severity'"

    # Test passing source and check to Result. This is used for loading
    # a previous output.
    try:
        r = Result(None, constants.SUCCESS)
    except TypeError as e:
        assert str(e) == "source and check or plugin must be provided"

    try:
        r = Result(None, constants.SUCCESS, source='test')
    except TypeError as e:
        assert str(e) == "source and check or plugin must be provided"

    try:
        r = Result(None, constants.SUCCESS, check='test')
    except TypeError as e:
        assert str(e) == "source and check or plugin must be provided"

    r = Result(None, constants.SUCCESS, source='test', check='test')

    # Test results
    r = Result(p, constants.SUCCESS)
    results = Results()
    results.add(r)

    assert len(results) == 1

    r = Result(p, constants.CRITICAL)
    results2 = Results()
    results2.add(r)

    assert len(results2) == 1

    results.extend(results2)

    assert len(results) == 2

    output = [x for x in results.output()]
    assert len(output) == 2
    for x in output:
        assert x['source'] == 'idmcheck.core.plugin'
        assert x['check'] == 'Plugin'
        assert x['severity'] in (constants.SUCCESS, constants.CRITICAL)
        assert len(x['kw']) == 0
