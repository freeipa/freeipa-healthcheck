#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import raises
from ipahealthcheck.core.plugin import Registry, Plugin, Result, Results
from ipahealthcheck.core import constants


def test_Result():
    """
    Test the `ipahealthcheck.plugin.Result` class
    """

    registry = Registry()
    p = Plugin(registry)

    # Standard case of passing plugin to Result
    r = Result(p, constants.SUCCESS)

    kw = dict(key='value')
    r = Result(p, constants.SUCCESS, **kw)

    e = raises(TypeError, Result)
    assert "__init__() missing 2 required positional arguments: " \
           "'plugin' and 'result'" in str(e)

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

    output = list(results.output())
    assert len(output) == 2
    for x in output:
        assert x['source'] == 'ipahealthcheck.core.plugin'
        assert x['check'] == 'Plugin'
        assert x['result'] in (constants.getLevelName(constants.SUCCESS),
                               constants.getLevelName(constants.CRITICAL))
        assert len(x['kw']) == 0


def test_getLevel():
    assert constants.getLevel('SUCCESS') == constants.SUCCESS
    assert constants.getLevel('WARNING') == constants.WARNING
    assert constants.getLevel('ERROR') == constants.ERROR
    assert constants.getLevel('CRITICAL') == constants.CRITICAL
    assert constants.getLevel('FOO') == 'FOO'


def test_Result_with_description():
    """Test Result with a plugin that has description set"""
    registry = Registry()

    class PluginWithDescription(Plugin):
        description = "This is a test description"

        def __init__(self, registry):
            super().__init__(registry)

    p = PluginWithDescription(registry)
    r = Result(p, constants.SUCCESS)

    assert r.description == "This is a test description"

    # Check that description appears in output
    results = Results()
    results.add(r)
    output = list(results.output())
    assert len(output) == 1
    assert 'description' in output[0]
    assert output[0]['description'] == "This is a test description"


def test_Result_without_description():
    """Test Result with a plugin that has no description"""
    registry = Registry()
    p = Plugin(registry)
    r = Result(p, constants.SUCCESS)

    assert r.description is None

    # Check that description does NOT appear in output
    results = Results()
    results.add(r)
    output = list(results.output())
    assert len(output) == 1
    assert 'description' not in output[0]


def test_Result_with_explicit_description():
    """Test Result created with source/check and explicit description"""
    r = Result(None, constants.SUCCESS, source='test.source',
               check='TestCheck', description='Explicit description')

    assert r.description == 'Explicit description'

    # Check that description appears in output
    results = Results()
    results.add(r)
    output = list(results.output())
    assert len(output) == 1
    assert 'description' in output[0]
    assert output[0]['description'] == 'Explicit description'


def test_json_to_results_with_description():
    """Test json_to_results() with description in input data"""
    from ipahealthcheck.core.plugin import json_to_results

    json_data = [
        {
            'source': 'test.source',
            'check': 'TestCheck',
            'result': 'SUCCESS',
            'uuid': '00000000-0000-0000-0000-000000000000',
            'when': '20250101000000Z',
            'duration': '0.000001',
            'description': 'Test description from JSON',
            'kw': {}
        }
    ]

    results = json_to_results(json_data)
    assert len(results.results) == 1
    assert results.results[0].description == 'Test description from JSON'

    # Check that description appears in output
    output = list(results.output())
    assert len(output) == 1
    assert 'description' in output[0]
    assert output[0]['description'] == 'Test description from JSON'


def test_json_to_results_without_description():
    """Test json_to_results() without description (backward compat)"""
    from ipahealthcheck.core.plugin import json_to_results

    json_data = [
        {
            'source': 'test.source',
            'check': 'TestCheck',
            'result': 'SUCCESS',
            'uuid': '00000000-0000-0000-0000-000000000000',
            'when': '20250101000000Z',
            'duration': '0.000001',
            'kw': {}
        }
    ]

    results = json_to_results(json_data)
    assert len(results.results) == 1
    assert results.results[0].description is None

    # Check that description does NOT appear in output
    output = list(results.output())
    assert len(output) == 1
    assert 'description' not in output[0]
