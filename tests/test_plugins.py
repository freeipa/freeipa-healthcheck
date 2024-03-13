#
# Copyright (C) 2021 FreeIPA Contributors see COPYING for license
#

import time

from ipahealthcheck.core.plugin import Plugin, Registry, Result
from ipahealthcheck.core.core import run_plugins
from ipahealthcheck.core import constants


def test_timeout():
    """
    Test that timeouts are detected.
    """
    class plugin_slow_passing_exception_up(Plugin):
        '''
        Some plugins will not catch unexpected exceptions, and they will be
        passed up to the caller.
        '''
        def check(self):
            time.sleep(5)

    class plugin_slow_catching_exception_and_ignoring(Plugin):
        '''
        Some plugins will catch unexpected exceptions and handle them in
        unpredictable ways, such as ignoring them.
        '''
        def check(self):
            try:
                time.sleep(5)
            except Exception:
                pass
            return  # ugly syntax to let us yield no results
            yield

    class plugin_slow_catching_exception_and_handling(Plugin):
        '''
        Some plugins will catch unexpected exceptions but handle them
        sanely, such as by yielding an error result.

        In this case, the user will get two failure results; one from
        the plugin itself, and one from the exception handler.
        '''
        def check(self):
            try:
                time.sleep(5)
            except Exception as e:
                yield Result(
                    self, constants.ERROR,
                    key='test', msg='fail',
                    exception=str(e)
                )

    class plugin_slow_raising_exception(Plugin):
        '''
        Some plugins will catch unexpected exceptions and handle them in
        unpredictable ways, such as raising their own exception.

        The user will get one failure result, from the exception handler.
        '''
        def check(self):
            try:
                time.sleep(5)
            except Exception:
                raise Exception("I didn't expect an exception to be thrown")

    class plugin_fast(Plugin):
        def check(self):
            yield Result(self, constants.SUCCESS, key='test', msg='pass')

    # Create a registry
    r = Registry()

    # Register the plugins
    r(plugin_slow_passing_exception_up)
    r(plugin_slow_catching_exception_and_ignoring)
    r(plugin_slow_catching_exception_and_handling)
    r(plugin_slow_raising_exception)
    r(plugin_fast)

    # Collect the results
    results = run_plugins(r.get_plugins(), (), None, None, {}, timeout=1)

    assert 7 == len(results.results)

    assert results.results[0].kw.get('exception') == 'Check' \
        ' test_plugins:plugin_slow_passing_exception_up' \
        ' cancelled after 1 sec'
    assert results.results[0].result == constants.CRITICAL
    assert results.results[0].kw.get('key') == 'healthcheck_timeout'

    assert results.results[1].kw.get('exception') == 'Check' \
        ' test_plugins:plugin_slow_catching_exception_and_ignoring' \
        ' cancelled after 1 sec'
    assert results.results[1].result == constants.CRITICAL
    assert results.results[1].kw.get('key') == 'healthcheck_timeout'

    assert results.results[2].kw.get('exception') == 'Check' \
        ' test_plugins:plugin_slow_catching_exception_and_handling' \
        ' cancelled after 1 sec'
    assert results.results[2].result == constants.ERROR
    assert results.results[2].kw.get('msg') == 'fail'
    assert results.results[2].kw.get('key') == 'test'

    assert results.results[3].kw.get('exception') == 'Check' \
        ' test_plugins:plugin_slow_catching_exception_and_handling' \
        ' cancelled after 1 sec'
    assert results.results[3].result == constants.CRITICAL
    assert results.results[3].kw.get('key') == 'healthcheck_timeout'

    assert results.results[4].kw.get('exception') == "I didn't expect an" \
        " exception to be thrown"
    assert results.results[4].result == constants.CRITICAL
    assert not results.results[4].kw.get('key')

    assert results.results[5].kw.get('exception') == 'Check' \
        ' test_plugins:plugin_slow_raising_exception cancelled after 1 sec'
    assert results.results[5].result == constants.CRITICAL
    assert results.results[5].kw.get('key') == 'healthcheck_timeout'

    assert results.results[6].kw.get('msg') == 'pass'
    assert not results.results[6].kw.get('exception')
    assert results.results[6].result == constants.SUCCESS
    assert results.results[6].kw.get('key') == 'test'
