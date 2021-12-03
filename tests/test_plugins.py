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
    class plugin1(Plugin):
        def check(self):
            time.sleep(5)

    class plugin2(Plugin):
        def check(self):
            yield Result(self, constants.SUCCESS, key='test', msg='pass')

    # Create a registry
    r = Registry()

    # Register the plugins
    r(plugin1)
    r(plugin2)

    # Collect the results
    results = run_plugins(r.get_plugins(), (), None, None, timeout=1)

    assert len(results.results) == 2

    assert results.results[0].result == constants.ERROR
    assert results.results[0].kw.get('exception') == 'Request timed out'

    assert results.results[1].result == constants.SUCCESS
    assert results.results[1].kw.get('msg') == 'pass'
