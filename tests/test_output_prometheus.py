#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import pytest
from util import assert_fixture

from ipahealthcheck.core import constants
from ipahealthcheck.core.output import Prometheus
from ipahealthcheck.core.plugin import Plugin, Registry, Result, Results


class OutputOptions:
    def __init__(self):
        self.__dict__ = {
            'all': True,
            'failures_only': False,
            'severity': None,
            'output_file': None,
            'metric_prefix': 'test',
        }

    def __iter__(self):
        return iter(self.__dict__)


@pytest.fixture
def check_results():
    registry = Registry()
    p = Plugin(registry)
    r = Result(p, constants.SUCCESS)
    f = Results()

    f.add(r)

    return f


@pytest.fixture
def output_options():
    o = OutputOptions()

    return o


def test_Prometheus(output_options, check_results, capsys):
    """
    Test the `ipahealthcheck.core.Prometheus` class
    """

    # Create an output
    p = Prometheus(output_options)

    p.render(check_results)

    captured = capsys.readouterr()

    assert_fixture(captured.out, 'output', 'prometheus', 'all.prom')
