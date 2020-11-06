#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import tempfile

import pytest

from ipahealthcheck.core.config import read_config


def test_config_no_section():
    with tempfile.NamedTemporaryFile('w') as f:
        f.write('\n')
        f.flush()

        config = read_config(f.name)

    assert config is None


def test_config_bad_format():
    with tempfile.NamedTemporaryFile('w') as f:
        f.write('bad\n')

        config = read_config(f.name)
        f.flush()

    assert config is None


def test_config_values():
    with tempfile.NamedTemporaryFile('w') as f:
        f.write('[default]\nfoo = bar\n')
        f.flush()

        config = read_config(f.name)

    assert config.foo == 'bar'

    with pytest.raises(KeyError):
        config.bar  # pylint: disable=pointless-statement


def test_config_recursion():
    with tempfile.NamedTemporaryFile('w') as f:
        f.write('[default]\nfoo = bar\n')
        f.flush()

        config = read_config(f.name)

    assert config.foo == 'bar'

    # The config dict is in the object
    assert isinstance(config._Config__d, dict)

    # But it isn't recursive
    try:
        config._Config__d['_Config__d']
    except KeyError:
        pass
