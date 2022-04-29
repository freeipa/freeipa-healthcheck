#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import tempfile

import pytest

from ipahealthcheck.core.config import read_config, convert_string


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


def test_convert_string():
    for value in ("s", "string", "BiggerString"):
        assert convert_string(value) == value

    for value in ("True", "true", True):
        assert convert_string(value) is True

    for value in ("False", "false", False):
        assert convert_string(value) is False

    for value in ("10", "99999", 807):
        assert convert_string(value) == int(value)
