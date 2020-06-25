#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.config import read_config
import tempfile


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

    try:
        config.bar
    except KeyError:
        pass
    else:
        assert('KeyError not raised')


def test_config_recursion():
    with tempfile.NamedTemporaryFile('w') as f:
        f.write('[default]\nfoo = bar\n')
        f.flush()

        config = read_config(f.name)

    assert config.foo == 'bar'

    # The config dict is in the object
    config._Config__d

    # But it isn't recursive
    try:
        config._Config__d['_Config__d']
    except KeyError:
        pass
