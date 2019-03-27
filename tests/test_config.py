#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import raises
from ipahealthcheck.core.config import Config, read_config
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
