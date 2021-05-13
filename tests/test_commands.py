#
# Copyright (C) 2021 FreeIPA Contributors see COPYING for license
#

import os

from ipapython.ipautil import run


def test_version():
    """
    Test the --version option
    """
    output = run(['ipa-healthcheck', '--version'], env=os.environ)
    assert 'ipahealthcheck' in output.raw_output.decode('utf-8')
