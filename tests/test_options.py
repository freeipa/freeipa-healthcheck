#
# Copyright (C) 2022 FreeIPA Contributors see COPYING for license
#

import argparse
import os
import tempfile
from unittest.mock import patch

from ipahealthcheck.core.core import RunChecks
from ipahealthcheck.core.plugin import Results

options = argparse.Namespace(check=None, source=None, debug=False,
                             indent=2, list_sources=False,
                             output_type='json', output_file=None,
                             verbose=False, version=False, config=None)


@patch('ipahealthcheck.core.core.run_service_plugins')
@patch('ipahealthcheck.core.core.run_plugins')
@patch('ipahealthcheck.core.core.parse_options')
def test_options_merge(mock_parse, mock_run, mock_service):
    """
    Test merging file-based and CLI options
    """
    mock_service.return_value = (Results(), [])
    mock_run.return_value = Results()
    mock_parse.return_value = options
    fd, config_path = tempfile.mkstemp()
    os.close(fd)
    with open(config_path, "w") as fd:
        fd.write('[default]\n')
        fd.write('output_type=human\n')
        fd.write('indent=5\n')

    try:
        run = RunChecks(['ipahealthcheck.registry'], config_path)

        run.run_healthcheck()

        # verify two valus that have defaults with our overriden values
        assert run.options.output_type == 'human'
        assert run.options.indent == 5
    finally:
        os.remove(config_path)
