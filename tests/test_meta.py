#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from tests.base import BaseTest
from collections import namedtuple
from unittest.mock import patch
from tests.util import capture_results

from ipahealthcheck.core import config, constants
from ipahealthcheck.meta.plugin import registry
from ipahealthcheck.meta.core import MetaCheck
from ipapython import ipautil
from ipaplatform.paths import paths

if 'FIPS_MODE_SETUP' not in dir(paths):
    paths.FIPS_MODE_SETUP = '/usr/bin/fips-mode-setup'


class TestMetaFIPS(BaseTest):
    @patch('os.path.exists')
    def test_fips_no_fips_mode_setup(self, mock_exists):
        mock_exists.return_value = False

        framework = object()
        registry.initialize(framework, config.Config())
        f = MetaCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.meta.core'
        assert result.check == 'MetaCheck'
        assert result.kw.get('fips') == 'missing %s' % paths.FIPS_MODE_SETUP

    @patch('os.path.exists')
    @patch('ipapython.ipautil.run')
    def test_fips_disabled(self, mock_run, mock_exists):
        mock_exists.return_value = True

        run_result = namedtuple('run', ['returncode', 'raw_output'])
        run_result.returncode = 2
        run_result.raw_output = b''

        mock_run.return_value = run_result

        framework = object()
        registry.initialize(framework, config.Config())
        f = MetaCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.meta.core'
        assert result.check == 'MetaCheck'
        assert result.kw.get('fips') == 'disabled'

    @patch('os.path.exists')
    @patch('ipapython.ipautil.run')
    def test_fips_enabled(self, mock_run, mock_exists):
        mock_exists.return_value = True

        run_result = namedtuple('run', ['returncode', 'raw_output'])
        run_result.returncode = 0
        run_result.raw_output = b''

        mock_run.return_value = run_result

        framework = object()
        registry.initialize(framework, config.Config())
        f = MetaCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.meta.core'
        assert result.check == 'MetaCheck'
        assert result.kw.get('fips') == 'enabled'

    @patch('os.path.exists')
    @patch('ipapython.ipautil.run')
    def test_fips_inconsistent(self, mock_run, mock_exists):
        mock_exists.return_value = True

        run_result = namedtuple('run', ['returncode', 'raw_output'])
        run_result.returncode = 1
        run_result.raw_output = b''

        mock_run.return_value = run_result

        framework = object()
        registry.initialize(framework, config.Config())
        f = MetaCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.meta.core'
        assert result.check == 'MetaCheck'
        assert result.kw.get('fips') == 'inconsistent'

    @patch('os.path.exists')
    @patch('ipapython.ipautil.run')
    def test_fips_unknown(self, mock_run, mock_exists):
        mock_exists.return_value = True

        run_result = namedtuple('run', ['returncode', 'raw_output'])
        run_result.returncode = 103
        run_result.raw_output = b''

        mock_run.return_value = run_result

        framework = object()
        registry.initialize(framework, config.Config())
        f = MetaCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.meta.core'
        assert result.check == 'MetaCheck'
        assert result.kw.get('fips') == 'unknown'

    @patch('os.path.exists')
    @patch('ipapython.ipautil.run')
    def test_fips_failed(self, mock_run, mock_exists):
        mock_exists.return_value = True

        run_result = namedtuple('run', ['returncode', 'raw_output'])
        run_result.returncode = 103
        run_result.raw_output = b''

        mock_run.side_effect = ipautil.CalledProcessError(
           1, 'fips-mode-setup', output='execution failed'
        )

        framework = object()
        registry.initialize(framework, config.Config())
        f = MetaCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.meta.core'
        assert result.check == 'MetaCheck'
        assert result.kw.get('fips') == 'failed to check'
