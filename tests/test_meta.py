#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from collections import namedtuple
from unittest.mock import patch
from util import capture_results

from ipahealthcheck.core import config, constants
from ipahealthcheck.meta.plugin import registry
from ipahealthcheck.meta.core import MetaCheck
from ipaplatform.paths import paths

if 'PROC_FIPS_ENABLED' not in dir(paths):
    paths.PROC_FIPS_ENABLED = '/proc/sys/crypto/fips_enabled'


def gen_result(returncode, output='', error=''):
    """
    Generate the result of an execution.

    Creates a run namespace and sets the output as provided.
    """
    run_result = namedtuple(
        'run', ['returncode', 'raw_output', 'output_log', 'error_log']
    )
    run_result.returncode = returncode
    run_result.raw_output = output.encode('utf-8')
    run_result.output_log = output
    run_result.error_log = error

    return run_result


class TestMetaFIPS(BaseTest):
    @patch('os.path.exists')
    def test_fips_no_fips_enabled(self, mock_exists):
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
        assert result.kw.get('fips') == 'missing %s' % paths.PROC_FIPS_ENABLED

    @patch('os.path.exists')
    @patch('pathlib.Path.read_text')
    @patch('ipapython.ipautil.run')
    def test_fips_disabled(self, mock_run, mock_result, mock_exists):
        mock_exists.return_value = True
        mock_result.return_value = '0'

        mock_run.side_effect = [
            gen_result(0, output='ACME is disabled'),
        ]

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
    @patch('pathlib.Path.read_text')
    @patch('ipapython.ipautil.run')
    def test_fips_enabled(self, mock_run, mock_result, mock_exists):
        mock_exists.return_value = True
        mock_result.return_value = '1'

        mock_run.side_effect = [
            gen_result(0, output='ACME is disabled'),
        ]

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
    @patch('pathlib.Path.read_text')
    @patch('ipapython.ipautil.run')
    def test_fips_unknown(self, mock_run, mock_result, mock_exists):
        mock_exists.return_value = True
        mock_result.return_value = '2'

        mock_run.side_effect = [
            gen_result(0, output='ACME is disabled'),
        ]

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
    @patch('pathlib.Path.read_text')
    @patch('ipapython.ipautil.run')
    def test_fips_non_numeric(self, mock_run, mock_result, mock_exists):
        mock_exists.return_value = True
        mock_result.return_value = 'test'

        mock_run.side_effect = [
            gen_result(0, output='ACME is disabled'),
        ]

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

    @patch('os.path.exists')
    @patch('pathlib.Path.read_text')
    @patch('ipapython.ipautil.run')
    def test_fips_failed(self, mock_run, mock_result, mock_exists):
        mock_exists.return_value = True

        mock_result.side_effect = [
            gen_result(constants.ERROR, output="failed to check"),
        ]

        mock_run.side_effect = [
            gen_result(0, output='ACME is disabled'),
        ]

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


class TestMetaACME(BaseTest):
    @patch('os.path.exists')
    def test_acme_no_ipa_acme_status(self, mock_exists):
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
        assert result.kw.get('acme') == \
            'missing %s' % '/usr/sbin/ipa-acme-manage'

    @patch('os.path.exists')
    @patch('pathlib.Path.read_text')
    @patch('ipapython.ipautil.run')
    def test_acme_disabled(self, mock_run, mock_result, mock_exists):
        mock_exists.return_value = True
        mock_result.return_value = '1'

        mock_run.side_effect = [
            gen_result(0, output='ACME is disabled'),
        ]

        framework = object()
        registry.initialize(framework, config.Config())
        f = MetaCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.meta.core'
        assert result.check == 'MetaCheck'
        assert result.kw.get('acme') == 'disabled'

    @patch('os.path.exists')
    @patch('pathlib.Path.read_text')
    @patch('ipapython.ipautil.run')
    def test_acme_enabled(self, mock_run, mock_result, mock_exists):
        mock_exists.return_value = True
        mock_result.return_value = '1'

        mock_run.side_effect = [
            gen_result(0, output='ACME is enabled'),
        ]

        framework = object()
        registry.initialize(framework, config.Config())
        f = MetaCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.meta.core'
        assert result.check == 'MetaCheck'
        assert result.kw.get('acme') == 'enabled'

    @patch('os.path.exists')
    @patch('pathlib.Path.read_text')
    @patch('ipapython.ipautil.run')
    def test_acme_unknown(self, mock_run, mock_result, mock_exists):
        mock_exists.return_value = True
        mock_result.return_value = '1'

        mock_run.side_effect = [
            gen_result(
                0,
                error="cannot connect to 'https://somewhere/acme/login"
            ),
        ]

        framework = object()
        registry.initialize(framework, config.Config())
        f = MetaCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.meta.core'
        assert result.check == 'MetaCheck'
        assert result.kw.get('acme') == 'unknown'
