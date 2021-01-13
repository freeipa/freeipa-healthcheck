#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from tests.base import BaseTest
from unittest.mock import Mock, patch
from tests.util import capture_results, CAInstance
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPAOpenSSLChainValidation

from ipapython.ipautil import _RunResult


class TestOpenSSLValidation(BaseTest):
    patches = {
        'ipaserver.install.cainstance.CAInstance':
        Mock(return_value=CAInstance()),
    }

    @patch('ipapython.ipautil.run')
    def test_openssl_validation_ok(self, mock_run):
        def run(args, raiseonerr=True):
            result = _RunResult('', '', 0)
            result.raw_output = bytes(
                '{}: OK'.format(args[-1]).encode('utf-8'))
            result.raw_error_output = b''
            return result

        mock_run.side_effect = run

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAOpenSSLChainValidation(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPAOpenSSLChainValidation'

    @patch('ipapython.ipautil.run')
    def test_openssl_validation_bad(self, mock_run):
        def run(args, raiseonerr=True):
            result = _RunResult('', '', 2)
            result.raw_output = bytes(
                'O = EXAMPLE.TEST, CN = ipa.example.test\n'
                'error 20 at 0 depth lookup: unable to get local issuer '
                'certificate\nerror {}: verification failed'.format(args[-1])
                .encode('utf-8'))
            result.raw_error_output = b''
            result.error_log = ''
            return result

        mock_run.side_effect = run

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAOpenSSLChainValidation(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2

        for result in self.results.results:
            assert result.result == constants.ERROR
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPAOpenSSLChainValidation'
            assert 'failed' in result.kw.get('msg')
