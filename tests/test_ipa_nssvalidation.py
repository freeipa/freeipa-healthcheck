#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from unittest.mock import Mock, patch
from util import capture_results, CAInstance
from ipapython.ipautil import _RunResult

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPANSSChainValidation


class DsInstance:
    def get_server_cert_nickname(self, serverid):
        return 'Server-Cert'


class TestNSSValidation(BaseTest):
    patches = {
        'ipaserver.install.installutils.check_server_configuration':
        Mock(return_value=None),
        'ipahealthcheck.ipa.certs.get_dogtag_cert_password':
        Mock(return_value='foo'),
        'ipaserver.install.dsinstance.DsInstance':
        Mock(return_value=DsInstance()),
    }

    @patch('ipaserver.install.cainstance.CAInstance')
    @patch('ipapython.ipautil.run')
    def test_nss_validation_ok(self, mock_run, mock_cainstance):
        def run(args, raiseonerr=True):
            result = _RunResult('', '', 0)
            result.raw_output = b'certutil: certificate is valid\n'
            result.raw_error_output = b''
            return result

        mock_run.side_effect = run
        mock_cainstance.return_value = CAInstance()

        framework = object()
        registry.initialize(framework)
        f = IPANSSChainValidation(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 2

        for result in self.results.results:
            assert result.severity == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPANSSChainValidation'

    @patch('ipaserver.install.cainstance.CAInstance')
    @patch('ipapython.ipautil.run')
    def test_nss_validation_bad(self, mock_run, mock_cainstance):
        def run(args, raiseonerr=True):
            result = _RunResult('', '', 255)
            result.raw_output = str.encode(
                'certutil: certificate is invalid: Peer\'s certificate issuer '
                'has been marked as not trusted by the user.'
            )
            result.raw_error_output = b''
            result.error_log = ''
            return result

        mock_run.side_effect = run
        mock_cainstance.return_value = CAInstance()

        framework = object()
        registry.initialize(framework)
        f = IPANSSChainValidation(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 2

        for result in self.results.results:
            assert result.severity == constants.ERROR
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPANSSChainValidation'

    @patch('ipaserver.install.cainstance.CAInstance')
    @patch('ipapython.ipautil.run')
    def test_nss_validation_ok_no_ca(self, mock_run, mock_cainstance):
        """Test with the CA marked as not configured so there should only
           be a DS certificate to check.
        """
        def run(args, raiseonerr=True):
            result = _RunResult('', '', 0)
            result.raw_output = b'certutil: certificate is valid\n'
            result.raw_error_output = b''
            return result

        mock_run.side_effect = run
        mock_cainstance.return_value = CAInstance(False)

        framework = object()
        registry.initialize(framework)
        f = IPANSSChainValidation(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 1

        for result in self.results.results:
            assert result.severity == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPANSSChainValidation'
            assert 'slapd-' in result.kw.get('key')
