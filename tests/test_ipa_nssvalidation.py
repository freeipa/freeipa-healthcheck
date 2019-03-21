#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPANSSChainValidation
from unittest.mock import patch
from util import capture_results, CAInstance

from ipapython.ipautil import _RunResult


class DsInstance:
    def get_server_cert_nickname(self, serverid):
        return 'Server-Cert'


@patch('ipahealthcheck.ipa.certs.get_dogtag_cert_password')
@patch('ipaserver.install.dsinstance.DsInstance')
@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipapython.ipautil.run')
def test_nss_validation_ok(mock_run,
                           mock_cainstance,
                           mock_dsinstance,
                           mock_get_dogtag_cert_password):

    def run(args, raiseonerr=True):
        result = _RunResult('', '', 0)
        result.raw_output = b'certutil: certificate is valid\n'
        result.raw_error_output = b''
        return result

    mock_cainstance.return_value = CAInstance()
    mock_dsinstance.return_value = DsInstance()
    mock_run.side_effect = run
    mock_get_dogtag_cert_password.return_value = 'foo'

    framework = object()
    registry.initialize(framework)
    f = IPANSSChainValidation(registry)

    f.config = config.Config()
    results = capture_results(f)

    assert len(results) == 2

    for result in results.results:
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPANSSChainValidation'


@patch('ipahealthcheck.ipa.certs.get_dogtag_cert_password')
@patch('ipaserver.install.dsinstance.DsInstance')
@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipapython.ipautil.run')
def test_nss_validation_bad(mock_run,
                            mock_cainstance,
                            mock_dsinstance,
                            mock_get_dogtag_cert_password):

    def run(args, raiseonerr=True):
        result = _RunResult('', '', 255)
        result.raw_output = str.encode(
            'certutil: certificate is invalid: Peer\'s certificate issuer '
            'has been marked as not trusted by the user.'
        )
        result.raw_error_output = b''
        result.error_log = ''
        return result

    mock_cainstance.return_value = CAInstance()
    mock_dsinstance.return_value = DsInstance()
    mock_run.side_effect = run
    mock_get_dogtag_cert_password.return_value = 'foo'

    framework = object()
    registry.initialize(framework)
    f = IPANSSChainValidation(registry)

    f.config = config.Config()
    results = capture_results(f)

    assert len(results) == 2

    for result in results.results:
        assert result.severity == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPANSSChainValidation'


@patch('ipaserver.install.dsinstance.DsInstance')
@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipapython.ipautil.run')
def test_nss_validation_ok_no_ca(mock_run,
                                 mock_cainstance,
                                 mock_dsinstance):
    """Test with the CA marked as not configured so there should only
       be a DS certificate to check.
    """

    def run(args, raiseonerr=True):
        result = _RunResult('', '', 0)
        result.raw_output = b'certutil: certificate is valid\n'
        result.raw_error_output = b''
        return result

    mock_cainstance.return_value = CAInstance(False)
    mock_dsinstance.return_value = DsInstance()
    mock_run.side_effect = run

    framework = object()
    registry.initialize(framework)
    f = IPANSSChainValidation(registry)

    f.config = config.Config()
    results = capture_results(f)

    assert len(results) == 1

    for result in results.results:
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPANSSChainValidation'
        assert 'slapd-' in result.kw.get('key')
