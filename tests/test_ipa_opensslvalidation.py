#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPAOpenSSLChainValidation
from unittest.mock import patch
from util import capture_results, CAInstance

from ipapython.ipautil import _RunResult


@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipapython.ipautil.run')
def test_openssl_validation_ok(mock_run,
                               mock_cainstance):

    def run(args, raiseonerr=True):
        result = _RunResult('', '', 0)
        result.raw_output = bytes('%s: OK'.format(args[-1]).encode('utf-8'))
        result.raw_error_output = b''
        return result

    mock_run.side_effect = run
    mock_cainstance.return_value = CAInstance()

    framework = object()
    registry.initialize(framework)
    f = IPAOpenSSLChainValidation(registry)

    f.config = config.Config()
    results = capture_results(f)

    assert len(results) == 2

    for result in results.results:
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPAOpenSSLChainValidation'


@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipapython.ipautil.run')
def test_openssl_validation_bad(mock_run,
                                mock_cainstance):

    def run(args, raiseonerr=True):
        result = _RunResult('', '', 2)
        result.raw_output = bytes(
            'O = EXAMPLE.TEST, CN = ipa.example.test\n'
            'error 20 at 0 depth lookup: unable to get local issuer '
            'certificate\nerror %s: verification failed'.format(args[-1])
            .encode('utf-8'))
        result.raw_error_output = b''
        result.error_log = ''
        return result

    mock_run.side_effect = run
    mock_cainstance.return_value = CAInstance()

    framework = object()
    registry.initialize(framework)
    f = IPAOpenSSLChainValidation(registry)

    f.config = config.Config()
    results = capture_results(f)

    assert len(results) == 2

    for result in results.results:
        assert result.severity == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPAOpenSSLChainValidation'
        assert 'failed' in result.kw.get('msg')
