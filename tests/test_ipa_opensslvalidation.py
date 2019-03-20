#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import config, constants
from ipahealthcheck.core.plugin import Results
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPAOpenSSLChainValidation
from unittest.mock import patch

from ipapython.ipautil import _RunResult


@patch('ipapython.ipautil.run')
def test_openssl_validation_ok(mock_run):

    def run(args, raiseonerr=True):
        result = _RunResult('', '', 0)
        result.raw_output = bytes('%s: OK'.format(args[-1]).encode('utf-8'))
        result.raw_error_output = b''
        return result

    mock_run.side_effect = run

    framework = object()
    registry.initialize(framework)
    f = IPAOpenSSLChainValidation(registry)

    f.config = config.Config()
    results = Results()
    for result in f.check():
        results.add(result)

    assert len(results) == 2

    for result in results.results:
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPAOpenSSLChainValidation'


@patch('ipapython.ipautil.run')
def test_openssl_validation_bad(mock_run):

    def run(args):
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

    framework = object()
    registry.initialize(framework)
    f = IPAOpenSSLChainValidation(registry)

    f.config = config.Config()
    results = Results()
    for result in f.check():
        results.add(result)

    assert len(results) == 2

    for result in results.results:
        assert result.severity == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPAOpenSSLChainValidation'
