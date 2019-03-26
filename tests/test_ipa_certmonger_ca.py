#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertmongerCA
from unittest.mock import patch
from util import capture_results, CAInstance, no_exceptions


@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipahealthcheck.ipa.certs.IPACertmongerCA.find_ca')
def test_certmogner_ok(mock_find_ca, mock_cainstance):

    mock_find_ca.side_effect = [
        'IPA',
        'dogtag-ipa-ca-renew-agent',
        'dogtag-ipa-ca-renew-agent-reuse'
    ]
    mock_cainstance.return_value = CAInstance()

    framework = object()
    registry.initialize(framework)
    f = IPACertmongerCA(registry)

    results = capture_results(f)

    assert len(results) == 3

    for result in results.results:
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertmongerCA'

    no_exceptions(results)


@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipahealthcheck.ipa.certs.IPACertmongerCA.find_ca')
def test_certmogner_missing(mock_find_ca, mock_cainstance):

    mock_find_ca.side_effect = [
        'IPA',
        'dogtag-ipa-ca-renew-agent',
    ]
    mock_cainstance.return_value = CAInstance()

    framework = object()
    registry.initialize(framework)
    f = IPACertmongerCA(registry)

    results = capture_results(f)

    assert len(results) == 3

    for r in range(0, 1):
        result = results.results[r]
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertmongerCA'

    assert results.results[2].severity == constants.ERROR
    assert results.results[2].kw.get('key') == \
        'dogtag-ipa-ca-renew-agent-reuse'
    assert results.results[2].kw.get('msg') == \
        "Certmonger CA 'dogtag-ipa-ca-renew-agent-reuse' missing"

    no_exceptions(results)
