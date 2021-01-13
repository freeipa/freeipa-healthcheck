#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from tests.util import capture_results, CAInstance
from tests.base import BaseTest
from ipahealthcheck.core import constants, config
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertmongerCA
from unittest.mock import Mock, patch


class TestCertmonger(BaseTest):
    patches = {
        'ipaserver.install.cainstance.CAInstance':
        Mock(return_value=CAInstance()),
    }

    @patch('ipahealthcheck.ipa.certs.IPACertmongerCA.find_ca')
    def test_certmogner_ok(self, mock_find_ca):
        mock_find_ca.side_effect = [
            'IPA',
            'dogtag-ipa-ca-renew-agent',
            'dogtag-ipa-ca-renew-agent-reuse'
        ]
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertmongerCA(registry)

        self.results = capture_results(f)

        assert len(self.results) == 3

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPACertmongerCA'

    @patch('ipahealthcheck.ipa.certs.IPACertmongerCA.find_ca')
    def test_certmogner_missing(self, mock_find_ca):
        mock_find_ca.side_effect = [
            'IPA',
            'dogtag-ipa-ca-renew-agent',
        ]

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertmongerCA(registry)

        self.results = capture_results(f)

        assert len(self.results) == 3

        for r in range(0, 1):
            result = self.results.results[r]
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPACertmongerCA'

        assert self.results.results[2].result == constants.ERROR
        assert self.results.results[2].kw.get('key') == \
            'dogtag-ipa-ca-renew-agent-reuse'
