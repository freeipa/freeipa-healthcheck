#
# Copyright (C) 2025 FreeIPA Contributors see COPYING for license
#

from util import capture_results, m_api
from base import BaseTest

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.topology import IPAReplicationAgreementCountCheck


class TestReplicationAgreementCount(BaseTest):
    def test_count_ok(self):
        m_api.Command.topologysegment_find.side_effect = [
            {u'count': 3},
            {u'count': 3},
        ]
        m_api.Command.ca_is_enabled.return_value = {'result': True}

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAReplicationAgreementCountCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2
        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.topology'
            assert result.check == 'IPAReplicationAgreementCountCheck'

        assert self.results.results[0].kw.get('suffix') == 'domain'
        assert self.results.results[0].kw.get('count') == 3
        assert self.results.results[1].kw.get('suffix') == 'ca'

    def test_count_no_ca(self):
        m_api.Command.topologysegment_find.side_effect = [
            {u'count': 5},
        ]
        m_api.Command.ca_is_enabled.return_value = {'result': False}

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAReplicationAgreementCountCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.kw.get('suffix') == 'domain'

    def test_count_domain_exceeded(self):
        m_api.Command.topologysegment_find.side_effect = [
            {u'count': 61},
            {u'count': 3},
        ]
        m_api.Command.ca_is_enabled.return_value = {'result': True}

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAReplicationAgreementCountCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.kw.get('suffix') == 'domain'
        assert result.kw.get('count') == 61
        assert result.kw.get('max') == 60
        assert 'exceeds the supported maximum' in result.kw.get('msg')

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.kw.get('suffix') == 'ca'

    def test_count_ca_exceeded(self):
        m_api.Command.topologysegment_find.side_effect = [
            {u'count': 3},
            {u'count': 100},
        ]
        m_api.Command.ca_is_enabled.return_value = {'result': True}

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAReplicationAgreementCountCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.kw.get('suffix') == 'domain'

        result = self.results.results[1]
        assert result.result == constants.CRITICAL
        assert result.kw.get('suffix') == 'ca'
        assert result.kw.get('count') == 100
