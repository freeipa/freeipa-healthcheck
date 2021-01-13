#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from tests.util import capture_results
from tests.util import m_api
from tests.base import BaseTest

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.topology import IPATopologyDomainCheck


class TestTopology(BaseTest):
    def test_topology_ok(self):
        m_api.Command.topologysuffix_verify.side_effect = [
            {
                u'result': {
                    u"in_order": True,
                }
            },
            {
                u'result': {
                    u"in_order": True,
                }
            },
        ]
        m_api.Command.ca_is_enabled.return_value = {'result': True}

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPATopologyDomainCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.topology'
            assert result.check == 'IPATopologyDomainCheck'

    def test_topology_domain_bad(self):
        m_api.Command.topologysuffix_verify.side_effect = [
            {
                u'result': {
                    u"connect_errors": [
                        [
                            u"ipa.example.test",
                            [u"ipa.example.test"],
                            [u"replica2.example.test"]
                        ],
                        [
                            u"replica2.example.test",
                            [u"replica2.example.test"],
                            [u"ipa.example.test"]
                        ]
                    ],
                    u"in_order": False,
                    u"max_agmts": 4,
                    u"max_agmts_errors": []
                }
            },
            {
                u'result': {
                    u"in_order": True,
                }
            },
        ]
        m_api.Command.ca_is_enabled.return_value = {'result': True}

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPATopologyDomainCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 3

        for result in self.results.results:
            assert result.source == 'ipahealthcheck.ipa.topology'
            assert result.check == 'IPATopologyDomainCheck'

        # The first two results are failures in the domain suffix, the
        # third is a success in the ca suffix.
        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.kw.get('key') == 'ipa.example.test'
        assert result.kw.get('replicas') == ['replica2.example.test']
        assert result.kw.get('suffix') == 'domain'
        assert result.kw.get('type') == 'connect'
        assert 'can\'t contact servers' in result.kw.get('msg')

        result = self.results.results[1]
        assert result.result == constants.ERROR
        assert result.kw.get('key') == 'replica2.example.test'
        assert result.kw.get('replicas') == ['ipa.example.test']
        assert result.kw.get('suffix') == 'domain'
        assert result.kw.get('type') == 'connect'
        assert 'can\'t contact servers' in result.kw.get('msg')

        result = self.results.results[2]
        assert result.result == constants.SUCCESS
        assert result.kw.get('suffix') == 'ca'

    def test_topology_ca_bad(self):
        m_api.Command.topologysuffix_verify.side_effect = [
            {
                u'result': {
                    u"in_order": True,
                }
            },
            {
                u'result': {
                    u"connect_errors": [
                        [
                            u"ipa.example.test",
                            [u"ipa.example.test"],
                            [u"replica2.example.test"]
                        ],
                        [
                            u"replica2.example.test",
                            [u"replica2.example.test"],
                            [u"ipa.example.test"]
                        ]
                    ],
                    u"in_order": False,
                    u"max_agmts": 4,
                    u"max_agmts_errors": []
                }
            },
        ]
        m_api.Command.ca_is_enabled.return_value = {'result': True}

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPATopologyDomainCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 3

        for result in self.results.results:
            assert result.source == 'ipahealthcheck.ipa.topology'
            assert result.check == 'IPATopologyDomainCheck'

        # The first result is ok (domain) and the last two are failures
        # (ca)
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.kw.get('suffix') == 'domain'

        result = self.results.results[1]
        assert result.result == constants.ERROR
        assert result.kw.get('key') == 'ipa.example.test'
        assert result.kw.get('replicas') == ['replica2.example.test']
        assert result.kw.get('suffix') == 'ca'
        assert result.kw.get('type') == 'connect'
        assert 'can\'t contact servers' in result.kw.get('msg')

        result = self.results.results[2]
        assert result.result == constants.ERROR
        assert result.kw.get('key') == 'replica2.example.test'
        assert result.kw.get('replicas') == ['ipa.example.test']
        assert result.kw.get('suffix') == 'ca'
        assert result.kw.get('type') == 'connect'
        assert 'can\'t contact servers' in result.kw.get('msg')

    def test_topology_domain_max_agmts(self):
        m_api.Command.topologysuffix_verify.side_effect = [
            {
                u'result': {
                    u"connect_errors": [],
                    u"in_order": False,
                    u"max_agmts": 1,
                    u"max_agmts_errors": [
                        [
                            u"ipa.example.test",
                            [u"replica2.example.test"],
                        ],
                    ],
                }
            },
            {
                u'result': {
                    u"in_order": True,
                }
            },
        ]
        m_api.Command.ca_is_enabled.return_value = {'result': True}

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPATopologyDomainCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2

        for result in self.results.results:
            assert result.source == 'ipahealthcheck.ipa.topology'
            assert result.check == 'IPATopologyDomainCheck'

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.kw.get('key') == 'ipa.example.test'
        assert result.kw.get('replicas') == ['replica2.example.test']
        assert result.kw.get('suffix') == 'domain'
        assert result.kw.get('type') == 'max'
        assert 'recommended max' in result.kw.get('msg')

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.kw.get('suffix') == 'ca'
