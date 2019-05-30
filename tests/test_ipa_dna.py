#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from unittest.mock import Mock, patch
from util import capture_results

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.dna import IPADNARangeCheck


class mock_ReplicationManager:
    def __init__(self, realm=None, host=None, start=None, max=None,
                 next=None, next_max=None):
        self.start = start
        self.max = max
        self.next = next
        self.next_max = next_max

    def get_DNA_range(self, host):
        return self.start, self.max

    def get_DNA_next_range(self, host):
        return self.next, self.next_max


class TestDNARange(BaseTest):
    patches = {
        'ipaserver.install.installutils.check_server_configuration':
        Mock(return_value=None),
    }

    @patch('ipaserver.install.replication.ReplicationManager')
    def test_dnarange_set(self, mock_manager):
        mock_manager.return_value = mock_ReplicationManager(start=1, max=100)
        framework = object()
        registry.initialize(framework)
        f = IPADNARangeCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.dna'
        assert result.check == 'IPADNARangeCheck'
        assert result.kw.get('range_start') == 1
        assert result.kw.get('range_max') == 100
        assert result.kw.get('next_start') == 0
        assert result.kw.get('next_max') == 0

    @patch('ipaserver.install.replication.ReplicationManager')
    def test_dnarange_noset(self, mock_manager):
        mock_manager.return_value = mock_ReplicationManager()
        framework = object()
        registry.initialize(framework)
        f = IPADNARangeCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.dna'
        assert result.check == 'IPADNARangeCheck'
        assert result.kw.get('range_start') == 0
        assert result.kw.get('range_max') == 0
        assert result.kw.get('next_start') == 0
        assert result.kw.get('next_max') == 0

    @patch('ipaserver.install.replication.ReplicationManager')
    def test_dnarange_next(self, mock_manager):
        mock_manager.return_value = mock_ReplicationManager(start=1,
                                                            max=100,
                                                            next=101,
                                                            next_max=200)
        framework = object()
        registry.initialize(framework)
        f = IPADNARangeCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.dna'
        assert result.check == 'IPADNARangeCheck'
        assert result.kw.get('range_start') == 1
        assert result.kw.get('range_max') == 100
        assert result.kw.get('next_start') == 101
        assert result.kw.get('next_max') == 200
