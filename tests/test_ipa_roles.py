#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from tests.base import BaseTest
from unittest.mock import patch
from tests.util import capture_results, CAInstance
from tests.util import m_api

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.roles import (IPACRLManagerCheck,
                                      IPARenewalMasterCheck)


class TestCRLManagerRole(BaseTest):
    @patch('ipaserver.install.cainstance.CAInstance')
    def test_not_crlmanager(self, mock_ca):
        mock_ca.return_value = CAInstance(crlgen=False)
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACRLManagerCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.roles'
        assert result.check == 'IPACRLManagerCheck'
        assert result.kw.get('crlgen_enabled') is False

    @patch('ipaserver.install.cainstance.CAInstance')
    def test_crlmanager(self, mock_ca):
        mock_ca.return_value = CAInstance()
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACRLManagerCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.roles'
        assert result.check == 'IPACRLManagerCheck'
        assert result.kw.get('crlgen_enabled') is True


class TestRenewalMaster(BaseTest):
    def test_renewal_master_not_set(self):
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPARenewalMasterCheck(registry)

        m_api.Command.config_show.side_effect = [{
            'result': {
            }
        }]

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.roles'
        assert result.check == 'IPARenewalMasterCheck'
        assert result.kw.get('master') is False

    def test_not_renewal_master(self):
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPARenewalMasterCheck(registry)

        m_api.Command.config_show.side_effect = [{
            'result': {
                'ca_renewal_master_server': 'something.ipa.example'
            }
        }]

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.roles'
        assert result.check == 'IPARenewalMasterCheck'
        assert result.kw.get('master') is False

    def test_is_renewal_master(self):
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPARenewalMasterCheck(registry)

        m_api.Command.config_show.side_effect = [{
            'result': {
                'ca_renewal_master_server': 'server.ipa.example'
            }
        }]

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.roles'
        assert result.check == 'IPARenewalMasterCheck'
        assert result.kw.get('master') is True
