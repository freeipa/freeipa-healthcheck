#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from unittest.mock import patch
from util import capture_results, CAInstance, KRAInstance
from util import m_api

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.roles import (IPACRLManagerCheck,
                                      IPARenewalMasterCheck,
                                      IPARenewalMasterHasKRACheck)


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

    @patch('ipaserver.install.cainstance.CAInstance')
    def test_crlmanager_no_ca(self, mock_ca):
        """There should be no CRLManagerCheck without a CA"""
        mock_ca.return_value = CAInstance(False)
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACRLManagerCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 0


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

    @patch('ipaserver.install.krainstance.KRAInstance')
    def test_is_renewal_master_with_kra(self, mock_kra):
        """Server is the renewal master and has a KRA configured"""
        framework = object()
        mock_kra.return_value = KRAInstance(True)

        registry.initialize(framework, config.Config)

        m_api.Command.config_show.side_effect = [{
            'result': {
                'ca_renewal_master_server': 'server.ipa.example',
                'kra_server_server': 'server.ipa.example'
            }
        }]

        f = IPARenewalMasterHasKRACheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.roles'
        assert result.check == 'IPARenewalMasterHasKRACheck'

    @patch('ipaserver.install.krainstance.KRAInstance')
    def test_is_renewal_master_with_no_kra(self, mock_kra):
        """Server is the renewal master and does not have KRA configured"""
        framework = object()
        mock_kra.return_value = KRAInstance(False)

        registry.initialize(framework, config.Config)

        m_api.Command.config_show.side_effect = [{
            'result': {
                'ca_renewal_master_server': 'server.ipa.example',
                'kra_server_server': 'replica.ipa.example'
            }
        }]

        f = IPARenewalMasterHasKRACheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.source == 'ipahealthcheck.ipa.roles'
        assert result.check == 'IPARenewalMasterHasKRACheck'

    @patch('ipaserver.install.krainstance.KRAInstance')
    def test_is_renewal_master_with_no_kras(self, mock_kra):
        """Server is the renewal master no KRAs are configured"""
        framework = object()
        mock_kra.return_value = KRAInstance(False)

        registry.initialize(framework, config.Config)

        m_api.Command.config_show.side_effect = [{
            'result': {
                'ca_renewal_master_server': 'server.ipa.example'
            }
        }]

        f = IPARenewalMasterHasKRACheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.roles'
        assert result.check == 'IPARenewalMasterHasKRACheck'

    @patch('ipaserver.install.krainstance.KRAInstance')
    def test_not_renewal_master_kra_check(self, mock_kra):
        """Server is not the renewal master no KRA check needed"""
        framework = object()
        mock_kra.return_value = KRAInstance(False)

        registry.initialize(framework, config.Config)

        m_api.Command.config_show.side_effect = [{
            'result': {
                'ca_renewal_master_server': 'replica.ipa.example'
            }
        }]

        f = IPARenewalMasterHasKRACheck(registry)

        self.results = capture_results(f)

        # No result is returned if not the renewal server
        assert len(self.results) == 0
