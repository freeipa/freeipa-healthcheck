#
# Copyright (C) 2024 FreeIPA Contributors see COPYING for license
#

from util import capture_results, m_api
from base import BaseTest
from unittest.mock import patch
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.config import (
    IPAkrbLastSuccessfulAuth,
    SSSDAllowedUids389Check
)

from SSSDConfig import NoOptionError
from SSSDConfig import NoServiceError


class SSSDService():
    def __init__(self, return_option, uids):
        self.uids = uids
        self.return_option = return_option

    def get_option(self, option):
        if not self.return_option:
            raise NoOptionError
        return self.uids


class SSSDConfig():
    def __init__(self, return_service=True, return_option=False, uids=None):
        """
        Knobs to control what data the configuration returns.
        """
        self.return_service = return_service
        self.return_option = return_option
        self.uids = uids

    def import_config(self):
        pass

    def get_service(self, service):
        if not self.return_service:
            raise NoServiceError()
        return SSSDService(self.return_option, self.uids)


class TestkrbLastSuccessfulAuth(BaseTest):

    def test_last_success_disabled(self):
        """Test that no warning is issued in the default config"""

        m_api.Command.config_show.side_effect = [{
            'result': {
                'ipaconfigstring': ['KDC:Disable Last Success',]
            }
        }]

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAkrbLastSuccessfulAuth(registry)
        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.config'
        assert result.check == 'IPAkrbLastSuccessfulAuth'

    def test_last_success_enabled(self):
        """Test that a warning is issued when krbLastSuccessfulAuth is
           replicated.
        """

        m_api.Command.config_show.side_effect = [{
            'result': {
                'ipaconfigstring': ['',]
            }
        }]

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAkrbLastSuccessfulAuth(registry)
        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.config'
        assert result.check == 'IPAkrbLastSuccessfulAuth'


class TestSSSDAllowedUids389Check(BaseTest):

    @patch('SSSDConfig.SSSDConfig')
    def test_sssd_no_pac_section(self, mock_sssd):
        """There is no pac section in sssd.conf"""
        mock_sssd.return_value = SSSDConfig(return_service=False,
                                            return_option=False)
        framework = object()
        registry.initialize(framework, config.Config())
        f = SSSDAllowedUids389Check(registry)
        self.results = capture_results(f)

        assert len(self.results) == 0

    @patch('SSSDConfig.SSSDConfig')
    def test_sssd_no_allowed_uids_configured(self, mock_sssd):
        """There is no allowed_uids option in the pac section"""
        mock_sssd.return_value = SSSDConfig(return_service=True,
                                            return_option=False)
        framework = object()
        registry.initialize(framework, config.Config())
        f = SSSDAllowedUids389Check(registry)
        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.config'
        assert result.check == 'SSSDAllowedUids389Check'

    @patch('SSSDConfig.SSSDConfig')
    def test_sssd_ok_allowed_uids_configured(self, mock_sssd):
        """There is now allowed_uids option in the pac section"""
        mock_sssd.return_value = SSSDConfig(return_service=True,
                                            return_option=True,
                                            uids='0')
        framework = object()
        registry.initialize(framework, config.Config())
        f = SSSDAllowedUids389Check(registry)
        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.config'
        assert result.check == 'SSSDAllowedUids389Check'

    @patch('SSSDConfig.SSSDConfig')
    def test_sssd_ok_multiple_allowed_uids_configured(self, mock_sssd):
        """There is now allowed_uids option in the pac section"""
        mock_sssd.return_value = SSSDConfig(return_service=True,
                                            return_option=True,
                                            uids='0, 100000')

        # uid 100000 is a value I picked out of the air. It doesn't
        # matter what it is as it isn't prohibited
        framework = object()
        registry.initialize(framework, config.Config())
        f = SSSDAllowedUids389Check(registry)
        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.config'
        assert result.check == 'SSSDAllowedUids389Check'

    @patch('SSSDConfig.SSSDConfig')
    def test_sssd_bad_allowed_uids_configured(self, mock_sssd):
        """There is now allowed_uids option in the pac section"""
        mock_sssd.return_value = SSSDConfig(return_service=True,
                                            return_option=True,
                                            uids='0, 389')
        framework = object()
        registry.initialize(framework, config.Config())
        f = SSSDAllowedUids389Check(registry)
        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.kw.get('invalid') == '389'
        assert result.source == 'ipahealthcheck.ipa.config'
        assert result.check == 'SSSDAllowedUids389Check'

    @patch('SSSDConfig.SSSDConfig')
    def test_sssd_bad_alpha_allowed_uids_configured(self, mock_sssd):
        """There is now allowed_uids option in the pac section"""
        mock_sssd.return_value = SSSDConfig(return_service=True,
                                            return_option=True,
                                            uids='root, dirsrv')
        framework = object()
        registry.initialize(framework, config.Config())
        f = SSSDAllowedUids389Check(registry)
        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.kw.get('invalid') == 'dirsrv'
        assert result.source == 'ipahealthcheck.ipa.config'
        assert result.check == 'SSSDAllowedUids389Check'
