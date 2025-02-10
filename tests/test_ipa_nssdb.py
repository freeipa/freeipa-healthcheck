#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import capture_results, CAInstance, KRAInstance
from base import BaseTest
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertNSSTrust
from ipaplatform.paths import paths
from unittest.mock import Mock, patch
from common import mock_NSSDatabase, my_unparse_trust_flags


# These tests make some assumptions about the order in which the
# results are returned.

class TestNSSDBTrust(BaseTest):
    patches = {
        'ipaserver.install.krainstance.KRAInstance':
        Mock(return_value=KRAInstance(False)),
        'ipapython.certdb.unparse_trust_flags':
        Mock(side_effect=my_unparse_trust_flags),
    }

    @patch('ipapython.certdb.NSSDatabase')
    @patch('ipaserver.install.cainstance.CAInstance')
    def test_trust_default_ok(self, mock_ca, mock_certdb):
        """Test what should be the standard case"""
        trust = {
            'ocspSigningCert cert-pki-ca': 'u,u,u',
            'subsystemCert cert-pki-ca': 'u,u,u',
            'auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'u,u,u'
        }
        mock_certdb.return_value = mock_NSSDatabase('nssdb', trust=trust)
        mock_ca.return_value = CAInstance()

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertNSSTrust(registry)

        self.results = capture_results(f)

        assert len(self.results) == 4

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPACertNSSTrust'
            assert 'cert-pki-ca' in result.kw.get('key')

    @patch('ipapython.certdb.NSSDatabase')
    @patch('ipaserver.install.cainstance.CAInstance')
    def test_trust_ocsp_missing(self, mock_ca, mock_certdb):
        """Test a missing certificate"""
        trust = {
            'subsystemCert cert-pki-ca': 'u,u,u',
            'auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'u,u,u'
        }

        mock_certdb.return_value = mock_NSSDatabase('nssdb', trust=trust)
        mock_ca.return_value = CAInstance()

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertNSSTrust(registry)

        self.results = capture_results(f)

        # The check reports success for those that it found and are correct and
        # reports missing certs last.
        num = len(self.results.results) - 2
        for r in range(0, num):
            result = self.results.results[r]
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPACertNSSTrust'
            assert 'cert-pki-ca' in result.kw.get('key')

        result = self.results.results[-1]

        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertNSSTrust'
        assert result.kw.get('key') == 'ocspSigningCert cert-pki-ca'
        assert result.kw.get('nickname') == 'ocspSigningCert cert-pki-ca'
        assert result.kw.get('dbdir') == paths.PKI_TOMCAT_ALIAS_DIR

        assert len(self.results) == 4

    @patch('ipapython.certdb.NSSDatabase')
    @patch('ipaserver.install.cainstance.CAInstance')
    def test_trust_bad(self, mock_ca, mock_certdb):
        """Test multiple unexpected trust flags"""
        trust = {
            'ocspSigningCert cert-pki-ca': 'u,u,u',
            'subsystemCert cert-pki-ca': 'X,u,u',
            'auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'X,u,u'
        }
        mock_certdb.return_value = mock_NSSDatabase('nssdb', trust=trust)
        mock_ca.return_value = CAInstance()

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertNSSTrust(registry)

        self.results = capture_results(f)

        result = self.results.results[1]

        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertNSSTrust'
        assert result.kw.get('key') == 'subsystemCert cert-pki-ca'
        assert result.kw.get('got') == 'X,u,u'
        assert result.kw.get('expected') == 'u,u,u'

        result = self.results.results[3]

        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertNSSTrust'
        assert result.kw.get('key') == 'Server-Cert cert-pki-ca'
        assert result.kw.get('got') == 'X,u,u'
        assert result.kw.get('expected') == 'u,u,u'

        assert len(self.results) == 4

    @patch('ipaserver.install.cainstance.CAInstance')
    def test_trust_caless(self, mock_cainstance):
        """Nothing to check if the master is CALess"""

        mock_cainstance.return_value = CAInstance(False)

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertNSSTrust(registry)

        self.results = capture_results(f)

        assert len(self.results) == 0

    @patch('ipahealthcheck.ipa.certs.get_token_password')
    @patch('ipapython.certdb.NSSDatabase')
    @patch('ipaserver.install.cainstance.CAInstance')
    def test_trust_token_ok(self, mock_ca, mock_certdb, mock_password):
        """Test what should be the standard token case"""
        trust = {
            'hsm:ocspSigningCert cert-pki-ca': 'u,u,u',
            'hsm:subsystemCert cert-pki-ca': 'u,u,u',
            'hsm:auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'u,u,u'
        }
        mock_certdb.return_value = mock_NSSDatabase('nssdb', token='hsm',
                                                    trust=trust)
        mock_ca.return_value = CAInstance(enabled=True, hsm_enabled=True,
                                          token='hsm')
        mock_password.return_value = 'Secret123'

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertNSSTrust(registry)

        self.results = capture_results(f)

        assert len(self.results) == 4

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPACertNSSTrust'
            assert 'cert-pki-ca' in result.kw.get('key')

    @patch('ipahealthcheck.ipa.certs.get_token_password')
    @patch('ipapython.certdb.NSSDatabase')
    @patch('ipaserver.install.cainstance.CAInstance')
    def test_trust_token_bad(self, mock_ca, mock_certdb, mock_password):
        """Test multiple unexpected trust flags"""
        trust = {
            'hsm:ocspSigningCert cert-pki-ca': 'u,u,u',
            'hsm:subsystemCert cert-pki-ca': 'X,u,u',
            'hsm:auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'X,u,u'
        }

        mock_certdb.return_value = mock_NSSDatabase('nssdb', token='hsm',
                                                    trust=trust)
        mock_ca.return_value = CAInstance(enabled=True, hsm_enabled=True,
                                          token='hsm')
        mock_password.return_value = 'Secret123'

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertNSSTrust(registry)

        self.results = capture_results(f)

        result = self.results.results[1]

        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertNSSTrust'
        assert result.kw.get('key') == 'hsm:subsystemCert cert-pki-ca'
        assert result.kw.get('got') == 'X,u,u'
        assert result.kw.get('expected') == 'u,u,u'

        result = self.results.results[3]

        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertNSSTrust'
        assert result.kw.get('key') == 'Server-Cert cert-pki-ca'
        assert result.kw.get('got') == 'X,u,u'
        assert result.kw.get('expected') == 'u,u,u'
