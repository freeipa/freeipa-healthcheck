#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import capture_results
from base import BaseTest

from ipahealthcheck.core import constants, config
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import (
    IPACertTracking,
    CertmongerStuckCheck,
    CertmongerFIPSTokensCheck
)
from unittest.mock import Mock, patch
from mock_certmonger import create_mock_dbus, _certmonger
from mock_certmonger import get_expected_requests, set_requests


class TestTracking(BaseTest):
    patches = {
        'ipahealthcheck.ipa.certs.get_expected_requests':
        Mock(return_value=get_expected_requests()),
        'ipalib.install.certmonger._cm_dbus_object':
        Mock(side_effect=create_mock_dbus),
        'ipalib.install.certmonger._certmonger':
        Mock(return_value=_certmonger())
    }

    def test_known_cert_tracking(self):
        set_requests()

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertTracking(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2

    def test_missing_cert_tracking(self):
        # remove one of the requests to force it to be missing
        set_requests(remove=0)

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertTracking(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertTracking'
        assert result.kw.get('key') == \
            "cert-file=/var/lib/ipa/ra-agent.pem, " \
            "key-file=/var/lib/ipa/ra-agent.key, " \
            "ca-name=dogtag-ipa-ca-renew-agent, " \
            "template_profile=caSubsystemCert, " \
            "cert-storage=FILE, "\
            "cert-presave-command=" \
            "/usr/libexec/ipa/certmonger/renew_ra_cert_pre, " \
            "cert-postsave-command=" \
            "/usr/libexec/ipa/certmonger/renew_ra_cert, " \
            "cert=----- BEGIN -----"

    def test_unknown_cert_tracking(self):
        # Add a custom, unknown request
        unknown = {
            'nickname': '7777',
            'cert-file': '/tmp/test.crt',
            'key-file': '/tmp/test.key',
            'ca-name': 'IPA',
        }
        set_requests(add=unknown)

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertTracking(registry)

        self.results = capture_results(f)

        assert len(self.results) == 3

        result = self.results.results[2]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertTracking'
        assert result.kw.get('key') == '7777'


class TestStuck(BaseTest):
    patches = {
        'ipahealthcheck.ipa.certs.get_expected_requests':
        Mock(return_value=get_expected_requests()),
        'ipalib.install.certmonger._cm_dbus_object':
        Mock(side_effect=create_mock_dbus),
        'ipalib.install.certmonger._certmonger':
        Mock(return_value=_certmonger())
    }

    def test_none_stuck(self):
        set_requests()

        framework = object()
        registry.initialize(framework, config.Config)
        f = CertmongerStuckCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS

    def test_one_stuck(self):
        stuck = {
            'nickname': '7777',
            'cert-file': '/tmp/test.crt',
            'key-file': '/tmp/test.key',
            'ca-name': 'IPA',
            'stuck': True,
        }
        set_requests(add=stuck)

        framework = object()
        registry.initialize(framework, config.Config)
        f = CertmongerStuckCheck(registry)

        self.results = capture_results(f)
        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.kw.get('key') == '7777'


class TestFIPSTokens(BaseTest):
    """Test the combination of FIPS configurations with tokens and
       also that when HSM is used the check is skipped.
    """
    patches = {
        'ipahealthcheck.ipa.certs.get_expected_requests':
        Mock(return_value=get_expected_requests()),
        'ipalib.install.certmonger._cm_dbus_object':
        Mock(side_effect=create_mock_dbus),
        'ipalib.install.certmonger._certmonger':
        Mock(return_value=_certmonger())
    }

    nss_tracking = {
        'nickname': '9876',
        'ca-name': 'dogtag-ipa-ca-renew-agent',
        'template_profile': 'caIPAserviceCert',
        'cert-storage': 'NSSDB',
        'cert-storage_location': '/etc/pki/pki-tomcat/alias',
        'cert-token': 'NSS Certificate DB',
        'key-storage': 'NSSDB',
        'key-storage_location': '/etc/pki/pki-tomcat/alias',
        'key-token': 'NSS Certificate DB',
    }

    @patch('ipahealthcheck.ipa.certs.tasks.is_fips_enabled')
    @patch('ipalib.install.certmonger.get_request_value')
    def test_nonfips_token_correct(self, mock_value, mock_fips):
        mock_value.side_effect = [
            'FILE',
            'FILE',
            'NSSDB', 'NSS Certificate DB',
        ]
        mock_fips.return_value = False
        set_requests(add=self.nss_tracking)

        framework = object()
        registry.initialize(framework, config.Config)
        f = CertmongerFIPSTokensCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS

    @patch('ipahealthcheck.ipa.certs.tasks.is_fips_enabled')
    @patch('ipalib.install.certmonger.get_request_value')
    def test_nonfips_token_wrong(self, mock_value, mock_fips):
        mock_value.side_effect = [
            'FILE',
            'FILE',
            'NSSDB', 'NSS FIPS 140-2 Certificate DB',
        ]
        mock_fips.return_value = False
        set_requests(add=self.nss_tracking)

        framework = object()
        registry.initialize(framework, config.Config)
        f = CertmongerFIPSTokensCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.kw.get('key') == '9876'
        assert result.kw.get('token') == 'NSS FIPS 140-2 Certificate DB'

    @patch('ipahealthcheck.ipa.certs.tasks.is_fips_enabled')
    @patch('ipalib.install.certmonger.get_request_value')
    def test_fips_token_correct(self, mock_value, mock_fips):
        mock_value.side_effect = [
            'FILE',
            'FILE',
            'NSSDB', 'NSS FIPS 140-2 Certificate DB',
        ]
        mock_fips.return_value = True
        set_requests(add=self.nss_tracking)

        framework = object()
        registry.initialize(framework, config.Config)
        f = CertmongerFIPSTokensCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS

    @patch('ipahealthcheck.ipa.certs.tasks.is_fips_enabled')
    @patch('ipalib.install.certmonger.get_request_value')
    def test_fips_token_wrong(self, mock_value, mock_fips):
        mock_value.side_effect = [
            'FILE',
            'FILE',
            'NSSDB', 'NSS Certificate DB',
        ]
        mock_fips.return_value = True
        set_requests(add=self.nss_tracking)

        framework = object()
        registry.initialize(framework, config.Config)
        f = CertmongerFIPSTokensCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.kw.get('key') == '9876'
        assert result.kw.get('token') == 'NSS Certificate DB'
        assert result.kw.get('expected_token') == \
            'NSS FIPS 140-2 Certificate DB'

    @patch('ipahealthcheck.ipa.certs.tasks.is_fips_enabled')
    @patch('ipalib.install.certmonger.get_request_value')
    def test_hsm_token_non_fips(self, mock_value, mock_fips):
        """FIPS shouldn't make a difference as HSM tokens should be skipped"""
        mock_value.side_effect = [
            'FILE',
            'FILE',
            'NSSDB', 'ipa_token',
        ]
        mock_fips.return_value = False
        set_requests(add=self.nss_tracking)

        framework = object()
        registry.initialize(framework, config.Config)
        f = CertmongerFIPSTokensCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS

    @patch('ipahealthcheck.ipa.certs.tasks.is_fips_enabled')
    @patch('ipalib.install.certmonger.get_request_value')
    def test_hsm_token_fips(self, mock_value, mock_fips):
        """FIPS shouldn't make a difference as HSM tokens should be skipped"""
        mock_value.side_effect = [
            'FILE',
            'FILE',
            'NSSDB', 'ipa_token',
        ]
        mock_fips.return_value = True
        set_requests(add=self.nss_tracking)

        framework = object()
        registry.initialize(framework, config.Config)
        f = CertmongerFIPSTokensCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
