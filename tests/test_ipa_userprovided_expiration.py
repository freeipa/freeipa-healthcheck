#
# Copyright (C) 2025 FreeIPA Contributors see COPYING for license
#

from util import capture_results
from base import BaseTest
from common import DsInstance
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPAUserProvidedExpirationCheck
from unittest.mock import Mock, patch
from ipapython.dn import DN
from common import mock_CertDB

from datetime import datetime, timedelta, timezone

CERT_EXPIRATION_DAYS = 30


class IPACertificate:
    def __init__(self, not_valid_after, serial_number=1):
        self.subject = 'CN=RA AGENT'
        self.issuer = 'CN=ISSUER'
        self.serial_number = serial_number
        self.not_valid_after_utc = not_valid_after


class TestIPACertificateFile(BaseTest):
    patches = {
        'ipaserver.install.dsinstance.DsInstance':
        Mock(return_value=DsInstance()),
        'ipalib.install.certstore.get_ca_subject':
        Mock(return_value=DN("CN=EXTERNAL")),
        'ipaserver.install.certs.is_ipa_issued_cert':
        Mock(return_value=False),
    }

    @patch('ipalib.x509.load_certificate_from_file')
    @patch('ipaserver.install.certs.CertDB')
    def test_certfile_expiration(self, mock_certdb, mock_load_cert):
        cert = IPACertificate(not_valid_after=datetime.now(tz=timezone.utc) +
                              timedelta(days=CERT_EXPIRATION_DAYS))
        mock_load_cert.return_value = cert
        mock_certdb.return_value = mock_CertDB({
            'Server-Cert cert-pki-ca': 'u,u,u',
        }, expiration_days=CERT_EXPIRATION_DAYS)

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAUserProvidedExpirationCheck(registry)

        f.config.cert_expiration_days = '28'
        self.results = capture_results(f)

        assert len(self.results) == 3

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPAUserProvidedExpirationCheck'

    @patch('ipalib.x509.load_certificate_from_file')
    @patch('ipaserver.install.certs.CertDB')
    def test_certfile_expiration_warning(self, mock_certdb, mock_load_cert):
        cert = IPACertificate(not_valid_after=datetime.now(tz=timezone.utc) +
                              timedelta(days=7))
        mock_load_cert.return_value = cert
        mock_certdb.return_value = mock_CertDB({
            'Server-Cert cert-pki-ca': 'u,u,u',
        }, expiration_days=7)

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAUserProvidedExpirationCheck(registry)

        f.config.cert_expiration_days = str(CERT_EXPIRATION_DAYS)
        self.results = capture_results(f)

        assert len(self.results) == 3

        for result in self.results.results:
            assert result.result == constants.WARNING
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPAUserProvidedExpirationCheck'
            assert result.kw.get('days') == 6

    @patch('ipalib.x509.load_certificate_from_file')
    @patch('ipaserver.install.certs.CertDB')
    def test_certfile_expiration_expired(self, mock_certdb, mock_load_cert):
        cert = IPACertificate(not_valid_after=datetime.now(tz=timezone.utc) +
                              timedelta(days=-100))
        mock_load_cert.return_value = cert
        mock_certdb.return_value = mock_CertDB({
            'Server-Cert cert-pki-ca': 'u,u,u',
        }, expiration_days=-100)

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAUserProvidedExpirationCheck(registry)

        f.config.cert_expiration_days = str(CERT_EXPIRATION_DAYS)
        self.results = capture_results(f)

        assert len(self.results) == 3

        for result in self.results.results:
            assert result.result == constants.ERROR
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPAUserProvidedExpirationCheck'
            assert 'expiration_date' in result.kw
