#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import capture_results
from base import BaseTest
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertfileExpirationCheck
from unittest.mock import Mock, patch
from mock_certmonger import create_mock_dbus, _certmonger
from mock_certmonger import (
    get_expected_requests,
    set_requests,
    CERT_EXPIRATION_DAYS,
)

from datetime import datetime, timedelta, timezone


class IPACertificate:
    def __init__(self, not_valid_after, serial_number=1):
        self.subject = 'CN=RA AGENT'
        self.issuer = 'CN=ISSUER'
        self.serial_number = serial_number
        self.not_valid_after_utc = not_valid_after


class TestIPACertificateFile(BaseTest):
    patches = {
        'ipahealthcheck.ipa.certs.get_expected_requests':
        Mock(return_value=get_expected_requests()),
        'ipalib.install.certmonger._cm_dbus_object':
        Mock(side_effect=create_mock_dbus),
        'ipalib.install.certmonger._certmonger':
        Mock(return_value=_certmonger()),
    }

    @patch('ipalib.x509.load_certificate_from_file')
    def test_certfile_expiration(self, mock_load_cert):
        set_requests(remove=1)

        cert = IPACertificate(not_valid_after=datetime.now(tz=timezone.utc) +
                              timedelta(days=CERT_EXPIRATION_DAYS))
        mock_load_cert.return_value = cert

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertfileExpirationCheck(registry)

        f.config.cert_expiration_days = '28'
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertfileExpirationCheck'
        assert result.kw.get('key') == '1234'

    @patch('ipalib.x509.load_certificate_from_file')
    def test_certfile_expiration_warning(self, mock_load_cert):
        set_requests(remove=1)

        cert = IPACertificate(not_valid_after=datetime.now(tz=timezone.utc) +
                              timedelta(days=7))
        mock_load_cert.return_value = cert

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertfileExpirationCheck(registry)

        f.config.cert_expiration_days = str(CERT_EXPIRATION_DAYS)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertfileExpirationCheck'
        assert result.kw.get('key') == '1234'
        assert result.kw.get('days') == 6

    @patch('ipalib.x509.load_certificate_from_file')
    def test_certfile_expiration_expired(self, mock_load_cert):
        set_requests(remove=1)

        cert = IPACertificate(not_valid_after=datetime.now(tz=timezone.utc) +
                              timedelta(days=-100))
        mock_load_cert.return_value = cert

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertfileExpirationCheck(registry)

        f.config.cert_expiration_days = str(CERT_EXPIRATION_DAYS)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertfileExpirationCheck'
        assert result.kw.get('key') == '1234'
        assert 'expiration_date' in result.kw
