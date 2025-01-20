#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import capture_results
from base import BaseTest
from ipaplatform.paths import paths
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertmongerExpirationCheck
from ipahealthcheck.ipa.certs import IPACAChainExpirationCheck
from unittest.mock import Mock, patch
from mock_certmonger import create_mock_dbus, _certmonger
from mock_certmonger import (
    get_expected_requests,
    set_requests,
    CERT_EXPIRATION_DAYS,
)

from datetime import datetime, timedelta, timezone


class TestExpiration(BaseTest):
    patches = {
        'ipahealthcheck.ipa.certs.get_expected_requests':
        Mock(return_value=get_expected_requests()),
        'ipalib.install.certmonger._cm_dbus_object':
        Mock(side_effect=create_mock_dbus),
        'ipalib.install.certmonger._certmonger':
        Mock(return_value=_certmonger())
    }

    def test_expiration(self):
        set_requests()

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertmongerExpirationCheck(registry)

        f.config.cert_expiration_days = '7'
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertmongerExpirationCheck'
        assert result.kw.get('key') == '1234'
        assert result.kw.get('expiration_date') == '19700101001704Z'

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertmongerExpirationCheck'
        assert result.kw.get('key') == '5678'

    def test_expiration_warning(self):
        warning = datetime.now(timezone.utc) + timedelta(days=20)
        replaceme = {
            'nickname': '7777',
            'cert-file': paths.RA_AGENT_PEM,
            'key-file': paths.RA_AGENT_KEY,
            'ca-name': 'dogtag-ipa-ca-renew-agent',
            'not-valid-after': int(warning.timestamp()),
        }

        set_requests(remove=0, add=replaceme)

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertmongerExpirationCheck(registry)

        f.config.cert_expiration_days = str(CERT_EXPIRATION_DAYS)
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertmongerExpirationCheck'
        assert result.kw.get('key') == '5678'

        result = self.results.results[1]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertmongerExpirationCheck'
        assert result.kw.get('key') == '7777'
        assert result.kw.get('days') == 19


class FakeIPACertificate:
    def __init__(self, cert, backend=None, subject=None, not_after=None):
        self.subj = subject
        self.not_after = not_after

    @property
    def subject(self):
        return self.subj

    @property
    def not_valid_after_utc(self):
        return self.not_after


class TestChainExpiration(BaseTest):
    root_ca = 'CN=Certificate Shack Root CA,O=Certificate Shack Ltd'
    sub_ca = 'CN=Certificate Shack Intermediate CA,O=Certificate Shack Ltd'

    @patch('ipalib.x509.load_certificate_list_from_file')
    def test_still_valid(self, mock_load):
        mock_load.return_value = [
            FakeIPACertificate(
                None,
                subject=self.sub_ca,
                not_after=datetime.now(timezone.utc) + timedelta(days=20)
            ),
            FakeIPACertificate(
                None,
                subject=self.root_ca,
                not_after=datetime.now(timezone.utc) + timedelta(days=20)
            )
        ]
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACAChainExpirationCheck(registry)

        f.config.cert_expiration_days = '7'
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACAChainExpirationCheck'
        assert result.kw.get('key') == self.sub_ca

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACAChainExpirationCheck'
        assert result.kw.get('key') == self.root_ca

    @patch('ipalib.x509.load_certificate_list_from_file')
    def test_expiring_soon(self, mock_load):
        mock_load.return_value = [
            FakeIPACertificate(
                None,
                subject=self.sub_ca,
                not_after=datetime.now(timezone.utc) +
                timedelta(days=3, minutes=1)
            ),
            FakeIPACertificate(
                None,
                subject=self.root_ca,
                not_after=datetime.now(timezone.utc) +
                timedelta(days=3, minutes=1)
            )
        ]
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACAChainExpirationCheck(registry)

        f.config.cert_expiration_days = '7'
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACAChainExpirationCheck'
        assert result.kw.get('key') == self.sub_ca
        assert result.kw.get('days') == 3
        assert 'expiring' in result.kw.get('msg')

        result = self.results.results[1]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACAChainExpirationCheck'
        assert result.kw.get('key') == self.root_ca
        assert result.kw.get('days') == 3
        assert 'expiring' in result.kw.get('msg')

    @patch('ipalib.x509.load_certificate_list_from_file')
    def test_all_expired(self, mock_load):
        mock_load.return_value = [
            FakeIPACertificate(
                None,
                subject=self.sub_ca,
                not_after=datetime.now(timezone.utc) + timedelta(days=-3)
            ),
            FakeIPACertificate(
                None,
                subject=self.root_ca,
                not_after=datetime.now(timezone.utc) + timedelta(days=-3)
            )
        ]
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACAChainExpirationCheck(registry)

        f.config.cert_expiration_days = '7'
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACAChainExpirationCheck'
        assert result.kw.get('key') == self.sub_ca
        assert 'expired' in result.kw.get('msg')

        result = self.results.results[1]
        assert result.result == constants.CRITICAL
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACAChainExpirationCheck'
        assert result.kw.get('key') == self.root_ca
        assert 'expired' in result.kw.get('msg')

    @patch('ipalib.x509.load_certificate_list_from_file')
    def test_one_expired(self, mock_load):
        mock_load.return_value = [
            FakeIPACertificate(
                None,
                subject=self.sub_ca,
                not_after=datetime.now(timezone.utc) + timedelta(days=-3)
            ),
            FakeIPACertificate(
                None,
                subject=self.root_ca,
                not_after=datetime.now(timezone.utc) + timedelta(days=20)
            )
        ]
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACAChainExpirationCheck(registry)

        f.config.cert_expiration_days = '7'
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACAChainExpirationCheck'
        assert result.kw.get('key') == self.sub_ca
        assert 'expired' in result.kw.get('msg')

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACAChainExpirationCheck'
        assert result.kw.get('key') == self.root_ca
