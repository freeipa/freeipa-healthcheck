#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipaplatform.paths import paths
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertfileExpirationCheck, DAY
from unittest.mock import patch
from mock_certmonger import create_mock_dbus, _certmonger
from mock_certmonger import get_expected_requests, set_requests

from util import capture_results, no_exceptions
from datetime import datetime, timedelta

class IPACertificate:
    def __init__(self, not_valid_after, serial_number=1):
        self.subject = 'CN=RA AGENT'
        self.issuer = 'CN=ISSUER'
        self.serial_number = serial_number
        self.not_valid_after = not_valid_after


@patch('ipalib.x509.load_certificate_from_file')
@patch('ipahealthcheck.ipa.certs.get_expected_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
def test_certfile_expiration(mock_certmonger,
                             mock_cm_dbus_object,
                             mock_get_expected_requests,
                             mock_load_cert):
    set_requests(remove=1)

    cert = IPACertificate(not_valid_after = datetime.utcnow() + timedelta(days=30))
    mock_load_cert.return_value = cert

    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_expected_requests.return_value = get_expected_requests()

    framework = object()
    registry.initialize(framework)
    f = IPACertfileExpirationCheck(registry)

    f.config = config.Config()
    f.config.cert_expiration_days = 28
    results = capture_results(f)

    assert len(results) == 1

    result = results.results[0]
    assert result.severity == constants.SUCCESS
    assert result.source == 'ipahealthcheck.ipa.certs'
    assert result.check == 'IPACertfileExpirationCheck'
    assert result.kw.get('key') == '1234'

    no_exceptions(results)


@patch('ipalib.x509.load_certificate_from_file')
@patch('ipahealthcheck.ipa.certs.get_expected_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
def test_certfile_expiration_warning(mock_certmonger,
                                     mock_cm_dbus_object,
                                     mock_get_expected_requests,
                                     mock_load_cert):

    set_requests(remove=1)

    cert = IPACertificate(not_valid_after = datetime.utcnow() + timedelta(days=7))
    mock_load_cert.return_value = cert
    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_expected_requests.return_value = get_expected_requests()

    framework = object()
    registry.initialize(framework)
    f = IPACertfileExpirationCheck(registry)

    f.config = config.Config()
    f.config.cert_expiration_days = 30
    results = capture_results(f)

    assert len(results) == 1

    result = results.results[0]
    assert result.severity == constants.WARNING
    assert result.source == 'ipahealthcheck.ipa.certs'
    assert result.check == 'IPACertfileExpirationCheck'
    assert result.kw.get('key') == '1234'
    assert 'expires in 6 days' in result.kw.get('msg') 

    no_exceptions(results)


@patch('ipalib.x509.load_certificate_from_file')
@patch('ipahealthcheck.ipa.certs.get_expected_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
def test_certfile_expiration_expired(mock_certmonger,
                                     mock_cm_dbus_object,
                                     mock_get_expected_requests,
                                     mock_load_cert):

    set_requests(remove=1)

    cert = IPACertificate(not_valid_after = datetime.utcnow() + timedelta(days=-100))
    mock_load_cert.return_value = cert
    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_expected_requests.return_value = get_expected_requests()

    framework = object()
    registry.initialize(framework)
    f = IPACertfileExpirationCheck(registry)

    f.config = config.Config()
    f.config.cert_expiration_days = 30
    results = capture_results(f)

    assert len(results) == 1

    result = results.results[0]
    assert result.severity == constants.ERROR
    assert result.source == 'ipahealthcheck.ipa.certs'
    assert result.check == 'IPACertfileExpirationCheck'
    assert result.kw.get('key') == '1234'
    assert 'Request id 1234 expired on' in result.kw.get('msg') 

    no_exceptions(results)
