#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import capture_results, CAInstance, no_exceptions
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertRevocation
from unittest.mock import patch
from mock_certmonger import create_mock_dbus, _certmonger
from mock_certmonger import get_expected_requests, set_requests

from ipapython.ipautil import _RunResult


class IPACertificate:
    def __init__(self, serial_number=1):
        self.subject = 'CN=RA AGENT'
        self.issuer = 'CN=ISSUER'
        self.serial_number = serial_number


@patch('ipaserver.install.certs.is_ipa_issued_cert')
@patch('ipalib.x509.load_certificate_from_file')
@patch('ipahealthcheck.ipa.certs.get_expected_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
@patch('ipaserver.install.cainstance.CAInstance')
def test_revocation_ok(mock_cainstance,
                       mock_certmonger,
                       mock_cm_dbus_object,
                       mock_get_expected_requests,
                       mock_loadcert,
                       mock_is_ipa_issued):
    set_requests()

    mock_cainstance.return_value = CAInstance()
    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_expected_requests.return_value = get_expected_requests()
    mock_loadcert.return_value = IPACertificate()
    mock_is_ipa_issued.return_value = True

    framework = object()
    registry.initialize(framework)
    f = IPACertRevocation(registry)

    f.config = config.Config()
    results = capture_results(f)

    assert len(results) == 2

    for result in results.results:
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertRevocation'

    no_exceptions(results)


@patch('ipaserver.install.certs.is_ipa_issued_cert')
@patch('ipalib.x509.load_certificate_from_file')
@patch('ipahealthcheck.ipa.certs.get_expected_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
@patch('ipaserver.install.cainstance.CAInstance')
def test_revocation_one_bad(mock_cainstance,
                            mock_certmonger,
                            mock_cm_dbus_object,
                            mock_get_expected_requests,
                            mock_loadcert,
                            mock_is_ipa_issued):
    set_requests()

    mock_cainstance.return_value = CAInstance()
    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_expected_requests.return_value = get_expected_requests()
    mock_loadcert.return_value = IPACertificate()
    mock_is_ipa_issued.return_value = True

    framework = object()
    registry.initialize(framework)
    f = IPACertRevocation(registry)

    f.config = config.Config()
    results = capture_results(f)

    assert len(results) == 2

    result = results.results[0]
    assert result.severity == constants.SUCCESS
    assert result.source == 'ipahealthcheck.ipa.certs'
    assert result.check == 'IPACertRevocation'

    result = results.results[1]
    assert result.severity == constants.ERROR
    assert result.source == 'ipahealthcheck.ipa.certs'
    assert result.check == 'IPACertRevocation'
    assert result.kw.get('revocation_reason') == 'superseded'

    no_exceptions(results)
