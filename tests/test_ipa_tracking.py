#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertTracking
from unittest.mock import patch
from mock_certmonger import create_mock_dbus, _certmonger, get_requests
from mock_certmonger import set_requests


@patch('ipahealthcheck.ipa.certs.get_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
def test_known_cert_tracking(mock_certmonger,
                             mock_cm_dbus_object,
                             mock_get_requests):
    set_requests()

    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_requests.return_value = get_requests()

    framework = object()
    registry.initialize(framework)
    f = IPACertTracking(registry)

    results = f.check()

    assert len(results) == 0


@patch('ipahealthcheck.ipa.certs.get_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
def test_missing_cert_tracking(mock_certmonger,
                               mock_cm_dbus_object,
                               mock_get_requests):

    # remove one of the requests to force it to be missing
    set_requests(remove=0)

    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_requests.return_value = get_requests()

    framework = object()
    registry.initialize(framework)
    f = IPACertTracking(registry)

    results = f.check()

    assert len(results) == 1

    result = results.results[0]
    assert result.severity == constants.ERROR
    assert result.source == 'ipahealthcheck.ipa.certs'
    assert result.check == 'IPACertTracking'
    assert result.kw.get('msg') == "Missing tracking for {" \
        "'cert-file': '/var/lib/ipa/ra-agent.pem', " \
        "'key-file': '/var/lib/ipa/ra-agent.key', " \
        "'ca-name': 'dogtag-ipa-ca-renew-agent', " \
        "'cert-presave-command': " \
        "'/usr/libexec/ipa/certmonger/renew_ra_cert_pre', " \
        "'cert-postsave-command': '/usr/libexec/ipa/certmonger/renew_ra_cert'}"


@patch('ipahealthcheck.ipa.certs.get_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
def test_unknown_cert_tracking(mock_certmonger,
                               mock_cm_dbus_object,
                               mock_get_requests):
    # Add a custom, unknown request
    unknown = {
        'nickname': '7777',
        'cert-file': '/tmp/test.crt',
        'key-file': '/tmp/test.key',
        'ca-name': 'IPA',
    }
    set_requests(add=unknown)

    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_requests.return_value = get_requests()

    framework = object()
    registry.initialize(framework)
    f = IPACertTracking(registry)

    results = f.check()

    assert len(results) == 1

    result = results.results[0]
    assert result.severity == constants.WARNING
    assert result.source == 'ipahealthcheck.ipa.certs'
    assert result.check == 'IPACertTracking'
    assert result.kw.get('msg') == 'Unknown certmonger id 7777'
