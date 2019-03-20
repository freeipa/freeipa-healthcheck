#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertmongerExpirationCheck
from unittest.mock import patch
from mock_certmonger import create_mock_dbus, _certmonger, get_requests
from mock_certmonger import set_requests

from util import capture_results


@patch('ipahealthcheck.ipa.certs.get_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
def test_expiration(mock_certmonger,
                    mock_cm_dbus_object,
                    mock_get_requests):
    set_requests()

    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_requests.return_value = get_requests()

    framework = object()
    registry.initialize(framework)
    f = IPACertmongerExpirationCheck(registry)

    f.config = config.Config()
    f.config.cert_expiration_days = 7
    results = capture_results(f)

    assert len(results) == 1
    result = results.results[0]
    assert result.severity == constants.ERROR
    assert result.source == 'ipahealthcheck.ipa.certs'
    assert result.check == 'IPACertmongerExpirationCheck'
    assert result.kw.get('key') == '1234'
    assert result.kw.get('msg') == 'Request id 1234 expired on 19691231191704Z'
