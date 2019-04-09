#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import capture_results
from base import BaseTest
from ipaplatform.paths import paths
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertmongerExpirationCheck
from unittest.mock import Mock
from mock_certmonger import create_mock_dbus, _certmonger
from mock_certmonger import get_expected_requests, set_requests

from datetime import datetime, timedelta, timezone


class TestExpiration(BaseTest):
    patches = {
        'ipaserver.install.installutils.check_server_configuration':
        Mock(return_value=None),
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
        registry.initialize(framework)
        f = IPACertmongerExpirationCheck(registry)

        f.config = config.Config()
        f.config.cert_expiration_days = 7
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.severity == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertmongerExpirationCheck'
        assert result.kw.get('key') == '1234'
        assert result.kw.get('msg') == 'Request id 1234 expired on ' \
                                       '19700101001704Z'

        result = self.results.results[1]
        assert result.severity == constants.SUCCESS
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
        registry.initialize(framework)
        f = IPACertmongerExpirationCheck(registry)

        f.config = config.Config()
        f.config.cert_expiration_days = 30
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertmongerExpirationCheck'
        assert result.kw.get('key') == '5678'

        result = self.results.results[1]
        assert result.severity == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertmongerExpirationCheck'
        assert result.kw.get('key') == '7777'
        assert 'expires in 19 days' in result.kw.get('msg')
