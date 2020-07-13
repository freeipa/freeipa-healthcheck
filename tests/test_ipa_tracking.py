#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import capture_results
from base import BaseTest

from ipahealthcheck.core import constants, config
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertTracking
from unittest.mock import Mock
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
            "/usr/libexec/ipa/certmonger/renew_ra_cert"

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
