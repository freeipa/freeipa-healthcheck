#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import capture_results, CAInstance
from util import m_api
from base import BaseTest
from unittest.mock import Mock

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertRevocation
from mock_certmonger import create_mock_dbus, _certmonger
from mock_certmonger import get_expected_requests, set_requests


class IPACertificate:
    def __init__(self, serial_number=1):
        self.subject = 'CN=RA AGENT'
        self.issuer = 'CN=ISSUER'
        self.serial_number = serial_number


class TestRevocation(BaseTest):
    patches = {
        'ipaserver.install.certs.is_ipa_issued_cert':
        Mock(return_value=True),
        'ipalib.x509.load_certificate_from_file':
        Mock(return_value=IPACertificate()),
        'ipahealthcheck.ipa.certs.get_expected_requests':
        Mock(return_value=get_expected_requests()),
        'ipalib.install.certmonger._cm_dbus_object':
        Mock(side_effect=create_mock_dbus),
        'ipalib.install.certmonger._certmonger':
        Mock(return_value=_certmonger()),
        'ipaserver.install.cainstance.CAInstance':
        Mock(return_value=CAInstance()),
    }

    def test_revocation_ok(self):
        m_api.Command.cert_show.side_effect = [
            {
                u'result': {
                    u"revoked": False,
                }
            },
            {
                u'result': {
                    u"revoked": False,
                }
            },
        ]

        set_requests()

        framework = object()
        registry.initialize(framework)
        f = IPACertRevocation(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 2

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPACertRevocation'

    def test_revocation_one_bad(self):
        m_api.Command.cert_show.side_effect = [
            {
                u'result': {
                    u"revoked": False,
                }
            },
            {
                u'result': {
                    u"revoked": True,
                    u"revocation_reason": 4,
                }
            },
        ]
        set_requests()

        framework = object()
        registry.initialize(framework)
        f = IPACertRevocation(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertRevocation'

        result = self.results.results[1]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertRevocation'
        assert result.kw.get('revocation_reason') == 'superseded'
