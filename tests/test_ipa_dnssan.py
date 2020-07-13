#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from util import capture_results, CAInstance
from util import m_api
from base import BaseTest
from unittest.mock import Mock, patch

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertDNSSAN
from mock_certmonger import create_mock_dbus, _certmonger
from mock_certmonger import get_expected_requests, set_requests


class IPACertificate:
    def __init__(self, serial_number=1, no_san=False):
        self.subject = 'CN=%s' % m_api.env.host
        self.issuer = 'CN=ISSUER'
        self.serial_number = serial_number
        self.san_a_label_dns_names = [m_api.env.host]
        if not no_san:
            self.san_a_label_dns_names.append('ipa-ca.%s' % m_api.env.domain)


class TestDNSSAN(BaseTest):
    patches = {
        'ipaserver.install.certs.is_ipa_issued_cert':
        Mock(return_value=True),
        'ipahealthcheck.ipa.certs.get_expected_requests':
        Mock(return_value=get_expected_requests()),
        'ipalib.install.certmonger._cm_dbus_object':
        Mock(side_effect=create_mock_dbus),
        'ipalib.install.certmonger._certmonger':
        Mock(return_value=_certmonger()),
        'ipaserver.install.cainstance.CAInstance':
        Mock(return_value=CAInstance()),
        'socket.getfqdn':
        Mock(return_value=m_api.env.host),
    }

    @patch('ipalib.install.certmonger.get_request_value')
    @patch('ipalib.x509.load_certificate_from_file')
    def test_dnssan_ok(self, mock_cert, mock_value):
        set_requests()

        mock_value.side_effect = ['dogtag-ipa-ca-renew-agent',
                                  'IPA', 'caIPAserviceCert']
        mock_cert.return_value = IPACertificate()

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertDNSSAN(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.kw.get('san') == [m_api.env.host,
                                        'ipa-ca.%s' % m_api.env.domain]
        assert result.kw.get('hostname') == [m_api.env.host,
                                             'ipa-ca.%s' % m_api.env.domain]
        assert result.kw.get('profile') == 'caIPAserviceCert'
        assert result.check == 'IPACertDNSSAN'

    @patch('ipalib.install.certmonger.get_request_value')
    def test_sandns_no_certs(self, mock_value):
        set_requests()

        mock_value.side_effect = ['dogtag-ipa-ca-renew-agent',
                                  'dogtag-ipa-ca-renew-agent']

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertDNSSAN(registry)

        self.results = capture_results(f)

        # No IPA CA, no results
        assert len(self.results) == 0

    @patch('ipalib.install.certmonger.get_request_value')
    @patch('ipalib.x509.load_certificate_from_file')
    def test_dnssan_missing_ipaca(self, mock_cert, mock_value):
        set_requests()

        mock_value.side_effect = ['dogtag-ipa-ca-renew-agent',
                                  'IPA', 'caIPAserviceCert']
        mock_cert.return_value = IPACertificate(no_san=True)

        framework = object()
        registry.initialize(framework, config.Config)
        f = IPACertDNSSAN(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.kw.get('san') == [m_api.env.host]
        assert result.kw.get('hostname') == 'ipa-ca.%s' % m_api.env.domain
        assert result.kw.get('profile') == 'caIPAserviceCert'
        assert result.kw.get('ca') == 'IPA'
        assert result.kw.get('key') == '5678'
