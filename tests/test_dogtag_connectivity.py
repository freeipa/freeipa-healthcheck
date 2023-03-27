#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from unittest.mock import Mock, patch
from util import capture_results, CAInstance
from util import m_api

from base import BaseTest
from ipahealthcheck.core import constants, config
from ipahealthcheck.dogtag.plugin import registry
from ipahealthcheck.dogtag.ca import DogtagCertsConnectivityCheck

from ipalib.errors import CertificateOperationError
from ipaplatform.paths import paths


default_subject_base = [{
    'result':
        {
            'ipacertificatesubjectbase': [f'O={m_api.env.realm}'],
        },
}]


class IPACertificate:
    def __init__(self, serial_number=1,
                 subject='CN=Certificate Authority, O=%s' % m_api.env.realm,
                 issuer='CN=Certificate Authority, O=%s' % m_api.env.realm):
        self.serial_number = serial_number
        self.subject = subject
        self.issuer = issuer

    def __eq__(self, other):
        return self.serial_number == other.serial_number

    def __hash__(self):
        return hash(self.serial_number)


subject_base = [{
    'result':
        {
            'ipacertificatesubjectbase': [f'O={m_api.env.realm}'],
        },
}]

bad_subject_base = [{
    'result':
        {
            'ipacertificatesubjectbase': ['O=BAD'],
        },
}]


class TestCAConnectivity(BaseTest):
    patches = {
        'ipaserver.install.cainstance.CAInstance':
        Mock(return_value=CAInstance()),
    }

    @patch('ipalib.x509.load_certificate_from_file')
    def test_ca_connection_ok(self, mock_load_cert):
        """CA connectivity check when cert_show returns a valid value"""
        m_api.Command.cert_show.side_effect = None
        m_api.Command.config_show.side_effect = subject_base
        m_api.Command.cert_show.return_value = {
            u'result': {u'revoked': False}
        }
        mock_load_cert.return_value = IPACertificate(12345)

        framework = object()
        registry.initialize(framework, config.Config)
        f = DogtagCertsConnectivityCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.dogtag.ca'
        assert result.check == 'DogtagCertsConnectivityCheck'

    @patch('ipalib.x509.load_certificate_from_file')
    def test_ca_connection_cert_not_found(self, mock_load_cert):
        """CA connectivity check for a cert that doesn't exist"""
        m_api.Command.cert_show.reset_mock()
        m_api.Command.config_show.side_effect = subject_base
        m_api.Command.cert_show.side_effect = CertificateOperationError(
            message='Certificate operation cannot be completed: '
                    'EXCEPTION (Certificate serial number 0x0 not found)'
        )
        mock_load_cert.return_value = IPACertificate(serial_number=7)

        framework = object()
        registry.initialize(framework, config.Config)
        f = DogtagCertsConnectivityCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.dogtag.ca'
        assert result.check == 'DogtagCertsConnectivityCheck'
        assert result.kw.get('key') == 'cert_show_ra'
        assert result.kw.get('serial') == '7'
        assert result.kw.get('msg') == 'Serial number not found: {error}'

    @patch('ipalib.x509.load_certificate_from_file')
    def test_ca_connection_cert_file_not_found(self, mock_load_cert):
        """CA connectivity check for a cert that doesn't exist"""
        m_api.Command.cert_show.reset_mock()
        m_api.Command.config_show.side_effect = subject_base
        mock_load_cert.side_effect = FileNotFoundError()

        framework = object()
        registry.initialize(framework, config.Config)
        f = DogtagCertsConnectivityCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.dogtag.ca'
        assert result.check == 'DogtagCertsConnectivityCheck'
        assert result.kw.get('key') == 'ipa_ra_crt_file_missing'
        assert result.kw.get('path') == paths.RA_AGENT_PEM

    @patch('ipalib.x509.load_certificate_from_file')
    def test_ca_connection_down(self, mock_load_cert):
        """CA connectivity check with the CA down"""
        m_api.Command.cert_show.side_effect = CertificateOperationError(
            message='Certificate operation cannot be completed: '
                    'Unable to communicate with CMS (503)'
        )
        m_api.Command.config_show.side_effect = subject_base
        mock_load_cert.return_value = IPACertificate()

        framework = object()
        registry.initialize(framework, config.Config)
        f = DogtagCertsConnectivityCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.dogtag.ca'
        assert result.check == 'DogtagCertsConnectivityCheck'
        assert result.kw.get('msg') == (
            'Request for certificate failed: {error}'
        )
