#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import capture_results, CAInstance
from util import m_api
from base import BaseTest
from ipahealthcheck.core import constants, config
from ipahealthcheck.dogtag.plugin import registry
from ipahealthcheck.dogtag.ca import DogtagCertsConnectivityCheck
from unittest.mock import Mock
from ipalib.errors import CertificateOperationError


class TestCAConnectivity(BaseTest):
    patches = {
        'ipaserver.install.cainstance.CAInstance':
        Mock(return_value=CAInstance()),
    }

    def test_ca_connection_ok(self):
        """CA connectivity check when cert_show returns a valid value"""
        m_api.Command.cert_show.side_effect = None
        m_api.Command.cert_show.return_value = {
            u'result': {u'revoked': False}
        }

        framework = object()
        registry.initialize(framework, config.Config)
        f = DogtagCertsConnectivityCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.dogtag.ca'
        assert result.check == 'DogtagCertsConnectivityCheck'

    def test_ca_connection_cert_not_found(self):
        """CA connectivity check for a cert that doesn't exist"""
        m_api.Command.cert_show.reset_mock()
        m_api.Command.cert_show.side_effect = CertificateOperationError(
            message='Certificate operation cannot be completed: '
                    'EXCEPTION (Certificate serial number 0x0 not found)'
        )

        framework = object()
        registry.initialize(framework, config.Config)
        f = DogtagCertsConnectivityCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.dogtag.ca'
        assert result.check == 'DogtagCertsConnectivityCheck'

    def test_ca_connection_down(self):
        """CA connectivity check with the CA down"""
        m_api.Command.cert_show.side_effect = CertificateOperationError(
            message='Certificate operation cannot be completed: '
                    'Unable to communicate with CMS (503)'
        )

        framework = object()
        registry.initialize(framework, config.Config)
        f = DogtagCertsConnectivityCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.dogtag.ca'
        assert result.check == 'DogtagCertsConnectivityCheck'
        assert 'Unable to communicate' in result.kw.get('msg')
