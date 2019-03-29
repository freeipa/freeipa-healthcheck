#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from util import capture_results, CAInstance, KRAInstance
from base import BaseTest
from ipahealthcheck.core import config, constants
from ipahealthcheck.dogtag.plugin import registry
from ipahealthcheck.dogtag.ca import DogtagCertsConfigCheck
from unittest.mock import Mock, patch


class mock_Cert:
    """Fake up a certificate.

      The contents are the NSS nickname of the certificate.
    """
    def __init__(self, text):
        self.text = text

    def public_bytes(self, encoding):
        return self.text.encode('utf-8')


class mock_CertDB:
    def __init__(self, trust):
        """A dict of nickname + NSSdb trust flags"""
        self.trust = trust

    def list_certs(self):
        return [(nickname, self.trust[nickname]) for nickname in self.trust]

    def get_cert_from_db(self, nickname):
        """Return the nickname. This will match the value of get_directive"""
        return mock_Cert(nickname)


class TestCACerts(BaseTest):
    patches = {
        'ipaserver.install.installutils.check_server_configuration':
        Mock(return_value=None),
        'ipaserver.install.cainstance.CAInstance':
        Mock(return_value=CAInstance()),
        'ipaserver.install.krainstance.KRAInstance':
        Mock(return_value=KRAInstance()),
    }

    @patch('ipahealthcheck.dogtag.ca.get_directive')
    @patch('ipaserver.install.certs.CertDB')
    def test_ca_certs_ok(self, mock_certdb, mock_directive):
        """Test what should be the standard case"""
        trust = {
            'ocspSigningCert cert-pki-ca': 'u,u,u',
            'subsystemCert cert-pki-ca': 'u,u,u',
            'auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'u,u,u',
            'caSigningCert cert-pki-ca': 'CT,C,C',
            'transportCert cert-pki-kra': 'u,u,u',
        }
        mock_certdb.return_value = mock_CertDB(trust)
        mock_directive.side_effect = [name for name, trust in trust.items()]

        framework = object()
        registry.initialize(framework)
        f = DogtagCertsConfigCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 6

        for result in self.results.results:
            assert result.severity == constants.SUCCESS
            assert result.source == 'ipahealthcheck.dogtag.ca'
            assert result.check == 'DogtagCertsConfigCheck'

    @patch('ipahealthcheck.dogtag.ca.get_directive')
    @patch('ipaserver.install.certs.CertDB')
    def test_cert_missing_from_file(self, mock_certdb, mock_directive):
        """Test a missing certificate.

           Note that if it is missing from the database then this check
           will not catch the error but it will be caught elsewhere.
        """
        trust = {
            'ocspSigningCert cert-pki-ca': 'u,u,u',
            'subsystemCert cert-pki-ca': 'u,u,u',
            'auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'u,u,u',
            'caSigningCert cert-pki-ca': 'CT,,',
            'transportCert cert-pki-kra': 'u,u,u',
        }

        # The 3rd cert won't match the results
        nicknames = [name for name, trust in trust.items()]
        location = nicknames.index('auditSigningCert cert-pki-ca')
        nicknames[location] = 'NOT auditSigningCert cert-pki-ca'

        mock_certdb.return_value = mock_CertDB(trust)
        mock_directive.side_effect = nicknames

        framework = object()
        registry.initialize(framework)
        f = DogtagCertsConfigCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        num = len(self.results.results)
        for r in range(0, num):
            if r == 2:  # skip the one that should be bad
                continue
            result = self.results.results[r]
            assert result.severity == constants.SUCCESS
            assert result.source == 'ipahealthcheck.dogtag.ca'
            assert result.check == 'DogtagCertsConfigCheck'

        result = self.results.results[2]

        assert result.severity == constants.ERROR
        assert result.source == 'ipahealthcheck.dogtag.ca'
        assert result.check == 'DogtagCertsConfigCheck'
        assert result.kw.get('key') == 'auditSigningCert cert-pki-ca'

        assert len(self.results) == 6

    @patch('ipaserver.install.cainstance.CAInstance')
    def test_cacert_caless(self, mock_cainstance):
        """Nothing to check if the master is CALess"""

        mock_cainstance.return_value = CAInstance(False)

        framework = object()
        registry.initialize(framework)
        f = DogtagCertsConfigCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 0
