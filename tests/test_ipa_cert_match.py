#
# Copyright (C) 2021 FreeIPA Contributors see COPYING for license
#

from util import capture_results, m_api, CAInstance, KRAInstance
from base import BaseTest
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertMatchCheck
from ipahealthcheck.ipa.certs import IPADogtagCertsMatchCheck
from unittest.mock import Mock, patch

from ipalib import errors
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient, LDAPEntry


class IPACertificate:
    def __init__(self, serial_number=1):
        self.serial_number = serial_number

    def __eq__(self, other):
        return self.serial_number == other.serial_number

    def __hash__(self):
        return hash(self.serial_number)


class mock_ldap:
    SCOPE_BASE = 1
    SCOPE_ONELEVEL = 2
    SCOPE_SUBTREE = 4

    def __init__(self, entries):
        """Initialize the results that we will return from get_entry"""
        self.results = {entry.dn: entry for entry in entries}

    def get_entry(self, dn, attrs_list=None, time_limit=None,
                  size_limit=None, get_effective_rights=False):
        if self.results is None:
            raise errors.NotFound(reason='test')
        return self.results[dn]

    def get_entries(self, base_dn, scope=SCOPE_SUBTREE, filter=None,
                    attrs_list=None, get_effective_rights=False, **kwargs):
        if self.results is None:
            raise errors.NotFound(reason='None')
        if filter:
            (attr, value) = filter.split('=', maxsplit=1)
            for result in self.results.values():
                if result.get(attr)[0] == value:
                    return [result]
            raise errors.NotFound(reason='Not found %s' % filter)

        return self.results


class mock_ldap_conn:
    def set_option(self, option, invalue):
        pass

    def search_s(self, base, scope, filterstr=None,
                 attrlist=None, attrsonly=0):
        return tuple()


class mock_CertDB:
    def __init__(self, trust):
        """A dict of nickname + NSSdb trust flags"""
        self.trust = trust
        self.secdir = '/foo/bar/testdir'

    def get_cert_from_db(self, nickname):
        if nickname not in self.trust.keys():
            raise errors.NotFound(reason='test')
        return IPACertificate()

    def run_certutil(self, args, capture_output):
        class RunResult:
            def __init__(self, output):
                self.raw_output = output

        return RunResult(b'test output')


class TestIPACertMatch(BaseTest):
    patches = {
        'ldap.initialize':
        Mock(return_value=mock_ldap_conn())
    }

    trust = {
        ('%s IPA CA' % m_api.env.realm): 'u,u,u'
    }

    @patch('ipalib.x509.load_certificate_list_from_file')
    @patch('ipaserver.install.certs.CertDB')
    def test_certs_match_ok(self, mock_certdb, mock_load_cert):
        """ Ensure match check is ok"""
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        cacertentry = LDAPEntry(fake_conn,
                                DN('cn=%s IPA CA' % m_api.env.realm,
                                   'cn=certificates,cn=ipa,cn=etc',
                                    m_api.env.basedn),
                                CACertificate=[IPACertificate()])

        mock_certdb.return_value = mock_CertDB(self.trust)
        mock_load_cert.return_value = [IPACertificate()]

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPACertMatchCheck(registry)
        f.conn = mock_ldap([cacertentry])
        self.results = capture_results(f)

        assert len(self.results) == 3
        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPACertMatchCheck'

    @patch('ipalib.x509.load_certificate_list_from_file')
    @patch('ipaserver.install.certs.CertDB')
    def test_etc_cacert_mismatch(self, mock_certdb, mock_load_cert):
        """ Test mismatch with /etc/ipa/ca.crt """
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        cacertentry = LDAPEntry(fake_conn,
                                DN('cn=%s IPA CA' % m_api.env.realm,
                                   'cn=certificates,cn=ipa,cn=etc',
                                    m_api.env.basedn),
                                CACertificate=[IPACertificate()])

        mock_certdb.return_value = mock_CertDB(self.trust)
        mock_load_cert.return_value = [IPACertificate(serial_number=2)]

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPACertMatchCheck(registry)
        f.conn = mock_ldap([cacertentry])
        self.results = capture_results(f)

        assert len(self.results) == 3
        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPACertMatchCheck'

    @patch('ipaserver.install.cainstance.CAInstance')
    def test_cacert_caless(self, mock_cainstance):
        """Nothing to check if the master is CALess"""

        mock_cainstance.return_value = CAInstance(False)

        framework = object()
        registry.initialize(framework, config)
        f = IPACertMatchCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 0


default_subject_base = [{
    'result':
        {
            'ipacertificatesubjectbase': [f'O={m_api.env.realm}'],
        },
}]

custom_subject_base = [{
    'result':
        {
            'ipacertificatesubjectbase': ['OU=Eng,O=ACME'],
        },
}]


class TestIPADogtagCertMatch(BaseTest):
    patches = {
        'ipaserver.install.krainstance.KRAInstance':
        Mock(return_value=KRAInstance()),
    }
    trust = {
        'ocspSigningCert cert-pki-ca': 'u,u,u',
        'caSigningCert cert-pki-ca': 'u,u,u',
        'subsystemCert cert-pki-ca': 'u,u,u',
        'auditSigningCert cert-pki-ca': 'u,u,Pu',
        'Server-Cert cert-pki-ca': 'u,u,u',
        'transportCert cert-pki-kra': 'u,u,u',
        'storageCert cert-pki-kra': 'u,u,u',
        'auditSigningCert cert-pki-kra': 'u,u,Pu',
    }

    def get_dogtag_subjects(self, hostname, base):
        subject_base = base[0]['result']['ipacertificatesubjectbase'][0]
        return (
            f'CN=OCSP Subsystem,{subject_base}',
            f'CN=CA Subsystem,{subject_base}',
            f'CN=CA Audit,{subject_base}',
            f'CN=%s,{subject_base}',
            f'CN=KRA Transport Certificate,{subject_base}',
            f'CN=KRA Storage Certificate,{subject_base}',
            f'CN=KRA Audit,{subject_base}',
            f'CN={hostname},{subject_base}',
        )

    @patch('ipaserver.install.certs.CertDB')
    def test_certs_match_ok(self, mock_certdb):
        """ Ensure match check is ok"""
        m_api.Command.config_show.side_effect = default_subject_base
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        pkidbentry = LDAPEntry(fake_conn,
                               DN('uid=pkidbuser,ou=people,o=ipaca'),
                               userCertificate=[IPACertificate()],
                               subjectName=['test'])
        casignentry = LDAPEntry(fake_conn,
                                DN('cn=%s IPA CA' % m_api.env.realm,
                                   'cn=certificates,cn=ipa,cn=etc',
                                    m_api.env.basedn),
                                CACertificate=[IPACertificate()],
                                userCertificate=[IPACertificate()],
                                subjectName=['test'])
        ldap_entries = [pkidbentry, casignentry]

        dogtag_entries_subjects = self.get_dogtag_subjects(
            m_api.env.host, default_subject_base
        )

        for i, subject in enumerate(dogtag_entries_subjects):
            entry = LDAPEntry(fake_conn,
                              DN('cn=%i,ou=certificateRepository' % i,
                                 'ou=ca,o=ipaca'),
                              userCertificate=[IPACertificate()],
                              subjectName=[subject])
            ldap_entries.append(entry)

        mock_certdb.return_value = mock_CertDB(self.trust)

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPADogtagCertsMatchCheck(registry)
        f.conn = mock_ldap(ldap_entries)
        self.results = capture_results(f)

        assert len(self.results) == 3
        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPADogtagCertsMatchCheck'

    @patch('ipaserver.install.certs.CertDB')
    def test_certs_mismatch(self, mock_certdb):
        """ Ensure mismatches are detected"""
        m_api.Command.config_show.side_effect = default_subject_base
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        pkidbentry = LDAPEntry(fake_conn,
                               DN('uid=pkidbuser,ou=people,o=ipaca'),
                               userCertificate=[IPACertificate(
                                   serial_number=2
                               )],
                               subjectName=['test'])
        casignentry = LDAPEntry(fake_conn,
                                DN('cn=%s IPA CA' % m_api.env.realm,
                                   'cn=certificates,cn=ipa,cn=etc',
                                    m_api.env.basedn),
                                CACertificate=[IPACertificate()],
                                userCertificate=[IPACertificate()],
                                subjectName=['test'])
        ldap_entries = [pkidbentry, casignentry]

        dogtag_entries_subjects = self.get_dogtag_subjects(
            m_api.env.host, default_subject_base
        )

        for i, subject in enumerate(dogtag_entries_subjects):
            entry = LDAPEntry(fake_conn,
                              DN('cn=%i,ou=certificateRepository' % i,
                                 'ou=ca,o=ipaca'),
                              userCertificate=[IPACertificate()],
                              subjectName=[subject])
            ldap_entries.append(entry)

        mock_certdb.return_value = mock_CertDB(self.trust)

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPADogtagCertsMatchCheck(registry)
        f.conn = mock_ldap(ldap_entries)
        self.results = capture_results(f)

        assert len(self.results) == 3
        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
        assert result.check == 'IPADogtagCertsMatchCheck'

    @patch('ipaserver.install.certs.CertDB')
    def test_certs_match_ok_subject(self, mock_certdb):
        """ Ensure match check is ok"""
        m_api.Command.config_show.side_effect = custom_subject_base
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        pkidbentry = LDAPEntry(fake_conn,
                               DN('uid=pkidbuser,ou=people,o=ipaca'),
                               userCertificate=[IPACertificate()],
                               subjectName=['test'])
        casignentry = LDAPEntry(fake_conn,
                                DN('cn=%s IPA CA' % m_api.env.realm,
                                   'cn=certificates,cn=ipa,cn=etc',
                                    m_api.env.basedn),
                                CACertificate=[IPACertificate()],
                                userCertificate=[IPACertificate()],
                                subjectName=['test'])
        ldap_entries = [pkidbentry, casignentry]

        dogtag_entries_subjects = self.get_dogtag_subjects(
            m_api.env.host, custom_subject_base
        )

        for i, subject in enumerate(dogtag_entries_subjects):
            entry = LDAPEntry(fake_conn,
                              DN('cn=%i,ou=certificateRepository' % i,
                                 'ou=ca,o=ipaca'),
                              userCertificate=[IPACertificate()],
                              subjectName=[subject])
            ldap_entries.append(entry)

        mock_certdb.return_value = mock_CertDB(self.trust)

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPADogtagCertsMatchCheck(registry)
        f.conn = mock_ldap(ldap_entries)
        self.results = capture_results(f)

        assert len(self.results) == 3
        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.certs'
            assert result.check == 'IPADogtagCertsMatchCheck'

    @patch('ipaserver.install.certs.CertDB')
    def test_certs_mismatch_subject(self, mock_certdb):
        """ Ensure mismatches are detected"""
        m_api.Command.config_show.side_effect = custom_subject_base
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        pkidbentry = LDAPEntry(fake_conn,
                               DN('uid=pkidbuser,ou=people,o=ipaca'),
                               userCertificate=[IPACertificate(
                                   serial_number=2
                               )],
                               subjectName=['test'])
        casignentry = LDAPEntry(fake_conn,
                                DN('cn=%s IPA CA' % m_api.env.realm,
                                   'cn=certificates,cn=ipa,cn=etc',
                                    m_api.env.basedn),
                                CACertificate=[IPACertificate()],
                                userCertificate=[IPACertificate()],
                                subjectName=['test'])
        ldap_entries = [pkidbentry, casignentry]

        dogtag_entries_subjects = self.get_dogtag_subjects(
            m_api.env.host, custom_subject_base
        )

        for i, subject in enumerate(dogtag_entries_subjects):
            entry = LDAPEntry(fake_conn,
                              DN('cn=%i,ou=certificateRepository' % i,
                                 'ou=ca,o=ipaca'),
                              userCertificate=[IPACertificate()],
                              subjectName=[subject])
            ldap_entries.append(entry)

        mock_certdb.return_value = mock_CertDB(self.trust)

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPADogtagCertsMatchCheck(registry)
        f.conn = mock_ldap(ldap_entries)
        self.results = capture_results(f)

        assert len(self.results) == 3
        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.certs'
