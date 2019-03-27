#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPARAAgent
from unittest.mock import patch

from ipalib import errors
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient, LDAPEntry

from util import capture_results, CAInstance, no_exceptions
from ldap import OPT_X_SASL_SSF_MIN


class IPACertificate:
    def __init__(self, serial_number=1):
        self.subject = 'CN=RA AGENT'
        self.issuer = 'CN=ISSUER'
        self.serial_number = serial_number


class mock_ldap:
    SCOPE_BASE = 1
    SCOPE_ONELEVEL = 2
    SCOPE_SUBTREE = 4

    def __init__(self, ldapentry):
        """Initialize the results that we will return from get_entries"""
        self.results = ldapentry

    def get_entries(self, base_dn, scope=SCOPE_SUBTREE, filter=None,
                    attrs_list=None, get_effective_rights=False, **kwargs):
        if self.results is None:
            raise errors.NotFound(reason='test')
        return self.results


class mock_ldap_conn:
    def set_option(self, option, invalue):
        pass

    def get_option(self, option):
        if option == OPT_X_SASL_SSF_MIN:
            return 256

    def search_s(self, base, scope, filterstr=None,
                 attrlist=None, attrsonly=0):
        return tuple()


@patch('ldap.initialize')
@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipalib.x509.load_certificate_from_file')
def test_nss_agent_ok(mock_load_cert, mock_cainstance, mock_ldapinit):

    cert = IPACertificate()
    mock_load_cert.return_value = cert
    mock_cainstance.return_value = CAInstance()
    mock_ldapinit.return_value = mock_ldap_conn()

    attrs = dict(
        description=['2;1;CN=ISSUER;CN=RA AGENT'],
        usercertificate=[cert],
    )
    fake_conn = LDAPClient('ldap://localhost')
    ldapentry = LDAPEntry(fake_conn, DN('uid=ipara,ou=people,o=ipaca'))
    for attr, values in attrs.items():
        ldapentry[attr] = values

    framework = object()
    registry.initialize(framework)
    f = IPARAAgent(registry)

    f.conn = mock_ldap([ldapentry])
    f.config = config.Config()
    results = capture_results(f)

    # A valid call relies on a success to be set by core
    assert len(results) == 0

    no_exceptions(results)


@patch('ldap.initialize')
@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipalib.x509.load_certificate_from_file')
def test_nss_agent_no_description(mock_load_cert, mock_cainstance,
                                  mock_ldapinit):

    cert = IPACertificate()
    mock_load_cert.return_value = cert
    mock_cainstance.return_value = CAInstance()
    mock_ldapinit.return_value = mock_ldap_conn()

    attrs = dict(
        usercertificate=[cert],
    )
    fake_conn = LDAPClient('ldap://localhost')
    ldapentry = LDAPEntry(fake_conn, DN('uid=ipara,ou=people,o=ipaca'))
    for attr, values in attrs.items():
        ldapentry[attr] = values

    framework = object()
    registry.initialize(framework)
    f = IPARAAgent(registry)

    f.conn = mock_ldap([ldapentry])
    f.config = config.Config()
    results = capture_results(f)
    result = results.results[0]

    assert result.severity == constants.ERROR
    assert result.kw.get('msg') == 'RA agent is missing description'

    no_exceptions(results)


@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipalib.x509.load_certificate_from_file')
def test_nss_agent_load_failure(mock_load_cert, mock_cainstance):

    mock_load_cert.side_effect = IOError('test')
    mock_cainstance.return_value = CAInstance()

    framework = object()
    registry.initialize(framework)
    f = IPARAAgent(registry)

    f.config = config.Config()
    results = capture_results(f)
    result = results.results[0]

    assert result.severity == constants.ERROR
    assert result.kw.get('msg') == 'Unable to load RA cert: test'

    no_exceptions(results)


@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipalib.x509.load_certificate_from_file')
def test_nss_agent_no_entry_found(mock_load_cert, mock_cainstance):

    cert = IPACertificate()
    mock_load_cert.return_value = cert
    mock_cainstance.return_value = CAInstance()

    framework = object()
    registry.initialize(framework)
    f = IPARAAgent(registry)

    f.conn = mock_ldap(None)  # None == NotFound
    f.config = config.Config()
    results = capture_results(f)
    result = results.results[0]

    assert result.severity == constants.ERROR
    assert result.kw.get('msg') == 'RA agent not found in LDAP'

    no_exceptions(results)


@patch('ldap.initialize')
@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipalib.x509.load_certificate_from_file')
def test_nss_agent_too_many(mock_load_cert, mock_cainstance, mock_ldapinit):

    cert = IPACertificate()
    mock_load_cert.return_value = cert
    mock_cainstance.return_value = CAInstance()
    mock_ldapinit.return_value = mock_ldap_conn()

    attrs = dict(
        description=['2;1;CN=ISSUER;CN=RA AGENT'],
        usercertificate=[cert],
    )
    fake_conn = LDAPClient('ldap://localhost')
    ldapentry = LDAPEntry(fake_conn, DN('uid=ipara,ou=people,o=ipaca'))
    for attr, values in attrs.items():
        ldapentry[attr] = values

    ldapentry2 = LDAPEntry(fake_conn, DN('uid=ipara2,ou=people,o=ipaca'))
    for attr, values in attrs.items():
        ldapentry[attr] = values

    framework = object()
    registry.initialize(framework)
    f = IPARAAgent(registry)

    f.conn = mock_ldap([ldapentry, ldapentry2])
    f.config = config.Config()
    results = capture_results(f)
    result = results.results[0]

    assert result.severity == constants.ERROR
    assert result.kw.get('msg') == 'Too many RA agent entries found, 2'


@patch('ldap.initialize')
@patch('ipaserver.install.cainstance.CAInstance')
@patch('ipalib.x509.load_certificate_from_file')
def test_nss_agent_nonmatching_cert(mock_load_cert,
                                    mock_cainstance,
                                    mock_ldapinit):

    cert = IPACertificate()
    cert2 = IPACertificate(2)
    mock_load_cert.return_value = cert
    mock_cainstance.return_value = CAInstance()
    mock_ldapinit.return_value = mock_ldap_conn()

    attrs = dict(
        description=['2;1;CN=ISSUER;CN=RA AGENT'],
        usercertificate=[cert2],
    )
    fake_conn = LDAPClient('ldap://localhost')
    ldapentry = LDAPEntry(fake_conn, DN('uid=ipara,ou=people,o=ipaca'))
    for attr, values in attrs.items():
        ldapentry[attr] = values

    framework = object()
    registry.initialize(framework)
    f = IPARAAgent(registry)

    f.conn = mock_ldap([ldapentry])
    f.config = config.Config()
    results = capture_results(f)
    result = results.results[0]

    assert result.severity == constants.ERROR
    assert result.kw.get('msg') == 'RA agent certificate not found in LDAP'


@patch('ldap.initialize')
@patch('ipalib.x509.load_certificate_from_file')
def test_nss_agent_multiple_certs(mock_load_cert, mock_ldapinit):

    cert = IPACertificate()
    cert2 = IPACertificate(2)
    mock_load_cert.return_value = cert
    mock_ldapinit.return_value = mock_ldap_conn()

    attrs = dict(
        description=['2;1;CN=ISSUER;CN=RA AGENT'],
        usercertificate=[cert2, cert],
    )
    fake_conn = LDAPClient('ldap://localhost')
    ldapentry = LDAPEntry(fake_conn, DN('uid=ipara,ou=people,o=ipaca'))
    for attr, values in attrs.items():
        ldapentry[attr] = values

    framework = object()
    registry.initialize(framework)
    f = IPARAAgent(registry)

    f.conn = mock_ldap([ldapentry])
    f.config = config.Config()
    results = capture_results(f)

    assert len(results) == 0
