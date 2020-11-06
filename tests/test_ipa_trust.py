#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import sys

from base import BaseTest
from collections import namedtuple
from unittest.mock import Mock, patch
from util import capture_results
from util import m_api

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.trust import (IPATrustAgentCheck,
                                      IPATrustDomainsCheck,
                                      IPADomainCheck,
                                      IPATrustCatalogCheck,
                                      IPAsidgenpluginCheck,
                                      IPATrustAgentMemberCheck,
                                      IPATrustControllerPrincipalCheck,
                                      IPATrustControllerServiceCheck,
                                      IPATrustControllerGroupSIDCheck,
                                      IPATrustControllerAdminSIDCheck,
                                      IPATrustControllerConfCheck,
                                      IPATrustPackageCheck)

from ipalib import errors
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient, LDAPEntry

try:
    from ipapython.ipaldap import realm_to_serverid
except ImportError:
    from ipaserver.install.installutils import realm_to_serverid

from ldap import OPT_X_SASL_SSF_MIN
from SSSDConfig import NoOptionError


class mock_ldap:
    SCOPE_BASE = 1
    SCOPE_ONELEVEL = 2
    SCOPE_SUBTREE = 4

    def __init__(self, ldapentry):
        """Initialize the results that we will return from get_entries"""
        self.results = ldapentry

#    def get_entries(self, base_dn, scope=SCOPE_SUBTREE, filter=None,
#                    attrs_list=None, get_effective_rights=False, **kwargs):
#        if self.results is None:
#            raise errors.NotFound(reason='test')
#        return self.results
    def get_entry(self, dn, attrs_list=None, time_limit=None,
                  size_limit=None, get_effective_rights=False):
        if self.results is None:
            raise errors.NotFound(reason='test')
        return self.results


class mock_ldap_conn:
    def set_option(self, option, invalue):
        pass

    def get_option(self, option):
        if option == OPT_X_SASL_SSF_MIN:
            return 256

        return None

    def search_s(self, base, scope, filterstr=None,
                 attrlist=None, attrsonly=0):
        return tuple()


class SSSDDomain:
    def __init__(self, return_ipa_server_mode=True, provider='ipa'):
        self.return_ipa_server_mode = return_ipa_server_mode
        self.provider = provider

    def get_option(self, option):
        if option in ('id_provider', 'auth_provider', 'chpass_provider',
                      'access_provider'):
            return self.provider
        elif option == 'ipa_server_mode':
            if self.return_ipa_server_mode is None:
                raise NoOptionError()
            return self.return_ipa_server_mode

        return None


class SSSDConfig():
    def __init__(self, return_domains=True, return_ipa_server_mode=True,
                 provider='ipa'):
        """
        Knobs to control what data the configuration returns.
        """
        self.return_domains = return_domains
        self.return_ipa_server_mode = return_ipa_server_mode
        self.provider = provider

    def import_config(self):
        pass

    def list_active_domains(self):
        return ('ipa.example',)

    def get_domain(self, name):
        return SSSDDomain(self.return_ipa_server_mode, self.provider)


class TestTrustAgent(BaseTest):
    def test_no_trust_agent(self):
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = False
        f = IPATrustAgentCheck(registry)

        self.results = capture_results(f)

        # Zero because the call was skipped altogether
        assert len(self.results) == 0

    @patch('SSSDConfig.SSSDConfig')
    def test_trust_agent_ok(self, mock_sssd):
        mock_sssd.return_value = SSSDConfig(return_domains=True,
                                            return_ipa_server_mode=True)
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPATrustAgentCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustAgentCheck'

    @patch('SSSDConfig.SSSDConfig')
    def test_trust_agent_not_ipa(self, mock_sssd):
        mock_sssd.return_value = SSSDConfig(return_domains=True,
                                            return_ipa_server_mode=False)
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPATrustAgentCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustAgentCheck'
        assert result.kw.get('key') == 'ipa_server_mode_false'
        assert result.kw.get('domain') == 'ipa.example'

    @patch('SSSDConfig.SSSDConfig')
    def test_trust_agent_fail(self, mock_sssd):
        mock_sssd.return_value = SSSDConfig(return_domains=True,
                                            return_ipa_server_mode=None)
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPATrustAgentCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustAgentCheck'
        assert result.kw.get('key') == 'ipa_server_mode_missing'
        assert result.kw.get('domain') == 'ipa.example'


class TestTrustDomains(BaseTest):
    def test_no_trust_agent(self):
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = False
        f = IPATrustDomainsCheck(registry)

        self.results = capture_results(f)

        # Zero because the call was skipped altogether
        assert len(self.results) == 0

    @patch('ipapython.ipautil.run')
    def test_trust_domain_list_fail(self, mock_run):
        run_result = namedtuple('run', ['returncode', 'error_log'])
        run_result.returncode = 1
        run_result.error_log = 'error'
        mock_run.return_value = run_result

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPATrustDomainsCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustDomainsCheck'
        assert result.kw.get('key') == 'domain_list_error'

    @patch('ipapython.ipautil.run')
    @patch('ipahealthcheck.ipa.trust.get_trust_domains')
    def test_trust_get_trust_domains_fail(self, mock_trust, mock_run):
        # sssctl domain-list
        run_result = namedtuple('run', ['returncode', 'error_log'])
        run_result.returncode = 0
        run_result.error_log = ''
        run_result.output = 'implicit_files\nipa.example\nad.example\n'
        mock_run.return_value = run_result

        mock_trust.side_effect = errors.NotFound(reason='bad')

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPATrustDomainsCheck(registry)

        self.results = capture_results(f)

        # There are more than one result I just care about this particular
        # value. The error is not fatal.
        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustDomainsCheck'
        assert result.kw.get('key') == 'trust-find'

    @patch('ipapython.ipautil.run')
    def test_trust_get_trust_domains_ok(self, mock_run):
        # sssctl domain-list
        dlresult = namedtuple('run', ['returncode', 'error_log'])
        dlresult.returncode = 0
        dlresult.error_log = ''
        dlresult.output = 'implicit_files\nipa.example\nad.example\n' \
            'child.example\n'
        olresult = namedtuple('run', ['returncode', 'error_log'])
        olresult.returncode = 0
        olresult.error_log = ''
        olresult.output = 'Online status: Online\n\n'

        mock_run.side_effect = [dlresult, olresult, olresult]

        # get_trust_domains()
        m_api.Command.trust_find.side_effect = [{
            'result': [
                {
                    'cn': ['ad.example'],
                    'ipantflatname': ['ADROOT'],
                    'ipanttrusteddomainsid': ['S-1-5-21-abc'],
                    'ipanttrusttype': ['2'],
                    'ipanttrustattributes': ['8'],
                    'trusttype': ['Active Directory domain'],
                },
                {
                    'cn': ['child.example'],
                    'ipantflatname': ['ADCHILD'],
                    'ipanttrusteddomainsid': ['S-1-5-22-def'],
                    'ipanttrusttype': ['2'],
                    'ipanttrustattributes': ['9'],
                    'trusttype': ['Non-transitive external trust to a domain '
                                  'in another Active Directory forest']
                },
            ]
        }]

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPATrustDomainsCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 3

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustDomainsCheck'
        assert result.kw.get('key') == 'domain-list'
        assert result.kw.get('trust_domains') == 'ad.example, child.example'
        assert result.kw.get('sssd_domains') == 'ad.example, child.example'

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustDomainsCheck'
        assert result.kw.get('key') == 'domain-status'
        assert result.kw.get('domain') == 'ad.example'

        result = self.results.results[2]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustDomainsCheck'
        assert result.kw.get('key') == 'domain-status'
        assert result.kw.get('domain') == 'child.example'

    @patch('ipapython.ipautil.run')
    def test_trust_get_trust_domains_mismatch(self, mock_run):
        # sssctl domain-list
        dlresult = namedtuple('run', ['returncode', 'error_log'])
        dlresult.returncode = 0
        dlresult.error_log = ''
        dlresult.output = 'implicit_files\nipa.example\n' \
            'child.example\n'
        olresult = namedtuple('run', ['returncode', 'error_log'])
        olresult.returncode = 0
        olresult.error_log = ''
        olresult.output = 'Online status: Online\n\n'

        mock_run.side_effect = [dlresult, olresult, olresult]

        # get_trust_domains()
        m_api.Command.trust_find.side_effect = [{
            'result': [
                {
                    'cn': ['ad.example'],
                    'ipantflatname': ['ADROOT'],
                    'ipanttrusteddomainsid': ['S-1-5-21-abc'],
                    'ipanttrusttype': ['2'],
                    'ipanttrustattributes': ['8'],
                    'trusttype': ['Active Directory domain'],
                },
                {
                    'cn': ['child.example'],
                    'ipantflatname': ['ADCHILD'],
                    'ipanttrusteddomainsid': ['S-1-5-22-def'],
                    'ipanttrusttype': ['2'],
                    'ipanttrustattributes': ['9'],
                    'trusttype': ['Non-transitive external trust to a domain '
                                  'in another Active Directory forest']
                },
            ]
        }]

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPATrustDomainsCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustDomainsCheck'
        assert result.kw.get('key') == 'domain-list'
        assert result.kw.get('trust_domains') == 'ad.example, child.example'
        assert result.kw.get('sssd_domains') == 'child.example'

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustDomainsCheck'
        assert result.kw.get('key') == 'domain-status'
        assert result.kw.get('domain') == 'child.example'


class TestIPADomain(BaseTest):
    @patch('SSSDConfig.SSSDConfig')
    def test_ipa_domain_ok(self, mock_sssd):
        mock_sssd.return_value = SSSDConfig(provider='ipa')
        framework = object()
        registry.initialize(framework, config.Config)
        # being a trust agent isn't mandatory, test without
        registry.trust_agent = False
        f = IPADomainCheck(registry)

        self.results = capture_results(f)

        print(self.results.results)
        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPADomainCheck'

    @patch('SSSDConfig.SSSDConfig')
    def test_ipa_domain_ad(self, mock_sssd):
        mock_sssd.return_value = SSSDConfig(provider='ad')
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPADomainCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 4

        for result in self.results.results:
            assert result.result == constants.ERROR
            assert result.source == 'ipahealthcheck.ipa.trust'
            assert result.check == 'IPADomainCheck'
            assert result.kw.get('provider') == 'ad'


class TestTrustCatalog(BaseTest):
    def test_no_trust_agent(self):
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = False
        f = IPATrustCatalogCheck(registry)

        self.results = capture_results(f)

        # Zero because the call was skipped altogether
        assert len(self.results) == 0

    @patch('pysss_nss_idmap.getnamebysid')
    @patch('ipapython.ipautil.run')
    def test_trust_catalog_ok(self, mock_run, mock_getnamebysid):
        # id Administrator@ad.example
        dsresult = namedtuple('run', ['returncode', 'error_log'])
        dsresult.returncode = 0
        dsresult.error_log = ''
        dsresult.output = 'Active servers:\nAD Global Catalog: ' \
            'root-dc.ad.vm\nAD Domain Controller: root-dc.ad.vm\n' \
            'IPA: master.ipa.vm\n\n'
        ds2result = namedtuple('run', ['returncode', 'error_log'])
        ds2result.returncode = 0
        ds2result.error_log = ''
        ds2result.output = 'Active servers:\nAD Global Catalog: ' \
            'root-dc.ad.vm\nAD Domain Controller: root-dc.ad.vm\n' \

        mock_run.side_effect = [dsresult, ds2result]
        mock_getnamebysid.side_effect = [
           {'S-1-5-21-abc-500': {'name': 'admin@ad.example', 'type': 3}},
           {'S-1-5-21-def-500': {'name': 'admin@child.example', 'type': 3}}
        ]

        # get_trust_domains()
        m_api.Command.trust_find.side_effect = [{
            'result': [
                {
                    'cn': ['ad.example'],
                    'ipantflatname': ['ADROOT'],
                    'ipanttrusteddomainsid': ['S-1-5-21-abc'],
                    'ipanttrusttype': ['2'],
                    'ipanttrustattributes': ['8'],
                    'trusttype': ['Active Directory domain'],
                },
                {
                    'cn': ['child.example'],
                    'ipantflatname': ['ADCHILD'],
                    'ipanttrusteddomainsid': ['S-1-5-22-def'],
                    'ipanttrusttype': ['2'],
                    'ipanttrustattributes': ['9'],
                    'trusttype': ['Non-transitive external trust to a domain '
                                  'in another Active Directory forest']
                },
            ]
        }]

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPATrustCatalogCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 6

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustCatalogCheck'
        assert result.kw.get('key') == 'Domain Security Identifier'
        assert result.kw.get('sid') == 'S-1-5-21-abc'

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustCatalogCheck'
        assert result.kw.get('key') == 'AD Global Catalog'
        assert result.kw.get('domain') == 'ad.example'

        result = self.results.results[2]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustCatalogCheck'
        assert result.kw.get('key') == 'AD Domain Controller'
        assert result.kw.get('domain') == 'ad.example'

        result = self.results.results[3]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustCatalogCheck'
        assert result.kw.get('key') == 'Domain Security Identifier'
        assert result.kw.get('sid') == 'S-1-5-22-def'

        result = self.results.results[4]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustCatalogCheck'
        assert result.kw.get('key') == 'AD Global Catalog'
        assert result.kw.get('domain') == 'child.example'

        result = self.results.results[5]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustCatalogCheck'
        assert result.kw.get('key') == 'AD Domain Controller'
        assert result.kw.get('domain') == 'child.example'


class Testsidgen(BaseTest):
    patches = {
        'ldap.initialize':
        Mock(return_value=mock_ldap_conn()),
    }

    def test_no_trust_agent(self):
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = False
        f = IPAsidgenpluginCheck(registry)

        self.results = capture_results(f)

        # Zero because the call was skipped altogether
        assert len(self.results) == 0

    def test_sidgen_ok(self):
        attrs = {
            'nsslapd-pluginEnabled': ['on'],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, DN('cn=plugin, cn=config'))
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPAsidgenpluginCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPAsidgenpluginCheck'
        assert result.kw.get('key') == 'IPA SIDGEN'

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPAsidgenpluginCheck'
        assert result.kw.get('key') == 'ipa-sidgen-task'

    def test_sidgen_fail(self):
        attrs = {
            'nsslapd-pluginEnabled': ['off'],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, DN('cn=plugin, cn=config'))
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPAsidgenpluginCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPAsidgenpluginCheck'
        assert result.kw.get('key') == 'IPA SIDGEN'

        result = self.results.results[1]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPAsidgenpluginCheck'
        assert result.kw.get('key') == 'ipa-sidgen-task'


class TestTrustAgentMember(BaseTest):
    patches = {
        'ldap.initialize':
        Mock(return_value=mock_ldap_conn()),
    }

    def test_no_trust_agent(self):
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = False
        f = IPATrustAgentMemberCheck(registry)

        self.results = capture_results(f)

        # Zero because the call was skipped altogether
        assert len(self.results) == 0

    def test_member_ok(self):
        agent_dn = DN(('fqdn', m_api.env.host), m_api.env.container_host,
                      m_api.env.basedn)
        group_dn = DN(('cn', 'adtrust agents'),
                      m_api.env.container_sysaccounts,
                      m_api.env.basedn)
        attrs = {
            'memberof': [group_dn],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, agent_dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPATrustAgentMemberCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustAgentMemberCheck'
        assert result.kw.get('key') == m_api.env.host

    def test_member_fail(self):
        agent_dn = DN(('fqdn', m_api.env.host), m_api.env.container_host,
                      m_api.env.basedn)
        attrs = {
            'memberof': [agent_dn],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, agent_dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPATrustAgentMemberCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustAgentMemberCheck'
        assert result.kw.get('key') == m_api.env.host


class TestControllerPrincipal(BaseTest):
    patches = {
        'ldap.initialize':
        Mock(return_value=mock_ldap_conn()),
    }

    def test_not_trust_controller(self):
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = False
        f = IPATrustControllerPrincipalCheck(registry)

        self.results = capture_results(f)

        # Zero because the call was skipped altogether
        assert len(self.results) == 0

    def test_principal_ok(self):
        agent_dn = DN(('krbprincipalname',
                      'cifs/%s@%s' % (m_api.env.host, m_api.env.realm)),
                      m_api.env.container_service, m_api.env.basedn)
        group_dn = DN(('cn', 'adtrust agents'),
                      m_api.env.container_sysaccounts,
                      m_api.env.basedn)
        attrs = {
            'memberof': [group_dn],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, agent_dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = True
        f = IPATrustControllerPrincipalCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustControllerPrincipalCheck'
        assert result.kw.get('key') == 'cifs/%s@%s' % \
                                       (m_api.env.host, m_api.env.realm)

    def test_member_fail(self):
        agent_dn = DN(('fqdn', m_api.env.host), m_api.env.container_host,
                      m_api.env.basedn)
        attrs = {
            'memberof': [agent_dn],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, agent_dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = True
        f = IPATrustControllerPrincipalCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.kw.get('key') == 'cifs/%s@%s' % \
                                       (m_api.env.host, m_api.env.realm)


class TestControllerService(BaseTest):
    patches = {
        'ldap.initialize':
        Mock(return_value=mock_ldap_conn()),
    }

    def test_not_trust_controller(self):
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = False
        f = IPATrustControllerServiceCheck(registry)

        self.results = capture_results(f)

        # Zero because the call was skipped altogether
        assert len(self.results) == 0

    def test_principal_ok(self):
        service_dn = DN(('cn', 'ADTRUST'))
        attrs = {
            'ipaconfigstring': ['enabledService'],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, service_dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = True
        f = IPATrustControllerServiceCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustControllerServiceCheck'
        assert result.kw.get('key') == 'ADTRUST'

    def test_principal_fail(self):
        service_dn = DN(('cn', 'ADTRUST'))
        attrs = {
            'ipaconfigstring': ['disabledService'],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, service_dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = True
        f = IPATrustControllerServiceCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.kw.get('key') == 'ADTRUST'


class TestControllerGroupSID(BaseTest):
    patches = {
        'ldap.initialize':
        Mock(return_value=mock_ldap_conn()),
    }

    def test_not_trust_controller(self):
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = False
        f = IPATrustControllerGroupSIDCheck(registry)

        self.results = capture_results(f)

        # Zero because the call was skipped altogether
        assert len(self.results) == 0

    def test_principal_ok(self):
        admins_dn = DN(('cn', 'admins'))
        attrs = {
            'ipantsecurityidentifier':
            ['S-1-5-21-1234-5678-1976041503-512'],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, admins_dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = True
        f = IPATrustControllerGroupSIDCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustControllerGroupSIDCheck'
        assert result.kw.get('key') == 'ipantsecurityidentifier'
        assert result.kw.get('rid') == 'S-1-5-21-1234-5678-1976041503-512'

    def test_principal_fail(self):
        admins_dn = DN(('cn', 'admins'))
        attrs = {
            'ipantsecurityidentifier':
            ['S-1-5-21-1234-5678-1976041503-500'],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, admins_dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = True
        f = IPATrustControllerGroupSIDCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustControllerGroupSIDCheck'
        assert result.kw.get('key') == 'ipantsecurityidentifier'
        assert result.kw.get('rid') == 'S-1-5-21-1234-5678-1976041503-500'


class TestControllerAdminSID(BaseTest):
    patches = {
        'ldap.initialize':
        Mock(return_value=mock_ldap_conn()),
    }

    def test_not_trust_controller(self):
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = False
        f = IPATrustControllerAdminSIDCheck(registry)

        self.results = capture_results(f)

        # Zero because the call was skipped altogether
        assert len(self.results) == 0

    def test_principal_ok(self):
        admin_dn = DN(('uid', 'admin'))
        attrs = {
            'ipantsecurityidentifier':
            ['S-1-5-21-1234-5678-1976041503-500'],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, admin_dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = True
        f = IPATrustControllerAdminSIDCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustControllerAdminSIDCheck'
        assert result.kw.get('key') == 'ipantsecurityidentifier'
        assert result.kw.get('rid') == 'S-1-5-21-1234-5678-1976041503-500'

    def test_principal_fail(self):
        admin_dn = DN(('uid', 'admin'))
        attrs = {
            'ipantsecurityidentifier':
            ['S-1-5-21-1234-5678-1976041503-400'],
        }
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, admin_dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = True
        f = IPATrustControllerAdminSIDCheck(registry)

        f.conn = mock_ldap(ldapentry)
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustControllerAdminSIDCheck'
        assert result.kw.get('key') == 'ipantsecurityidentifier'
        assert result.kw.get('rid') == 'S-1-5-21-1234-5678-1976041503-400'


class TestControllerConf(BaseTest):
    patches = {
        'ldap.initialize':
        Mock(return_value=mock_ldap_conn()),
    }

    def test_not_trust_controller(self):
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = False
        f = IPATrustControllerConfCheck(registry)

        self.results = capture_results(f)

        # Zero because the call was skipped altogether
        assert len(self.results) == 0

    @patch('ipapython.ipautil.run')
    def test_ldapi_ok(self, mock_run):
        ldapi_socket = "ipasam:ldapi://%%2fvar%%2frun%%2fslapd-%s.socket" % \
                       realm_to_serverid(m_api.env.realm)
        run_result = namedtuple('run', ['returncode', 'output'])
        run_result.returncode = 0
        run_result.output = '[global]\n\tpassdb backend=%s' % ldapi_socket
        mock_run.return_value = run_result

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = True
        f = IPATrustControllerConfCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustControllerConfCheck'
        assert result.kw.get('key') == 'net conf list'


class TestPackageCheck(BaseTest):
    def test_agent_with_package(self):
        # Note that this test assumes the import is installed
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = False
        registry.trust_agent = True
        f = IPATrustPackageCheck(registry)
        self.results = capture_results(f)
        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustPackageCheck'

    def test_agent_without_package(self):
        # Note that this test assumes the import is installed
        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_controller = False
        registry.trust_agent = True
        # Hose up the module so the import fails
        save = sys.modules['ipaserver.install']
        sys.modules['ipaserver.install'] = 'foo'
        f = IPATrustPackageCheck(registry)
        self.results = capture_results(f)
        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.trust'
        assert result.check == 'IPATrustPackageCheck'
        sys.modules['ipaserver.install'] = save
