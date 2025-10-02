#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from unittest.mock import Mock
from util import capture_results

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.groups import IPAManagedGroupCheck

from ipalib import errors
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient, LDAPEntry

from ldap import OPT_X_SASL_SSF_MIN


class mock_ldap:
    SCOPE_BASE = 1
    SCOPE_ONELEVEL = 2
    SCOPE_SUBTREE = 4

    def __init__(self, ldapentry, found=True):
        """Initialize the results that we will return from get_entries"""
        self.results = ldapentry
        self.found = found

    def find_entries(self, filter=None, attrs_list=None, base_dn=None,
                     scope=SCOPE_SUBTREE, time_limit=None, size_limit=None,
                     paged_search=False, get_effective_rights=False):
        if self.results is None:
            raise errors.NotFound(reason='test')
        return self.results, False

    def get_entry(self, dn, attrs_list=None, time_limit=None,
                  size_limit=None, get_effective_rights=False):
        if self.found:
            return []
        else:
            raise errors.NotFound(reason='test')


class mock_ldap_conn:
    def set_option(self, option, invalue):
        pass

    def get_option(self, option):
        if option == OPT_X_SASL_SSF_MIN:
            return 256

    def search_s(self, base, scope, filterstr=None,
                 attrlist=None, attrsonly=0):
        return tuple()


class TestManagedGroups(BaseTest):
    patches = {
        'ldap.initialize':
        Mock(return_value=mock_ldap_conn()),
    }

    def test_no_dangling_groups(self):

        attrs = dict(
            mepmanagedby=[
                'cn=tuser1,cn=groups,cn=accounts,dc=example,dc=test'],
            objectclass=['mepManagedEntry'],
            cn=['tuser1'],
        )
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(
            fake_conn,
            DN('cn=user0,cn=groups,cn=accounts,dc=example,dc=test')
        )
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAManagedGroupCheck(registry)

        f.conn = mock_ldap([ldapentry])
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.groups'
        assert result.check == 'IPAManagedGroupCheck'

    def test_nss_agent_no_description(self):

        attrs = dict(
            mepmanagedby=[
                'cn=tuser1,cn=groups,cn=accounts,dc=example,dc=test'],
            objectclass=['mepManagedEntry'],
            cn=['tuser1'],
        )
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, DN('uid=ipara,ou=people,o=ipaca'))
        for attr, values in attrs.items():
            ldapentry[attr] = values

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAManagedGroupCheck(registry)

        f.conn = mock_ldap([ldapentry], False)
        self.results = capture_results(f)
        result = self.results.results[0]

        assert result.result == constants.ERROR
        assert result.kw.get('msg') == \
            'Private group {group} has no associated user.'
