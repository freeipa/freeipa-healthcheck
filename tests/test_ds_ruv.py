#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from unittest.mock import Mock
from util import capture_results, m_api

from ipahealthcheck.core import config, constants
from ipahealthcheck.ds.plugin import registry
from ipahealthcheck.ds.ruv import RUVCheck

from ipalib import errors
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient, LDAPEntry


class mock_ldap:
    SCOPE_BASE = 1
    SCOPE_ONELEVEL = 2
    SCOPE_SUBTREE = 4

    def __init__(self, ldapentry):
        """Initialize the results that we will return from get_entries"""
        self.results = ldapentry
        self.index = 0

    def get_entry(self, dn, attrs_list=None, time_limit=None,
                  size_limit=None, get_effective_rights=False):
        if len(self.results) == 0:
            raise errors.NotFound(reason='test')
        self.index += 1
        if self.results[self.index - 1] is None:
            raise errors.NotFound(reason='test')
        return self.results[self.index - 1]


class mock_ldap_conn:
    def set_option(self, option, invalue):
        pass

    def search_s(self, base, scope, filterstr=None,
                 attrlist=None, attrsonly=0):
        return tuple()


class TestRUV(BaseTest):
    patches = {
        'ldap.initialize':
        Mock(return_value=mock_ldap_conn()),
    }

    def create_entry(self, conn, dn, attrs):
        """Create an LDAPEntry object from the provided dn and attrs
           dn: DN() object
           attrs: dict of name/value pairs of LDAP attributes
        """
        ldapentry = LDAPEntry(conn, dn)
        for attr, values in attrs.items():
            ldapentry[attr] = values

        return ldapentry

    def test_no_ruvs(self):
        framework = object()
        registry.initialize(framework)
        f = RUVCheck(registry)

        f.conn = mock_ldap(None)
        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 0

    def test_both_ruvs(self):
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        entries = []

        entries.append(
            self.create_entry(fake_conn,
                              DN('dc=example,cn=mapping tree,cn=config'),
                              {'nsds5ReplicaId': ['3']})
        )
        entries.append(
            self.create_entry(fake_conn,
                              DN('o=ipaca,cn=mapping tree,cn=config'),
                              {'nsds5ReplicaId': ['5']})
        )

        framework = object()
        registry.initialize(framework)
        f = RUVCheck(registry)

        f.conn = mock_ldap(entries)
        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ds.ruv'
        assert result.check == 'RUVCheck'
        assert result.kw.get('key') == str(m_api.env.basedn)
        assert result.kw.get('ruv') == '3'

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ds.ruv'
        assert result.check == 'RUVCheck'
        assert result.kw.get('key') == 'o=ipaca'
        assert result.kw.get('ruv') == '5'

    def test_one_ruvs(self):
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        entries = []

        entries.append(
            self.create_entry(fake_conn,
                              DN('dc=example,cn=mapping tree,cn=config'),
                              {'nsds5ReplicaId': ['3']})
        )
        entries.append(None)

        framework = object()
        registry.initialize(framework)
        f = RUVCheck(registry)

        f.conn = mock_ldap(entries)
        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ds.ruv'
        assert result.check == 'RUVCheck'
        assert result.kw.get('key') == str(m_api.env.basedn)
        assert result.kw.get('ruv') == '3'
