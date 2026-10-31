#
# Copyright (C) 2025 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from util import capture_results

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.config import IPAnsslapdIdleTimeoutCheck

from ipalib import errors
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient, LDAPEntry


class mock_ldap:
    def __init__(self, ldapentry):
        self.results = ldapentry

    def get_entry(self, dn, attrs_list=None, time_limit=None,
                  size_limit=None, get_effective_rights=False):
        if self.results is None:
            raise errors.NotFound(reason='test')
        return self.results


def make_entry(value):
    fake_conn = LDAPClient('ldap://localhost', no_schema=True)
    ldapentry = LDAPEntry(fake_conn, DN('cn=config'))
    if value is not None:
        ldapentry['nsslapd-idletimeout'] = [str(value)]
    return ldapentry


class TestIdleTimeout(BaseTest):
    def run_check(self, value):
        framework = object()
        registry.initialize(framework, config.Config)
        f = IPAnsslapdIdleTimeoutCheck(registry)
        f.conn = mock_ldap(make_entry(value))
        return capture_results(f)

    def test_idletimeout_default(self):
        self.results = self.run_check(3600)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.config'
        assert result.check == 'IPAnsslapdIdleTimeoutCheck'
        assert result.kw.get('value') == 3600

    def test_idletimeout_high(self):
        self.results = self.run_check(7200)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.kw.get('value') == 7200

    def test_idletimeout_low(self):
        self.results = self.run_check(10)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.kw.get('value') == 10
        assert result.kw.get('default') == 3600
        assert 'lower than the default' in result.kw.get('msg')

    def test_idletimeout_zero(self):
        self.results = self.run_check(0)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.kw.get('value') == 0
        assert 'unlimited' in result.kw.get('msg')

    def test_idletimeout_unset(self):
        self.results = self.run_check(None)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
