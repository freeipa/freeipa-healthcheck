#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ldap import OPT_X_SASL_SSF_MIN
from util import capture_results
from base import BaseTest
from ipahealthcheck.core import config, constants
from ipahealthcheck.dogtag.plugin import registry
from ipahealthcheck.dogtag.range import (DogtagRequestRangeCheck,
                                         DogtagConfigRangeCheck)
from unittest.mock import Mock, patch
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

    def get_entries(self, base_dn, scope=SCOPE_SUBTREE, filter=None,
                    attrs_list=None, get_effective_rights=False, **kwargs):
        if len(self.results) == 0:
            raise errors.NotFound(reason='test')
        self.index += 1
        if isinstance(self.results[self.index - 1], LDAPEntry):
            return [self.results[self.index - 1]]
        else:
            return self.results[self.index - 1]


class mock_ldap_conn:
    def set_option(self, option, invalue):
        pass

    def get_option(self, option):
        if option == OPT_X_SASL_SSF_MIN:
            return 256

    def search_s(self, base, scope, filterstr=None,
                 attrlist=None, attrsonly=0):
        return tuple()

    def sasl_interactive_bind_s(who, auth, serverctrls=None,
                                clientctrls=None, sasl_flags=0):
        return None


class TestRequestRange(BaseTest):
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

    def test_range_ok(self):
        """Test what should be the standard case"""
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        entries = []

        entries.append(
            self.create_entry(fake_conn,
                              DN('ou=certificateRepository,ou=ca,o=ipaca'),
                              {'nextRange': ['1001']})
        )
        entries.append(
            self.create_entry(fake_conn,
                              DN('cn=1,ou=requests,ou=ranges,o=ipaca'),
                              {
                                  'host': ['ipa.example.test'],
                                  'beginRange': ['1'],
                                  'endRange': ['1000'],
                              })
        )

        framework = object()
        registry.initialize(framework)
        f = DogtagRequestRangeCheck(registry)
        f.conn = mock_ldap(entries)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 2

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.dogtag.range'
            assert result.check == 'DogtagRequestRangeCheck'

        result = self.results.results[0]
        assert result.kw.get('key') == 'nextRange'
        assert result.kw.get('nextrange') == 1001

        result = self.results.results[1]
        assert result.kw.get('key') == 'ipa.example.test'
        assert result.kw.get('beginrange') == 1
        assert result.kw.get('endrange') == 1000

    def test_no_range_set(self):
        """There is no nextRange key in ou=certificateRepository"""
        framework = object()
        registry.initialize(framework)
        f = DogtagRequestRangeCheck(registry)
        f.conn = mock_ldap([])

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.source == 'ipahealthcheck.dogtag.range'
        assert result.check == 'DogtagRequestRangeCheck'
        assert result.kw.get('key') == 'nextRange'
        assert result.kw.get('dn') == \
            'ou=certificateRepository,ou=ca,o=ipaca'
        assert result.kw.get('msg') == 'No {key} is set in {dn}'

    def test_range_end_less_than_begin(self):
        """The range end is less than the beginning range"""
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        entries = []

        entries.append(
            self.create_entry(fake_conn,
                              DN('ou=certificateRepository,ou=ca,o=ipaca'),
                              {'nextRange': ['1001']})
        )
        entries.append(
            self.create_entry(fake_conn,
                              DN('cn=1,ou=requests,ou=ranges,o=ipaca'),
                              {
                                  'host': ['ipa.example.test'],
                                  'beginRange': ['1000'],
                                  'endRange': ['1'],
                              })
        )

        framework = object()
        registry.initialize(framework)
        f = DogtagRequestRangeCheck(registry)
        f.conn = mock_ldap(entries)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 2

        # First result is the nextRange SUCCESS and we aren't interested
        # in that.
        result = self.results.results[1]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.dogtag.range'
        assert result.check == 'DogtagRequestRangeCheck'
        assert result.kw.get('key') == 'ipa.example.test'
        assert result.kw.get('beginrange') == 1000
        assert result.kw.get('endrange') == 1
        assert result.kw.get('msg') == \
            'endRange is less than beginRange'

    def test_range_end_greater_than_nextrange(self):
        """The end range is greater than nextRange"""
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        entries = []

        entries.append(
            self.create_entry(fake_conn,
                              DN('ou=certificateRepository,ou=ca,o=ipaca'),
                              {'nextRange': ['1001']})
        )
        entries.append(
            self.create_entry(fake_conn,
                              DN('cn=1,ou=requests,ou=ranges,o=ipaca'),
                              {
                                  'host': ['ipa.example.test'],
                                  'beginRange': ['1'],
                                  'endRange': ['1002'],
                              })
        )

        framework = object()
        registry.initialize(framework)
        f = DogtagRequestRangeCheck(registry)
        f.conn = mock_ldap(entries)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 2

        # First result is the nextRange SUCCESS and we aren't interested
        # in that.
        result = self.results.results[1]
        assert result.result == constants.ERROR
        assert result.source == 'ipahealthcheck.dogtag.range'
        assert result.check == 'DogtagRequestRangeCheck'
        assert result.kw.get('key') == 'ipa.example.test'
        assert result.kw.get('beginrange') == 1
        assert result.kw.get('endrange') == 1002
        assert result.kw.get('msg') == \
            'endRange is greater than nextRange'

    def test_too_many_nextrange(self):
        """Test what should be the standard case"""
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        entries = []

        nextrange = [
            self.create_entry(fake_conn,
                              DN('ou=certificateRepository,ou=ca,o=ipaca'),
                              {'nextRange': ['1001']})
        ]
        nextrange.append(
            self.create_entry(fake_conn,
                              DN('cn=1,ou=certificateRepository,ou=ca,'
                                 'o=ipaca'),
                              {'nextRange': ['2001']})
        )
        entries.append(nextrange)

        framework = object()
        registry.initialize(framework)
        f = DogtagRequestRangeCheck(registry)
        f.conn = mock_ldap(entries)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.source == 'ipahealthcheck.dogtag.range'
        assert result.check == 'DogtagRequestRangeCheck'
        assert result.kw.get('key') == 'nextRange'
        assert result.kw.get('count') == 2
        assert result.kw.get('msg') == '{count} {key} values in {dn}, ' \
                                       'there should be only one'

    def test_ranges_ok(self):
        """Test multiple ranges that do not overlap."""
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        entries = []

        entries.append(
            self.create_entry(fake_conn,
                              DN('ou=certificateRepository,ou=ca,o=ipaca'),
                              {'nextRange': ['3001']})
        )
        ranges = [
            self.create_entry(fake_conn,
                              DN('cn=1,ou=requests,ou=ranges,o=ipaca'),
                              {
                                  'host': ['ipa.example.test'],
                                  'beginRange': ['1'],
                                  'endRange': ['1000'],
                              })
        ]
        ranges.append(
            self.create_entry(fake_conn,
                              DN('cn=1001,ou=requests,ou=ranges,o=ipaca'),
                              {
                                  'host': ['replica.example.test'],
                                  'beginRange': ['1001'],
                                  'endRange': ['2000'],
                              })
        )
        entries.append(ranges)

        framework = object()
        registry.initialize(framework)
        f = DogtagRequestRangeCheck(registry)
        f.conn = mock_ldap(entries)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 3

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.dogtag.range'
            assert result.check == 'DogtagRequestRangeCheck'

        result = self.results.results[0]
        assert result.kw.get('key') == 'nextRange'
        assert result.kw.get('nextrange') == 3001

        result = self.results.results[1]
        assert result.kw.get('key') == 'ipa.example.test'
        assert result.kw.get('beginrange') == 1
        assert result.kw.get('endrange') == 1000

        result = self.results.results[2]
        assert result.kw.get('key') == 'replica.example.test'
        assert result.kw.get('beginrange') == 1001
        assert result.kw.get('endrange') == 2000

    def test_ranges_overlap(self):
        """Test multiple ranges with an overlap"""
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        entries = []

        entries.append(
            self.create_entry(fake_conn,
                              DN('ou=certificateRepository,ou=ca,o=ipaca'),
                              {'nextRange': ['3001']})
        )
        ranges = [
            self.create_entry(fake_conn,
                              DN('cn=1,ou=requests,ou=ranges,o=ipaca'),
                              {
                                  'host': ['ipa.example.test'],
                                  'beginRange': ['1'],
                                  'endRange': ['1000'],
                              })
        ]
        ranges.append(
            self.create_entry(fake_conn,
                              DN('cn=1001,ou=requests,ou=ranges,o=ipaca'),
                              {
                                  'host': ['replica.example.test'],
                                  'beginRange': ['999'],
                                  'endRange': ['2000'],
                              })
        )
        entries.append(ranges)

        framework = object()
        registry.initialize(framework)
        f = DogtagRequestRangeCheck(registry)
        f.conn = mock_ldap(entries)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 4

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.kw.get('key') == 'nextRange'
        assert result.kw.get('nextrange') == 3001

        result = self.results.results[1]
        assert result.result == constants.SUCCESS
        assert result.kw.get('key') == 'ipa.example.test'
        assert result.kw.get('beginrange') == 1
        assert result.kw.get('endrange') == 1000

        result = self.results.results[2]
        assert result.result == constants.SUCCESS
        assert result.kw.get('key') == 'replica.example.test'
        assert result.kw.get('beginrange') == 999
        assert result.kw.get('endrange') == 2000

        result = self.results.results[3]
        assert result.result == constants.ERROR
        assert result.kw.get('msg') == 'Range overlap'


class TestConfigRange(BaseTest):

    @patch('ipahealthcheck.dogtag.range.get_directive')
    def test_config_ok(self, mock_directive):
        """Test what should be the standard case"""
        values = {
            'dbs.beginSerialNumber': 1,
            'dbs.endSerialNumber': 1000,
            'dbs.nextBeginSerialNumber': 1001,
            'dbs.nextEndSerialNumber': 2000,
        }
        mock_directive.side_effect = [value for name, value in values.items()]

        framework = object()
        registry.initialize(framework)
        f = DogtagConfigRangeCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 4

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.dogtag.range'
            assert result.check == 'DogtagConfigRangeCheck'
            name = result.kw.get('key')
            assert result.kw.get(name) == values[name]

    @patch('ipahealthcheck.dogtag.range.get_directive')
    def test_range_missing_required(self, mock_directive):
        """Test a missing required value in CS.cfg"""
        values = {
            'dbs.beginSerialNumber': 1,
            'dbs.endSerialNumber': None,
            'dbs.nextBeginSerialNumber': 1001,
            'dbs.nextEndSerialNumber': 2000,
        }
        mock_directive.side_effect = [value for name, value in values.items()]

        framework = object()
        registry.initialize(framework)
        f = DogtagConfigRangeCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 4

        for i in range(len(self.results)):
            if i == 1:
                # the expected error
                continue
            result = self.results.results[i]
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.dogtag.range'
            assert result.check == 'DogtagConfigRangeCheck'
            name = result.kw.get('key')
            assert result.kw.get(name) == values[name]

        result = self.results.results[1]
        assert result.result == constants.CRITICAL
        name = result.kw.get('key') == 'dbs.endSerialNumber'
        name = result.kw.get('msg') == '{key} missing from {path}'
