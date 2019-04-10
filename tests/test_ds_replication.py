#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import pytest
from base import BaseTest
from unittest.mock import Mock, patch
from util import capture_results, m_api

from ipahealthcheck.core import config, constants
from ipahealthcheck.ds.plugin import registry
from ipahealthcheck.ds.replication import ReplicationConflictCheck

from ipalib import errors
from ipapython.dn import DN
from ipapython.version import NUM_VERSION
from ipapython.ipaldap import LDAPClient, LDAPEntry


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
            raise errors.EmptyResult(reason='no matching entry found')
        return self.results

    def external_bind(self):
        pass


class TestReplicationConflicts(BaseTest):
    patches = {
        'ipaserver.install.installutils.check_server_configuration':
        Mock(return_value=None),
    }

    @pytest.mark.skipif(NUM_VERSION < 40790,
                        reason="no way of currently testing this")
    @patch('ipapython.ipaldap.LDAPClient.from_realm')
    def test_no_conflicts(self, mock_conn):
        mock_conn.return_value = mock_ldap(None)

        framework = object()
        registry.initialize(framework)
        f = ReplicationConflictCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        # A valid call relies on a success to be set by core
        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.severity == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ds.replication'
        assert result.check == 'ReplicationConflictCheck'

    @pytest.mark.skipif(NUM_VERSION < 40790,
                        reason="no way of currently testing this")
    @patch('ipapython.ipaldap.LDAPClient.from_realm')
    def test_conflicts(self, mock_conn):
        attrs = dict(
            nsds5ReplConflict=['deletedEntryHasChildren'],
            objectclass=['top']
        )
        fake_conn = LDAPClient('ldap://localhost', no_schema=True)
        ldapentry = LDAPEntry(fake_conn, DN('cn=conflict', m_api.env.domain))
        for attr, values in attrs.items():
            ldapentry[attr] = values
        mock_conn.return_value = mock_ldap([ldapentry])

        framework = object()
        registry.initialize(framework)
        f = ReplicationConflictCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)
        result = self.results.results[0]

        assert result.severity == constants.ERROR
        assert result.source == 'ipahealthcheck.ds.replication'
        assert result.check == 'ReplicationConflictCheck'
        assert result.kw.get('msg') == 'Replication conflict'
        assert result.kw.get('glue') is False
        assert result.kw.get('key') == ldapentry.dn
