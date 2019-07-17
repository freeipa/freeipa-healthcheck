#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import ldap
import logging

from ipahealthcheck.ds.plugin import DSPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

from ipalib import api, errors
from ipapython import ipaldap

logger = logging.getLogger()


@registry
class ReplicationConflictCheck(DSPlugin):
    """
    Look for entries with an nsds5ReplConflict attribute.

    The presence of this indicates a replication error. Report any
    found as errors.
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        try:
            conn = ipaldap.LDAPClient.from_realm(api.env.realm)
        except AttributeError:
            conn = ipaldap.LDAPClient(api.env.ldap_uri)
        conn.external_bind()

        filterstr = "(&(!(objectclass=nstombstone))(nsds5ReplConflict=*))"
        attrlist = ['nsds5ReplConflict', 'objectclass']
        try:
            entries = conn.get_entries(
                api.env.basedn, ldap.SCOPE_SUBTREE, filterstr, attrlist)
        except errors.EmptyResult:
            entries = []

        if entries:
            for entry in entries:
                glue = 'glue' in entry['objectclass']
                yield Result(self, constants.ERROR,
                             key=str(entry.dn),
                             glue=glue,
                             conflict=entry['nsds5replconflict'][0],
                             msg='Replication conflict')
        else:
            yield Result(self, constants.SUCCESS)
