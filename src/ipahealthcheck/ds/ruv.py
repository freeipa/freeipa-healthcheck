#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

import logging
import re
from urllib.parse import urlparse

from ipahealthcheck.ds.plugin import DSPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

from ipalib import api, errors
from ipapython.dn import DN

logger = logging.getLogger()


@registry
class RUVCheck(DSPlugin):
    """
    Provide the main and dogtag RUV.

    Local analysis is not possible since it requires collecting the
    RUV from all masters and healthcheck is limited to only talking
    to itself.
    """
    requires = ('dirsrv',)

    def get_ruv(self, dn):
        """Identify the RUV for a suffix on this master"""
        try:
            entry = self.conn.get_entry(dn)
        except Exception:
            return None
        else:
            return entry.single_value.get('nsDS5ReplicaID')

    @duration
    def check(self):
        ruv = self.get_ruv(DN(('cn', 'replica'), ('cn', api.env.basedn),
                           ('cn', 'mapping tree'), ('cn', 'config')))
        csruv = self.get_ruv(DN(('cn', 'replica'), ('cn', 'o=ipaca'),
                             ('cn', 'mapping tree'), ('cn', 'config')))

        if ruv is not None:
            yield Result(self, constants.SUCCESS,
                         key=str(api.env.basedn),
                         ruv=ruv)
        if csruv is not None:
            yield Result(self, constants.SUCCESS,
                         key='o=ipaca',
                         ruv=csruv)


@registry
class KnownRUVCheck(DSPlugin):
    """Return all known RUVs. This can be used to identify "dangling"
       RUVs, or left-overs from previous replication agreements.
    """
    requires = ('dirsrv',)

    def get_all_ruvs(self, suffix):
        """Get all known RUVs on this master

           Return the RUV entries as a list of tuples: (hostname, rid)
        """
        search_filter = '(&(nsuniqueid=ffffffff-ffffffff-ffffffff-ffffffff)' \
                        '(objectclass=nstombstone))'
        try:
            entries = self.conn.get_entries(
                suffix, self.conn.SCOPE_SUBTREE, search_filter,
                ['nsds50ruv'])
        except errors.NotFound:
            logger.debug("No RUV records found.")
            return []
            # raise NoRUVsFound("No RUV records found.")

        servers = []
        for e in entries:
            for ruv in e['nsds50ruv']:
                if ruv.startswith('{replicageneration'):
                    continue
                data = re.match(
                    r'\{replica (\d+) (ldap://.*:\d+)\}(\s+\w+\s+\w*){0,1}',
                    ruv
                )
                if data:
                    rid = data.group(1)
                    (
                        _scheme, netloc, _path, _params, _query, _fragment
                    ) = urlparse(data.group(2))
                    servers.append((re.sub(r':\d+', '', netloc), rid))
                else:
                    logger.debug("Unable to decode RUV: %s", ruv)

        return servers

    @duration
    def check(self):

        ruvs = self.get_all_ruvs(api.env.basedn)
        csruvs = self.get_all_ruvs(DN('o=ipaca'))

        if ruvs:
            yield Result(self, constants.SUCCESS,
                         key='ruvs_' + str(api.env.basedn),
                         suffix=str(api.env.basedn),
                         ruvs=ruvs)

        if csruvs:
            yield Result(self, constants.SUCCESS,
                         key='ruvs_o=ipaca',
                         suffix='o=ipaca',
                         ruvs=csruvs)
