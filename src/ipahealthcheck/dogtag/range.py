#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import ldap
import logging

from ipahealthcheck.dogtag.plugin import DogtagPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

from ipalib import api, errors
from ipaplatform.paths import paths
from ipapython import ipaldap
from ipapython.dn import DN
from ipapython.directivesetter import get_directive

logger = logging.getLogger()


def range_overlap(range1, range2):
    return max(range1[0], range2[0]) <= min(range1[1], range2[1])


@registry
class DogtagRequestRangeCheck(DogtagPlugin):
    """
    Look for overlapping request ranges
    """
    @duration
    def check(self):

        if not self.ca.is_configured():
            logger.debug("No CA configured, skipping dogtag config check")
            return

        try:
            conn = ipaldap.LDAPClient.from_realm(api.env.realm)
        except AttributeError:
            conn = ipaldap.LDAPClient(api.env.ldap_uri)
        conn.external_bind()

        # Get the max nextRange first
        filterstr = "(objectclass=repository)"
        attrlist = ['nextRange', ]
        try:
            entries = self.conn.get_entries(
                DN('ou=certificateRepository,ou=ca,o=ipaca'),
                ldap.SCOPE_BASE, filterstr, attrlist)
        except errors.EmptyResult:
            entries = []
        except errors.NotFound:
            entries = []

        if entries:
            if len(entries) != 1:
                # Can't really proceed if there are multiple so fail loudly.
                yield Result(self, constants.CRITICAL,
                             key='nextRange',
                             dn='ou=certificateRepository,ou=ca,o=ipaca',
                             count=len(entries),
                             msg='{count} {key} values in {dn}, there '
                                 'should be only one')
                return
            else:
                nextrange = int(entries[0].single_value.get('nextRange', 0))
        else:
            yield Result(self, constants.CRITICAL,
                         key='nextRange',
                         dn='ou=certificateRepository,ou=ca,o=ipaca',
                         msg='No {key} is set in {dn}')
            return

        yield Result(self, constants.SUCCESS,
                     key='nextRange',
                     nextrange=nextrange)

        filterstr = "(objectclass=pkiRange)"
        attrlist = ['beginRange', 'endRange', 'host']
        try:
            entries = self.conn.get_entries(
                DN('ou=requests,ou=ranges,o=ipaca'),
                ldap.SCOPE_SUBTREE, filterstr, attrlist)
        except errors.EmptyResult:
            entries = []

        ranges = []
        if entries:
            for entry in entries:
                host = entry.single_value.get('host')
                msg = None
                beginrange = int(entry.single_value.get('beginRange', 0))
                endrange = int(entry.single_value.get('endRange', 0))
                if beginrange == 0:
                    msg = 'beginRange is not defined'
                if endrange == 0:
                    msg = 'endRange is not defined'
                if endrange < beginrange:
                    msg = 'endRange is less than beginRange'
                if endrange > nextrange:
                    msg = 'endRange is greater than nextRange'
                if msg:
                    yield Result(self, constants.ERROR,
                                 key=host,
                                 beginrange=beginrange,
                                 endrange=endrange,
                                 msg=msg)
                    continue
                ranges.append((beginrange, endrange))

                yield Result(self, constants.SUCCESS,
                             key=host,
                             beginrange=beginrange,
                             endrange=endrange)

            range_len = len(ranges)
            for i in range(range_len - 1):
                for j in range(i+1, range_len):
                    if range_overlap(ranges[i], ranges[j]):
                        yield Result(self, constants.ERROR,
                                     key=entries[i].single_value.get('host'),
                                     beginrange=ranges[i][0],
                                     endrange=ranges[i][1],
                                     msg='Range overlap')


@registry
class DogtagConfigRangeCheck(DogtagPlugin):
    """
    Report on current ranges set in CS.cfg.

    This is for information purposes only. An external tool will need
    to combine all the values and evaluate for overlap or other issues.
    """
    @duration
    def check(self):

        if not self.ca.is_configured():
            logger.debug("No CA configured, skipping dogtag config check")
            return

        # (key_name, required)
        keys = [('dbs.beginSerialNumber', True),
                ('dbs.endSerialNumber', True),
                ('dbs.nextBeginSerialNumber', False),
                ('dbs.nextEndSerialNumber', False)]

        for key, required in keys:
            try:
                val = get_directive(paths.CA_CS_CFG_PATH,
                                    key, '=')
            except KeyError:
                if not required:
                    continue
                yield Result(self, constants.CRITICAL,
                             key=key,
                             path=paths.CA_CS_CFG_PATH,
                             msg='{key} missing from {path}')
            else:
                if val is None:
                    if not required:
                        continue
                    else:
                        yield Result(self, constants.CRITICAL,
                                     key=key,
                                     path=paths.CA_CS_CFG_PATH,
                                     msg='{key} missing from {path}')
                        continue
                result = {'key': key, key: val}
                yield Result(self, constants.SUCCESS,
                             **result)
