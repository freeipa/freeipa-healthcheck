#
# Copyright (C) 2002 FreeIPA Contributors see COPYING for license
#

import logging

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration

from ipalib import api, errors

from ipapython.dn import DN


logger = logging.getLogger()


@registry
class IPAManagedGroupCheck(IPAPlugin):

    @duration
    def check(self):
        ok = True
        basedn = DN(api.env.container_group, api.env.basedn)
        search_filter = '(objectclass=mepManagedEntry)'
        (entries, _truncated) = self.conn.find_entries(search_filter,
                                                       ['cn', 'mepManagedBy'],
                                                       basedn)
        for entry in entries:
            try:
                self.conn.get_entry(entry.get('mepManagedBy')[0], [])
            except errors.NotFound:
                ok = False
                yield Result(self, constants.ERROR,
                             key='detached_group',
                             group=entry.get('cn')[0],
                             msg='Private group {group} has no associated '
                                 'user.')

        if ok:
            yield Result(self, constants.SUCCESS,
                         key='detached_group')
