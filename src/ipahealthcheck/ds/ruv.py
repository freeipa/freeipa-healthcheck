#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ds.plugin import DSPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants
from ipalib import api
from ipapython.dn import DN


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
