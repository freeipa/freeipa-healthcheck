#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import socket
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.meta.plugin import Plugin, registry
from ipapython.version import VERSION, API_VERSION
from ipapython.dn import DN
from ipalib import api


@registry
class MetaCheck(Plugin):
    @duration
    def check(self):
        conn = api.Backend.ldap2
        masters_dn = DN(api.env.container_masters, api.env.basedn)
        masters = conn.get_entries(masters_dn, conn.SCOPE_ONELEVEL)
        known = [master.single_value['cn'] for master in masters]

        yield Result(self, constants.SUCCESS,
                     fqdn=socket.getfqdn(),
                     masters=known,
                     ipa_version=VERSION,
                     ipa_api_version=API_VERSION,)
