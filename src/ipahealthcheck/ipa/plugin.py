#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipalib import api, errors
try:
    from ipapython.ipaldap import realm_to_serverid
except ImportError:
    from ipaserver.install.installutils import realm_to_serverid
from ipaserver.install import cainstance
from ipaserver.install import dsinstance
from ipaserver.install import httpinstance
from ipaserver.install import installutils


from ipahealthcheck.core.plugin import Plugin, Registry


class IPAPlugin(Plugin):
    def __init__(self, reg):
        super(IPAPlugin, self).__init__(reg)
        self.ca = cainstance.CAInstance(api.env.realm,
                                        host_name=api.env.host)
        self.http = httpinstance.HTTPInstance()
        self.ds = dsinstance.DsInstance()
        self.serverid = realm_to_serverid(api.env.realm)
        self.conn = api.Backend.ldap2


class IPARegistry(Registry):
    def initialize(self, framework):
        installutils.check_server_configuration()
        if not api.isdone('bootstrap'):
            api.bootstrap(in_server=True,
                          context='ipahealthcheck',
                          log=None)
        if not api.isdone('finalize'):
            api.finalize()

        if not api.Backend.ldap2.isconnected():
            try:
                api.Backend.ldap2.connect()
            except errors.CCacheError:
                pass
            except errors.NetworkError:
                pass


registry = IPARegistry()
