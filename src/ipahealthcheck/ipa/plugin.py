#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
from ipalib import api, errors
from ipapython.dn import DN
try:
    from ipapython.ipaldap import realm_to_serverid
except ImportError:
    from ipaserver.install.installutils import realm_to_serverid
from ipaserver.install import cainstance
from ipaserver.install import dsinstance
from ipaserver.install import httpinstance
from ipaserver.install import installutils

from ipahealthcheck.core.plugin import Plugin, Registry


logging.getLogger()


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
    def __init__(self):
        super(IPARegistry, self).__init__()
        self.trust_agent = False
        self.trust_controller = False

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
            except (errors.CCacheError, errors.NetworkError) as e:
                logging.debug('Failed to connect to LDAP: %s', e)
            else:
                # Have to use LDAP because the host principal doesn't have
                # rights to read server roles.
                conn = api.Backend.ldap2
                server_dn = DN(('cn', api.env.host),
                               api.env.container_masters, api.env.basedn)
                try:
                    entry = conn.get_entry(
                        server_dn,
                        attrs_list=['enabled_role_servrole'])
                except Exception as e:
                    logging.debug('Failed to retrieve IPA master: %s', e)
                else:
                    roles = entry.get('enabled_role_servrole', [])
                    self.trust_agent = 'AD trust agent' in roles
                    self.trust_controller = 'AD trust controller' in roles


registry = IPARegistry()
