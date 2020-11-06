#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
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


logging.getLogger()


class IPAPlugin(Plugin):
    def __init__(self, reg):
        super().__init__(reg)
        self.ca = cainstance.CAInstance(api.env.realm, host_name=api.env.host)
        self.http = httpinstance.HTTPInstance()
        self.ds = dsinstance.DsInstance()
        self.serverid = realm_to_serverid(api.env.realm)
        self.conn = api.Backend.ldap2


class IPARegistry(Registry):
    def __init__(self):
        super().__init__()
        self.trust_agent = False
        self.trust_controller = False

    def initialize(self, framework, config, options=None):
        super().initialize(framework, config)
        # deferred import for mock
        from ipaserver.servroles import ADtrustBasedRole, ServiceBasedRole

        installutils.check_server_configuration()

        if not api.isdone('finalize'):
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
            return

        # This package is pulled in when the trust package is installed
        # and is required to lookup trust users. If this is not installed
        # then it can be inferred that trust is not enabled.
        try:
            import pysss_nss_idmap  # noqa: F401
        except ImportError:
            return

        roles = (
            ADtrustBasedRole(u"ad_trust_agent_server",
                             u"AD trust agent"),
            ServiceBasedRole(
                u"ad_trust_controller_server",
                u"AD trust controller",
                component_services=['ADTRUST']
            ),
        )
        role = roles[0].status(api)[0]
        if role.get('status') == 'enabled':
            self.trust_agent = True
        role = roles[1].status(api)[0]
        if role.get('status') == 'enabled':
            self.trust_controller = True


registry = IPARegistry()
