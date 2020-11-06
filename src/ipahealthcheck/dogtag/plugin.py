#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.plugin import Plugin, Registry
from ipaserver.install import cainstance
from ipaserver.install import installutils
from ipalib import api, errors


class DogtagPlugin(Plugin):
    def __init__(self, reg):
        super().__init__(reg)
        self.ca = cainstance.CAInstance(api.env.realm, host_name=api.env.host)


class DogtagRegistry(Registry):
    def initialize(self, framework, config, options=None):
        super().initialize(framework, config)
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


registry = DogtagRegistry()
