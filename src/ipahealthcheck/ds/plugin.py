#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.plugin import Plugin, Registry
from ipaserver.install import dsinstance
from ipaserver.install import installutils
from ipalib import api, errors


class DSPlugin(Plugin):
    def __init__(self, registry):
        super(DSPlugin, self).__init__(registry)
        self.ds = self.ds = dsinstance.DsInstance()


class DSRegistry(Registry):
    def initialize(self, framework):
        installutils.check_server_configuration()
        if not api.isdone('bootstrap'):
            api.bootstrap(in_server=True,
                          context='ipahealthcheck',
                          log=None)
        if not api.isdone('finalize'):
            api.finalize()


registry = DSRegistry()
