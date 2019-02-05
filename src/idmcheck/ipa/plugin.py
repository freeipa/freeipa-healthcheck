from ipalib import api

from idmcheck.core.plugin import Plugin, Registry


class IPAPlugin(Plugin):
    pass


class IPARegistry(Registry):
    def initialize(self, framework):
        if not api.isdone('bootstrap'):
            api.bootstrap(in_server=False,
                          context='idmcheck',
                          log=None)
        if not api.isdone('finalize'):
            api.finalize()
# the backend is only available if in_server=True which requires
# the ipaserver package
#        if not api.Backend.ldap2.isconnected():
#            api.Backend.ldap2.connect()


registry = IPARegistry()
