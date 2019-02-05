from ipalib import api

from idmcheck.core.plugin import Plugin, Registry


class IPAPlugin(Plugin):
    pass


class IPARegistry(Registry):
    def initialize(self, framework):
        return None
        if not api.isdone('bootstrap'):
            api.bootstrap()
        if not api.isdone('finalize'):
            api.finalize()
        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()


registry = IPARegistry()
