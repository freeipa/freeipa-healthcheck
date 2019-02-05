from idmcheck.ipa.plugin import IPAPlugin, registry

@registry
class IPACertCheck(IPAPlugin):
    def check(self):
        print('Called check on', self)


@registry
class IPANSSCheck(IPAPlugin):
    def check(self):
        print('Called check on', self)
