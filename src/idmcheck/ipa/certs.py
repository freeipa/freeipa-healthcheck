from idmcheck.core.plugin import Plugin

def register(api):
    return [
        IPACertCheck(api),
        IPANSSCheck(api),
    ]


class IPACertCheck(Plugin):
    def check(self):
        print(self)


class IPANSSCheck(Plugin):
    def check(self):
        print(self)
