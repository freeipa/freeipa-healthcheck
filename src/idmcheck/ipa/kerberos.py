from idmcheck.core.plugin import Plugin

def register(api):
    return [
        IPAKerberosCheck(api)
    ]


class IPAKerberosCheck(Plugin):
    def check(self):
        print(self)
