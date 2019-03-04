#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ipa.plugin import IPAPlugin, registry


@registry
class IPAKerberosCheck(IPAPlugin):
    def check(self):
        pass
