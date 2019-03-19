#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import socket
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.meta.plugin import Plugin, registry


@registry
class MetaCheck(Plugin):
    def check(self):
        result = Result(self, constants.SUCCESS,
                        fqdn=socket.getfqdn(),)
        return result
