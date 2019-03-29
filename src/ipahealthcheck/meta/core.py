#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import socket
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.meta.plugin import Plugin, registry
from ipapython.version import VERSION, API_VERSION


@registry
class MetaCheck(Plugin):
    @duration
    def check(self):
        yield Result(self, constants.SUCCESS,
                     fqdn=socket.getfqdn(),
                     ipa_version=VERSION,
                     ipa_api_version=API_VERSION,)
