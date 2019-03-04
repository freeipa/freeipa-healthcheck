#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from datetime import datetime
import socket
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.meta.plugin import Plugin, registry


@registry
class MetaCheck(Plugin):
    def check(self):
        dt = datetime.utcnow()

        result = Result(self, constants.SUCCESS,
                        time=dt.strftime('%Y%m%d%H%M%SZ'),
                        fqdn=socket.getfqdn(),)

        return result
