from datetime import datetime
import socket
from idmcheck.core import constants
from idmcheck.core.plugin import Result
from idmcheck.meta.plugin import Plugin, registry


@registry
class MetaCheck(Plugin):
    def check(self):
        dt = datetime.utcnow()

        result = Result(self, constants.SUCCESS,
                        time=dt.strftime('%Y%m%d%H%M%SZ'),
                        fqdn=socket.getfqdn(),)

        return result
