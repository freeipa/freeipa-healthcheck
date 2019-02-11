from idmcheck.core import constants
from idmcheck.core.plugin import Result
from idmcheck.meta.plugin import Plugin, registry
from idmcheck.meta.systemd import SystemdService

@registry
class ApacheCheck(Plugin, SystemdService):
    def check(self):
        print('Called check on', self)
        self.service_name = 'httpd'

        status, msg = super(ApacheCheck, self).check()

        if msg:
            result = Result(self, constants.ERROR,
                            status=status, msg='%s: %s' % (self.service_name, msg))
        else:
            result = Result(self, constants.SUCCESS,
                            status=status)

        return result

