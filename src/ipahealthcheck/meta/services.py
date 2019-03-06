#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.meta.plugin import Plugin, registry
from ipahealthcheck.meta.systemd import SystemdService


class ServiceCheck(Plugin, SystemdService):
    def check(self):
        status, msg = SystemdService.check_service(self)

        if msg:
            result = Result(self, constants.ERROR,
                            status=status, msg='%s: %s' %
                            (self.service_name, msg))
        else:
            result = Result(self, constants.SUCCESS,
                            status=status)

        return result


@registry
class httpd(ServiceCheck):
    def check(self):
        self.service_name = 'httpd'

        return super(httpd, self).check()


@registry
class pki_tomcatd(ServiceCheck):
    def check(self):
        self.service_name = 'pki-tomcatd@pki-tomcat.service'

        return super(pki_tomcatd, self).check()
