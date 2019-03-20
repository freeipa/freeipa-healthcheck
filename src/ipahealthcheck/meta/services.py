#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from datetime import datetime

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.meta.plugin import Plugin, registry
from ipahealthcheck.meta.systemd import SystemdService


class ServiceCheck(Plugin, SystemdService):
    def check(self):
        start = datetime.utcnow()
        status, msg = SystemdService.check_service(self)

        if msg:
            yield Result(self, constants.ERROR,
                         start=start,
                         status=status, msg='%s: %s' %
                         (self.service_name, msg))
        else:
            yield Result(self, constants.SUCCESS,
                         start=start,
                         status=status)


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
