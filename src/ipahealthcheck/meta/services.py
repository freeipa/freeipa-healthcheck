#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core.service import ServiceCheck
from ipahealthcheck.meta.plugin import registry
try:
    from ipapython.ipaldap import realm_to_serverid
except ImportError:
    from ipaserver.install.installutils import realm_to_serverid

from ipalib import api
from ipaplatform import services
from ipaserver.install import bindinstance
from ipaserver.install import cainstance

logger = logging.getLogger()


class IPAServiceCheck(ServiceCheck):
    @duration
    def check(self, instance=''):
        try:
            # services named with a hyphen cannot be addressed
            # as knownservices.name
            # so use knownservices['name'] instead
            self.service = services.knownservices[self.service_name]
        except KeyError:
            logger.debug(
                "Service '%s' is unknown to ipaplatform, skipping check",
                self.service_name
            )
            return ()

        status = self.service.is_running(instance)

        if status is False:
            yield Result(self, constants.ERROR,
                         status=status, msg='%s: not running' %
                         self.service.service_name)
        else:
            yield Result(self, constants.SUCCESS,
                         status=status)


@registry
class certmonger(IPAServiceCheck):
    def check(self):
        self.service_name = 'certmonger'

        return super(certmonger, self).check()


@registry
class dirsrv(IPAServiceCheck):
    def check(self):
        self.service_name = 'dirsrv'

        return super(dirsrv, self).check(realm_to_serverid(api.env.realm))


@registry
class gssproxy(IPAServiceCheck):
    def check(self):
        self.service_name = 'gssproxy'

        return super(gssproxy, self).check()


@registry
class httpd(IPAServiceCheck):
    def check(self):
        self.service_name = 'httpd'

        return super(httpd, self).check()


@registry
class ipa_custodia(IPAServiceCheck):
    def check(self):
        self.service_name = 'ipa-custodia'

        return super(ipa_custodia, self).check()


@registry
class ipa_dnskeysyncd(IPAServiceCheck):
    def check(self):
        self.service_name = 'ipa-dnskeysyncd'

        if not bindinstance.named_conf_exists():
            return ()

        return super(ipa_dnskeysyncd, self).check()


@registry
class ipa_otpd(IPAServiceCheck):
    def check(self):
        self.service_name = 'ipa-otpd'

        return super(ipa_otpd, self).check()


@registry
class kadmin(IPAServiceCheck):
    def check(self):
        self.service_name = 'kadmin'

        return super(kadmin, self).check()


@registry
class krb5kdc(IPAServiceCheck):
    def check(self):
        self.service_name = 'krb5kdc'

        return super(krb5kdc, self).check()


@registry
class named(IPAServiceCheck):
    def check(self):
        self.service_name = 'named'

        if not bindinstance.named_conf_exists():
            return ()

        return super(named, self).check()


@registry
class pki_tomcatd(IPAServiceCheck):
    def check(self):
        self.service_name = 'pki_tomcatd'

        ca = cainstance.CAInstance(api.env.realm, host_name=api.env.host)
        if not ca.is_configured():
            return ()

        return super(pki_tomcatd, self).check()


@registry
class sssd(IPAServiceCheck):
    def check(self):
        self.service_name = 'sssd'

        return super(sssd, self).check()
