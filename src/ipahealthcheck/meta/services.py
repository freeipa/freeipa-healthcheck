#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.meta.plugin import Plugin, registry
try:
    from ipapython.ipaldap import realm_to_serverid
except ImportError:
    from ipaserver.install.installutils import realm_to_serverid

from ipalib import api
from ipaplatform import services
from ipaserver.install import bindinstance
from ipaserver.install import cainstance


class ServiceCheck(Plugin):
    @duration
    def check(self, instance=''):
        status = self.service.is_running(instance)

        if status is False:
            yield Result(self, constants.ERROR,
                         status=status, msg='%s: not running' %
                         self.service.service_name)
        else:
            yield Result(self, constants.SUCCESS,
                         status=status)


@registry
class certmonger(ServiceCheck):
    def check(self):
        self.service = services.knownservices.certmonger

        return super(certmonger, self).check()


@registry
class dirsrv(ServiceCheck):
    def check(self):
        self.service = services.knownservices.dirsrv

        return super(dirsrv, self).check(realm_to_serverid(api.env.realm))


@registry
class gssproxy(ServiceCheck):
    def check(self):
        self.service = services.knownservices.gssproxy

        return super(gssproxy, self).check()


@registry
class httpd(ServiceCheck):
    def check(self):
        self.service = services.knownservices.httpd

        return super(httpd, self).check()


# services named with a hyphen cannot be addresses as knownservices.name
# so use knownservices['name'] instead
@registry
class ipa_custodia(ServiceCheck):
    def check(self):
        self.service = services.knownservices['ipa-custodia']

        return super(ipa_custodia, self).check()


@registry
class ipa_dnskeysyncd(ServiceCheck):
    def check(self):
        self.service = services.knownservices['ipa-dnskeysyncd']

        if not bindinstance.named_conf_exists():
            return ()

        return super(ipa_dnskeysyncd, self).check()


@registry
class ipa_otpd(ServiceCheck):
    def check(self):
        self.service = services.knownservices['ipa-otpd']

        return super(ipa_otpd, self).check()


@registry
class kadmin(ServiceCheck):
    def check(self):
        self.service = services.knownservices.kadmin

        return super(kadmin, self).check()


@registry
class krb5kdc(ServiceCheck):
    def check(self):
        self.service = services.knownservices.krb5kdc

        return super(krb5kdc, self).check()


@registry
class named(ServiceCheck):
    def check(self):
        self.service = services.knownservices.named

        if not bindinstance.named_conf_exists():
            return ()

        return super(named, self).check()


@registry
class pki_tomcatd(ServiceCheck):
    def check(self):
        self.service = services.knownservices.pki_tomcatd

        ca = cainstance.CAInstance(api.env.realm, host_name=api.env.host)
        if not ca.is_configured():
            return ()

        return super(pki_tomcatd, self).check()


@registry
class sssd(ServiceCheck):
    def check(self):
        self.service = services.knownservices.sssd

        return super(sssd, self).check()
