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

from ipalib import api, errors
from ipaplatform import services
from ipapython.dn import DN
from ipaserver.install import service

logger = logging.getLogger()


class IPAServiceCheck(ServiceCheck):
    def get_service_name(self, role):
        """Roles define broad services. Translate a role name into
           an individual service name.

           Returns a string on success, None if the service is not
           configured or cannot be determined.
        """
        conn = api.Backend.ldap2
        try:
            if not api.Backend.ldap2.isconnected():
                api.Backend.ldap2.connect()
        except errors.NetworkError:
            logger.debug("Service '%s' is not running", self.service_name)
            return None

        dn = DN(
            ("cn", role), ("cn", api.env.host),
            ("cn", "masters"), ("cn", "ipa"), ("cn", "etc"),
            api.env.basedn
        )
        try:
            entry = conn.get_entry(dn, ['cn'])
        except errors.NotFound:
            logger.debug("server %s does not run role %s",
                         api.env.host, role)
        else:
            svc = entry.single_value['cn']
            if svc in service.SERVICE_LIST:
                return service.SERVICE_LIST[svc].systemd_name
            else:
                logger.debug("role %s defines service %s but it isn't in"
                             "service.SERVICE_LIST", role, svc)
        return None

    @duration
    def check(self, instance='', check_enabled=False):
        if self.service_name in services.knownservices:
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
        else:
            # Fall back to manually creating the service. This relies
            # on the service actually existing.
            self.service = services.service(self.service_name, api)

        if check_enabled and not self.service.is_enabled(instance):
            return ()

        status = self.service.is_running(instance)

        if status is False:
            yield Result(self, constants.ERROR,
                         status=status, msg='%s: not running' %
                         self.service.service_name)

        else:
            yield Result(self, constants.SUCCESS,
                         status=status)

        return None


@registry
class certmonger(IPAServiceCheck):
    def check(self, instance=''):
        self.service_name = 'certmonger'

        return super().check()


@registry
class dirsrv(IPAServiceCheck):
    def check(self, instance=''):
        self.service_name = 'dirsrv'

        return super().check(realm_to_serverid(api.env.realm))


@registry
class gssproxy(IPAServiceCheck):
    def check(self, instance=''):
        self.service_name = 'gssproxy'

        return super().check()


@registry
class httpd(IPAServiceCheck):
    def check(self, instance=''):
        self.service_name = 'httpd'

        return super().check()


@registry
class ipa_custodia(IPAServiceCheck):
    requires = ('dirsrv',)

    def check(self, instance=''):
        self.service_name = self.get_service_name('KEYS')

        if self.service_name is None:
            # No service name means it is not configured
            return ()

        return super().check()


@registry
class ipa_otpd(IPAServiceCheck):
    def check(self, instance=''):
        self.service_name = 'ipa-otpd'

        return super().check()


@registry
class kadmin(IPAServiceCheck):
    requires = ('dirsrv',)

    def check(self, instance=''):
        self.service_name = self.get_service_name('KPASSWD')

        if self.service_name is None:
            # No service name means it is not configured
            return ()

        return super().check()


@registry
class krb5kdc(IPAServiceCheck):
    requires = ('dirsrv',)

    def check(self, instance=''):
        self.service_name = self.get_service_name('KDC')

        if self.service_name is None:
            # No service name means it is not configured
            return ()

        return super().check()


@registry
class named(IPAServiceCheck):
    requires = ('dirsrv',)

    def check(self, instance=''):
        self.service_name = self.get_service_name('DNS')

        if self.service_name is None:
            # No service name means it is not configured
            return ()

        return super().check()


@registry
class ods_enforcerd(IPAServiceCheck):
    requires = ('dirsrv',)

    def check(self, instance=''):
        self.service_name = self.get_service_name('DNSSEC')

        if self.service_name is None:
            # No service name means it is not configured
            return ()

        return super().check()


@registry
class ipa_ods_exporter(IPAServiceCheck):
    requires = ('dirsrv',)

    def check(self, instance=''):
        self.service_name = self.get_service_name('DNSKeyExporter')

        if self.service_name is None:
            # No service name means it is not configured
            return ()

        return super().check()


@registry
class ipa_dnskeysyncd(IPAServiceCheck):
    requires = ('dirsrv',)

    def check(self, instance=''):
        self.service_name = self.get_service_name('DNSKeySync')

        if self.service_name is None:
            # No service name means it is not configured
            return ()

        return super().check()


@registry
class pki_tomcatd(IPAServiceCheck):
    requires = ('dirsrv',)

    def check(self, instance=''):
        self.service_name = self.get_service_name('CA')

        if self.service_name is None:
            # No service name means it is not configured
            return ()

        return super().check()


@registry
class sssd(IPAServiceCheck):
    def check(self, instance=''):
        self.service_name = 'sssd'

        return super().check()


@registry
class chronyd(IPAServiceCheck):
    def check(self, instance=''):
        self.service_name = 'chronyd'

        return super().check(check_enabled=True)


@registry
class smb(IPAServiceCheck):
    requires = ('dirsrv',)

    def check(self, instance=''):
        self.service_name = self.get_service_name('ADTRUST')

        if self.service_name is None:
            # No service name means it is not configured
            return ()

        return super().check()


@registry
class winbind(IPAServiceCheck):
    requires = ('dirsrv',)

    def check(self, instance=''):
        self.service_name = self.get_service_name('EXTID')

        if self.service_name is None:
            # No service name means it is not configured
            return ()

        return super().check()
