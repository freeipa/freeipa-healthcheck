
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import gssapi
import logging
import os
import tempfile

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

from ipalib import api
from ipalib.install.kinit import kinit_keytab
from ipaplatform.paths import paths
from ipapython import ipautil


logger = logging.getLogger()


class CheckKeytab(IPAPlugin):
    service = None
    keytab = None

    @duration
    def check(self):
        if not os.path.exists(self.keytab):
            yield Result(
                self,
                constants.ERROR,
                service=self.service,
                path=self.keytab,
                msg="Service {service} keytab {path} does not exist.")
            return

        ccache_dir = tempfile.mkdtemp()
        ccache_name = os.path.join(ccache_dir, 'ccache')

        try:
            princ = str(
                "%s/%s@%s" % (self.service, api.env.host, api.env.realm)
            )
            kinit_keytab(princ, self.keytab, ccache_name)
        except gssapi.exceptions.GSSError as e:
            yield Result(
                self,
                constants.ERROR,
                service=self.service,
                error=str(e),
                msg="Failed to obtain {service} TGT: {error}",
            )
        finally:
            ipautil.remove_file(ccache_name)
            os.rmdir(ccache_dir)


@registry
class IPAHostKeytab(CheckKeytab):
    """Ensure the host keytab can get a TGT"""
    requires = ('krb5kdc', 'dirsrv')
    service = 'host'
    keytab = paths.KRB5_KEYTAB

    def check(self):
        return super().check()


@registry
class DSKeytab(CheckKeytab):
    """Ensure the dirsrv keytab can get a TGT"""
    requires = ('krb5kdc', 'dirsrv')
    service = 'ldap'
    keytab = paths.DS_KEYTAB

    def check(self):
        return super().check()


@registry
class HTTPKeytab(CheckKeytab):
    """Ensure the Apache keytab can get a TGT"""
    requires = ('krb5kdc', 'dirsrv')
    service = 'HTTP'
    keytab = paths.HTTP_KEYTAB

    def check(self):
        return super(HTTPKeytab, self).check()


@registry
class DNSKeytab(CheckKeytab):
    """Ensure the DNS keytab can get a TGT"""
    requires = ('krb5kdc', 'dirsrv')
    service = 'DNS'
    keytab = paths.NAMED_KEYTAB

    def check(self):
        result = api.Command.config_show()

        if api.env.host not in result['result'].get('dns_server_server', []):
            logger.debug("DNS service is not configured")
            return ()

        return super().check()


@registry
class ODS_EXPORTERKeytab(CheckKeytab):
    """Ensure the ODS exporter keytab can get a TGT"""
    requires = ('krb5kdc', 'dirsrv')
    service = 'ipa-ods-exporter'
    keytab = paths.IPA_ODS_EXPORTER_KEYTAB

    def check(self):
        result = api.Command.config_show()

        if api.env.host not in result["result"].get(
            "dnssec_key_master_server", []
        ):
            logger.debug("Not a DNSSEC master server")
            return ()

        return super().check()


@registry
class DNS_keysyncKeytab(CheckKeytab):
    """Ensure the DNS keysync keytab can get a TGT"""
    requires = ('krb5kdc', 'dirsrv')
    service = 'ipa-dnskeysyncd'
    keytab = paths.IPA_DNSKEYSYNCD_KEYTAB

    def check(self):
        result = api.Command.config_show()

        if api.env.host not in result["result"].get(
            "dns_server_server", []
        ):
            logger.debug("Not a DNSSEC master server")
            return ()

        return super().check()
