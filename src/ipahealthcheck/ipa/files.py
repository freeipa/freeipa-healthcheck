#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
import os

from ipahealthcheck.core.files import FileCheck
from ipahealthcheck.ipa.plugin import IPAPlugin, registry

from ipalib import api, errors

from ipaplatform.paths import paths
from ipaplatform.constants import constants
from ipapython.certdb import NSS_SQL_FILES
from ipapython.dn import DN

from ipaserver.install import dsinstance
from ipaserver.install import krbinstance


logger = logging.getLogger()


@registry
class IPAFileNSSDBCheck(IPAPlugin, FileCheck):

    def collect_files(self, basedir, filelist, owner, group, perms):
        for file in filelist:
            self.files.append((os.path.join(basedir, file), owner, group,
                              perms))

    def check(self):
        self.files = []

        self.collect_files(dsinstance.config_dirname(self.serverid),
                           NSS_SQL_FILES, 'dirsrv', 'root', '0640')

        # There always has to be a special one. pkcs11.txt has a different
        # group so pop off the auto-generated one and add a replacement.
        old = (os.path.join(dsinstance.config_dirname(self.serverid),
               'pkcs11.txt'), 'dirsrv', 'root', '0640')
        self.files.remove(old)
        new = (os.path.join(dsinstance.config_dirname(self.serverid),
               'pkcs11.txt'), 'dirsrv', 'dirsrv', '0640')
        self.files.append(new)

        if self.ca.is_configured():
            self.collect_files(paths.PKI_TOMCAT_ALIAS_DIR, NSS_SQL_FILES,
                               'pkiuser', 'pkiuser', '0600')

        return FileCheck.check(self)


@registry
class IPAFileCheck(IPAPlugin, FileCheck):
    def dns_container_exists(self):
        try:
            self.conn.get_entry(DN(api.env.container_dns,
                                api.env.basedn), [])
        except errors.NotFound:
            return False
        except AttributeError:
            logger.debug("LDAP is down, can't tell whether DNS is available."
                         " Skipping those file checks.")
            return False
        return True

    def check(self):
        self.files = []

        if self.ca.is_configured():
            self.files.append((paths.RA_AGENT_PEM, 'root', 'ipaapi', '0440'))
            self.files.append((paths.RA_AGENT_KEY, 'root', 'ipaapi', '0440'))

        if krbinstance.is_pkinit_enabled():
            self.files.append((paths.KDC_CERT, 'root', 'root', '0644'))
            self.files.append((paths.KDC_KEY, 'root', 'root', '0600'))

        if self.dns_container_exists():
            self.files.append((paths.NAMED_KEYTAB,
                              constants.NAMED_USER,
                              constants.NAMED_GROUP, '0400'))
            if os.path.exists(paths.IPA_DNSKEYSYNCD_KEYTAB):
                self.files.append((paths.IPA_DNSKEYSYNCD_KEYTAB,
                                  'root', constants.ODS_GROUP, '0440'))

        self.files.append((paths.GSSAPI_SESSION_KEY,
                          'root', 'root', '0600'))
        self.files.append((paths.DS_KEYTAB,
                           constants.DS_USER, constants.DS_GROUP, '0600'))
        self.files.append((paths.IPA_CA_CRT, 'root', 'root', '0644'))
        self.files.append((paths.IPA_CUSTODIA_KEYS, 'root', 'root', '0600'))

        self.files.append((paths.RESOLV_CONF, 'root', 'root', '0644'))
        self.files.append((paths.HOSTS, 'root', 'root', '0644'))

        return FileCheck.check(self)


@registry
class TomcatFileCheck(IPAPlugin, FileCheck):
    def check(self):
        if not self.ca.is_configured():
            logger.debug('CA is not configured, skipping')
            self.files = []
        else:
            self.files = [
                (paths.PKI_TOMCAT_PASSWORD_CONF,
                 constants.PKI_USER, constants.PKI_GROUP, '0660'),
                (paths.CA_CS_CFG_PATH,
                 constants.PKI_USER, constants.PKI_GROUP, '0660'),
                (os.path.join(paths.PKI_TOMCAT, 'server.xml'),
                 constants.PKI_USER, constants.PKI_GROUP, '0660'),
            ]

        return FileCheck.check(self)
