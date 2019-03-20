#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import os

from ipahealthcheck.core.files import FileCheck
from ipahealthcheck.ipa.plugin import IPAPlugin, registry

from ipaplatform.paths import paths
from ipapython.certdb import NSS_SQL_FILES

from ipaserver.install import dsinstance
from ipaserver.install import krbinstance


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
    def check(self):
        self.files = []

        if self.ca.is_configured():
            self.files.append((paths.RA_AGENT_PEM, 'root', 'ipaapi', '0440'))
            self.files.append((paths.RA_AGENT_KEY, 'root', 'ipaapi', '0440'))

        if krbinstance.is_pkinit_enabled():
            self.files.append((paths.KDC_CERT, 'root', 'root', '0644'))
            self.files.append((paths.KDC_KEY, 'root', 'root', '0600'))

        return FileCheck.check(self)
