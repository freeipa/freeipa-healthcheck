import os

from idmcheck.core.files import FileCheck
from idmcheck.ipa.plugin import IPAPlugin, registry

from ipaplatform.paths import paths
from ipapython.certdb import NSS_SQL_FILES

from ipaserver.install import dsinstance


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

            self.files.append((paths.RA_AGENT_PEM, 'root', 'ipaapi', '0440'))
            self.files.append((paths.RA_AGENT_KEY, 'root', 'ipaapi', '0440'))

        return FileCheck.check(self)
