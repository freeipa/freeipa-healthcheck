import grp
import os
import pwd

from idmcheck.ipa.plugin import IPAPlugin, registry

from idmcheck.core.plugin import Result, Results
from idmcheck.core import constants

from ipaplatform.paths import paths

from ipaserver.install import dsinstance

@registry
class IPAFileNSSDBCheck(IPAPlugin):
    def check(self):
        print('Called check on', self)

        results = Results()

        databases = [
            {
                'dirname': dsinstance.config_dirname(self.serverid),
                'files': [
                    ('key4.db', 'dirsrv', 'root', '0640'),
                    ('cert9.db', 'dirsrv', 'root', '0640'),
                    ('pkcs11.txt', 'dirsrv', 'dirsrv', '0640'),
                ]
            },
        ]

        if self.ca.is_configured():
            databases.append(
                {
                    'dirname': paths.VAR_LIB_IPA,
                    'files': [
                        ('ra-agent.key', 'root', 'ipaapi', '0440'),
                        ('ra-agent.pem', 'root', 'ipaapi', '0440'),
                    ]
                },
            )

            databases.append(
                {
                    'dirname': paths.PKI_TOMCAT_ALIAS_DIR,
                    'files': [
                        ('key4.db', 'pkiuser', 'pkiuser', '0600'),
                        ('cert9.db', 'pkiuser', 'pkiuser', '0600'),
                        ('pkcs11.txt', 'pkiuser', 'pkiuser', '0600'),
                    ]
                },
            )

        for db in databases:
            for (file, owner, group, mode) in db['files']:
                path = os.path.join(db['dirname'], file)
                stat = os.stat(path)
                fmode = str(oct(stat.st_mode)[-4:])
                key = '%s_mode' % path.replace('/', '_')
                if mode != fmode:
                    result = Result(self, constants.WARNING, key=key,
                                    path=path, expected=mode,
                                    got=fmode,
                                    msg='Permissions of %s are %s and '
                                    'should be %s' % (path, fmode, mode))
                else:
                    result = Result(self, constants.SUCCESS, key=key,
                                    path=path)
                fowner = pwd.getpwnam(owner)
                key = '%s_owner' % path.replace('/', '_')
                if fowner.pw_uid != stat.st_uid:
                    actual = pwd.getpwuid(stat.st_uid)
                    result = Result(self, constants.WARNING, key=key,
                                    path=path, expected=owner,
                                    got=actual.pw_name,
                                    msg='Ownership of %s is %s and should '
                                        'be %s' %
                                        (path, actual.pw_name, owner))
                else:
                    result = Result(self, constants.SUCCESS, key=key,
                                    path=path)
                fgroup = grp.getgrnam(group)
                key = '%s_group' % path.replace('/', '_')
                if fgroup.gr_gid != stat.st_gid:
                    actual = grp.getgrgid(stat.st_gid)
                    result = Result(self, constants.WARNING, key=key,
                                    path=path, expected=group,
                                    got=actual.gr_name,
                                    msg='Group of %s is %s and should '
                                        'be %s' %
                                        (path, actual.gr_name, group))
                else:
                    result = Result(self, constants.SUCCESS, key=key,
                                    path=path)
                results.add(result)

        return results
