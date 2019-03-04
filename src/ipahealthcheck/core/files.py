import grp
import os
import pwd

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, Results


class FileCheck:
    """Generic check to validate permission and ownership of files

       files is a tuple of tuples. Each tuple consists of:
           (path, expected_perm, expected_owner, expected_group)

       perm is in the form of a POSIX ACL: e.g. 0440, 0770.
       Owner and group are names, not uid/gid.
    """

    def check(self):
        results = Results()

        for (path, owner, group, mode) in self.files:
            stat = os.stat(path)
            fmode = str(oct(stat.st_mode)[-4:])
            key = '%s_mode' % path.replace('/', '_')
            if mode != fmode:
                result = Result(self, constants.WARNING, key=key,
                                path=path, type='mode', expected=mode,
                                got=fmode,
                                msg='Permissions of %s are %s and '
                                'should be %s' % (path, fmode, mode))
            else:
                result = Result(self, constants.SUCCESS, key=key,
                                type='mode', path=path)
            results.add(result)

            fowner = pwd.getpwnam(owner)
            key = '%s_owner' % path.replace('/', '_')
            if fowner.pw_uid != stat.st_uid:
                actual = pwd.getpwuid(stat.st_uid)
                result = Result(self, constants.WARNING, key=key,
                                path=path, type='owner', expected=owner,
                                got=actual.pw_name,
                                msg='Ownership of %s is %s and should '
                                    'be %s' %
                                    (path, actual.pw_name, owner))
            else:
                result = Result(self, constants.SUCCESS, key=key,
                                type='owner', path=path)
            results.add(result)

            fgroup = grp.getgrnam(group)
            key = '%s_group' % path.replace('/', '_')
            if fgroup.gr_gid != stat.st_gid:
                actual = grp.getgrgid(stat.st_gid)
                result = Result(self, constants.WARNING, key=key,
                                path=path, type='group', expected=group,
                                got=actual.gr_name,
                                msg='Group of %s is %s and should '
                                    'be %s' %
                                    (path, actual.gr_name, group))
            else:
                result = Result(self, constants.SUCCESS, key=key,
                                type='group', path=path)
            results.add(result)

        return results
