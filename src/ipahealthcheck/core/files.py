#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import grp
import os
import pwd

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration


class FileCheck:
    """Generic check to validate permission and ownership of files

       files is a tuple of tuples. Each tuple consists of:
           (path, expected_perm, expected_owner, expected_group)

       perm is in the form of a POSIX ACL: e.g. 0440, 0770.
       owner and group are names or a tuple of names, not uid/gid.

       If owner and/or group are tuples then all names are checked.
       If a match is found that that is the one reported in SUCCESS.
       If it fails then all values are reported.
    """
    def __init__(self):
        self.files = []

    @duration
    def check(self):
        for (path, owner, group, mode) in self.files:
            if not isinstance(owner, tuple):
                owner = tuple((owner,))
            if not isinstance(group, tuple):
                group = tuple((group,))
            stat = os.stat(path)
            fmode = str(oct(stat.st_mode)[-4:])
            key = '%s_mode' % path.replace('/', '_')
            if mode != fmode:
                if mode < fmode:
                    yield Result(self, constants.WARNING, key=key,
                                 path=path, type='mode', expected=mode,
                                 got=fmode,
                                 msg='Permissions of %s are too permissive: '
                                 '%s and should be %s' % (path, fmode, mode))
                if mode > fmode:
                    yield Result(self, constants.ERROR, key=key,
                                 path=path, type='mode', expected=mode,
                                 got=fmode,
                                 msg='Permissions of %s are too restrictive: '
                                 '%s and should be %s' % (path, fmode, mode))
            else:
                yield Result(self, constants.SUCCESS, key=key,
                             type='mode', path=path)

            found = False
            for o in owner:
                fowner = pwd.getpwnam(o)
                if fowner.pw_uid == stat.st_uid:
                    found = True
                    break

            if not found:
                actual = pwd.getpwuid(stat.st_uid)
                key = '%s_owner' % path.replace('/', '_')
                if len(owner) == 1:
                    msg = 'Ownership of %s is %s and should ' \
                          'be %s' % \
                          (path, actual.pw_name, owner[0])
                else:
                    msg = 'Ownership of %s is %s and should ' \
                          'be one of %s' % \
                          (path, actual.pw_name, ','.join(owner))
                owner = ','.join(owner)
                yield Result(self, constants.WARNING, key=key,
                             path=path, type='owner', expected=owner,
                             got=actual.pw_name,
                             msg=msg)
            else:
                yield Result(self, constants.SUCCESS, key=key,
                             type='owner', path=path)

            found = False
            for g in group:
                fgroup = grp.getgrnam(g)
                if fgroup.gr_gid == stat.st_gid:
                    found = True
                    break

            if not found:
                key = '%s_group' % path.replace('/', '_')
                actual = grp.getgrgid(stat.st_gid)
                if len(group) == 1:
                    msg = 'Group of %s is %s and should ' \
                          'be %s' % \
                          (path, actual.gr_name, group[0])
                else:
                    msg = 'Group of %s is %s and should ' \
                          'be one of %s' % \
                          (path, actual.gr_name, ','.join(group))
                group = ','.join(group)
                yield Result(self, constants.WARNING, key=key,
                             path=path, type='group', expected=group,
                             got=actual.gr_name,
                             msg=msg)
            else:
                yield Result(self, constants.SUCCESS, key=key,
                             type='group', path=path)
