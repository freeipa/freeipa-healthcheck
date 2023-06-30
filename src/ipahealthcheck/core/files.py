#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import grp
import logging
import os
import pwd

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration

logger = logging.getLogger()


class FileCheck:
    """Generic check to validate permission and ownership of files

       files is a tuple of tuples. Each tuple consists of:
           (path, expected_perm, expected_owner, expected_group)

       perm is a POSIX ACL as either a string or tuple: e.g. 0440, (0770,).
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
            if not isinstance(mode, tuple):
                mode = tuple((mode,))
            if not os.path.exists(path):
                for type in ('mode', 'owner', 'group'):
                    key = '%s_%s' % (path.replace('/', '_'), type)
                    yield Result(self, constants.SUCCESS, key=key,
                                 type=type, path=path,
                                 msg='File does not exist')
                continue
            stat = os.stat(path)
            fmode = str(oct(stat.st_mode)[-4:])
            key = '%s_mode' % path.replace('/', '_')
            if fmode not in mode:
                if len(mode) == 1:
                    modes = mode[0]
                else:
                    modes = 'one of {}'.format(','.join(mode))
                if all(m < fmode for m in mode):
                    yield Result(self, constants.WARNING, key=key,
                                 path=path, type='mode', expected=modes,
                                 got=fmode,
                                 msg='Permissions of %s are too permissive: '
                                 '%s and should be %s' %
                                 (path, fmode, modes))
                elif all(m > fmode for m in mode):
                    yield Result(self, constants.ERROR, key=key,
                                 path=path, type='mode', expected=modes,
                                 got=fmode,
                                 msg='Permissions of %s are too restrictive: '
                                 '%s and should be %s' %
                                 (path, fmode, modes))
                else:
                    yield Result(self, constants.ERROR, key=key,
                                 path=path, type='mode', expected=modes,
                                 got=fmode,
                                 msg='Permissions of %s are unexpected: '
                                 '%s and should be %s' %
                                 (path, fmode, modes))
            else:
                yield Result(self, constants.SUCCESS, key=key,
                             type='mode', path=path)

            found = False
            for o in owner:
                try:
                    fowner = pwd.getpwnam(o)
                except Exception as e:
                    logging.debug('user lookup "%s" for "%s" failed: %s',
                                  o, path, e)
                    continue
                if fowner.pw_uid == stat.st_uid:
                    found = True
                    break

            if not found:
                key = '%s_owner' % path.replace('/', '_')
                try:
                    actual = pwd.getpwuid(stat.st_uid)
                except Exception:
                    yield Result(self, constants.WARNING, key=key,
                                 path=path, type='owner', expected=owner,
                                 got='Unknown uid %s' % stat.st_uid)
                    continue
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
                try:
                    fgroup = grp.getgrnam(g)
                except Exception as e:
                    logging.debug('group lookup "%s" for "%s" failed: %s',
                                  g, path, e)
                    continue
                if fgroup.gr_gid == stat.st_gid:
                    found = True
                    break

            if not found:
                key = '%s_group' % path.replace('/', '_')
                try:
                    actual = grp.getgrgid(stat.st_gid)
                except Exception:
                    yield Result(self, constants.WARNING, key=key,
                                 path=path, type='group', expected=group,
                                 got='Unknown gid %s' % stat.st_gid)
                    continue
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
