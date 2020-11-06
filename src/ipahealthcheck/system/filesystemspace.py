#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#
from __future__ import division

import os
import shutil

from ipahealthcheck.system.plugin import SystemPlugin, registry
from ipahealthcheck.core.plugin import duration, Result
from ipahealthcheck.core import constants


def in_container():
    """Determine if we're running in a container."""
    with open('/proc/1/sched', 'r') as sched:
        data_sched = sched.readline()

    with open('/proc/self/cgroup', 'r') as cgroup:
        data_cgroup = cgroup.readline()

    checks = [
        data_sched.split()[0] not in ('systemd', 'init',),
        data_cgroup.split()[0] not in ('libpod'),
        os.path.exists('/.dockerenv'),
        os.path.exists('/.dockerinit'),
        os.getenv('container', None) is not None
    ]

    return any(checks)


@registry
class FileSystemSpaceCheck(SystemPlugin):
    """
    """

    # watch important directories for FreeIPA
    _pathchecks = {
        '/var/lib/dirsrv/': 1024,
        '/var/lib/ipa/backup/': 512,
        '/var/log/': 1024,
        '/var/tmp/': 512,
        '/tmp': 512
    }

    if not in_container():
        _pathchecks['/var/log/audit/'] = 512

    # File systems reaching 90% capacity risk fragmentation.
    # Defragmentation is never desirable and not available
    # on ext4 anyway. So error out at 20% free space.
    min_free_percent = 20

    def get_fs_free_space(self, pathname):
        stat = shutil.disk_usage(pathname)
        return int(stat.free / 2**20)

    def get_fs_free_space_percentage(self, pathname):
        stat = shutil.disk_usage(pathname)
        return int(stat.free * 100 / stat.total)

    @duration
    def check(self):
        for store in self._pathchecks:
            try:
                percent_free = self.get_fs_free_space_percentage(store)
            except FileNotFoundError:
                yield Result(
                    self, constants.WARNING,
                    msg='File system {store} is not mounted',
                    store=store
                )
                continue
            if percent_free < self.min_free_percent:
                yield Result(
                    self, constants.ERROR,
                    msg='%s: %s %s%% < %s%%' % (
                        store, 'free space percentage under threshold:',
                        percent_free, self.min_free_percent
                    ),
                    store=store, percent_free=percent_free,
                    threshold=self.min_free_percent
                )
            else:
                yield Result(
                    self, constants.SUCCESS,
                    msg='%s: %s %s%% >= %s%%' % (
                        store, 'free space percentage within limits:',
                        percent_free, self.min_free_percent
                    ),
                    store=store, percent_free=percent_free,
                    threshold=self.min_free_percent
                )
            free_space = self.get_fs_free_space(store)
            threshold = self._pathchecks[store]
            if free_space < threshold:
                yield Result(
                     self, constants.ERROR,
                     msg='%s: %s %s MiB < %s MiB' % (
                         store, 'free space under threshold:',
                         free_space, threshold
                     ),
                     store=store, free_space=free_space, threshold=threshold
                )
            else:
                yield Result(
                     self, constants.SUCCESS,
                     msg='%s: %s %s MiB >= %s MiB' % (
                         store, 'free space within limits:',
                         free_space, threshold
                     ),
                     store=store, free_space=free_space, threshold=threshold
                )
