#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import shutil

from ipahealthcheck.system.plugin import SystemPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core import constants


@registry
class FileSystemSpaceCheck(SystemPlugin):
    """
    """

    # watch important directories for FreeIPA
    _pathchecks = {
        '/var/lib/dirsrv/': 1024,
        '/var/lib/ipa/backup/': 512,
        '/var/log/': 1024,
        '/var/log/audit/': 512,
        '/var/tmp/': 512,
        '/tmp': 512
    }

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

    def check(self):
        for store in self._pathchecks:
            percent_free = self.get_fs_free_space_percentage(store)
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
