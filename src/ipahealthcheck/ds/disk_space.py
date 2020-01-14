#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.monitor import MonitorDiskSpace


@registry
class DiskSpaceCheck(DSPlugin):
    """
    Check the all the disks that the DS uses
    """
    check_class = MonitorDiskSpace
