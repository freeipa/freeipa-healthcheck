#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.dseldif import FSChecks


@registry
class FSCheck(DSPlugin):
    """
    Check the FS for permissions issues impacting DS
    """
    check_class = FSChecks
