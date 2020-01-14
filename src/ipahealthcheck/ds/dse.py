#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.dseldif import DSEldif


@registry
class DSECheck(DSPlugin):
    """
    Check the dse.ldif/cn=config for obvious issues
    """
    check_class = DSEldif
