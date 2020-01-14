#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.plugins import ReferentialIntegrityPlugin


@registry
class RIPluginCheck(DSPlugin):
    """
    Check that the RI plugin configuration is valid and properly indexed
    """
    check_class = ReferentialIntegrityPlugin
