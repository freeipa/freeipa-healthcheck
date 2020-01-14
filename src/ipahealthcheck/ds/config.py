#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.config import Config


@registry
class ConfigCheck(DSPlugin):
    """
    Check the DS config for obvious errors
    """
    check_class = Config
