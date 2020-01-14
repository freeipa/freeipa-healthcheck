#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.config import Encryption


@registry
class EncryptionCheck(DSPlugin):
    """
    Check the DS security configuration for obvious errors
    """
    check_class = Encryption
