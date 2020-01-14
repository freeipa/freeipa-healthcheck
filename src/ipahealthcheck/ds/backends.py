#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.backend import Backends


@registry
class BackendsCheck(DSPlugin):
    """
    Check all the backends for misconfigurations
    """
    check_class = Backends
    many = True
