#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.replica import Replica, Changelog5


@registry
class ReplicationCheck(DSPlugin):
    """
    Check the agreement status for various states, and check for conflicts
    """
    check_class = Replica


@registry
class ReplicationChangelogCheck(DSPlugin):
    """
    Check the replication changelog has some sort of trimming configured
    """
    check_class = Changelog5
