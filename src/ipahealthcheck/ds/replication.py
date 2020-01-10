#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

import logging
from ipahealthcheck.ds.plugin import DSPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants
from lib389.replica import Replica, Changelog5

logger = logging.getLogger()


@registry
class ReplicationCheck(DSPlugin):
    """
    Check the agreement status for various states, and check for conflicts
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        results = self.doCheck(Replica)
        if len(results) > 0:
            for result in results:
                yield result
        else:
            yield Result(self, constants.SUCCESS)


@registry
class ReplicationChangelogCheck(DSPlugin):
    """
    Check the replication changelog has some sort of trimming configured
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        results = self.doCheck(Changelog5)
        if len(results) > 0:
            for result in results:
                yield result
        else:
            yield Result(self, constants.SUCCESS)
