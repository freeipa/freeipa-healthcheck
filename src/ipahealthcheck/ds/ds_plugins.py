#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.plugins import ReferentialIntegrityPlugin


@registry
class RIPluginCheck(DSPlugin):
    """
    Check that the RI plugin configuration is valid and properly indexed
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        results = self.doCheck(ReferentialIntegrityPlugin)
        if len(results) > 0:
            for result in results:
                yield result
        else:
            yield Result(self, constants.SUCCESS)
