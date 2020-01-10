#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.config import Config


@registry
class ConfigCheck(DSPlugin):
    """
    Check the DS config for obvious errors
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        results = self.doCheck(Config)
        if len(results) > 0:
            for result in results:
                yield result
        else:
            yield Result(self, constants.SUCCESS)
