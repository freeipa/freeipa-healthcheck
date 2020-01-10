#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.nss_ssl import NssSsl


@registry
class NssCheck(DSPlugin):
    """
    Check the NSS database certificates for expiring issues
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        results = self.doCheck(NssSsl)
        if len(results) > 0:
            for result in results:
                yield result
        else:
            yield Result(self, constants.SUCCESS)
