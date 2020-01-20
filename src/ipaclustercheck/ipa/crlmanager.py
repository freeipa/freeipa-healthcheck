#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipaclustercheck.ipa.plugin import ClusterPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants


@registry
class ClusterExpirationCheck(ClusterPlugin):

    @duration
    def check(self):
        yield Result(self, constants.SUCCESS)
