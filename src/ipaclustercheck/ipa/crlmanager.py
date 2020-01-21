#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipaclustercheck.ipa.plugin import ClusterPlugin, registry, find_check
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants


@registry
class ClusterCRLManagerCheck(ClusterPlugin):

    @duration
    def check(self):
        data = self.registry.json
        crlmanagers = []

        for fqdn in data.keys():
             output = find_check(data[fqdn], 'ipahealthcheck.ipa.roles',
                                 'IPACRLManagerCheck')
             enabled = output.get('kw').get('crlgen_enabled')
             if enabled:
                 crlmanagers.append(fqdn)
        if len(crlmanagers) == 0:
            yield Result(self, constants.ERROR, error='No CRL Manager defined')
        elif len(crlmanagers) == 1:
            yield Result(self, constants.SUCCESS, crlmanager=crlmanagers[0])
        else:
            yield Result(self, constants.ERROR,
                         crlmanager=','.join(crlmanagers),
                         error='Multiple CRL Managers defined')
