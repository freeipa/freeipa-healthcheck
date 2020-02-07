#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipalib import api


@registry
class IPAMetaCheck(IPAPlugin):
    """Return meta data for the IPA installation"""
    @duration
    def check(self):
        try:
            result = api.Command.server_find(pkey_only=True)
        except Exception as e:
            yield Result(self, constants.ERROR,
                         msg='server-show failed, %s' % e)
        else:
            masters = []
            for server in result['result']:
                masters.append(server['cn'][0])
            yield Result(self, constants.SUCCESS,
                         masters=masters)
