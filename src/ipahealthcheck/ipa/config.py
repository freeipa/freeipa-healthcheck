
# Copyright (C) 2025 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

from ipalib import api


@registry
class IPAkrbLastSuccessfulAuth(IPAPlugin):
    """Warn if krbLastSuccessfulAuth is enabled. It can cause
       performance issues.
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        try:
            result = api.Command.config_show()
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='krbLastSuccessfulAuth',
                         msg='Request for configuration failed, %s' % e)
            return

        configstring = result["result"].get(
            "ipaconfigstring", []
        )

        if 'KDC:Disable Last Success' not in configstring:
            yield Result(
                self,
                constants.WARNING,
                key='krbLastSuccessfulAuth',
                configstring=configstring,
                msg="Last Successful Auth is enabled. It may cause "
                    "performance problems.")
        else:
            yield Result(
                self,
                constants.SUCCESS,
                key='krbLastSuccessfulAuth'
            )
