#
# Copyright (C) 2025 FreeIPA Contributors see COPYING for license
#

import logging
import SSSDConfig

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

from ipalib import api
from ipaplatform.constants import constants as platformconstants

logger = logging.getLogger(__name__)
DS_USER = platformconstants.DS_USER


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


@registry
class SSSDAllowedUids389Check(IPAPlugin):
    """
    Checks if UID 389 (LDAP service account) is listed in allowed_uids
    in sssd.conf.

    If UID 389 is in allowed_uids, SSSD will prevent local resolution
    which will cause issues with the IPA services.
    """

    @duration
    def check(self):
        try:
            sssdconfig = SSSDConfig.SSSDConfig()
            sssdconfig.import_config()
        except Exception as e:
            logger.debug('Failed to parse sssd.conf: %s', e)
            yield Result(self, constants.CRITICAL, error=str(e),
                         msg='Unable to parse sssd.conf: {error}')
            return

        try:
            service = sssdconfig.get_service('pac')
        except SSSDConfig.NoServiceError:
            logger.debug('No pac section found.')
            return

        try:
            uids = service.get_option('allowed_uids')
        except SSSDConfig.NoOptionError:
            logger.debug('ok, allowed_uids is undefined')
            yield Result(self, constants.SUCCESS, key='SSSD_allowed_uids')
            return
        else:
            uids = {s.strip() for s in uids.split(',') if s.strip()}
            candidates = {'389', DS_USER}
            invalid = uids.intersection(candidates)
            if invalid:
                yield Result(
                    self, constants.ERROR,
                    key='SSSD_allowed_uids',
                    invalid=', '.join(invalid),
                    msg="User/UID {invalid} found in 'allowed_uids' in "
                        "the [pac] section of sssd.conf."
                )
                return

        yield Result(self, constants.SUCCESS, key='SSSD_allowed_uids')
