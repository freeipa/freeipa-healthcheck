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
from ipapython.dn import DN

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


@registry
class IPAnsslapdIdleTimeoutCheck(IPAPlugin):
    """Warn if nsslapd-idletimeout is set lower than the default or is 0.

    nsslapd-idletimeout controls how long 389-ds lets a client connection
    remain idle before closing it. The default is 3600 seconds and a value
    of 0 means idle connections are never closed.

    A value lower than the default can cause clients to have their
    connections dropped unexpectedly, leading to failures reported much
    later as SERVER_DOWN. The attribute lives in cn=config.
    """
    requires = ('dirsrv',)

    DEFAULT_IDLETIMEOUT = 3600

    @duration
    def check(self):
        config_dn = DN('cn=config')
        try:
            entry = self.conn.get_entry(
                config_dn, attrs_list=['nsslapd-idletimeout'])
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='nsslapd-idletimeout',
                         error=str(e),
                         msg='Unable to retrieve cn=config: {error}')
            return

        values = entry.get('nsslapd-idletimeout', [])
        if not values:
            # The attribute defaults to 3600 when not explicitly set
            yield Result(self, constants.SUCCESS, key='nsslapd-idletimeout')
            return

        try:
            idletimeout = int(values[0])
        except (TypeError, ValueError):
            yield Result(self, constants.ERROR,
                         key='nsslapd-idletimeout',
                         value=str(values[0]),
                         msg='nsslapd-idletimeout has a non-integer value: '
                             '{value}')
            return

        if idletimeout == 0:
            yield Result(self, constants.WARNING,
                         key='nsslapd-idletimeout',
                         value=idletimeout,
                         msg='nsslapd-idletimeout is set to 0 (unlimited). '
                             'Idle connections will never be closed.')
        elif idletimeout < self.DEFAULT_IDLETIMEOUT:
            yield Result(self, constants.WARNING,
                         key='nsslapd-idletimeout',
                         value=idletimeout,
                         default=self.DEFAULT_IDLETIMEOUT,
                         msg='nsslapd-idletimeout is set to {value} which is '
                             'lower than the default of {default}. This may '
                             'cause clients to see connections dropped '
                             'unexpectedly.')
        else:
            yield Result(self, constants.SUCCESS,
                         key='nsslapd-idletimeout',
                         value=idletimeout)
