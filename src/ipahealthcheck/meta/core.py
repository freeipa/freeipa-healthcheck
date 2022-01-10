#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
import os
import socket
from ipahealthcheck.core import constants
from ipahealthcheck.core.exceptions import TimeoutError
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.meta.plugin import Plugin, registry
from ipapython import ipautil
from ipapython.version import VERSION, API_VERSION
from ipaplatform.paths import paths

if 'FIPS_MODE_SETUP' not in dir(paths):
    paths.FIPS_MODE_SETUP = '/usr/bin/fips-mode-setup'

logger = logging.getLogger()


@registry
class MetaCheck(Plugin):
    @duration
    def check(self):

        rval = constants.SUCCESS
        if not os.path.exists(paths.FIPS_MODE_SETUP):
            fips = "missing {}".format(paths.FIPS_MODE_SETUP)
            logger.debug('%s is not installed, skipping',
                         paths.FIPS_MODE_SETUP)
        else:
            try:
                result = ipautil.run([paths.FIPS_MODE_SETUP,
                                      '--is-enabled'],
                                     capture_output=True,
                                     raiseonerr=False,)
            except TimeoutError:
                logger.debug('fips-mode-setup timed out')
                fips = "check timed out"
                rval = constants.ERROR
            except Exception as e:
                logger.debug('fips-mode-setup failed: %s', e)
                fips = "failed to check"
                rval = constants.ERROR
            else:
                logger.debug(result.raw_output.decode('utf-8'))
                if result.returncode == 0:
                    fips = "enabled"
                elif result.returncode == 1:
                    fips = "inconsistent"
                elif result.returncode == 2:
                    fips = "disabled"
                else:
                    fips = "unknown"

        if not os.path.exists('/usr/sbin/ipa-acme-manage'):
            acme = "missing {}".format('/usr/sbin/ipa-acme-manage')
            logger.debug('%s is not installed, skipping',
                         '/usr/sbin/ipa-acme-manage')
        else:
            try:
                result = ipautil.run(['ipa-acme-manage', 'status'],
                                     capture_output=True,
                                     raiseonerr=False,)
            except TimeoutError:
                logger.debug('ipa-acme-manage timed out')
                acme = "check timed out"
                rval = constants.ERROR
            except Exception as e:
                logger.debug('ipa-acme-manage failed: %s', e)
                acme = "failed to check"
                rval = constants.ERROR
            else:
                logger.debug(result.raw_output.decode('utf-8'))
                if "disabled" in result.output_log:
                    acme = "disabled"
                elif "enabled" in result.output_log:
                    acme = "enabled"
                else:
                    acme = "unknown"

        yield Result(self, rval,
                     key='meta',
                     fqdn=socket.getfqdn(),
                     fips=fips,
                     acme=acme,
                     ipa_version=VERSION,
                     ipa_api_version=API_VERSION,)
