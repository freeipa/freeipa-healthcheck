#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
import os
import socket
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.meta.plugin import Plugin, registry
from ipapython import ipautil
from ipapython.version import VERSION, API_VERSION
from ipaplatform.paths import paths

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

        yield Result(self, rval,
                     fqdn=socket.getfqdn(),
                     fips=fips,
                     ipa_version=VERSION,
                     ipa_api_version=API_VERSION,)
