
# Copyright (C) 2022 FreeIPA Contributors see COPYING for license
#

import logging
import os

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants


logger = logging.getLogger()
SYSCONFIG = '/etc/sysconfig/krb5kdc'


def get_contents(file):
    with open(SYSCONFIG, "r") as fd:
        lines = fd.readlines()
    return lines


@registry
class KDCWorkersCheck(IPAPlugin):
    """Verify that the number of workers matches the number of cores"""

    @duration
    def check(self):
        key = 'workers'
        cpus = os.sysconf('SC_NPROCESSORS_ONLN')
        logging.debug('Detected %s CPUs', cpus)

        lines = get_contents(SYSCONFIG)

        args_read = False
        for line in lines:
            sline = line.strip()
            workers = 0
            if sline.startswith('KRB5KDC_ARGS'):
                args_read = True
                sline = sline.split('=', maxsplit=1)[1]
                if sline.find("-w") == -1:
                    if cpus == 1:
                        # -w is not configured when cpus == 1
                        yield Result(self, constants.SUCCESS, key=key)
                        return
                    else:
                        yield Result(self, constants.WARNING, key=key,
                                     sysconfig=SYSCONFIG,
                                     msg='No KDC workers defined in '
                                     '{sysconfig}')
                        return

                # Making an assumption that this line is not misconfigured
                # otherwise the KDC wouldn't start at all.
                sline = sline.replace("'", "")
                sline = sline.replace('"', "")
                sline = sline.split()
                for i in range(len(sline)):
                    if sline[i] == '-w':
                        workers = int(sline[i+1])
                        break
                if cpus == workers:
                    yield Result(self, constants.SUCCESS, key=key)
                else:
                    yield Result(self, constants.WARNING, key=key,
                                 cpus=cpus, workers=workers,
                                 sysconfig=SYSCONFIG,
                                 msg='The number of CPUs {cpus} does not '
                                     'match the number of workers '
                                     '{workers} in {sysconfig}')
                break
        if not args_read:
            yield Result(self, constants.WARNING, key=key,
                         sysconfig=SYSCONFIG,
                         msg='KRB5KDC_ARGS is not set in '
                         '{sysconfig}')
