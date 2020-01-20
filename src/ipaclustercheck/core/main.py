#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

import sys

from ipahealthcheck.core.core import RunChecks


def main():
    clusterchecks = RunChecks(['ipaclustercheck.registry'],
                               '/etc/ipa/clustercheck.conf')
    sys.exit(clusterchecks.run_healthcheck())
