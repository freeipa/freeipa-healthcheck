#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

import sys

from ipaclustercheck.core.output import output_registry
from ipahealthcheck.core.core import RunChecks


class ClusterChecks(RunChecks):

    def add_options(self):
        parser = self.parser
        parser.add_argument('--directory', dest='dir',
                            help='Directory holding healthcheck logs')

    def validate_options(self):
        super().validate_options()

        if self.options.dir is None:
            print("--directory containing logs to check is required")
            return 1

        return None


def main():
    clusterchecks = ClusterChecks(['ipaclustercheck.registry'],
                                   '/etc/ipa/clustercheck.conf',
                                   output_registry, 'ansible')
    sys.exit(clusterchecks.run_healthcheck())
