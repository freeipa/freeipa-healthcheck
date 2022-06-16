#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import os
import sys

from ipahealthcheck.core import constants
from ipahealthcheck.core.core import RunChecks

try:
    from ipalib.facts import is_ipa_configured
except ImportError:
    is_ipa_configured = None


class IPAChecks(RunChecks):
    def pre_check(self):
        if is_ipa_configured is None:
            print("IPA server is not installed")
            return 1

        if not is_ipa_configured():
            print("IPA server is not configured")
            return 1

        return None

    def add_options(self):
        parser = self.parser
        parser.add_argument('--input-file', dest='infile',
                            help='File to read as input')
        parser.add_argument('--failures-only', dest='failures_only',
                            action='store_true', default=False,
                            help='Exclude SUCCESS results on output (see '
                            'man page for more details)')
        parser.add_argument('--all', dest='all',
                            action='store_true', default=False,
                            help='Report all results on output')
        parser.add_argument('--severity', dest='severity', action="append",
                            help='Include only the selected severity(s)',
                            choices=list(constants._nameToLevel))


def main():
    if not os.getegid() == 0:
        sys.exit("\nYou must be root to run this script.\n")
    os.environ["KRB5_CLIENT_KTNAME"] = "/etc/krb5.keytab"
    os.environ["KRB5CCNAME"] = "MEMORY:"

    ipachecks = IPAChecks(['ipahealthcheck.registry',
                           'pkihealthcheck.registry'],
                          constants.CONFIG_FILE)
    sys.exit(ipachecks.run_healthcheck())
