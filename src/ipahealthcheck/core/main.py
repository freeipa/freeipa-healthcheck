#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from os import environ
import sys

from ipahealthcheck.core import constants
from ipahealthcheck.core.core import RunChecks


from ipaserver.install.installutils import is_ipa_configured


class IPAChecks(RunChecks):
    def pre_check(self):
        if not is_ipa_configured():
            print("IPA is not configured")
            return 1

        return None

    def add_options(self):
        parser = self.parser
        parser.add_argument('--input-file', dest='infile',
                            help='File to read as input')
        parser.add_argument('--failures-only', dest='failures_only',
                            action='store_true', default=False,
                            help='Exclude SUCCESS results on output (see'
                            'man page for more details)')
        parser.add_argument('--all', dest='all',
                            action='store_true', default=False,
                            help='Report all results on output')
        parser.add_argument('--severity', dest='severity', action="append",
                            help='Include only the selected severity(s)',
                            choices=[key for key in constants._nameToLevel])


def main():
    environ["KRB5_CLIENT_KTNAME"] = "/etc/krb5.keytab"
    environ["KRB5CCNAME"] = "MEMORY:"

    ipachecks = IPAChecks(['ipahealthcheck.registry',
                           'pkihealthcheck.registry'],
                          constants.CONFIG_FILE)
    sys.exit(ipachecks.run_healthcheck())
