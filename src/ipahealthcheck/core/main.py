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


def main():
    environ["KRB5_CLIENT_KTNAME"] = "/etc/krb5.keytab"
    environ["KRB5CCNAME"] = "MEMORY:"

    ipachecks = IPAChecks(['ipahealthcheck.registry',
                           'pkihealthcheck.registry'],
                          constants.CONFIG_FILE)
    sys.exit(ipachecks.run_healthcheck())
