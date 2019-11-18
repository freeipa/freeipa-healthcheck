#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from os import environ
import sys

from ipahealthcheck.core import constants
from ipahealthcheck.core.core import run_healthcheck


def main():
    environ["KRB5_CLIENT_KTNAME"] = "/etc/krb5.keytab"
    environ["KRB5CCNAME"] = "MEMORY:"

    sys.exit(run_healthcheck(['ipahealthcheck.registry'],
                             constants.CONFIG_FILE))
