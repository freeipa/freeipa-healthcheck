#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.ds.plugin import DSPlugin, registry
from lib389.nss_ssl import NssSsl


@registry
class NssCheck(DSPlugin):
    """
    Check the NSS database certificates for expiring issues
    """
    check_class = NssSsl
