
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import gssapi
import logging
import os
import tempfile

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

from ipalib import api
from ipalib.install.kinit import kinit_keytab
from ipaplatform.paths import paths
from ipaserver.install import installutils


logger = logging.getLogger()


@registry
class IPAHostKeytab(IPAPlugin):
    """Ensure the host keytab can get a TGT"""
    requires = ('krb5kdc',)

    @duration
    def check(self):
        ccache_dir = tempfile.mkdtemp()
        ccache_name = os.path.join(ccache_dir, 'ccache')

        try:
            try:
                host_princ = str('host/%s@%s' % (api.env.host, api.env.realm))
                kinit_keytab(host_princ, paths.KRB5_KEYTAB, ccache_name)
            except gssapi.exceptions.GSSError as e:
                yield Result(self, constants.ERROR,
                             msg='Failed to obtain host TGT: %s' % e)
        finally:
            installutils.remove_file(ccache_name)
            os.rmdir(ccache_dir)
