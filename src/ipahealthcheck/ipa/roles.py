#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

from ipalib import api
from ipaserver.install import krainstance

logger = logging.getLogger()


@registry
class IPACRLManagerCheck(IPAPlugin):
    """
    Determine if this master is the CRL manager

    This check in itself will always return SUCCESS and is only
    useful in the context of the ohter masters. Some external
    service is expected to aggregate this.
    """
    @duration
    def check(self):
        if not self.ca.is_configured():
            return
        try:
            enabled = self.ca.is_crlgen_enabled()
        except AttributeError:
            yield Result(self, constants.SUCCESS,
                         key='crl_manager',
                         crlgen_enabled=None,
                         msg='Not available in this version of IPA')
        else:
            yield Result(self, constants.SUCCESS,
                         key='crl_manager',
                         crlgen_enabled=enabled)


@registry
class IPARenewalMasterCheck(IPAPlugin):
    """
    Determine if this master is the CA renewal master.

    This check in itself will always return SUCCESS and is only
    useful in the context of the ohter masters. Some external
    service is expected to aggregate this.
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        try:
            result = api.Command.config_show()
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='renewal_master',
                         msg='Request for configuration failed, %s' % e)
        else:
            server = result['result'].get('ca_renewal_master_server', None)
            yield Result(self, constants.SUCCESS,
                         key='renewal_master',
                         master=server == api.env.host)


@registry
class IPARenewalMasterHasKRACheck(IPAPlugin):
    """
    Determine if this master is the CA renewal master and has a KRA installed.

    If this is the CA renewal master and there is a KRA in the topology
    but not here then the KRA certificates will not be renewed.
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        try:
            result = api.Command.config_show()
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='kra_renewal_master',
                         msg='Request for configuration failed, %s' % e)
            return

        renewal = result['result'].get('ca_renewal_master_server', None)
        if renewal != api.env.host:
            # Not the renewal server, nothing to do
            logger.debug("Not the renewal server")
            return

        kra = krainstance.KRAInstance(api.env.realm)
        if kra.is_installed():
            yield Result(self, constants.SUCCESS,
                         key='kra_renewal_master')
            return

        if result['result'].get('kra_server_server'):
            yield Result(self, constants.CRITICAL,
                         key='kra_renewal_master',
                         msg="There are KRA(s) in the topology but "
                         "not on the renewal server. "
                         "The KRA service certificates will not be "
                         "renewed.")
            return

        # it should never hit here but what the heck.
        yield Result(self, constants.SUCCESS,
                     key='kra_renewal_master')
