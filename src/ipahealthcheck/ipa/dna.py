
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

from ipalib import api
from ipaserver.install import replication


logger = logging.getLogger()


@registry
class IPADNARangeCheck(IPAPlugin):
    """
    Report the configured DNA range, if any.

    This expects some external system to analyze and determine if
    any or all masters have a DNA range configured. It is not an error
    if a master does not have a range. It IS an error if no masters have
    a range.
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        try:
            agmt = replication.ReplicationManager(api.env.realm, api.env.host)
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='agreement_creation_error_dna',
                         error=str(e),
                         msg='Connection to replica failed {error}')
            logging.debug('Establishing agreement failed %s', e)

        (range_start, range_max) = agmt.get_DNA_range(api.env.host)
        (next_start, next_max) = agmt.get_DNA_next_range(api.env.host)

        if range_start is not None:
            yield Result(self, constants.SUCCESS,
                         range_start=range_start,
                         range_max=range_max,
                         next_start=next_start or 0,
                         next_max=next_max or 0)
        else:
            yield Result(self, constants.WARNING,
                         key='no_dna_range_defined',
                         range_start=0,
                         range_max=0,
                         next_start=0,
                         next_max=0,
                         msg='No DNA range defined. If no masters define a '
                             'range then users and groups cannot be '
                             'created.')
