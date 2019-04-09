#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

from ipalib import api

logger = logging.getLogger()


@registry
class IPATopologyDomainCheck(IPAPlugin):
    """
    Execute the equivalant of ipa topologysuffix-verify domain

    Return any errors discovered. This can include:
      * too many agreements
      * connection errors
    """
    def report_errors(self, suffix, result):
        if result['result']['in_order']:
            yield Result(self, constants.SUCCESS, suffix=suffix)
        else:
            max_agmts = result['result']['max_agmts']
            connect_errors = result['result']['connect_errors']
            max_agmts_errors = result['result']['max_agmts_errors']
            cmsg = 'Server %(srv)s can\'t contact servers: %(replicas)s'
            mmsg = 'Server "%(srv)s" has %(n)d agreements, recommended ' \
                   'max %(m)d'

            if connect_errors:
                for error in connect_errors:
                    msg = cmsg % {'srv': error[0],
                                  'replicas': ', '.join(error[1])}
                    yield Result(self, constants.ERROR,
                                 key=error[0],
                                 replicas=error[2],
                                 suffix=suffix,
                                 type='connect',
                                 msg=msg)
            if max_agmts_errors:
                for error in max_agmts_errors:
                    msg = mmsg % {'srv': error[0],
                                  'n': len(error[1]),
                                  'm': max_agmts}
                    yield Result(self, constants.ERROR,
                                 key=error[0],
                                 replicas=error[1],
                                 suffix=suffix,
                                 type='max',
                                 msg=msg)

    def run_check(self, suffix):
        try:
            result = api.Command.topologysuffix_verify(suffix)
        except Exception as e:
            yield Result(self, constants.ERROR,
                         msg='topologysuffix-verify domain failed, %s' %
                         e)
        else:
            for r in self.report_errors(suffix, result):
                yield r

    @duration
    def check(self):

        for y in self.run_check(u'domain'):
            yield y
        if api.Command.ca_is_enabled()['result']:
            for y in self.run_check(u'ca'):
                yield y
