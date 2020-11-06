#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging

from ipaclustercheck.ipa.plugin import (
    ClusterPlugin,
    registry,
    find_checks,
    get_masters
)
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants
from ipalib import api
from ipapython.dn import DN


logger = logging.getLogger()


@registry
class ClusterRUVCheck(ClusterPlugin):

    # TODO: confirm that all masters are represented, otherwise the
    #       trustworthiness of dangling RUV is mixed.
    #
    #       gah, need to provide full list of all masters in a check.

    @duration
    def check(self):
        data = self.registry.json

        # Start with the list of masters from the file(s) collected
        # and find a MetaCheck with a full list of masters. For
        # backwards compatibility.
        try:
            masters = get_masters(data)
        except ValueError as e:
            yield Result(self, constants.ERROR,
                         name='dangling_ruv',
                         error=str(e))
            return

        if len(data.keys()) < len(masters):
            yield Result(self, constants.ERROR,
                         name='dangling_ruv',
                         error='Unable to determine list of RUVs, missing '
                               'some masters: %s' %
                               ''.join(set(masters) - set(data.keys())))
            return

        # collect the full set of known RUVs for each master
        info = {}
        for master in masters:
            info[master] = {
                'ca': False,           # does the host have ca configured?
                'ruvs': set(),         # ruvs on the host
                'csruvs': set(),       # csruvs on the host
                'clean_ruv': set(),    # ruvs to be cleaned from the host
                'clean_csruv': set()   # csruvs to be cleaned from the host
                }

        for fqdn in data.keys():
            outputs = find_checks(data[fqdn], 'ipahealthcheck.ds.ruv',
                                  'KnownRUVCheck')
            for output in outputs:
                if not 'suffix' in output.get('kw'):
                    continue
                basedn = DN(output.get('kw').get('suffix'))

                ruvset = set()
                ruvtmp = output.get('kw').get('ruvs')
                for ruv in ruvtmp:
                    ruvset.add(tuple(ruv))

                if basedn == DN('o=ipaca'):
                    info[fqdn]['ca'] = True
                    info[fqdn]['csruvs'] = ruvset
                elif basedn == api.env.basedn:
                    info[fqdn]['ruvs'] = ruvset
                else:
                    yield Result(self, constants.WARNING,
                                 name='dangling_ruv',
                                 error='Unknown suffix found %s expected %s'
                                       % (basedn, api.env.basedn))

        # Collect the nsDS5ReplicaID for each master
        ruvs = set()
        csruvs = set()
        for fqdn in data.keys():
            outputs = find_checks(data[fqdn], 'ipahealthcheck.ds.ruv',
                                  'RUVCheck')
            for output in outputs:
                if not 'key' in output.get('kw'):
                    continue
                basedn = DN(output.get('kw').get('key'))
                ruv = (fqdn, (output.get('kw').get('ruv')))
                if basedn == DN('o=ipaca'):
                    csruvs.add(ruv)
                elif basedn == api.env.basedn:
                    ruvs.add(ruv)
                else:
                    yield Result(self, constants.WARNING,
                                 name='dangling_ruv',
                                 error='Unknown suffix found %s expected %s'
                                       % (basedn, api.env.basedn))

        dangles = False
        # get the dangling RUVs
        for master_info in info.values():
            for ruv in master_info['ruvs']:
                if ruv not in ruvs:
                    master_info['clean_ruv'].add(ruv)
                    dangles = True

            # if ca is not configured, there will be no csruvs in master_info
            for csruv in master_info['csruvs']:
                if csruv not in csruvs:
                    master_info['clean_csruv'].add(csruv)
                    dangles = True

        clean_csruvs = set()
        clean_ruvs = set()
        if dangles:
            for _, master_info in info.items():
                for ruv in master_info['clean_ruv']:
                    logger.debug(
                        "Dangling RUV id: %s, hostname: %s", ruv[1], ruv[0]
                    )
                    clean_ruvs.add(ruv[1])
                for csruv in master_info['clean_csruv']:
                    logger.debug(
                        "Dangling CS RUV id: %s, hostname: %s",
                        csruv[1],
                        csruv[0]
                    )
                    clean_csruvs.add(csruv[1])

        if clean_ruvs:
            yield Result(self, constants.ERROR,
                         name='dangling_ruv',
                         value=', '.join(clean_ruvs))
        else:
            yield Result(self, constants.SUCCESS,
                         name='dangling_ruv',
                         value='No dangling RUVs found')
        if clean_csruvs:
            yield Result(self, constants.ERROR,
                         name='dangling_csruv',
                         value=', '.join(clean_csruvs))
        else:
            yield Result(self, constants.SUCCESS,
                         name='dangling_csruv',
                         value='No dangling CS RUVs found')
