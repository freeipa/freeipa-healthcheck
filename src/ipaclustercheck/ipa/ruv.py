#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging

from ipaclustercheck.ipa.plugin import ClusterPlugin, registry, find_checks
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
        test_masters = list(data)
        masters = None
        for master in test_masters:
            output = find_checks(data[master], 'ipahealthcheck.meta.core',
                                 'MetaCheck')
            # TODO: catch if no masters
            masters = output[0].get('kw').get('masters')
            if masters:
                break

        if masters is None:
            yield Result(self, constants.ERROR,
                         name='ruv',
                         error='Full list of masters not found in log files.'
                               'This should be in ipahealthcheck.meta.core '
                               'MetaCheck')
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
                                 name='ruv',
                                 error='Unknown suffix found %s' % basedn)

        # Collect the nsDS5ReplicaID for each master
        ruvs = set()
        csruvs = set()
        for fqdn in data.keys():
            outputs = find_checks(data[fqdn], 'ipahealthcheck.ds.ruv',
                                  'RUVCheck')
            for output in outputs:
                basedn = DN(output.get('kw').get('key'))
                ruv = (fqdn, (output.get('kw').get('ruv')))
                if basedn == DN('o=ipaca'):
                    csruvs.add(ruv)
                elif basedn == api.env.basedn:
                    ruvs.add(ruv)
                else:
                    yield Result(self, constants.WARNING,
                                 name='ruv',
                                 error='Unknown suffix found %s' % basedn)

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

        if dangles:
            clean_csruvs = set()
            clean_ruvs = set()
            for master_cn, master_info in info.items():
                for ruv in master_info['clean_ruv']:
                    logger.debug('Dangling RUV id: {id}, hostname: {host}'
                                 .format(id=ruv[1], host=ruv[0]))
                    clean_ruvs.add(ruv[1])
                for csruv in master_info['clean_csruv']:
                    logger.debug('Dangling CS RUV id: {id}, hostname: {host}'
                                 .format(id=csruv[1], host=csruv[0]))
                    clean_csruvs.add(csruv[1])

            if clean_ruvs:
                yield Result(self, constants.ERROR,
                             name='dangling_ruv',
                             value=', '.join(clean_ruvs))
            if clean_csruvs:
                yield Result(self, constants.ERROR,
                             name='dangling_csruv',
                             value=', '.join(clean_csruvs))
        else:
            yield Result(self, constants.SUCCESS,
                         name='dangling_ruv',
                         value='No dangling RUVs found')
            yield Result(self, constants.SUCCESS,
                         name='dangling_csruv',
                         value='No dangling CS RUVs found')
