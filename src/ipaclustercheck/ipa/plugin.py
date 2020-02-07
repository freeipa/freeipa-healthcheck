#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from copy import deepcopy
import json
import logging
from os import listdir
from os.path import isfile, join

from ipahealthcheck.core.plugin import Plugin, Registry
from ipalib import api


logger = logging.getLogger()

def find_checks(data, source, check):
    """Look through the dict for a matching source and check.

       data: dict of source and check output
       source: name of source to find
       check: name of check to find

       Returns list of contents of source + check or empty list
    """
    rval = []
    for d in data:
        if d.get('source') == source and d.get('check') == check:
            rval.append(d)

    return rval


class ClusterPlugin(Plugin):
    def __init__(self, registry):
        super(ClusterPlugin, self).__init__(registry)


class ClusterRegistry(Registry):
    def initialize(self, framework, config, options):
        super(ClusterRegistry, self).initialize(framework, config, options)

        self.json = {}

        self.load_files(options.dir)

        if not api.isdone('finalize'):
            if not api.isdone('bootstrap'):
                api.bootstrap(in_server=True,
                              context='ipahealthcheck',
                              log=None)
            if not api.isdone('finalize'):
                api.finalize()

    def load_files(self, dir):
        if self.json:
            return

        files = [f for f in listdir(dir) if isfile(join(dir, f))]
        for file in files:
            fname = join(dir, file)
            logger.debug("Reading %s", fname)
            try:
                with open(fname, 'r') as fd:
                    data = fd.read()
            except Exception as e:
                logger.error("Unable to read %s: %s", fname, e)
                continue
        
            try:
                data = json.loads(data)
            except Exception as e:
                logger.error("Unable to parse JSON in %s: %s", fname, e)
                continue

            meta = find_checks(data, 'ipahealthcheck.meta.core',
                                   'MetaCheck')
            if meta:
                fqdn = meta[0].get('kw').get('fqdn')
                self.json[fqdn] = deepcopy(data)
            else:
                logger.error("No fqdn defined in JSON in %s", fname)
                continue
        
        
registry = ClusterRegistry()
