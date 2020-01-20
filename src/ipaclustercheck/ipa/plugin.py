#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.plugin import Plugin, Registry


class ClusterPlugin(Plugin):
    def __init__(self, registry):
        super(ClusterPlugin, self).__init__(registry)


class ClusterRegistry(Registry):
    def initialize(self, framework, config):
        super(ClusterRegistry, self).initialize(framework, config)

        self.load_files()

    def load_files(self, dir='/tmp/clustercheck'):
        pass


registry = ClusterRegistry()
