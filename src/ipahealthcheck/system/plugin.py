#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.plugin import Plugin, Registry


class SystemPlugin(Plugin):
    pass


class SystemRegistry(Registry):
    def initialize(self, framework, config, options=None):
        pass


registry = SystemRegistry()
