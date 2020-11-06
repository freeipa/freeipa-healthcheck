#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.plugin import Plugin


class ServiceCheck(Plugin):
    def __init__(self, registry):
        super().__init__(registry)
        self.service = None
        self.service_name = None

    def check(self, instance=''):
        raise NotImplementedError
