#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.plugin import Plugin


class ServiceCheck(Plugin):
    def check(self, instance=''):
        raise NotImplementedError
