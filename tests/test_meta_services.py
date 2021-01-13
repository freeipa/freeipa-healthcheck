#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from tests.util import capture_results
from tests.base import BaseTest

from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.meta.services import httpd
from ipahealthcheck.core import config


class TestServices(BaseTest):
    def test_simple_service(self):
        """
        Test a service. It was chosen at random.

        The purpose of this test is to exercise the service check
        code path and not to confirm that a particular service is
        running.
        """
        framework = object()
        registry.initialize(framework, config.Config)
        f = httpd(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1
