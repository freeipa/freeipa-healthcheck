#
# Copyright (C) 2025 FreeIPA Contributors see COPYING for license
#

from util import capture_results, m_api
from base import BaseTest
from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.config import IPAkrbLastSuccessfulAuth


class TestkrbLastSuccessfulAuth(BaseTest):

    def test_last_success_disabled(self):
        """Test that no warning is issued in the default config"""

        m_api.Command.config_show.side_effect = [{
            'result': {
                'ipaconfigstring': ['KDC:Disable Last Success',]
            }
        }]

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAkrbLastSuccessfulAuth(registry)
        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.config'
        assert result.check == 'IPAkrbLastSuccessfulAuth'

    def test_last_success_enabled(self):
        """Test that a warning is issued when krbLastSuccessfulAuth is
           replicated.
        """

        m_api.Command.config_show.side_effect = [{
            'result': {
                'ipaconfigstring': ['',]
            }
        }]

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAkrbLastSuccessfulAuth(registry)
        self.results = capture_results(f)

        assert len(self.results) == 1
        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.config'
        assert result.check == 'IPAkrbLastSuccessfulAuth'
