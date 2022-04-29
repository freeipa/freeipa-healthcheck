#
# Copyright (C) 2022 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from unittest.mock import patch
from util import capture_results

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.kdc import KDCWorkersCheck


class TestKDCWorkers(BaseTest):
    @patch('ipahealthcheck.ipa.kdc.get_contents')
    @patch('os.sysconf')
    def test_no_workers(self, mock_sysconf, mock_sysconfig):
        mock_sysconf.return_value = 1
        mock_sysconfig.return_value = ""
        framework = object()
        registry.initialize(framework, config.Config)
        f = KDCWorkersCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.kdc'
        assert result.check == 'KDCWorkersCheck'
        assert result.kw.get('key') == 'workers'
        assert result.kw.get('sysconfig') == '/etc/sysconfig/krb5kdc'
        assert result.kw.get('msg') == 'KRB5KDC_ARGS is not set in {sysconfig}'

    @patch('ipahealthcheck.ipa.kdc.get_contents')
    @patch('os.sysconf')
    def test_workers_match_single(self, mock_sysconf, mock_sysconfig):
        mock_sysconf.return_value = 1
        mock_sysconfig.return_value = (
            ("KRB5KDC_ARGS='-w 1'", "KRB5REALM=EXAMPLE.TEST")
        )
        framework = object()
        registry.initialize(framework, config.Config)
        f = KDCWorkersCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.kdc'
        assert result.check == 'KDCWorkersCheck'
        assert result.kw.get('key') == 'workers'

    @patch('ipahealthcheck.ipa.kdc.get_contents')
    @patch('os.sysconf')
    def test_workers_match_double(self, mock_sysconf, mock_sysconfig):
        mock_sysconf.return_value = 1
        mock_sysconfig.return_value = (
            ('KRB5KDC_ARGS="-w 1"', "KRB5REALM=EXAMPLE.TEST")
        )
        framework = object()
        registry.initialize(framework, config.Config)
        f = KDCWorkersCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS
        assert result.source == 'ipahealthcheck.ipa.kdc'
        assert result.check == 'KDCWorkersCheck'

    @patch('ipahealthcheck.ipa.kdc.get_contents')
    @patch('os.sysconf')
    def test_workers_mismatch(self, mock_sysconf, mock_sysconfig):
        mock_sysconf.return_value = 2
        mock_sysconfig.return_value = (
            ("KRB5KDC_ARGS='-w 1'", "KRB5REALM=EXAMPLE.TEST")
        )
        framework = object()
        registry.initialize(framework, config.Config)
        f = KDCWorkersCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.source == 'ipahealthcheck.ipa.kdc'
        assert result.check == 'KDCWorkersCheck'
        assert result.kw.get('key') == 'workers'
        assert result.kw.get('cpus') == 2
        assert result.kw.get('workers') == 1
        assert result.kw.get("msg") == "The number of CPUs {cpus} " \
                                       "does not match the number of " \
                                       "workers {workers} in {sysconfig}"
