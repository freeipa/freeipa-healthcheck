#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from util import capture_results

from ipahealthcheck.core import config
from ipaclustercheck.ipa.plugin import ClusterRegistry
from ipaclustercheck.ipa.ruv import ClusterRUVCheck

import clusterdata


class RUVRegistry(ClusterRegistry):
    def load_files(self, dir):
        self.json = dir


class Options:
    def __init__(self, data):
        self.data = data

    @property
    def dir(self):
        return self.data


registry = RUVRegistry()


class TestClusterRUV(BaseTest):

    def test_no_ruvs(self):
        """Single master test that has never created a replica

           This type of master will have no RUVs created at all.
        """
        framework = object()
        registry.initialize(framework, config.Config,
                            Options(clusterdata.ONE_MASTER))
        f = ClusterRUVCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2
        result = self.results.results[0]
        assert result.kw.get('name') == 'dangling_ruv'
        assert result.kw.get('value') == 'No dangling RUVs found'
        result = self.results.results[1]
        assert result.kw.get('name') == 'dangling_csruv'
        assert result.kw.get('value') == 'No dangling CS RUVs found'

    def test_six_ruvs_ok(self):
        """Three master test with each having a CA, no dangling
        """
        framework = object()
        registry.initialize(framework, config.Config,
                            Options(clusterdata.THREE_MASTERS_OK))
        f = ClusterRUVCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2
        result = self.results.results[0]
        assert result.kw.get('name') == 'dangling_ruv'
        assert result.kw.get('value') == 'No dangling RUVs found'
        result = self.results.results[1]
        assert result.kw.get('name') == 'dangling_csruv'
        assert result.kw.get('value') == 'No dangling CS RUVs found'

    def test_six_ruvs_ipa_bad(self):
        """Three master test with each having a CA, dangling IPA RUV
        """
        framework = object()
        registry.initialize(framework, config.Config,
                            Options(clusterdata.THREE_MASTERS_BAD_IPA_RUV))
        f = ClusterRUVCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2
        result = self.results.results[0]
        assert result.kw.get('name') == 'dangling_ruv'
        assert result.kw.get('value') == '9'
        result = self.results.results[1]
        assert result.kw.get('name') == 'dangling_csruv'
        assert result.kw.get('value') == 'No dangling CS RUVs found'

    def test_six_ruvs_cs_bad(self):
        """Three master test with each having a CA, dangling CA RUV
        """
        framework = object()
        registry.initialize(framework, config.Config,
                            Options(clusterdata.THREE_MASTERS_BAD_CS_RUV))
        f = ClusterRUVCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 2
        result = self.results.results[0]
        assert result.kw.get('name') == 'dangling_ruv'
        assert result.kw.get('value') == 'No dangling RUVs found'
        result = self.results.results[1]
        assert result.kw.get('name') == 'dangling_csruv'
        assert result.kw.get('value') == '9'
