#
# Copyright (C) 2021 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from collections import namedtuple
from unittest.mock import patch
from util import capture_results

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.nss import IPAGroupMemberCheck


struct_group = namedtuple(
    'struct_group', ['gr_name', 'gr_passwd', 'gr_gid', 'gr_mem']
)


def make_group(name, members):
    return struct_group(name, 'x', 999, members)


class TestGroupMember(BaseTest):
    @patch('grp.getgrnam')
    def test_ipaapi_group_ok(self, mock_grp):
        mock_grp.return_value = make_group('apache', ('apache', 'ipaapi',))

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPAGroupMemberCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS

    @patch('grp.getgrnam')
    def test_ipaapi_bad_group(self, mock_grp):
        mock_grp.side_effect = KeyError("name not found: 'ipaapi'")

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPAGroupMemberCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.kw.get('key') == 'ipaapi'
        assert result.kw.get('msg') == 'group {key} does not exist'

    @patch('grp.getgrnam')
    def test_ipaapi_missing_member(self, mock_grp):
        mock_grp.return_value = make_group('apache', ('foo',))

        framework = object()
        registry.initialize(framework, config.Config)
        registry.trust_agent = True
        f = IPAGroupMemberCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.ERROR
        assert result.kw.get('key') == 'ipaapi'
        assert result.kw.get('msg') == \
            '{member} is not a member of group {key}'
