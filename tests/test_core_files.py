#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ldap import OPT_X_SASL_SSF_MIN
import pwd
import posix
from util import m_api
from util import capture_results

from ipahealthcheck.core import config
from ipahealthcheck.core.files import FileCheck
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Results
from ipahealthcheck.ipa.files import IPAFileCheck
from ipahealthcheck.system.plugin import registry
from unittest.mock import patch
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient, LDAPEntry


nobody = pwd.getpwnam('nobody')

# Mock files to test
files = (('foo', 'root', 'root', '0660'),
         ('bar', 'nobody', 'nobody', '0664'),
         ('baz', ('root', 'nobody'), ('root', 'nobody'), '0664'),
         ('fiz', ('root', 'bin'), ('root', 'bin'), '0664'),
         ('zap', ('root', 'bin'), ('root', 'bin'), ('0664', '0640'),))

bad_modes = (('biz', ('root', 'bin'), ('root', 'bin'), '0664', '0640'),)


class mock_ldap:
    SCOPE_BASE = 1
    SCOPE_ONELEVEL = 2
    SCOPE_SUBTREE = 4

    def __init__(self, ldapentry):
        """Initialize the results that we will return from get_entries"""
        self.results = ldapentry

    def get_entry(self, dn, attrs_list=None, time_limit=None,
                  size_limit=None, get_effective_rights=False):
        return []  # the call doesn't check the value


class mock_ldap_conn:
    def set_option(self, option, invalue):
        pass

    def get_option(self, option):
        if option == OPT_X_SASL_SSF_MIN:
            return 256

        return None

    def search_s(self, base, scope, filterstr=None,
                 attrlist=None, attrsonly=0):
        return tuple()


def make_stat(mode=33200, uid=0, gid=0):
    """Return a mocked-up stat.

       The default is:
            mode = 0660
            owner = root
            group = root

       Cheat sheet equivalents:
           0600 = 33152
           0640 = 33184
           0644 = 33188
           0660 = 33200
           0666 = 33206
    """
    # (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime)
    return posix.stat_result((mode, 1, 42, 1, uid, gid, 0, 1, 1, 1,))


def get_results(results, type):
    """Pull out the type of results I want to look at: owner, group or mode"""
    my_results = Results()
    for r in results.results:
        kw = r.kw
        if kw.get('type') != type:
            continue
        my_results.add(r)

    return my_results


@patch('os.stat')
def test_files_owner(mock_stat):
    """
    Test the file owner.

    Our mocked files want root, nobody, (root, nobody), (root, root).
    """
    f = FileCheck()
    f.files = files

    mock_stat.return_value = make_stat()
    results = capture_results(f)

    my_results = get_results(results, 'owner')
    assert my_results.results[0].result == constants.SUCCESS
    assert my_results.results[1].result == constants.WARNING
    assert my_results.results[2].result == constants.SUCCESS
    assert my_results.results[3].result == constants.SUCCESS

    mock_stat.return_value = make_stat(uid=nobody.pw_uid)
    results = capture_results(f)
    my_results = get_results(results, 'owner')
    assert my_results.results[0].result == constants.WARNING
    assert my_results.results[0].kw.get('got') == 'nobody'
    assert my_results.results[0].kw.get('expected') == 'root'
    assert my_results.results[0].kw.get('type') == 'owner'

    assert my_results.results[1].result == constants.SUCCESS
    assert my_results.results[2].result == constants.SUCCESS

    assert my_results.results[3].result == constants.WARNING
    assert my_results.results[3].kw.get('got') == 'nobody'
    assert my_results.results[3].kw.get('expected') == 'root,bin'
    assert my_results.results[3].kw.get('type') == 'owner'
    assert my_results.results[3].kw.get('msg') == \
        'Ownership of fiz is nobody and should be one of root,bin'

    assert my_results.results[4].result == constants.WARNING
    assert my_results.results[4].kw.get('got') == 'nobody'
    assert my_results.results[4].kw.get('expected') == 'root,bin'
    assert my_results.results[4].kw.get('type') == 'owner'


@patch('os.stat')
def test_files_group(mock_stat):
    """
    Test the file group.

    Our mocked files want root, nobody, (root, nobody), (root, root).
    """
    f = FileCheck()
    f.files = files

    mock_stat.return_value = make_stat()
    results = capture_results(f)

    my_results = get_results(results, 'group')
    assert my_results.results[0].result == constants.SUCCESS
    assert my_results.results[1].result == constants.WARNING
    assert my_results.results[2].result == constants.SUCCESS
    assert my_results.results[3].result == constants.SUCCESS

    mock_stat.return_value = make_stat(gid=nobody.pw_gid)
    results = capture_results(f)
    my_results = get_results(results, 'group')
    assert my_results.results[0].result == constants.WARNING
    assert my_results.results[0].kw.get('got') == 'nobody'
    assert my_results.results[0].kw.get('expected') == 'root'
    assert my_results.results[0].kw.get('type') == 'group'

    assert my_results.results[1].result == constants.SUCCESS
    assert my_results.results[2].result == constants.SUCCESS

    assert my_results.results[3].result == constants.WARNING
    assert my_results.results[3].kw.get('got') == 'nobody'
    assert my_results.results[3].kw.get('expected') == 'root,bin'
    assert my_results.results[3].kw.get('type') == 'group'
    assert my_results.results[3].kw.get('msg') == \
        'Group of fiz is nobody and should be one of root,bin'

    assert my_results.results[4].result == constants.WARNING
    assert my_results.results[4].kw.get('got') == 'nobody'
    assert my_results.results[4].kw.get('expected') == 'root,bin'
    assert my_results.results[4].kw.get('type') == 'group'


@patch('os.stat')
def test_files_mode(mock_stat):
    mock_stat.return_value = make_stat()

    f = FileCheck()
    f.files = files

    results = capture_results(f)

    my_results = get_results(results, 'mode')
    assert my_results.results[0].result == constants.SUCCESS
    assert my_results.results[1].result == constants.ERROR

    # Too restrictive
    mock_stat.return_value = make_stat(mode=33152)  # 0600
    results = capture_results(f)
    my_results = get_results(results, 'mode')
    assert my_results.results[0].result == constants.ERROR
    assert my_results.results[1].result == constants.ERROR
    assert my_results.results[2].result == constants.ERROR
    assert my_results.results[3].result == constants.ERROR
    assert my_results.results[4].result == constants.ERROR

    # Too permissive
    mock_stat.return_value = make_stat(mode=33206)  # 0666
    results = capture_results(f)
    my_results = get_results(results, 'mode')
    assert my_results.results[0].result == constants.WARNING
    assert my_results.results[1].result == constants.WARNING
    assert my_results.results[2].result == constants.WARNING
    assert my_results.results[3].result == constants.WARNING
    assert my_results.results[4].result == constants.WARNING

    # Too restrictive with allowed multi-mode value
    mock_stat.return_value = make_stat(mode=33184)  # 0640
    results = capture_results(f)
    my_results = get_results(results, 'mode')
    assert my_results.results[0].result == constants.ERROR
    assert my_results.results[1].result == constants.ERROR
    assert my_results.results[2].result == constants.ERROR
    assert my_results.results[3].result == constants.ERROR
    assert my_results.results[4].result == constants.SUCCESS


@patch('os.path.exists')
def test_files_not_found(mock_exists):
    mock_exists.return_value = False

    f = FileCheck()
    f.files = files

    results = capture_results(f)

    for type in ('mode', 'group', 'owner'):
        my_results = get_results(results, type)
        assert len(my_results.results) == len(f.files)
        for result in my_results.results:
            assert result.result == constants.SUCCESS
            assert result.kw.get('msg') == 'File does not exist'


@patch('os.stat')
@patch('pwd.getpwnam')
@patch('pwd.getpwuid')
def test_files_owner_not_found(mock_pwuid, mock_pwnam, mock_stat):
    mock_pwuid.side_effect = KeyError('getpwnam(): name not found')
    mock_pwnam.side_effect = KeyError('getpwuid(): uid not found')
    mock_stat.return_value = make_stat()

    f = FileCheck()
    f.files = files

    results = capture_results(f)

    my_results = get_results(results, 'owner')
    for result in my_results.results:
        assert result.result == constants.WARNING
        assert result.kw.get('got') == 'Unknown uid 0'


@patch('os.stat')
@patch('grp.getgrnam')
@patch('grp.getgrgid')
def test_files_group_not_found(mock_grgid, mock_grnam, mock_stat):
    mock_grgid.side_effect = KeyError('getgrnam(): name not found')
    mock_grnam.side_effect = KeyError('getgruid(): gid not found')
    mock_stat.return_value = make_stat()

    f = FileCheck()
    f.files = files

    results = capture_results(f)

    my_results = get_results(results, 'group')
    for result in my_results.results:
        assert result.result == constants.WARNING


def test_bad_modes():
    f = FileCheck()
    f.files = bad_modes

    results = capture_results(f)

    for result in results.results:
        assert result.result == constants.ERROR
        assert result.kw.get('msg') == 'Code format is incorrect for file'


@patch('ipaserver.install.krbinstance.is_pkinit_enabled')
def test_ipa_files_format(mock_pkinit):
    mock_pkinit.return_value = True

    fake_conn = LDAPClient('ldap://localhost', no_schema=True)
    ldapentry = LDAPEntry(fake_conn, DN(m_api.env.container_dns,
                          m_api.env.basedn))
    framework = object()
    registry.initialize(framework, config.Config)
    f = IPAFileCheck(registry)

    f.conn = mock_ldap(ldapentry)

    results = capture_results(f)

    for result in results.results:
        assert result.result == constants.SUCCESS
