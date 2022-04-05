#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import pwd
import posix
from ipahealthcheck.core.files import FileCheck
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Results
from unittest.mock import patch

from util import capture_results

nobody = pwd.getpwnam('nobody')

# Mock files to test
files = (('foo', 'root', 'root', '0660'),
         ('bar', 'nobody', 'nobody', '0664'),
         ('baz', ('root', 'nobody'), ('root', 'nobody'), '0664'),
         ('fiz', ('root', 'bin'), ('root', 'bin'), '0664'),
         ('zap', ('root', 'bin'), ('root', 'bin'), ('0664', '0640'),))


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
