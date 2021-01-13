#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import pwd
import posix
from ipahealthcheck.core.files import FileCheck
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Results
from unittest.mock import patch

from tests.util import capture_results

nobody = pwd.getpwnam('nobody')

# Mock files to test
files = (('foo', 'root', 'root', '0660'),
         ('bar', 'nobody', 'nobody', '0664'),
         ('baz', ('root', 'nobody'), ('root', 'nobody'), '0664'),
         ('fiz', ('root', 'bin'), ('root', 'bin'), '0664'),)


def make_stat(mode=33200, uid=0, gid=0):
    """Return a mocked-up stat.

       The default is:
            mode = 0660
            owner = root
            group = root
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
    assert my_results.results[1].result == constants.SUCCESS
    assert my_results.results[2].result == constants.SUCCESS
    assert my_results.results[3].result == constants.WARNING
    assert my_results.results[3].kw.get('msg') == \
        'Ownership of fiz is nobody and should be one of root,bin'


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
    assert my_results.results[1].result == constants.SUCCESS
    assert my_results.results[2].result == constants.SUCCESS
    assert my_results.results[3].result == constants.WARNING
    assert my_results.results[3].kw.get('msg') == \
        'Group of fiz is nobody and should be one of root,bin'


@patch('os.stat')
def test_files_mode(mock_stat):
    mock_stat.return_value = make_stat()

    f = FileCheck()
    f.files = files

    results = capture_results(f)

    my_results = get_results(results, 'mode')
    assert my_results.results[0].result == constants.SUCCESS
    assert my_results.results[1].result == constants.ERROR

    mock_stat.return_value = make_stat(mode=33152)
    results = capture_results(f)
    my_results = get_results(results, 'mode')
    assert my_results.results[0].result == constants.ERROR
    assert my_results.results[1].result == constants.ERROR

    mock_stat.return_value = make_stat(mode=33206)
    results = capture_results(f)
    my_results = get_results(results, 'mode')
    assert my_results.results[0].result == constants.WARNING
    assert my_results.results[1].result == constants.WARNING
