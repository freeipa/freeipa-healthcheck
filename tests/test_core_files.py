#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import pwd
import posix
from ipahealthcheck.core.files import FileCheck
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Results
from unittest.mock import patch

nobody = pwd.getpwnam('nobody')

# Mock files to test
files = (('foo', 'root', 'root', '0660'),
         ('bar', 'nobody', 'nobody', '0664'),)


def make_stat(mode=33200, uid=0, gid=0):
    """Return a mocked-up stat.

       The default is:
            mode = 0660
            owner = root
            group = root
    """
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
    mock_stat.return_value = make_stat()

    f = FileCheck()
    f.files = files

    results = f.check()

    my_results = get_results(results, 'owner')
    assert my_results.results[0].severity == constants.SUCCESS
    assert my_results.results[1].severity == constants.WARNING

    mock_stat.return_value = make_stat(uid=nobody.pw_uid)
    results = f.check()
    my_results = get_results(results, 'owner')
    assert my_results.results[0].severity == constants.WARNING
    assert my_results.results[1].severity == constants.SUCCESS


@patch('os.stat')
def test_files_group(mock_stat):
    mock_stat.return_value = make_stat()

    f = FileCheck()
    f.files = files

    results = f.check()

    my_results = get_results(results, 'group')
    assert my_results.results[0].severity == constants.SUCCESS
    assert my_results.results[1].severity == constants.WARNING

    mock_stat.return_value = make_stat(gid=nobody.pw_gid)
    results = f.check()
    my_results = get_results(results, 'group')
    assert my_results.results[0].severity == constants.WARNING
    assert my_results.results[1].severity == constants.SUCCESS


@patch('os.stat')
def test_files_mode(mock_stat):
    mock_stat.return_value = make_stat()

    f = FileCheck()
    f.files = files

    results = f.check()

    my_results = get_results(results, 'mode')
    assert my_results.results[0].severity == constants.SUCCESS
    assert my_results.results[1].severity == constants.WARNING

    mock_stat.return_value = make_stat(mode=33204)
    results = f.check()
    my_results = get_results(results, 'mode')
    assert my_results.results[0].severity == constants.WARNING
    assert my_results.results[1].severity == constants.SUCCESS
