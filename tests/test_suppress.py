#
# Copyright (C) 2022 FreeIPA Contributors see COPYING for license
#

import argparse
import os
import tempfile
from unittest.mock import patch

from ipahealthcheck.core import constants
from ipahealthcheck.core.core import RunChecks
from ipahealthcheck.core.plugin import Result, Results, Plugin, duration

from ipahealthcheck.system.plugin import Registry

from ipahealthcheck.core.output import output_registry, Output

options = argparse.Namespace(check=None, source=None, debug=False,
                             indent=2, list_sources=False,
                             output_type='suppresstest', output_file=None,
                             verbose=False, version=False, config=None)

outputdata = None


@output_registry
class SuppressTest(Output):
    """Test suppression"""
    options = ()

    def generate(self, data):
        global outputdata

        outputdata = data


class UserPlugin(Plugin):
    pass


class UserRegistry(Registry):
    def initialize(self, framework, config, options=None):
        pass


registry = UserRegistry()


@registry
class PluginOne(UserPlugin):
    @duration
    def check(self):
        yield Result(self, constants.ERROR, key="test1", msg="test1")


@registry
class PluginTwo(UserPlugin):
    @duration
    def check(self):
        yield Result(self, constants.ERROR, key="test2", msg="test2")


@patch('ipahealthcheck.core.core.run_service_plugins')
@patch('ipahealthcheck.core.core.parse_options')
@patch('ipahealthcheck.core.core.find_registries')
def test_suppress_none(mock_find, mock_parse, mock_service):
    """
    Test suppressing plugins
    """
    global outputdata
    mock_service.return_value = (Results(), [])
    mock_parse.return_value = options
    mock_find.return_value = {'test': registry}

    outputdata = None

    fd, config_path = tempfile.mkstemp()
    os.close(fd)
    with open(config_path, "w") as fd:
        fd.write('[default]\n')

    try:
        run = RunChecks(['test'], config_path)

        run.run_healthcheck()
        assert len(outputdata) == 2
    finally:
        os.remove(config_path)


@patch('ipahealthcheck.core.core.run_service_plugins')
@patch('ipahealthcheck.core.core.parse_options')
@patch('ipahealthcheck.core.core.find_registries')
def test_suppress_source(mock_find, mock_parse, mock_service):
    """
    Test suppressing plugins
    """
    global outputdata
    mock_service.return_value = (Results(), [])
    mock_parse.return_value = options
    mock_find.return_value = {'test': registry}

    outputdata = None

    fd, config_path = tempfile.mkstemp()
    os.close(fd)
    with open(config_path, "w") as fd:
        fd.write('[default]\n')
        fd.write('[excludes]\n')
        fd.write('source=test_suppress\n')

    try:
        run = RunChecks(['test'], config_path)

        run.run_healthcheck()
        assert len(outputdata) == 0
    finally:
        os.remove(config_path)


@patch('ipahealthcheck.core.core.run_service_plugins')
@patch('ipahealthcheck.core.core.parse_options')
@patch('ipahealthcheck.core.core.find_registries')
def test_suppress_check(mock_find, mock_parse, mock_service):
    """
    Test suppressing plugins
    """
    global outputdata
    mock_service.return_value = (Results(), [])
    mock_parse.return_value = options
    mock_find.return_value = {'test': registry}

    outputdata = None

    fd, config_path = tempfile.mkstemp()
    os.close(fd)
    with open(config_path, "w") as fd:
        fd.write('[default]\n')
        fd.write('[excludes]\n')
        fd.write('check=PluginOne\n')

    try:
        run = RunChecks(['test'], config_path)

        run.run_healthcheck()

        assert len(outputdata) == 1
        assert outputdata[0].get('check') == 'PluginTwo'
    finally:
        os.remove(config_path)


@patch('ipahealthcheck.core.core.run_service_plugins')
@patch('ipahealthcheck.core.core.parse_options')
@patch('ipahealthcheck.core.core.find_registries')
def test_suppress_key(mock_find, mock_parse, mock_service):
    """
    Test suppressing plugins
    """
    global outputdata
    mock_service.return_value = (Results(), [])
    mock_parse.return_value = options
    mock_find.return_value = {'test': registry}

    outputdata = None

    fd, config_path = tempfile.mkstemp()
    os.close(fd)
    with open(config_path, "w") as fd:
        fd.write('[default]\n')
        fd.write('[excludes]\n')
        fd.write('key=test2\n')

    try:
        run = RunChecks(['test'], config_path)

        run.run_healthcheck()

        assert len(outputdata) == 1
        assert outputdata[0].get('check') == 'PluginOne'
        assert outputdata[0].get('kw').get('msg') == 'test1'
    finally:
        os.remove(config_path)
