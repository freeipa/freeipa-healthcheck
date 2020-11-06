#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
import os
from configparser import ConfigParser, ParsingError

from ipahealthcheck.core.constants import CONFIG_SECTION
from ipahealthcheck.core.constants import DEFAULT_CONFIG

logger = logging.getLogger()


class Config:
    """Helper class to manage configuration

       Let one treat config items as properties instead of using
       a dict. It just allows for an easier-to-read shorthand.

       >>> config = Config()
       >>> config.foo = 'bar'
       >>> config.foo
       'bar'

       Return a list of the configuration option keys.

       >>> list(config)
       ['foo']
    """

    def __init__(self):
        object.__setattr__(self, '_Config__d', {})

    def __setattr__(self, key, value):
        """
        Set the attribute named ``name`` to ``value``.
        """

        self[key] = value

    def __setitem__(self, key, value):
        """
        Set ``key`` to ``value``.
        """
        object.__setattr__(self, key, value)
        self.__d[key] = value

    def __getattr__(self, key):
        """
        Return the value corresponding to ``key``.
        """
        return self.__d[key]

    def __iter__(self):
        """
        Iterate through keys in ascending order.
        """
        for key in sorted(self.__d):
            yield key

    def merge(self, d):
        """
        Merge variables from dict ``d`` into the configuration

        The last one wins.

        :param d: dict containing configuration
        """
        for key in d:
            self.__d[key] = d[key]


def read_config(config_file):
    """
    Simple configuration file reader

    Read and return the configuration for only the default section.

    Returns a dict on success, None on failure
    """
    config = Config()
    config.merge(DEFAULT_CONFIG)
    if not os.path.exists(config_file):
        logging.warning(
            "config file %s does not exist, using defaults", config_file
        )
        return config

    parser = ConfigParser()
    try:
        parser.read(config_file)
    except ParsingError as e:
        logging.error("Unable to parse %s: %s", config_file, e)
        return None
    if not parser.has_section(CONFIG_SECTION):
        logging.error(
            "Config file %s missing %s section", config_file, CONFIG_SECTION
        )
        return None

    items = parser.items(CONFIG_SECTION)

    for (key, value) in items:
        config[key] = value

    return config
