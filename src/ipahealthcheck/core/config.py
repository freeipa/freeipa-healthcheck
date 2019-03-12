#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
from configparser import SafeConfigParser, ParsingError

from ipahealthcheck.core.constants import CONFIG_FILE, CONFIG_SECTION
from ipahealthcheck.core.constants import DEFAULT_CONFIG

logger = logging.getLogger()


class Config:
    """Helper class to manage configuration

       Let one treat config items as properties instead of using
       a dict. It just allows for an easier-to-read shorthand.
    """

    def __init__(self):
        self.__d = dict()

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

    def merge(self, d):
        """
        Merge variables from dict ``d`` into the configuration

        The last one wins.

        :param d: dict containing configuration
        """
        for key in d:
            self.__d[key] = d[key]


def read_config(config_file=CONFIG_FILE):
    """
    Simple configuration file reader

    Read and return the configuration for only the default section.

    Returns a dict on success, None on failure
    """
    config = Config()
    parser = SafeConfigParser()
    try:
        parser.read(config_file)
    except ParsingError as e:
        logging.error("Unable to parse {}: {}".format(config_file, e))
        return None
    if not parser.has_section(CONFIG_SECTION):
        logging.error("Config file {} missing {} section".format(
            config_file, CONFIG_SECTION))
        return None

    items = parser.items(CONFIG_SECTION)

    config.merge(DEFAULT_CONFIG)

    for (key, value) in items:
        config[key] = value

    return config
