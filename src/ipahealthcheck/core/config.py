#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
import os
from configparser import ConfigParser, ParsingError
from collections import OrderedDict

from ipahealthcheck.core.constants import CONFIG_SECTION, EXCLUDE_SECTION
from ipahealthcheck.core.constants import DEFAULT_CONFIG

logger = logging.getLogger()


class DuplicateOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        """Duplicate keys will be concatenated strings separated by new-line"""
        if isinstance(value, list) and key in self:
            self[key].extend(value)
        else:
            super().__setitem__(key, value)


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

    def __getitem__(self, key):
        """
        Return the value corresponding to ``key``.
        """
        return self.__d[key]

    def __contains__(self, key):
        """
        Return True if instance contains ``key``; otherwise return False.
        """
        return key in self.__d

    def __iter__(self):
        """
        Iterate through keys in ascending order.
        """
        for key in sorted(self.__d):
            yield key

    def merge(self, d):
        """
        Merge variables from dict ``d`` into the configuration

        The first one wins.

        :param d: dict containing configuration
        """
        for key in d:
            self.__d[key] = d[key]


def convert_string(value):
    """
    Reading options from the configuration file will leave them as
    strings. This breaks boolean values so attempt to convert them.
    """
    if not isinstance(value, str):
        return value

    if value.lower() in (
        "true",
        "false",
    ):
        return value.lower() == 'true'
    else:
        try:
            value = int(value)
        except ValueError:
            pass
    return value


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

    parser = ConfigParser(dict_type=DuplicateOrderedDict, strict=False,
                          delimiters='=')
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
        if not key.startswith('excludes_'):
            if len(value) == 0 or value is None:
                logging.error(
                    "Empty value for %s in %s [%s]",
                    key, config_file, CONFIG_SECTION
                )
                return None
            else:
                # Try to do some basic validation. This is unfortunately
                # hardcoded.
                if key in ('all', 'debug', 'failures_only', 'verbose'):
                    if value.lower() not in ('true', 'false'):
                        logging.error(
                            "%s is not a valid boolean in %s [%s]",
                            key, config_file, CONFIG_SECTION
                        )
                        return None
                elif key in ('indent', 'timeout'):
                    if not isinstance(convert_string(value), int):
                        logging.error(
                            "%s is not a valid integer in %s [%s]",
                            key, config_file, CONFIG_SECTION
                        )
                        return None
                # Some rough type translation from strings
                config[key] = convert_string(value)

    if parser.has_section(EXCLUDE_SECTION):
        items = parser.items(EXCLUDE_SECTION)
        for (key, value) in items:
            config[EXCLUDE_SECTION + '_' + key] = value.split(os.linesep)

    return config
