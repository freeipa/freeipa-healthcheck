#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
import os
from configparser import SafeConfigParser, ParsingError

from ipahealthcheck.core.constants import CONFIG_FILE, CONFIG_SECTION
from ipahealthcheck.core.constants import DEFAULT_CONFIG

logger = logging.getLogger()


def read_config(config_file=CONFIG_FILE):
    """
    Simple configuration file reader

    Read and return the configuration for only the default section.

    Returns a dict on success, None on failure
    """
    config = dict()
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

    for c in DEFAULT_CONFIG:
        config[c] = DEFAULT_CONFIG[c]

    for (key, value) in items:
        config[key] = value

    return config
