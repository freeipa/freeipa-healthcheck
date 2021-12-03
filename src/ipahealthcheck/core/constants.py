#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

DEFAULT_OUTPUT = 'json'

# Error reporting result
SUCCESS = 0
WARNING = 10
ERROR = 20
CRITICAL = 30

_levelToName = {
    SUCCESS: 'SUCCESS',
    WARNING: 'WARNING',
    ERROR: 'ERROR',
    CRITICAL: 'CRITICAL',
}

_nameToLevel = {
    'SUCCESS': SUCCESS,
    'WARNING': WARNING,
    'ERROR': ERROR,
    'CRITICAL': CRITICAL,
}


def getLevelName(level):
    """
    Translate between level constants and their textual mappings.

    If the level is one of the predefined levels then returns the
    corresponding string.

    If a numeric value corresponding to one of the defined levels
    is passed in instead the corresponding string representation is
    returned.
    """
    name = _levelToName.get(level) or _nameToLevel.get(level)
    if name is not None:
        return name

    return level


def getLevel(name):
    """
    Translate between level text and their numeric constants

    If the level is one of the predefined levels then returns the
    corresponding number.
    """
    level = _nameToLevel.get(name)
    if level is not None:
        return level

    return name


CONFIG_FILE = '/etc/ipahealthcheck/ipahealthcheck.conf'
CONFIG_SECTION = 'default'

DEFAULT_TIMEOUT = 10

DEFAULT_CONFIG = {
    'cert_expiration_days': 28,
    'timeout': DEFAULT_TIMEOUT,
}
