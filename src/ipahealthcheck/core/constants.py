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
    return _levelToName.get(level) or _nameToLevel.get(level) or level


CONFIG_FILE = '/etc/ipahealthcheck/ipahealthcheck.conf'
CONFIG_SECTION = 'default'

DEFAULT_CONFIG = {
    'cert_expiration_days': 28,
}
