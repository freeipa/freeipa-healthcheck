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


def getLevelName(level):
    """
    Translate a level constant to a textual level name.
    """
    name = _levelToName.get(level)
    if name is not None:
        return name
    else:
        return level


CONFIG_FILE = '/etc/ipahealthcheck/ipahealthcheck.conf'
CONFIG_SECTION = 'default'

DEFAULT_CONFIG = {
    'cert_expiration_days': 28,
}
