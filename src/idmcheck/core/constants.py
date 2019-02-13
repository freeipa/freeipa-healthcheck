# Error reporting severity
SUCCESS = 0
CRITICAL = 1
ERROR = 2
WARNING = 4

_levelToName = {
    SUCCESS: 'SUCCESS',
    CRITICAL: 'CRITICAL',
    ERROR: 'ERROR',
    WARNING: 'WARNING',
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
