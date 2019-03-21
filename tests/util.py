#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.plugin import Results


class ExceptionNotRaised(Exception):
    """
    Exception raised when an *expected* exception is *not* raised during a
    unit test.
    """
    msg = 'expected %s'

    def __init__(self, expected):
        self.expected = expected

    def __str__(self):
        return self.msg % self.expected.__name__


def raises(exception, callback, *args, **kw):
    """
    Tests that the expected exception is raised; raises ExceptionNotRaised
    if test fails.
    """
    try:
        callback(*args, **kw)
    except exception as e:
        return e
    raise ExceptionNotRaised(exception)


def capture_results(f):
    """
    Loop over check() and collect the results.
    """
    results = Results()
    for result in f.check():
        if result is not None:
            results.add(result)

    return results


class CAInstance:
    """A bare-bones CAinistance override

       This is needed to control whether the underlying master is
       CAless or CAful.
    """
    def __init__(self, enabled=True):
        self.enabled = enabled

    def is_configured(self):
        return self.enabled
