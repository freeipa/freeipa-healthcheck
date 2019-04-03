#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.plugin import Results
from unittest.mock import patch, Mock
import ipalib


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


class KRAInstance:
    """A bare-bones KRAinistance override

       This is needed to control whether the underlying master is
       has a KRA installed or not.
    """
    def __init__(self, installed=True):
        self.installed = installed

    def is_installed(self):
        return self.installed


# Mock api. This file needs to be imported before anything that would
# import ipalib.api in order for it to be replaced properly.

p_api = patch('ipalib.api', autospec=ipalib.api)
m_api = p_api.start()
m_api.isdone.return_value = False
m_api.env = Mock()
m_api.env.server = 'server.ipa.example'
m_api.env.realm = u'IPA.EXAMPLE'
m_api.env.domain = u'dc=ipa,dc=example'
m_api.Backend = Mock()
m_api.Command = Mock()
m_api.Command.ping.return_value = {
    u'summary': u'IPA server version 4.4.3. API version 2.215',
}


def no_exceptions(results):
    """Given Results ensure that an except was not raised"""
    for result in results.results:
        assert 'exception' not in result.kw
