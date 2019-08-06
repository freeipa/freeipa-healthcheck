#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.plugin import Results
from unittest.mock import patch, Mock
import ipalib
from ipapython.dn import DN


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
    def __init__(self, enabled=True, crlgen=True):
        self.enabled = enabled
        self.crlgen = crlgen

    def is_configured(self):
        return self.enabled

    def is_crlgen_enabled(self):
        return self.crlgen


class KRAInstance:
    """A bare-bones KRAinistance override

       This is needed to control whether the underlying master is
       has a KRA installed or not.
    """
    def __init__(self, installed=True):
        self.installed = installed

    def is_installed(self):
        return self.installed


class ServiceBasedRole:
    """A bare-bones role override

       This is just enough to satisfy the initialization code so
       the AD Trust status can be determined. It will always default
       to false and the registry should be overridden directly in the
       test cases.
    """
    def __init__(self, attr_name=None, name=None, component_services=None):
        pass

    def status(self, api_instance, server=None, attrs_list=("*",)):
        return [dict()]


class ADtrustBasedRole(ServiceBasedRole):
    """A bare-bones role override

       This is just enough to satisfy the initialization code so
       the AD Trust status can be determined. It will always default
       to false and the registry should be overridden directly in the
       test cases.
    """
    def __init__(self, attr_name=None, name=None):
        pass


# Mock api. This file needs to be imported before anything that would
# import ipalib.api in order for it to be replaced properly.

p_api = patch('ipalib.api', autospec=ipalib.api)
m_api = p_api.start()
m_api.isdone.return_value = True
m_api.env = Mock()
m_api.env.host = 'server.ipa.example'
m_api.env.server = 'server.ipa.example'
m_api.env.realm = u'IPA.EXAMPLE'
m_api.env.domain = u'ipa.example'
m_api.env.basedn = u'dc=ipa,dc=example'
m_api.env.container_group = DN(('cn', 'groups'), ('cn', 'accounts'))
m_api.env.container_host = DN(('cn', 'computers'), ('cn', 'accounts'))
m_api.env.container_sysaccounts = DN(('cn', 'sysaccounts'), ('cn', 'etc'))
m_api.env.container_service = DN(('cn', 'services'), ('cn', 'accounts'))
m_api.env.container_masters = DN(('cn', 'masters'))
m_api.Backend = Mock()
m_api.Command = Mock()
m_api.Command.ping.return_value = {
    u'summary': u'IPA server version 4.4.3. API version 2.215',
}


def no_exceptions(results):
    """Given Results ensure that an except was not raised"""
    for result in results.results:
        assert 'exception' not in result.kw
