#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import copy

from ipahealthcheck.core import constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.certs import IPACertTracking
from ipaplatform.paths import paths
from unittest.mock import patch

# Fake certmonger tracked request list. This is similar but can be
# distinct from the value from the overrident get_defaults() method.
template = paths.CERTMONGER_COMMAND_TEMPLATE
cm_requests = [
    {
        'nickname': '1234',
        'cert-file': paths.RA_AGENT_PEM,
        'key-file': paths.RA_AGENT_KEY,
        'ca-name': 'dogtag-ipa-ca-renew-agent',
        'cert-presave-command': template % 'renew_ra_cert_pre',
        'cert-postsave-command': template % 'renew_ra_cert',
    },
    {
        'nickname': '5678',
        'cert-file': paths.HTTPD_CERT_FILE,
        'key-file': paths.HTTPD_KEY_FILE,
        'ca-name': 'IPA',
        'cert-postsave-command': template % 'restart_httpd',
    },
]


class mock_property:
    def __init__(self, index):
        self.index = index

    def Get(self, object_path, name):
        """Always return a match"""
        if self.index is None:
            return None
        return cm_requests[self.index].get(name)


class mock_dbus:
    """Create a fake dbus representation of a tracked certificate

       The index is used to look up values within the cm_requests
       list of known tracked certificates.
    """
    def __init__(self, request_id):
        self.index = None
        for i in range(len(cm_requests)):
            if request_id == cm_requests[i].get('nickname'):
                self.index = i
                break
        self.prop_if = mock_property(self.index)
        self.obj_if = mock_obj_if(self.index)


class mock_obj_if:
    def __init__(self, index):
        self.index = index

    def find_request_by_nickname(self, nickname):
        return None

    def get_requests(self):
        """Return list of request ids that dbus would have returned"""
        return [n.get('nickname') for n in cm_requests]

    def get_nickname(self):
        """Retrieve the certmonger CA nickname"""
        if self.index is None:
            return None
        return cm_requests[self.index].get('ca-name')

    def get_ca(self):
        """Return the CA name for the current request"""
        return cm_requests[self.index].get('nickname')


class _certmonger():
    """An empty object, not needed directly for testing

       Needed to keep the real certmonger from blowing up.
    """
    def __init__(self):
        self.obj_if = mock_obj_if(None)
        self.bus = None


def create_mock_dbus(bus, parent, object_path, object_dbus_interface,
                     parent_dbus_interface=None, property_interface=False):
    """Create a fake dbus object for a given path (request_id)"""
    return mock_dbus(object_path)


def get_requests():
    """The list of requests known by the IPACertCheck plugin

       The list is copied and the nickname popped off to match the
       format that the check uses.

       nickname has two meanings in certmonger: the request id and
       the NSS nickname.
    """
    requests = copy.deepcopy(cm_requests)
    for request in requests:
        try:
            request.pop('nickname')
        except KeyError:
            pass

    return requests


@patch('ipahealthcheck.ipa.certs.get_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
def test_known_cert_tracking(mock_certmonger,
                             mock_cm_dbus_object,
                             mock_get_requests):
    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_requests.return_value = get_requests()

    framework = object()
    registry.initialize(framework)
    f = IPACertTracking(registry)

    results = f.check()

    assert len(results) == 0


@patch('ipahealthcheck.ipa.certs.get_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
def test_missing_cert_tracking(mock_certmonger,
                               mock_cm_dbus_object,
                               mock_get_requests):
    global cm_requests

    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_requests.return_value = get_requests()

    orig_requests = copy.deepcopy(cm_requests)
    cm_requests.remove(cm_requests[0])

    framework = object()
    registry.initialize(framework)
    f = IPACertTracking(registry)

    results = f.check()

    assert len(results) == 1

    result = results.results[0]
    assert result.severity == constants.ERROR
    assert result.source == 'ipahealthcheck.ipa.certs'
    assert result.check == 'IPACertTracking'
    assert result.kw.get('msg') == "Missing tracking for {" \
        "'cert-file': '/var/lib/ipa/ra-agent.pem', " \
        "'key-file': '/var/lib/ipa/ra-agent.key', " \
        "'ca-name': 'dogtag-ipa-ca-renew-agent', " \
        "'cert-presave-command': " \
        "'/usr/libexec/ipa/certmonger/renew_ra_cert_pre', " \
        "'cert-postsave-command': '/usr/libexec/ipa/certmonger/renew_ra_cert'}"

    cm_requests = orig_requests


@patch('ipahealthcheck.ipa.certs.get_requests')
@patch('ipalib.install.certmonger._cm_dbus_object')
@patch('ipalib.install.certmonger._certmonger')
def test_unknown_cert_tracking(mock_certmonger,
                               mock_cm_dbus_object,
                               mock_get_requests):
    global cm_requests
    unknown = {
        'nickname': '7777',
        'cert-file': '/tmp/test.crt',
        'key-file': '/tmp/test.key',
        'ca-name': 'IPA',
    }
    mock_cm_dbus_object.side_effect = create_mock_dbus
    mock_certmonger.return_value = _certmonger()
    mock_get_requests.return_value = get_requests()

    orig_requests = copy.deepcopy(cm_requests)
    cm_requests.append(unknown)

    framework = object()
    registry.initialize(framework)
    f = IPACertTracking(registry)

    results = f.check()

    assert len(results) == 1

    result = results.results[0]
    assert result.severity == constants.WARNING
    assert result.source == 'ipahealthcheck.ipa.certs'
    assert result.check == 'IPACertTracking'
    assert result.kw.get('msg') == 'Unknown certmonger id 7777'

    cm_requests = orig_requests
