#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import copy
from datetime import datetime, timedelta, timezone

from ipaplatform.paths import paths

# Fake certmonger tracked request list. This is similar but can be
# distinct from the value from the overrident get_defaults() method.
template = paths.CERTMONGER_COMMAND_TEMPLATE

CERT_EXPIRATION_DAYS = 30

pristine_cm_requests = [
    {
        'nickname': '1234',
        'cert-file': paths.RA_AGENT_PEM,
        'key-file': paths.RA_AGENT_KEY,
        'ca-name': 'dogtag-ipa-ca-renew-agent',
        'template_profile': 'caSubsystemCert',
        'cert-storage': 'FILE',
        'cert-presave-command': template % 'renew_ra_cert_pre',
        'cert-postsave-command': template % 'renew_ra_cert',
        'not-valid-after': (
            int(
                datetime(1970, 1, 1, 0, 17, 4, tzinfo=timezone.utc).timestamp()
            )
        ),
    },
    {
        'nickname': '5678',
        'cert-file': paths.HTTPD_CERT_FILE,
        'key-file': paths.HTTPD_KEY_FILE,
        'ca-name': 'IPA',
        'template_profile': 'caIPAserviceCert',
        'cert-storage': 'FILE',
        'cert-postsave-command': template % 'restart_httpd',
        'not-valid-after': (
            int(
                (
                    datetime.now(timezone.utc) +
                    timedelta(days=CERT_EXPIRATION_DAYS + 1)
                ).timestamp()
            )
        ),
    },
]


class dbus_results:
    """Class to manage the results returned by dbus"""
    def __init__(self):
        self.requests = copy.deepcopy(pristine_cm_requests)

    def __iter__(self):
        for entry in self.requests:
            yield entry

    def __len__(self):
        return len(self.requests)

    def __getitem__(self, index):
        return self.requests[index]

    def append(self, entry):
        self.requests.append(entry)

    def remove(self, index):
        self.requests.remove(self.requests[index])

    def __repr__(self):
        return repr(self.requests)


cm_requests = []


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
        for i, cm_request in enumerate(cm_requests):
            if request_id == cm_request.get('nickname'):
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


class _certmonger:
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


def get_expected_requests():
    """The list of requests known by the IPACertCheck plugin

       The list is copied and the nickname popped off to match the
       format that the check uses.

       nickname has two meanings in certmonger: the request id and
       the NSS nickname.
    """
    requests = copy.deepcopy(pristine_cm_requests)
    for request in requests:
        try:
            request.pop('nickname')
            request.pop('not-valid-after')
        except KeyError:
            pass

    return requests


def set_requests(add=None, remove=None):
    """Set the list of requests within a test"""
    global cm_requests
    cm_requests = dbus_results()
    if add is not None:
        cm_requests.append(add)
    if remove is not None:
        cm_requests.remove(remove)
