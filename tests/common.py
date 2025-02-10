#
# Copyright (C) 2025 FreeIPA Contributors see COPYING for license
#
from datetime import datetime, timedelta, timezone


class mock_Cert:
    """Fake up a certificate.

    The contents are the NSS nickname of the certificate.
    """

    def __init__(
        self,
        text,
        issuer="CN=Someone",
        not_after=datetime.now(tz=timezone.utc),
    ):
        self.text = text
        self._issuer = issuer
        self._not_valid_after_utc = not_after

    def public_bytes(self, encoding):
        return self.text.encode("utf-8")

    @property
    def issuer(self):
        return self._issuer

    @property
    def not_valid_after_utc(self):
        return self._not_valid_after_utc


class mock_CertDB:
    def __init__(self, trust, expiration_days=0):
        """A dict of nickname + NSSdb trust flags"""
        self.trust = trust
        self._expiration_days = expiration_days

    def list_certs(self):
        return [
            (nickname, self.trust[nickname]) for nickname in self.trust
        ]

    def get_cert_from_db(self, nickname):
        """Return the nickname. This will match the value of get_directive"""
        notafter = datetime.now(tz=timezone.utc) + timedelta(
            days=self._expiration_days
        )
        return mock_Cert(nickname, not_after=notafter)


class mock_NSSDatabase:
    def __init__(self, nssdir, token=None, pwd_file=None, trust=None):
        self.trust = trust
        self.token = token

    def list_certs(self):
        return [
            (nickname, self.trust[nickname]) for nickname in self.trust
        ]


def my_unparse_trust_flags(trust_flags):
    return trust_flags


class DsInstance:
    def get_server_cert_nickname(self, serverid):
        return "Server-Cert"
