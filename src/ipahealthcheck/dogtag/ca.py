#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging

from ipahealthcheck.dogtag.plugin import DogtagPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

from ipalib import api, errors, x509
from ipaplatform.paths import paths
from ipaserver.install import certs
from ipaserver.install import krainstance
from ipapython.directivesetter import get_directive
from cryptography.hazmat.primitives.serialization import Encoding

import pki.util

logger = logging.getLogger()


@registry
class DogtagCertsConfigCheck(DogtagPlugin):
    """
    Compare the cert blob in the NSS database to that stored in CS.cfg
    """
    @duration
    def check(self):
        if not self.ca.is_configured():
            logger.debug("No CA configured, skipping dogtag config check")
            return

        pki_version = pki.util.Version(pki.specification_version())
        if pki_version >= pki.util.Version("11.5.0"):
            logger.debug(
                "PKI 11.5.0 no longer stores certificats in CS.cfg"
            )
            return

        kra = krainstance.KRAInstance(api.env.realm)

        blobs = {'auditSigningCert cert-pki-ca': 'ca.audit_signing.cert',
                 'ocspSigningCert cert-pki-ca': 'ca.ocsp_signing.cert',
                 'caSigningCert cert-pki-ca': 'ca.signing.cert',
                 'subsystemCert cert-pki-ca': 'ca.subsystem.cert',
                 'Server-Cert cert-pki-ca': 'ca.sslserver.cert'}

        # Nicknames to skip because their certs are not in CS.cfg
        skip = []

        if kra.is_installed():
            kra_blobs = {
                'transportCert cert-pki-kra':
                'ca.connector.KRA.transportCert',
            }
            blobs.update(kra_blobs)
            skip.append('storageCert cert-pki-kra')
            skip.append('auditSigningCert cert-pki-kra')

        db = certs.CertDB(api.env.realm, paths.PKI_TOMCAT_ALIAS_DIR)
        for nickname, _trust_flags in db.list_certs():
            if nickname in skip:
                logger.debug('Skipping nickname %s because it isn\'t in '
                             'the configuration file')
                continue
            try:
                val = get_directive(paths.CA_CS_CFG_PATH,
                                    blobs[nickname], '=')
            except KeyError:
                logger.debug("%s not found, assuming 3rd party", nickname)
                continue
            if val is None:
                yield Result(self, constants.ERROR,
                             key=nickname,
                             configfile=paths.CA_CS_CFG_PATH,
                             msg='Certificate %s not found in %s' %
                             (blobs[nickname], paths.CA_CS_CFG_PATH))
                continue
            cert = db.get_cert_from_db(nickname)
            pem = cert.public_bytes(Encoding.PEM).decode()
            pem = pem.replace('\n', '')
            pem = pem.replace('-----BEGIN CERTIFICATE-----', '')
            pem = pem.replace('-----END CERTIFICATE-----', '')

            if pem.strip() != val:
                yield Result(self, constants.ERROR,
                             key=nickname,
                             directive=blobs[nickname],
                             configfile=paths.CA_CS_CFG_PATH,
                             msg='Certificate \'%s\' does not match the value '
                             'of %s in %s' %
                             (nickname, blobs[nickname], paths.CA_CS_CFG_PATH))
            else:
                yield Result(self, constants.SUCCESS,
                             key=nickname,
                             configfile=paths.CA_CS_CFG_PATH)


@registry
class DogtagCertsConnectivityCheck(DogtagPlugin):
    """
    Test basic connectivity by using cert-show to fetch a cert

    The RA agent certificate is used because if a CA is configured we
    know this certificate should exist. Use its serial number to do
    the lookup.
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        if not self.ca.is_configured():
            logger.debug('CA is not configured, skipping connectivity check')
            return

        try:
            cert = x509.load_certificate_from_file(paths.RA_AGENT_PEM)
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='ipa_ra_crt_file_missing',
                         path=paths.RA_AGENT_PEM,
                         error=str(e),
                         msg='The IPA RA cert file {path} could not be '
                             'opened: {error}')
            return

        # We used to use serial #1 but with RSNv3 it can be anything.
        try:
            api.Command.cert_show(cert.serial_number, all=True)
        except errors.CertificateOperationError as e:
            if 'not found' in str(e):
                yield Result(self, constants.ERROR,
                             key='cert_show_ra',
                             error=str(e),
                             serial=str(cert.serial_number),
                             msg='Serial number not found: {error}')
            else:
                yield Result(self, constants.ERROR,
                             key='cert_show_ra',
                             error=str(e),
                             serial=str(cert.serial_number),
                             msg='Request for certificate failed: {error}')
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='cert_show_ra',
                             error=str(e),
                         serial=str(cert.serial_number),
                         msg='Request for certificate failed: {error}')
        else:
            yield Result(self, constants.SUCCESS)
