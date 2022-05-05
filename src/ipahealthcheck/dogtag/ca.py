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
from ipaserver.install import ca
from ipaserver.install import krainstance
from ipapython.directivesetter import get_directive
from ipapython.dn import DN
from cryptography.hazmat.primitives.serialization import Encoding

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
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        if not self.ca.is_configured():
            logger.debug('CA is not configured, skipping connectivity check')
            return

        config = api.Command.config_show()

        subject_base = config['result']['ipacertificatesubjectbase'][0]
        ipa_subject = ca.lookup_ca_subject(api, subject_base)
        try:
            certs = x509.load_certificate_list_from_file(paths.IPA_CA_CRT)
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='ipa_ca_crt_file_missing',
                         path=paths.IPA_CA_CRT,
                         error=str(e),
                         msg='The IPA CA cert file {path} could not be '
                             'opened: {error}')
            return

        found = False
        for cert in certs:
            if DN(cert.subject) == ipa_subject:
                found = True
                break

        if not found:
            yield Result(self, constants.ERROR,
                         key='ipa_ca_cert_not_found',
                         subject=str(ipa_subject),
                         path=paths.IPA_CA_CRT,
                         msg='The CA certificate with subject {subject} '
                             'was not found in {path}')
            return
        # Load the IPA CA certificate to obtain its serial number. This
        # was traditionally 1 prior to random serial number support.
        # There is nothing special about cert 1. Even if there is no cert
        # serial number 1 but the connection is ok it is considered passing.
        try:
            api.Command.cert_show(cert.serial_number, all=True)
        except errors.CertificateOperationError as e:
            if 'not found' in str(e):
                yield Result(self, constants.ERROR,
                             key='cert_show_1',
                             error=str(e),
                             serial=str(cert.serial_number),
                             msg='Serial number not found: {error}')
            else:
                yield Result(self, constants.ERROR,
                             key='cert_show_1',
                             error=str(e),
                             serial=str(cert.serial_number),
                             msg='Request for certificate failed: {error}')
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='cert_show_1',
                             error=str(e),
                         serial=str(cert.serial_number),
                         msg='Request for certificate failed: {error')
        else:
            yield Result(self, constants.SUCCESS)
