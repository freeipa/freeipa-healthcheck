#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import datetime
import logging
import os
import tempfile

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result, Results
from ipahealthcheck.core import constants

from ipalib import api
from ipalib import x509
from ipalib.install import certmonger
from ipaplatform.paths import paths
from ipaserver.install import certs
from ipaserver.install import dsinstance
from ipaserver.install import installutils
from ipapython import certdb
from ipapython import ipautil


logger = logging.getLogger()
DAY = 60 * 60 * 24


def get_requests(ca, ds, serverid):
    """Provide the expected certmonger tracking request data

      :param ca: the CAInstance
      :param ds: the DSInstance
      :param serverid: the DS serverid name
    """
    template = paths.CERTMONGER_COMMAND_TEMPLATE

    if ca.is_configured():
        requests = [
            {
                'cert-file': paths.RA_AGENT_PEM,
                'key-file': paths.RA_AGENT_KEY,
                'ca-name': 'dogtag-ipa-ca-renew-agent',
                'cert-presave-command': template % 'renew_ra_cert_pre',
                'cert-postsave-command': template % 'renew_ra_cert',
            },
        ]
    else:
        requests = []

    ca_requests = [
        {
            'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
            'cert-nickname': 'auditSigningCert cert-pki-ca',
            'ca-name': 'dogtag-ipa-ca-renew-agent',
            'cert-presave-command': template % 'stop_pkicad',
            'cert-postsave-command': (
                template %
                'renew_ca_cert "auditSigningCert cert-pki-ca"'),
        },
        {
            'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
            'cert-nickname': 'ocspSigningCert cert-pki-ca',
            'ca-name': 'dogtag-ipa-ca-renew-agent',
            'cert-presave-command': template % 'stop_pkicad',
            'cert-postsave-command': (
                template %
                'renew_ca_cert "ocspSigningCert cert-pki-ca"'),
        },
        {
            'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
            'cert-nickname': 'subsystemCert cert-pki-ca',
            'ca-name': 'dogtag-ipa-ca-renew-agent',
            'cert-presave-command': template % 'stop_pkicad',
            'cert-postsave-command': (
                template %
                'renew_ca_cert "subsystemCert cert-pki-ca"'),
        },
        {
            'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
            'cert-nickname': 'caSigningCert cert-pki-ca',
            'ca-name': 'dogtag-ipa-ca-renew-agent',
            'cert-presave-command': template % 'stop_pkicad',
            'cert-postsave-command': (
                template % 'renew_ca_cert "caSigningCert cert-pki-ca"'),
            'template-profile': None,
        },
        {
            'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
            'cert-nickname': 'Server-Cert cert-pki-ca',
            'ca-name': 'dogtag-ipa-ca-renew-agent',
            'cert-presave-command': template % 'stop_pkicad',
            'cert-postsave-command': (
                template %
                'renew_ca_cert "Server-Cert cert-pki-ca"'),
        },
    ]

    if ca.is_configured():
        db = certs.CertDB(api.env.realm, paths.PKI_TOMCAT_ALIAS_DIR)
        for nickname, _trust_flags in db.list_certs():
            if nickname.startswith('caSigningCert cert-pki-ca '):
                requests.append(
                    {
                        'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                        'cert-nickname': nickname,
                        'ca-name': 'dogtag-ipa-ca-renew-agent',
                        'cert-presave-command': template % 'stop_pkicad',
                        'cert-postsave-command':
                            (template % ('renew_ca_cert "%s"' % nickname)),
                        'template-profile': 'caCACert',
                    }
                )
        requests += ca_requests
    else:
        logger.debug('CA is not configured, skipping CA tracking')

    cert = x509.load_certificate_from_file(paths.HTTPD_CERT_FILE)
    if certs.is_ipa_issued_cert(api, cert):
        requests.append(
            {
                'cert-file': paths.HTTPD_CERT_FILE,
                'key-file': paths.HTTPD_KEY_FILE,
                'ca-name': 'IPA',
                'cert-postsave-command': template % 'restart_httpd',
            }
        )
    else:
        logger.debug('HTTP cert not issued by IPA, %s', cert.issuer)

    # Check the ldap server cert if issued by IPA
    ds_nickname = ds.get_server_cert_nickname(serverid)
    ds_db_dirname = dsinstance.config_dirname(serverid)
    ds_db = certs.CertDB(api.env.realm, nssdir=ds_db_dirname)
    if ds_db.is_ipa_issued_cert(api, ds_nickname):
        requests.append(
            {
                'cert-database': ds_db_dirname[:-1],
                'cert-nickname': ds_nickname,
                'ca-name': 'IPA',
                'cert-postsave-command':
                    '%s %s' % (template % 'restart_dirsrv', serverid),
            }
        )
    else:
        logger.debug('DS cert not issued by IPA')

    # Check the KDC cert if issued by IPA
    cert = x509.load_certificate_from_file(paths.KDC_CERT)
    if certs.is_ipa_issued_cert(api, cert):
        requests.append(
            {
                'cert-file': paths.KDC_CERT,
                'key-file': paths.KDC_KEY,
                'ca-name': 'IPA',
                'cert-postsave-command':
                    template % 'renew_kdc_cert',
            }
        )
    else:
        logger.debug('KDC cert not issued by IPA, %s', cert.issuer)

    return requests


def get_dogtag_cert_password(self):
    """Return the NSSDB token password

       Will raise IOError if there is a problem reading the file.
    """
    ca_passwd = None
    token = 'internal'
    with open(paths.PKI_TOMCAT_PASSWORD_CONF, 'r') as f:
        for line in f:
            (tok, pin) = line.split('=', 1)
            if token == tok:
                ca_passwd = pin.strip()
                break

    return ca_passwd


@registry
class IPACertmongerExpirationCheck(IPAPlugin):
    """
    Collect the known/tracked certificates and check the validity

    This verifies only the information that certmonger has and uses
    to schedule renewal.

    This is to ensure something hasn't changed certmonger's view of
    the world.
    """
    def check(self):
        results = Results()
        cm = certmonger._certmonger()

        all_requests = cm.obj_if.get_requests()
        for req in all_requests:
            request = certmonger._cm_dbus_object(cm.bus, cm, req,
                                                 certmonger.DBUS_CM_REQUEST_IF,
                                                 certmonger.DBUS_CM_IF, True)
            id = request.prop_if.Get(certmonger.DBUS_CM_REQUEST_IF,
                                     'nickname')
            notafter = request.prop_if.Get(certmonger.DBUS_CM_REQUEST_IF,
                                           'not-valid-after')
            notafter = datetime.datetime.fromtimestamp(notafter)
            now = datetime.datetime.utcnow()

            if now > notafter:
                result = Result(self, constants.ERROR,
                                key=id,
                                msg='Request id %s is expired' % id)
                results.add(result)
                continue

            delta = notafter - now
            diff = int(delta.total_seconds() / DAY)
            if diff < self.config.cert_expiration_days:
                result = Result(self, constants.WARNING,
                                key=id,
                                msg='Request id %s expires in %s days'
                                % (id, diff))
                results.add(result)

        return results


@registry
class IPACertfileExpirationCheck(IPAPlugin):
    """
    Collect the known/tracked certificates and check file validity

    Look into the certificate file or NSS database to check the
    validity of the on-disk certificate.

    This is to ensure a certificate wasn't replaced without
    certmonger being notified.
    """
    def check(self):
        results = Results()
        cm = certmonger._certmonger()

        all_requests = cm.obj_if.get_requests()
        for req in all_requests:
            request = certmonger._cm_dbus_object(cm.bus, cm, req,
                                                 certmonger.DBUS_CM_REQUEST_IF,
                                                 certmonger.DBUS_CM_IF, True)
            id = request.prop_if.Get(certmonger.DBUS_CM_REQUEST_IF,
                                     'nickname')

            store = request.prop_if.Get(certmonger.DBUS_CM_REQUEST_IF,
                                        'cert-storage')
            if store == 'FILE':
                certfile = str(request.prop_if.Get(
                               certmonger.DBUS_CM_REQUEST_IF, 'cert-file'))
                try:
                    cert = x509.load_certificate_from_file(certfile)
                except Exception as e:
                    result = Result(self, constants.ERROR,
                                    key=id,
                                    msg='Unable to open cert file %s: %s'
                                    % (certfile, e))
                    results.add(result)
                    continue
            elif store == 'NSSDB':
                nickname = str(request.prop_if.Get(
                               certmonger.DBUS_CM_REQUEST_IF, 'key_nickname'))
                dbdir = str(request.prop_if.Get(
                            certmonger.DBUS_CM_REQUEST_IF, 'cert_database'))
                try:
                    db = certdb.NSSDatabase(dbdir)
                except Exception as e:
                    result = Result(self, constants.ERROR,
                                    key=id,
                                    msg='Unable to open NSS database %s: %s'
                                    % (dbdir, e))
                    results.add(result)
                    continue

                try:
                    cert = db.get_cert(nickname)
                except Exception as e:
                    result = Result(self, constants.ERROR,
                                    key=id,
                                    msg='Unable to retrieve cert %s from '
                                    '%s: %s'
                                    % (nickname, dbdir, e))
                    results.add(result)
                    continue
            else:
                result = Result(self, constants.ERROR,
                                key=id,
                                msg='Unknown storage type: %s'
                                % store)
                results.add(result)
                continue

            now = datetime.datetime.utcnow()
            notafter = cert.not_valid_after

            if now > notafter:
                result = Result(self, constants.ERROR,
                                key=id,
                                msg='Request id %s is expired: %s' % id)
                results.add(result)
                continue

            delta = notafter - now
            diff = int(delta.total_seconds() / DAY)
            if diff < self.config.cert_expiration_days:
                result = Result(self, constants.WARNING,
                                key=id,
                                msg='Request id %s expires in %s days'
                                % (id, diff))
                results.add(result)

        return results


@registry
class IPACertTracking(IPAPlugin):
    """Compare the certificates tracked by certmonger to those that
       are configured by default.

       Steps:
       1. Collect all expected certificates into `requests`
       2. Get the ids of all the certificates that certmonger is tracking
       3. Iterate over `requests` to retrieve the request id of the
          expected tracking.
       4. If the id is found we remove it from the ids list and move on
       5. In the unlikely event that the request_id is not in the
          ids list of all tracked certs report it.
       6. Report on all tracked certs that IPA didn't setup itself as
          potential issues.
    """

    def check(self):
        results = Results()

        requests = get_requests(self.ca, self.ds, self.serverid)
        cm = certmonger._certmonger()

        ids = []
        all_requests = cm.obj_if.get_requests()
        for req in all_requests:
            request = certmonger._cm_dbus_object(cm.bus, cm, req,
                                                 certmonger.DBUS_CM_REQUEST_IF,
                                                 certmonger.DBUS_CM_IF, True)
            id = request.prop_if.Get(certmonger.DBUS_CM_REQUEST_IF,
                                     'nickname')
            ids.append(str(id))

        for request in requests:
            request_id = certmonger.get_request_id(request)
            try:
                if request_id is not None:
                    ids.remove(request_id)
            except ValueError as e:
                result = Result(self, constants.ERROR,
                                key=request_id,
                                msg='Request id %s is not tracked: %s'
                                % (request_id, e))
                results.add(result)

            if request_id is None:
                result = Result(self, constants.ERROR,
                                msg='Missing tracking for %s' % request)
                results.add(result)

        if ids:
            for id in ids:
                result = Result(self, constants.WARNING, key=id,
                                msg='Unknown certmonger id %s' % id)
                results.add(result)

        return results


@registry
class IPACertNSSTrust(IPAPlugin):
    """Compare the NSS trust for the CA certs to a known good value"""
    def check(self):
        results = Results()

        expected_trust = {
            'ocspSigningCert cert-pki-ca': 'u,u,u',
            'subsystemCert cert-pki-ca': 'u,u,u',
            'auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'u,u,u'
        }

        if not self.ca.is_configured():
            return

        db = certs.CertDB(api.env.realm, paths.PKI_TOMCAT_ALIAS_DIR)
        for nickname, _trust_flags in db.list_certs():
            flags = certdb.unparse_trust_flags(_trust_flags)
            if nickname.startswith('caSigningCert cert-pki-ca'):
                expected = 'CTu,Cu,Cu'
            else:
                try:
                    expected = expected_trust[nickname]
                except KeyError:
                    # FIXME: is this a warning, skip?
                    print("%s not found, assuming 3rd party" % nickname)
                    continue
            try:
                expected_trust.pop(nickname)
            except KeyError:
                pass
            if flags != expected:
                result = Result(
                    self, constants.ERROR, key=nickname,
                    msg='Incorrect NSS trust for %s. Got %s expected %s'
                    % (nickname, flags, expected))
            else:
                result = Result(self, constants.SUCCESS, key=nickname)
            results.add(result)

        for nickname in expected_trust:
            result = Result(
                self, constants.ERROR, key=nickname,
                msg='Certificate %s missing while verifying trust'
                % nickname)
            results.add(result)

        return results


@registry
class IPANSSChainValidation(IPAPlugin):
    """Validate the certificate chain of the certs to ensure trust is ok"""

    def check(self):
        results = Results()

        validate = []
        ca_pw_fname = None

        if self.ca.is_configured():
            try:
                ca_passwd = get_dogtag_cert_password()
            except IOError as e:
                result = Result(
                    self, constants.ERROR,
                    msg='Unable to read CA NSSDB token password: %s'
                    % e)
                results.add(result)
            else:
                with tempfile.NamedTemporaryFile(mode='w',
                                                 delete=False) as ca_pw_file:
                    ca_pw_file.write(ca_passwd)
                    ca_pw_fname = ca_pw_file.name

                validate.append(
                    (
                        paths.PKI_TOMCAT_ALIAS_DIR,
                        'Server-Cert cert-pki-ca',
                        ca_pw_fname,
                    ),
                )

        validate.append(
            (
                dsinstance.config_dirname(self.serverid),
                self.ds.get_server_cert_nickname(self.serverid),
                os.path.join(dsinstance.config_dirname(self.serverid),
                             'pwdfile.txt'),
            )
        )

        # Wrap in try/except to ensure the temporary password file is
        # removed
        try:
            for (dbdir, nickname, pinfile) in validate:
                args = [paths.CERTUTIL, "-V", "-u", "V", "-e"]
                args.extend(["-d", dbdir])
                args.extend(["-n", nickname])
                args.extend(["-f", pinfile])

                key = os.path.normpath(dbdir) + ':' + nickname
                try:
                    response = ipautil.run(args)
                except ipautil.CalledProcessError as e:
                    result = Result(
                        self, constants.ERROR, key=key,
                        msg='Validation of %s in %s failed: %s'
                            % (nickname, dbdir, e))
                else:
                    if 'certificate is valid' not in \
                            response.raw_output.decode('utf-8'):
                        result = Result(
                            self, constants.ERROR, key=key,
                            msg='Validation of %s in %s failed: '
                                '%s %s' % (
                                    nickname, dbdir,
                                    response.raw_output.decode('utf-8'),
                                    response.error_log)
                                )
                    else:
                        result = Result(self, constants.SUCCESS,
                                        key=key)
                results.add(result)
        finally:
            if ca_pw_fname:
                installutils.remove_file(ca_pw_fname)

        return results


@registry
class IPAOpenSSLChainValidation(IPAPlugin):
    """Validate the certificate chain of the certs to ensure trust is ok"""

    def validate_openssl(self, file):
        """Call out to openssl to verify a certificate against global chain

           The caller must handle the exceptions
        """
        args = [paths.OPENSSL, "verify", file]

        return ipautil.run(args)

    def check(self):
        results = Results()

        certs = [paths.HTTPD_CERT_FILE]
        if self.ca.is_configured():
            certs.append(paths.RA_AGENT_PEM)

        for cert in certs:
            try:
                response = self.validate_openssl(cert)
            except Exception as e:
                result = Result(
                    self, constants.ERROR, key=cert,
                    msg='Certificate validation for %s failed: %s' %
                        (cert, e))
            else:
                if ': OK' not in response.raw_output.decode('utf-8'):
                    result = Result(
                        self, constants.ERROR, key=cert,
                        msg='Certificate validation for %s failed: %s' %
                            (cert, response.raw_output.decode('utf-8')))
                else:
                    result = Result(
                        self, constants.SUCCESS, key=cert)
            results.add(result)

        return results
