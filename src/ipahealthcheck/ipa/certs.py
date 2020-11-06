#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#
from __future__ import division

from datetime import datetime, timezone, timedelta
import itertools
import logging
import os
import socket
import tempfile

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result, generalized_time
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

from ipalib import api
from ipalib import errors
from ipalib import x509
from ipalib.install import certmonger
from ipalib.constants import RENEWAL_CA_NAME, IPA_CA_RECORD
from ipaplatform.paths import paths
from ipaserver.install import certs
from ipaserver.install import dsinstance
from ipaserver.install import krainstance
from ipaserver.install import krbinstance
from ipaserver.plugins import ldap2
from ipapython import certdb
from ipapython import ipautil
from ipapython.dn import DN

logger = logging.getLogger()
DAY = 60 * 60 * 24


def is_ipa_issued_cert(myapi, cert):
    """Thin wrapper around certs.is_ipa_issued to test for LDAP"""
    if not myapi.Backend.ldap2.isconnected():
        return None

    return certs.is_ipa_issued_cert(myapi, cert)


def get_expected_requests(ca, ds, serverid):
    """Provide the expected certmonger tracking request data

       This list is based in part on certificate_renewal_update() in
       ipaserver/install/server/upgrade.py and various
       start_tracking_certificates() methods in *instance.py.

       The list is filtered depending on whether a CA is running
       and the certificates have been issued by IPA.

      :param ca: the CAInstance
      :param ds: the DSInstance
      :param serverid: the DS serverid name
    """
    template = paths.CERTMONGER_COMMAND_TEMPLATE

    if api.Command.ca_is_enabled()['result']:
        requests = [
            {
                'cert-file': paths.RA_AGENT_PEM,
                'key-file': paths.RA_AGENT_KEY,
                'ca-name': RENEWAL_CA_NAME,
                'cert-presave-command': template % 'renew_ra_cert_pre',
                'cert-postsave-command': template % 'renew_ra_cert',
            },
        ]
    else:
        requests = []

    if ca.is_configured():
        dogtag_reqs = ca.tracking_reqs.items()
        kra = krainstance.KRAInstance(api.env.realm)
        if kra.is_installed():
            dogtag_reqs = itertools.chain(dogtag_reqs,
                                          kra.tracking_reqs.items())
        for nick, profile in dogtag_reqs:
            req = {
                'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                'cert-nickname': nick,
                'ca-name': RENEWAL_CA_NAME,
                'cert-presave-command': template % 'stop_pkicad',
                'cert-postsave-command':
                    (template % 'renew_ca_cert "{}"'.format(nick)),
                'template-profile': profile,
            }
            requests.append(req)
    else:
        logger.debug('CA is not configured, skipping CA tracking')

    cert = x509.load_certificate_from_file(paths.HTTPD_CERT_FILE)
    issued = is_ipa_issued_cert(api, cert)
    if issued is None:
        logger.debug('Unable to determine if \'%s\' was issued by IPA '
                     'because no LDAP connection, assuming yes.')
    if issued or issued is None:
        requests.append(
            {
                'cert-file': paths.HTTPD_CERT_FILE,
                'key-file': paths.HTTPD_KEY_FILE,
                'ca-name': 'IPA',
                'cert-postsave-command': template % 'restart_httpd',
            }
        )
    else:
        logger.debug('HTTP cert not issued by IPA, \'%s\', skip tracking '
                     'check', DN(cert.issuer))

    # Check the ldap server cert if issued by IPA
    ds_nickname = ds.get_server_cert_nickname(serverid)
    ds_db_dirname = dsinstance.config_dirname(serverid)
    ds_db = certs.CertDB(api.env.realm, nssdir=ds_db_dirname)
    connected = api.Backend.ldap2.isconnected()
    if not connected:
        logger.debug('Unable to determine if \'%s\' was issued by IPA '
                     'because no LDAP connection, assuming yes.')
    if not connected or ds_db.is_ipa_issued_cert(api, ds_nickname):
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
        logger.debug('DS cert is not issued by IPA, skip tracking check')

    # Check if pkinit is enabled
    if os.path.exists(paths.KDC_CERT):
        pkinit_request_ca = krbinstance.get_pkinit_request_ca()
        requests.append(
            {
                'cert-file': paths.KDC_CERT,
                'key-file': paths.KDC_KEY,
                'ca-name': pkinit_request_ca,
                'cert-postsave-command':
                    template % 'renew_kdc_cert',
            }
        )
    else:
        logger.debug('No KDC pkinit certificate')

    return requests


def get_dogtag_cert_password():
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
    @duration
    def check(self):
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
            if notafter == 0:
                yield Result(self, constants.ERROR,
                             key=id,
                             msg='certmonger request id {key} does not have '
                                 'a not-valid-after date, assuming it '
                                 'has not been issued yet.')
                continue

            nafter = datetime.fromtimestamp(notafter, timezone.utc)
            now = datetime.now(timezone.utc)

            if now > nafter:
                yield Result(self, constants.ERROR,
                             key=id,
                             expiration_date=generalized_time(nafter),
                             msg='Request id {key} expired on '
                                 '{expiration_date}')
            else:
                delta = nafter - now
                diff = int(delta.total_seconds() / DAY)
                if diff < int(self.config.cert_expiration_days):
                    yield Result(self, constants.WARNING,
                                 key=id,
                                 expiration_date=generalized_time(nafter),
                                 days=diff,
                                 msg='Request id {key} expires in {days} '
                                     'days. certmonger should renew this '
                                     'automatically. Watch the status with '
                                     'getcert list -i {key}.')
                else:
                    yield Result(self, constants.SUCCESS,
                                 key=id)


@registry
class IPACertfileExpirationCheck(IPAPlugin):
    """
    Collect the known/tracked certificates and check file validity

    Look into the certificate file or NSS database to check the
    validity of the on-disk certificate.

    This is to ensure a certificate wasn't replaced without
    certmonger being notified.
    """
    @duration
    def check(self):
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
                    yield Result(self, constants.ERROR,
                                 key=id,
                                 certfile=certfile,
                                 error=str(e),
                                 msg='Request id {key}: Unable to open cert '
                                     'file \'{certfile}\': {error}')
                    continue
            elif store == 'NSSDB':
                nickname = str(request.prop_if.Get(
                               certmonger.DBUS_CM_REQUEST_IF, 'key_nickname'))
                dbdir = str(request.prop_if.Get(
                            certmonger.DBUS_CM_REQUEST_IF, 'cert_database'))
                try:
                    db = certdb.NSSDatabase(dbdir)
                except Exception as e:
                    yield Result(self, constants.ERROR,
                                 key=id,
                                 dbdir=dbdir,
                                 error=str(e),
                                 msg='Request id {key}: Unable to open NSS '
                                     'database \'{dbdir}\': {error}')
                    continue

                try:
                    cert = db.get_cert(nickname)
                except Exception as e:
                    yield Result(self, constants.ERROR,
                                 key=id,
                                 dbdir=dbdir,
                                 nickname=nickname,
                                 error=str(e),
                                 msg='Request id {key}: Unable to retrieve '
                                     'cert \'{nickname}\' from \'{dbdir}\': '
                                     '{error}')
                    continue
            else:
                yield Result(self, constants.ERROR,
                             key=id,
                             store=store,
                             msg='Request id {key}: Unknown certmonger '
                                 'storage type: {store}')
                continue

            now = datetime.utcnow()
            notafter = cert.not_valid_after

            if now > notafter:
                yield Result(self, constants.ERROR,
                             key=id,
                             expiration_date=generalized_time(notafter),
                             msg='Request id {key} expired on '
                                 '{expiration_date}')
                continue

            delta = notafter - now
            diff = int(delta.total_seconds() / DAY)
            if diff < int(self.config.cert_expiration_days):
                yield Result(self, constants.WARNING,
                             key=id,
                             expiration_date=generalized_time(notafter),
                             days=diff,
                             msg='Request id {key} expires in {days} '
                                 'days. certmonger should renew this '
                                 'automatically. Watch the status with'
                                 'getcert list -i {key}.')
            else:
                yield Result(self, constants.SUCCESS, key=id)


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

    requires = ('dirsrv',)

    @duration
    def check(self):
        requests = get_expected_requests(self.ca, self.ds, self.serverid)
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
                    # Tracking found, move onto the next
                    ids.remove(request_id)
                    yield Result(self, constants.SUCCESS,
                                 key=request_id)
                    continue
            except ValueError as e:
                # A request was found but the id isn't in the
                # list from certmonger!?
                yield Result(self, constants.ERROR,
                             key=request_id,
                             error=str(e),
                             msg='Found request id {key} but it is not tracked'
                                 'by certmonger!?: {error}')
                continue

            # The criteria was not met
            if request_id is None:
                flatten = ', '.join("{!s}={!s}".format(key, val)
                                    for (key, val) in request.items())
                yield Result(self, constants.ERROR,
                             key=flatten,
                             msg='Expected certmonger tracking is missing for '
                                 '{key}. Automated renewal will not happen '
                                 'for this certificate')
                continue

        # Report any unknown certmonger requests as warnings
        if ids:
            for id in ids:
                yield Result(self, constants.WARNING, key=id,
                             msg='certmonger tracking request {key} found and '
                                 'is not expected on an IPA master.')


@registry
class IPACertDNSSAN(IPAPlugin):
    """Check whether a IPA-issued certificates have a SAN configured

       Steps:
       1. Collect all expected certificates into `requests`
       2. Iterate over the list of certificates
       3. If issued by IPA and a caIPAserviceCert then verify that
          the host FQDN is in the list of SAN
       4. If a CA is configured on this host then also verify that
          ipa-ca.$DOMAIN is in the SAN.
    """

    requires = ('dirsrv',)

    @duration
    def check(self):
        fqdn = socket.getfqdn()
        requests = get_expected_requests(self.ca, self.ds, self.serverid)

        for request in requests:
            request_id = certmonger.get_request_id(request)
            if request_id is None:
                yield Result(self, constants.ERROR,
                             key=request_id,
                             msg='Found request id {key} but it is not tracked'
                                 'by certmonger!?')
                continue

            ca_name = certmonger.get_request_value(request_id, 'ca-name')
            if ca_name != 'IPA':
                logger.debug('Skipping request %s with CA %s',
                             request_id, ca_name)
                continue
            profile = certmonger.get_request_value(request_id,
                                                   'template_profile')
            if profile != 'caIPAserviceCert':
                logger.debug('Skipping request %s with profile %s',
                             request_id, profile)
                continue

            certfile = None
            if request.get('cert-file') is not None:
                certfile = request.get('cert-file')
                try:
                    cert = x509.load_certificate_from_file(certfile)
                except Exception as e:
                    yield Result(self, constants.ERROR,
                                 key=request_id,
                                 certfile=certfile,
                                 error=str(e),
                                 msg='Unable to open cert file {certfile}: '
                                     '{error}')
                    continue
            elif request.get('cert-database') is not None:
                nickname = request.get('cert-nickname')
                dbdir = request.get('cert-database')
                try:
                    db = certdb.NSSDatabase(dbdir)
                except Exception as e:
                    yield Result(self, constants.ERROR,
                                 key=request_id,
                                 dbdir=dbdir,
                                 error=str(e),
                                 msg='Unable to open NSS database {dbdir}: '
                                     '{error}')
                    continue
                try:
                    cert = db.get_cert(nickname)
                except Exception as e:
                    yield Result(self, constants.ERROR,
                                 key=id,
                                 dbdir=dbdir,
                                 nickname=nickname,
                                 error=str(e),
                                 msg='Unable to retrieve certificate '
                                     '\'{nickname}\' from {dbdir}: {error}')
                    continue

            hostlist = [fqdn]
            if self.ca.is_configured() and certfile == paths.HTTPD_CERT_FILE:
                hostlist.append(f'{IPA_CA_RECORD}.{api.env.domain}')
            error = False
            for host in hostlist:
                if host not in cert.san_a_label_dns_names:
                    error = True
                    yield Result(self, constants.ERROR,
                                 key=request_id,
                                 hostname=host,
                                 san=cert.san_a_label_dns_names,
                                 ca=ca_name,
                                 profile=profile,
                                 msg='Certificate request id {key} with '
                                     'profile {profile} for CA {ca} does not '
                                     'have a DNS SAN {san} matching name '
                                     '{hostname}')
            if not error:
                yield Result(self, constants.SUCCESS,
                             key=request_id,
                             hostname=hostlist,
                             san=cert.san_a_label_dns_names,
                             ca=ca_name,
                             profile=profile)


@registry
class IPACertNSSTrust(IPAPlugin):
    """Compare the NSS trust for the CA certs to a known good value"""
    @duration
    def check(self):
        expected_trust = {
            'ocspSigningCert cert-pki-ca': 'u,u,u',
            'subsystemCert cert-pki-ca': 'u,u,u',
            'auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'u,u,u',
        }
        kra = krainstance.KRAInstance(api.env.realm)
        if kra.is_installed():
            kra_trust = {
                'transportCert cert-pki-kra': 'u,u,u',
                'storageCert cert-pki-kra': 'u,u,u',
                'auditSigningCert cert-pki-kra': 'u,u,Pu',
            }
            expected_trust.update(kra_trust)

        if not self.ca.is_configured():
            logger.debug('CA is not configured, skipping NSS trust check')
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
                    logger.debug(
                        "%s not found in %s, assuming 3rd party",
                        nickname,
                        paths.PKI_TOMCAT_ALIAS_DIR,
                    )
                    continue
            try:
                expected_trust.pop(nickname)
            except KeyError:
                pass
            if flags != expected:
                yield Result(
                    self, constants.ERROR, key=nickname,
                    expected=expected,
                    got=flags,
                    nickname=nickname,
                    dbdir=paths.PKI_TOMCAT_ALIAS_DIR,
                    msg='Incorrect NSS trust for {nickname} in {dbdir}. '
                        'Got {got} expected {expected}.')
                continue

            yield Result(self, constants.SUCCESS, key=nickname)

        for nickname in expected_trust:
            yield Result(
                self, constants.ERROR,
                key=nickname,
                nickname=nickname,
                dbdir=paths.PKI_TOMCAT_ALIAS_DIR,
                msg='Certificate {nickname} missing from {dbdir} while '
                    'verifying trust')


@registry
class IPANSSChainValidation(IPAPlugin):
    """Validate the certificate chain of the certs."""

    def validate_nss(self, dbdir, dbtype, pinfile, nickname):
        """Call out to certutil to verify a certificate.

           The caller must handle the exceptions
        """
        args = [paths.CERTUTIL, '-V', '-u', 'V', '-e']
        args.extend(['-d', dbtype + ':' + dbdir])
        args.extend(['-n', nickname])
        args.extend(['-f', pinfile])

        return ipautil.run(args, raiseonerr=False)

    @duration
    def check(self):
        validate = []
        ca_pw_fname = None

        if self.ca.is_configured():
            try:
                ca_passwd = get_dogtag_cert_password()
            except IOError as e:
                yield Result(
                    self, constants.ERROR,
                    error=str(e),
                    msg='Unable to read CA NSSDB token password: {error}')
                return
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
                # detect the database type so we have the right prefix
                db = certdb.NSSDatabase(dbdir)

                key = os.path.normpath(dbdir) + ':' + nickname
                try:
                    response = self.validate_nss(dbdir, db.dbtype, pinfile,
                                                 nickname)
                except ipautil.CalledProcessError as e:
                    logger.debug('Validation of NSS certificate failed %s', e)
                    yield Result(
                        self, constants.ERROR,
                        key=key,
                        dbdir=dbdir,
                        nickname=nickname,
                        reason=response.output_error,
                        msg='Validation of {nickname} in {dbdir} failed: '
                            '{reason}')
                else:
                    if 'certificate is valid' not in \
                            response.raw_output.decode('utf-8'):
                        yield Result(
                            self, constants.ERROR,
                            key=key,
                            dbdir=dbdir,
                            nickname=nickname,
                            reason="%s: %s" %
                            (response.raw_output.decode('utf-8'),
                             response.error_log),
                            msg='Validation of {nickname} in {dbdir} failed: '
                                '{reason}')
                    else:
                        yield Result(self, constants.SUCCESS,
                                     dbdir=dbdir, nickname=nickname,
                                     key=key)
        finally:
            if ca_pw_fname:
                ipautil.remove_file(ca_pw_fname)


@registry
class IPAOpenSSLChainValidation(IPAPlugin):
    """Validate the certificate chain of the certs."""

    def validate_openssl(self, file):
        """Call out to openssl to verify a certificate against global chain

           The caller must handle the exceptions
        """
        args = [paths.OPENSSL, 'verify',
                '-verbose',
                '-show_chain',
                '-CAfile', paths.IPA_CA_CRT,
                file]

        return ipautil.run(args, raiseonerr=False)

    @duration
    def check(self):
        certlist = [paths.HTTPD_CERT_FILE]
        if self.ca.is_configured():
            certlist.append(paths.RA_AGENT_PEM)

        for cert in certlist:
            try:
                response = self.validate_openssl(cert)
            except Exception as e:
                yield Result(
                    self, constants.ERROR,
                    key=cert,
                    error=str(e),
                    msg='Certificate validation for {key} failed: {error}')
                continue
            else:
                if ': OK' not in response.raw_output.decode('utf-8'):
                    yield Result(
                        self, constants.ERROR, key=cert,
                        reason=response.raw_error_output.decode('utf-8'),
                        msg='Certificate validation for {key} failed: '
                            '{reason}')
                else:
                    yield Result(
                        self, constants.SUCCESS, key=cert)


@registry
class IPARAAgent(IPAPlugin):
    """Validate the RA Agent used to talk to the CA

       Compare the description and usercertificate values.
    """

    requires = ('dirsrv',)

    @duration
    def check(self):
        if not self.ca.is_configured():
            logger.debug('CA is not configured, skipping RA Agent check')
            return

        try:
            cert = x509.load_certificate_from_file(paths.RA_AGENT_PEM)
        except Exception as e:
            yield Result(self, constants.ERROR,
                         error=str(e),
                         msg='Unable to load RA cert: {error}')
            return

        serial_number = cert.serial_number
        subject = DN(cert.subject)
        issuer = DN(cert.issuer)
        description = '2;%d;%s;%s' % (serial_number, issuer, subject)

        logger.debug('RA agent description should be %s', description)

        db_filter = ldap2.ldap2.combine_filters(
            [
                ldap2.ldap2.make_filter({'objectClass': 'inetOrgPerson'}),
                ldap2.ldap2.make_filter({'sn': 'ipara'}),
                ldap2.ldap2.make_filter(
                    {'description': ';%s;%s' % (issuer, subject)},
                    exact=False, trailing_wildcard=False),
            ],
            ldap2.ldap2.MATCH_ALL)

        base_dn = DN(('o', 'ipaca'))
        try:
            entries = self.conn.get_entries(base_dn,
                                            self.conn.SCOPE_SUBTREE,
                                            db_filter)
        except errors.NotFound:
            yield Result(self, constants.ERROR,
                         description=description,
                         msg='RA agent not found in LDAP')
            return
        except Exception as e:
            yield Result(self, constants.ERROR,
                         error=str(e),
                         msg='Retrieving RA agent from LDAP failed {error}')
            return
        else:
            logger.debug('RA agent description is %s', description)
            if len(entries) != 1:
                yield Result(self, constants.ERROR,
                             found=len(entries),
                             msg='Too many RA agent entries found, {found}')
                return
            entry = entries[0]
            raw_desc = entry.get('description')
            if raw_desc is None:
                yield Result(self, constants.ERROR,
                             msg='RA agent is missing the description '
                                 'attribute or it is not readable')
                return
            ra_desc = raw_desc[0]
            ra_certs = entry.get('usercertificate')
            if ra_desc != description:
                yield Result(self, constants.ERROR,
                             expected=description,
                             got=ra_desc,
                             msg='RA agent description does not match. Found '
                             '{got} in LDAP and expected {expected}')
                return
            found = False
            for candidate in ra_certs:
                if candidate == cert:
                    found = True
                    break
            if not found:
                yield Result(self, constants.ERROR,
                             certfile=paths.RA_AGENT_PEM,
                             dn=str(entry.dn),
                             msg='RA agent certificate in {certfile} not '
                                 'found in LDAP userCertificate attribute '
                                 'for the entry {dn}')
            yield Result(self, constants.SUCCESS)


@registry
class IPACertRevocation(IPAPlugin):
    """Confirm that the IPA certificates are not revoked

       This uses the certmonger expected tracking list to know which
       one(s) to consider.
    """

    revocation_reason = [
        "unspecified",
        "key compromise",
        "CA compromise",
        "affiliation changed",
        "superseded",
        "cessation of operation",
        "certificate hold",
        "",  # unused
        "remove from CRL",
        "privilege withdrawn",
        "AA compromise",
    ]

    requires = ('dirsrv',)

    @duration
    def check(self):
        # For simplicity use the expected certmonger tracking for the
        # list of certificates to check because it already filters out
        # based on whether the CA system is configure and whether the
        # certificates were issued by IPA.
        if not self.ca.is_configured():
            logger.debug('CA is not configured, skipping revocation check')
            return
        requests = get_expected_requests(self.ca, self.ds, self.serverid)
        for request in requests:
            id = certmonger.get_request_id(request)
            if request.get('cert-file') is not None:
                certfile = request.get('cert-file')
                try:
                    cert = x509.load_certificate_from_file(certfile)
                except Exception as e:
                    yield Result(self, constants.ERROR,
                                 key=id,
                                 certfile=certfile,
                                 error=str(e),
                                 msg='Unable to open cert file {certfile}: '
                                     '{error}')
                    continue
            elif request.get('cert-database') is not None:
                nickname = request.get('cert-nickname')
                dbdir = request.get('cert-database')
                try:
                    db = certdb.NSSDatabase(dbdir)
                except Exception as e:
                    yield Result(self, constants.ERROR,
                                 key=id,
                                 dbdir=dbdir,
                                 error=str(e),
                                 msg='Unable to open NSS database {dbdir}: '
                                     '{error}')
                    continue
                try:
                    cert = db.get_cert(nickname)
                except Exception as e:
                    yield Result(self, constants.ERROR,
                                 key=id,
                                 dbdir=dbdir,
                                 nickname=nickname,
                                 error=str(e),
                                 msg='Unable to retrieve certificate '
                                     '\'{nickname}\' from {dbdir}: {error}')
                    continue
            else:
                yield Result(self, constants.ERROR,
                             key=id,
                             msg='Unable to to identify certificate storage '
                                 'type for request {key}')
                continue

            issued = is_ipa_issued_cert(api, cert)
            if issued is False:
                logger.debug('\'%s\' was not issued by IPA, skipping',
                             DN(cert.subject))
                continue
            if issued is None:
                logger.debug('LDAP is down, skipping \'%s\'',
                             DN(cert.subject))
                continue

            # Now we have the cert either way, check the recovation
            try:
                result = api.Command.cert_show(cert.serial_number,
                                               all=True)
            except Exception as e:
                yield Result(self, constants.ERROR,
                             key=id,
                             serial=cert.serial_number,
                             error=str(e),
                             msg='Request for certificate serial number '
                                 '{serial} in request {key} failed: {error}')
                continue

            try:
                if result['result']['revoked']:
                    reason = result['result']['revocation_reason']
                    reason_txt = self.revocation_reason[reason]
                    yield Result(self, constants.ERROR,
                                 revocation_reason=reason_txt,
                                 key=id,
                                 msg='Certificate tracked by {key} is revoked '
                                     '{revocation_reason}')
                else:
                    yield Result(self, constants.SUCCESS, key=id)
            except Exception as e:
                yield Result(self, constants.ERROR,
                             key=id,
                             error=str(e),
                             msg='Unable to determine revocation '
                                 'status for {key}: {error}')


@registry
class IPACertmongerCA(IPAPlugin):
    """Ensure that the required CAs are available in certmonger

       Addresses symptom of https://pagure.io/freeipa/issue/7870
    """

    def find_ca(self, name):
        cm = certmonger._certmonger()
        ca_path = cm.obj_if.find_ca_by_nickname(name)
        return certmonger._cm_dbus_object(cm.bus, cm, ca_path,
                                          certmonger.DBUS_CM_CA_IF,
                                          certmonger.DBUS_CM_IF, True)

    @duration
    def check(self):
        ca_list = ['IPA']
        if self.ca.is_configured():
            ca_list.extend([
               'dogtag-ipa-ca-renew-agent',
               'dogtag-ipa-ca-renew-agent-reuse'
            ])
        for ca in ca_list:
            logger.debug('Checking for existence of certmonger CA \'%s\'',
                         ca)
            try:
                self.find_ca(ca)
            except Exception as e:
                logger.debug('Search for certmonger CA %s failed: %s', ca, e)
                yield Result(self, constants.ERROR,
                             key=ca,
                             msg='Certmonger CA \'{key}\' missing')
            else:
                yield Result(self, constants.SUCCESS,
                             key=ca)


@registry
class IPACAChainExpirationCheck(IPAPlugin):
    """Verify that the certs in the CA chain in /etc/ipa/ca.crt are valid
    """

    @duration
    def check(self):
        try:
            ca_certs = x509.load_certificate_list_from_file(paths.IPA_CA_CRT)
        except IOError as e:
            logger.debug("Could not open %s: %s", paths.IPA_CA_CRT, e)
            yield Result(self, constants.ERROR,
                         key=paths.IPA_CA_CRT,
                         error=str(e),
                         msg='Error opening IPA CA chain at {key}: {error}')
            return
        except ValueError as e:
            logger.debug(
                "% contains an invalid certificate", paths.IPA_CA_CRT
            )
            yield Result(self, constants.ERROR,
                         key=paths.IPA_CA_CRT,
                         error=str(e),
                         msg='IPA CA chain {key} contains an invalid '
                             'certificate: {error}')
            return

        now = datetime.now(timezone.utc)
        soon = now + timedelta(days=int(self.config.cert_expiration_days))
        for cert in ca_certs:
            subject = DN(cert.subject)
            subject = str(subject).replace('\\;', '\\3b')
            dt = cert.not_valid_after.replace(tzinfo=timezone.utc)
            if dt < now:
                logger.debug("%s is expired", subject)
                yield Result(self, constants.CRITICAL,
                             path=paths.IPA_CA_CRT,
                             key=subject,
                             msg='CA \'{key}\' in {path} is expired.')
            elif dt <= soon:
                logger.debug("%s is expiring soon", subject)
                yield Result(self, constants.WARNING,
                             path=paths.IPA_CA_CRT,
                             key=subject,
                             days=(dt - now).days,
                             msg='CA \'{key}\' in {path} is expiring in '
                                 '{days} days.')
            else:
                yield Result(self, constants.SUCCESS,
                             path=paths.IPA_CA_CRT,
                             key=subject,
                             days=(dt - now).days)
