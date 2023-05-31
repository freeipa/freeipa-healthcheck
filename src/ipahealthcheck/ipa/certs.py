#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#
from __future__ import division

from datetime import datetime, timezone, timedelta
import itertools
from inspect import signature
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
from ipapython.ipaldap import realm_to_serverid

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
            if profile in ('caSignedLogCert', 'caOCSPCert',
                           'caSubsystemCert', 'caCACert',
                           'caAuditSigningCert', 'caTransportCert',
                           'caStorageCert'):
                token = ca.token_name
            else:
                token = None

            req = {
                'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                'cert-nickname': nick,
                'ca-name': RENEWAL_CA_NAME,
                'cert-presave-command': template % 'stop_pkicad',
                'cert-postsave-command':
                    (template % 'renew_ca_cert "{}"'.format(nick)),
                'template-profile': profile,
            }
            if token and token != 'internal':
                req['key-token'] = token
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

    # See if a host certificate was issued. This is only to
    # prevent a false-positive if one is indeed installed.
    local = {
        paths.IPA_NSSDB_DIR: 'Local IPA host',
        paths.NSS_DB_DIR: 'IPA Machine Certificate - %s' % socket.getfqdn(),
    }
    for db, nickname in local.items():
        nssdb = certdb.NSSDatabase(db)
        if nssdb.has_nickname(nickname):
            requests.append(
                {
                    'cert-database': db,
                    'cert-nickname': nickname,
                    'ca-name': 'IPA',
                }
            )

    return requests


def expected_token(token_name, certmonger_token):
    """The value is stored in two places, do some sanity checking"""
    if token_name != str(certmonger_token):
        logger.debug(
            "The IPA token %s doesn't match the certmonger token "
            "%s.", token_name, certmonger_token
        )
        return False

    return True


def get_token_password(hsm_enabled, token):
    if not hsm_enabled:
        return None

    with open(paths.PKI_TOMCAT_PASSWORD_CONF, "r") as passfile:
        contents = passfile.readlines()

    for line in contents:
        data = line.split('=', 1)
        if data[0] == 'hardware-' + token:
            return data[1]

    return None


def get_token_password_file(hsm_enabled, token):
    """The CA contains the list of HSM passwords, find ours"""
    pwdfile = None
    token_pw = get_token_password(hsm_enabled, token)

    if hsm_enabled and token_pw:
        pwdfile = ipautil.write_tmp_file(token_pw)

    return pwdfile


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
                token = request.prop_if.Get(certmonger.DBUS_CM_REQUEST_IF,
                                            'key-token')
                nickname = str(request.prop_if.Get(
                               certmonger.DBUS_CM_REQUEST_IF, 'key_nickname'))
                if token and expected_token(self.ca.token_name, token):
                    nickname = '{}:{}'.format(token, nickname)
                dbdir = str(request.prop_if.Get(
                            certmonger.DBUS_CM_REQUEST_IF, 'cert_database'))

                pwd_file = get_token_password_file(self.ca.hsm_enabled,
                                                   token)

                try:
                    if 'pwd_file' in signature(certdb.NSSDatabase).parameters:
                        db = certdb.NSSDatabase(
                            dbdir, token=token,
                            pwd_file=pwd_file.name if pwd_file else None)
                    else:
                        # Fall back to older API
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
                                 ' by certmonger!?: {error}')
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
                # log and skip. Missed tracking is reported by IPACertTracking
                flatten = ', '.join("{!s}={!s}".format(key, val)
                                    for (key, val) in request.items())

                logger.debug(
                    "Skipping %s since it is handled by IPACertTracking",
                    flatten
                )
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
        if not self.ca.is_configured():
            logger.debug('CA is not configured, skipping NSS trust check')
            return

        if self.ca.hsm_enabled:
            token = self.ca.token_name + ":"
        else:
            token = ""

        expected_trust = {
            f'{token}ocspSigningCert cert-pki-ca': 'u,u,u',
            f'{token}subsystemCert cert-pki-ca': 'u,u,u',
            f'{token}auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'u,u,u',
        }
        kra = krainstance.KRAInstance(api.env.realm)
        if kra.is_installed():
            kra_trust = {
                f'{token}transportCert cert-pki-kra': 'u,u,u',
                f'{token}storageCert cert-pki-kra': 'u,u,u',
                f'{token}auditSigningCert cert-pki-kra': 'u,u,Pu',
            }
            expected_trust.update(kra_trust)

        db = certdb.NSSDatabase(paths.PKI_TOMCAT_ALIAS_DIR)
        certlist = db.list_certs()
        if token:
            token = token[:-1]  # Strip off trailing colon

            pwd_file = get_token_password_file(self.ca.hsm_enabled,
                                               token)

            db = certdb.NSSDatabase(
                paths.PKI_TOMCAT_ALIAS_DIR, token=token,
                pwd_file=pwd_file.name if pwd_file else None)

            certlist += db.list_certs()

        for nickname, _trust_flags in certlist:
            flags = certdb.unparse_trust_flags(_trust_flags)
            if nickname == f'{token}caSigningCert cert-pki-ca':
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
class IPACertMatchCheck(IPAPlugin):
    """
    Ensure certificates match between LDAP and NSS databases
    """

    requires = ('dirsrv',)

    def get_cert_list_from_db(self, nssdb, nickname):
        """
        Retrieve all certificates from an NSS database for nickname.
        """
        try:
            args = ["-L", "-n", nickname, "-a"]
            result = nssdb.run_certutil(args, capture_output=True)
            return x509.load_certificate_list(result.raw_output)
        except ipautil.CalledProcessError:
            return []

    @duration
    def check(self):
        if not self.ca.is_configured():
            logger.debug("No CA configured, skipping certificate match check")
            return

        # Ensure /etc/ipa/ca.crt matches the NSS DB CA certificates
        def match_cacert_and_db(plugin, cacerts, dbpath):
            db = certs.CertDB(api.env.realm, dbpath)
            nickname = '%s IPA CA' % api.env.realm
            try:
                dbcacerts = self.get_cert_list_from_db(db, nickname)
            except Exception as e:
                yield Result(plugin, constants.ERROR,
                             key=nickname,
                             error=str(e),
                             msg='Unable to load CA cert: {error}')
                return False

            ok = True
            for cert in dbcacerts:
                if cert not in cacerts:
                    ok = False
                    yield Result(plugin, constants.ERROR,
                                 key=nickname,
                                 nickname=nickname,
                                 serial_number=cert.serial_number,
                                 dbdir=dbpath,
                                 certdir=paths.IPA_CA_CRT,
                                 msg=('CA Certificate nickname {nickname} '
                                      'with serial number {serial} '
                                      'is in {dbdir} but is not in'
                                      '%s' % paths.IPA_CA_CRT))
            return ok

        try:
            cacerts = x509.load_certificate_list_from_file(paths.IPA_CA_CRT)
        except Exception:
            yield Result(self, constants.ERROR,
                         key=paths.IPA_CA_CRT.replace(os.path.sep, '_'),
                         path=paths.IPA_CA_CRT,
                         msg='Unable to load CA cert file {path}: {error}')
            return

        # Ensure CA cert entry from LDAP matches /etc/ipa/ca.crt
        dn = DN('cn=%s IPA CA' % api.env.realm,
                'cn=certificates,cn=ipa,cn=etc',
                api.env.basedn)
        try:
            entry = self.conn.get_entry(dn)
        except errors.NotFound:
            yield Result(self, constants.ERROR,
                         key=str(dn),
                         dn=str(dn),
                         msg='CA Certificate entry \'{dn}\' '
                             'not found in LDAP')
            return

        cacerts_ok = True
        # Are all the certs in LDAP for the IPA CA in /etc/ipa/ca.crt
        for cert in entry['CACertificate']:
            if cert not in cacerts:
                cacerts_ok = False
                yield Result(self, constants.ERROR,
                             key=str(dn),
                             dn=str(dn),
                             serial_number=cert.serial_number,
                             msg=('CA Certificate serial number {serial} is '
                                  'in LDAP \'{dn}\' but is not in '
                                  '%s' % paths.IPA_CA_CRT))

        # Ensure NSS DBs have matching CA certs for /etc/ipa/ca.crt
        serverid = realm_to_serverid(api.env.realm)
        dspath = paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % serverid

        cacertds_ok = yield from match_cacert_and_db(self, cacerts, dspath)
        cacertnss_ok = yield from match_cacert_and_db(self, cacerts,
                                                      paths.IPA_NSSDB_DIR)
        if cacerts_ok:
            yield Result(self, constants.SUCCESS,
                         key=paths.IPA_CA_CRT)
        if cacertds_ok:
            yield Result(self, constants.SUCCESS,
                         key=dspath)
        if cacertnss_ok:
            yield Result(self, constants.SUCCESS,
                         key=paths.IPA_NSSDB_DIR)


@registry
class IPADogtagCertsMatchCheck(IPAPlugin):
    """
    Check if dogtag certs present in both NSS DB and LDAP match
    """
    requires = ('dirsrv',)

    @duration
    def check(self):
        if not self.ca.is_configured():
            logger.debug('CA is not configured, skipping match check')
            return

        def match_ldap_nss_cert(plugin, ldap, db, cert_dn, attr, cert_nick):
            try:
                entry = ldap.get_entry(cert_dn)
            except errors.NotFound:
                yield Result(plugin, constants.ERROR,
                             key=cert_dn,
                             msg='%s entry not found in LDAP' % cert_dn)
                return False
            try:
                nsscert = db.get_cert_from_db(cert_nick)
            except Exception as e:
                yield Result(plugin, constants.ERROR,
                             key=cert_nick,
                             error=str(e),
                             msg=('Unable to load %s certificate:'
                                  '{error}' % cert_nick))
                return False
            cert_matched = any(cert == nsscert for cert in entry[attr])
            if not cert_matched:
                yield Result(plugin, constants.ERROR,
                             key=cert_nick,
                             nickname=cert_nick,
                             dbdir=db.secdir,
                             msg=('{nickname} certificate in NSS DB {dbdir} '
                                  'does not match entry in LDAP'))
                return False
            return True

        def match_ldap_nss_certs_by_subject(plugin, ldap, db, dn,
                                            expected_nicks_subjects):
            all_ok = True
            for nick, subject in expected_nicks_subjects.items():
                entries = ldap.get_entries(
                    dn,
                    filter=f'subjectname={subject}'
                )
                cert = db.get_cert_from_db(nick)
                ok = any(
                    cert in entry["userCertificate"]
                    for entry in entries
                    if "userCertificate" in entry
                )
                if not ok:
                    all_ok = False
                    yield Result(plugin, constants.ERROR,
                                 key=nick,
                                 nickname=nick,
                                 dbdir=db.secdir,
                                 msg=('{nickname} certificate in NSS DB '
                                      '{dbdir} does not match entry in LDAP'))
            return all_ok

        if self.ca.hsm_enabled:
            token = self.ca.token_name + ':'
        else:
            token = ''
        pwd_file = get_token_password_file(self.ca.hsm_enabled,
                                           self.ca.token_name)
        if 'pwd_file' in signature(certs.CertDB).parameters:
            # pylint: disable=unexpected-keyword-arg
            db = certs.CertDB(api.env.realm, paths.PKI_TOMCAT_ALIAS_DIR,
                              pwd_file=pwd_file.name if pwd_file else None)
        else:
            # Fall back to older API
            db = certs.CertDB(api.env.realm, paths.PKI_TOMCAT_ALIAS_DIR)
        dn = DN('uid=pkidbuser,ou=people,o=ipaca')
        subsystem_nick = f'{token}subsystemCert cert-pki-ca'
        subsystem_ok = yield from match_ldap_nss_cert(self, self.conn,
                                                      db, dn,
                                                      'userCertificate',
                                                      subsystem_nick)
        dn = DN('cn=%s IPA CA' % api.env.realm,
                'cn=certificates,cn=ipa,cn=etc',
                api.env.basedn)
        casigning_nick = f'{token}caSigningCert cert-pki-ca'
        casigning_ok = yield from match_ldap_nss_cert(self, self.conn,
                                                      db, dn, 'CACertificate',
                                                      casigning_nick)

        config = api.Command.config_show()
        subject_base = config['result']['ipacertificatesubjectbase'][0]
        expected_nicks_subjects = {
            f'{token}ocspSigningCert cert-pki-ca':
                f'CN=OCSP Subsystem,{subject_base}',
            f'{token}subsystemCert cert-pki-ca':
                f'CN=CA Subsystem,{subject_base}',
            f'{token}auditSigningCert cert-pki-ca':
                f'CN=CA Audit,{subject_base}',
            'Server-Cert cert-pki-ca':
                f'CN={api.env.host},{subject_base}',
        }

        kra = krainstance.KRAInstance(api.env.realm)
        if kra.is_installed():
            kra_expected_nicks_subjects = {
                f'{token}transportCert cert-pki-kra':
                    f'CN=KRA Transport Certificate,{subject_base}',
                f'{token}storageCert cert-pki-kra':
                    f'CN=KRA Storage Certificate,{subject_base}',
                f'{token}auditSigningCert cert-pki-kra':
                    f'CN=KRA Audit,{subject_base}',
            }
            expected_nicks_subjects.update(kra_expected_nicks_subjects)

        ipaca_basedn = DN('ou=certificateRepository,ou=ca,o=ipaca')
        ipaca_certs_ok = yield from match_ldap_nss_certs_by_subject(
                                    self, self.conn, db,
                                    ipaca_basedn,
                                    expected_nicks_subjects
                                )

        if subsystem_ok:
            yield Result(self, constants.SUCCESS,
                         key=subsystem_nick)
        if casigning_ok:
            yield Result(self, constants.SUCCESS,
                         key=casigning_nick)
        if ipaca_certs_ok:
            yield Result(self, constants.SUCCESS,
                         key=str(ipaca_basedn))


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
                    key='db_authenticate',
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
                        reason=str(e),
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


def check_agent(plugin, base_dn, agent_type):
    """Check RA/KRA Agent"""

    try:
        cert = x509.load_certificate_from_file(paths.RA_AGENT_PEM)
    except Exception as e:
        yield Result(plugin, constants.ERROR,
                     key=paths.RA_AGENT_PEM.replace(os.path.sep, '_'),
                     error=str(e),
                     msg='Unable to load RA cert: {error}')
        return
    serial_number = cert.serial_number
    subject = DN(cert.subject)
    issuer = DN(cert.issuer)
    description = '2;%d;%s;%s' % (serial_number, issuer, subject)
    logger.debug('%s agent description should be %s', agent_type, description)
    db_filter = ldap2.ldap2.combine_filters(
        [
            ldap2.ldap2.make_filter({'objectClass': 'inetOrgPerson'}),
            ldap2.ldap2.make_filter(
                {'description': ';%s;%s' % (issuer, subject)},
                exact=False, trailing_wildcard=False),
        ],
        ldap2.ldap2.MATCH_ALL)
    try:
        entries = plugin.conn.get_entries(base_dn,
                                          plugin.conn.SCOPE_SUBTREE,
                                          db_filter)
    except errors.NotFound:
        yield Result(plugin, constants.ERROR,
                     key=agent_type,
                     description=description,
                     msg='%s agent not found in LDAP' % agent_type)
        return
    except Exception as e:
        yield Result(plugin, constants.ERROR,
                     key=agent_type,
                     error=str(e),
                     msg='Retrieving %s agent from LDAP failed {error}'
                         % agent_type)
        return
    else:
        logger.debug('%s agent description is %s', agent_type, description)
        if len(entries) != 1:
            yield Result(plugin, constants.ERROR,
                         key='too_many_agents',
                         found=len(entries),
                         msg='Too many %s agent entries found, {found}'
                             % agent_type)
            return
        entry = entries[0]
        raw_desc = entry.get('description')
        if raw_desc is None:
            yield Result(plugin, constants.ERROR,
                         key='agent_missing_description',
                         msg='%s agent is missing the description '
                             'attribute or it is not readable' % agent_type)
            return
        ra_desc = raw_desc[0]
        ra_certs = entry.get('usercertificate')
        (_version, exp_serial, exp_issuer, exp_subject) = \
            ra_desc.split(';')
        matched = all(
            [
                str(serial_number) == exp_serial,
                DN(issuer) == DN(exp_issuer),
                DN(subject) == DN(exp_subject),
            ]
        )
        if not matched:
            yield Result(plugin, constants.ERROR,
                         key='description_mismatch',
                         expected=description,
                         got=ra_desc,
                         msg='%s agent description does not match. Found '
                         '{got} in LDAP and expected {expected}' % agent_type)
            return
        found = False
        for candidate in ra_certs:
            if candidate == cert:
                found = True
                break
        if not found:
            yield Result(plugin, constants.ERROR,
                         key='ldap_mismatch',
                         certfile=paths.RA_AGENT_PEM,
                         dn=str(entry.dn),
                         msg='%s agent certificate in {certfile} not '
                             'found in LDAP userCertificate attribute '
                             'for the entry {dn}' % agent_type)
        yield Result(plugin, constants.SUCCESS)


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

        base_dn = DN('uid=ipara,ou=people,o=ipaca')
        yield from check_agent(self, base_dn, 'RA')


@registry
class IPAKRAAgent(IPAPlugin):
    """Validate the KRA Agent

       Compare the description and usercertificate values.
    """

    requires = ('dirsrv',)

    @duration
    def check(self):
        if not self.ca.is_configured():
            logger.debug('CA is not configured, skipping KRA Agent check')
            return

        kra = krainstance.KRAInstance(api.env.realm)
        if not kra.is_installed():
            logger.debug('KRA is not installed, skipping KRA Agent check')
            return

        base_dn = DN('uid=ipakra,ou=people,o=kra,o=ipaca')
        yield from check_agent(self, base_dn, 'KRA')


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
        pwd_file = get_token_password_file(self.ca.hsm_enabled,
                                           self.ca.token_name)
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
                token = request.get('key-token')
                if token == 'internal':
                    token = None
                dbdir = request.get('cert-database')
                try:
                    if 'pwd_file' in signature(certdb.NSSDatabase).parameters:
                        db = certdb.NSSDatabase(
                            dbdir, token=token,
                            pwd_file=pwd_file.name if pwd_file else None
                        )
                    else:
                        # Fall back to older API that doesn't support tokens
                        db = certdb.NSSDatabase(dbdir)
                except Exception as e:
                    yield Result(self, constants.ERROR,
                                 key=id,
                                 dbdir=dbdir,
                                 error=str(e),
                                 msg='Unable to open NSS database {dbdir}: '
                                     '{error}')
                    continue
                if token:
                    nickname = f'{token}:{nickname}'
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


@registry
class CertmongerStuckCheck(IPAPlugin):
    """Check for certonger requests in the stuck state
    """

    @duration
    def check(self):
        requests = certmonger._get_requests({'stuck': True})
        for request in requests:
            id = request.prop_if.Get(certmonger.DBUS_CM_REQUEST_IF, 'nickname')
            yield Result(self, constants.WARNING,
                         key=id,
                         msg='certmonger request {key} is in the '
                         'stuck state')

        if len(requests) == 0:
            yield Result(self, constants.SUCCESS, key='no_stuck')
