from idmcheck.ipa.plugin import IPAPlugin, registry
from idmcheck.core.plugin import Result, Results
from idmcheck.core import constants

from ipalib import api
from ipalib import x509
from ipalib.install import certmonger
from ipaplatform.paths import paths
from ipapython.certdb import unparse_trust_flags
from ipaserver.install import certs
from ipaserver.install import dsinstance


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

    if ca.is_configured():
        requests += ca_requests

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

    return requests


@registry
class IPACertCheck(IPAPlugin):
    def check(self):
        pass


@registry
class IPANSSCheck(IPAPlugin):
    def check(self):
        pass


@registry
class IPACertTracking(IPAPlugin):
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
                                msg='Failure trying to remove % from '
                                'list: %s' % (request_id, e))
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
            flags = unparse_trust_flags(_trust_flags)
            if nickname.startswith('caSigningCert cert-pki-ca'):
                expected = 'CTu,Cu,Cu'
            else:
                try:
                    expected = expected_trust[nickname]
                except KeyError:
                    # FIXME: is this a warning, skip?
                    print("%s not found, assuming 3rd party" % nickname)
                    continue
            if flags != expected:
                result = Result(
                    self, constants.ERROR, key=nickname,
                    msg='Incorrect NSS trust for %s. Got %s expected %s'
                    % (nickname, flags, expected))
                results.add(result)

        return results
