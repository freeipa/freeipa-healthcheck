#
# Copyright (C) 2021 FreeIPA Contributors see COPYING for license
#

import logging
import lxml.etree
import re

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

from ipaplatform.paths import paths


logger = logging.getLogger()


def read_ipa_pki_proxy():
    """Read the IPA Proxy configuration file

       Split out to make it easier to mock
    """
    with open(paths.HTTPD_IPA_PKI_PROXY_CONF, "r") as fd:
        lines = fd.readlines()

    return lines


@registry
class IPAProxySecretCheck(IPAPlugin):
    """
    Ensure that the proxy secrets match between tomcat and Apache

    Also report if tomcat has both secret and requiredSecret
    defined and whether all three secrets match.
    """
    @duration
    def check(self):
        if not self.ca.is_configured():
            logger.debug("CA is not configured, skipping IPAProxySecretCheck")
            return

        PROXY_SECRETS = 'proxy_secrets'

        # so many things can go wrong just keep one big global to
        # determine if we can eventually return SUCCESS
        failures = False

        server_xml = lxml.etree.parse(paths.PKI_TOMCAT_SERVER_XML)
        doc = server_xml.getroot()

        # no AJP connector means nothing to check
        connectors = doc.xpath('//Connector[@protocol="AJP/1.3"]')
        if len(connectors) == 0:
            yield Result(self, constants.CRITICAL,
                         key=PROXY_SECRETS,
                         server_xml=paths.PKI_TOMCAT_SERVER_XML,
                         msg='No AJP/1.3 Connectors defined in {server_xml}')
            return

        # IPA only deals with the first connect so that's all we'll check
        connector = connectors[0]

        ajp_secret = []
        if 'secret' in connector.attrib:
            ajp_secret.append(connector.attrib['secret'])

        if 'requiredSecret' in connector.attrib:
            ajp_secret.append(connector.attrib['requiredSecret'])

        if len(ajp_secret) > 1:
            if ajp_secret[0] != ajp_secret[1]:
                failures = True
                yield Result(
                    self, constants.WARNING,
                    key=PROXY_SECRETS,
                    server_xml=paths.PKI_TOMCAT_SERVER_XML,
                    msg='The AJP secrets in {server_xml} do not match'
                )
        # We could warn that both secret and requiredSecret are defined
        # but the presence of both with the same password doesn't
        # break anything so we will not warn for now.

        lines = read_ipa_pki_proxy()

        proxy_secrets = []
        PROXY_RE = r'\s+ProxyPassMatch ajp://localhost:8009 secret=(\w+)$'
        # Collect all the ipa-pki-proxy.conf secrets and ensure they all match
        for line in lines:
            m = re.match(PROXY_RE, line)
            if m:
                proxy_secrets.extend(m.groups(1))

        if not proxy_secrets:
            failures = True
            yield Result(
                self, constants.CRITICAL,
                key=PROXY_SECRETS,
                proxy_conf=paths.HTTPD_IPA_PKI_PROXY_CONF,
                msg='No ProxyPassMatch secrets found in {proxy_conf}'
            )
            return

        if len(set(proxy_secrets)) != 1:
            failures = True
            yield Result(
                self, constants.CRITICAL,
                key=PROXY_SECRETS,
                proxy_conf=paths.HTTPD_IPA_PKI_PROXY_CONF,
                msg='Not all ProxyPassMatch secrets match in {proxy_conf}'
            )

        for secret in proxy_secrets:
            if secret not in ajp_secret:
                failures = True
                yield Result(
                    self, constants.CRITICAL,
                    key=PROXY_SECRETS,
                    server_xml=paths.PKI_TOMCAT_SERVER_XML,
                    msg='A ProxyPassMatch secret not found in {server_xml}'
                )

        if not failures:
            yield Result(self, constants.SUCCESS,
                         key=PROXY_SECRETS)
