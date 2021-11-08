#
# Copyright (C) 2021 FreeIPA Contributors see COPYING for license
#

from base import BaseTest
from io import BytesIO
from unittest.mock import patch
from util import capture_results
import lxml.etree

from ipahealthcheck.core import config, constants
from ipahealthcheck.meta.plugin import registry
from ipahealthcheck.ipa.proxy import IPAProxySecretCheck

# Pre-parse the XML to avoid Mock weirdness
good_xml_input = """
<Server port="8005" shutdown="SHUTDOWN">
   <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" address="127.0.0.1" name="Connector1" secret="somesecret"/>
   <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" address="::1" name="Connector1" secret="somesecret"/>
</Server>
"""  # noqa: E501
good_xml = lxml.etree.parse(BytesIO(good_xml_input.encode('utf-8')))

good_ipa_proxy = """
<LocationMatch "^/ca/ee/ca/checkRequest">
    SSLOptions +StdEnvVars +ExportCertData +StrictRequire +OptRenegotiate
    SSLVerifyClient none
    ProxyPassMatch ajp://localhost:8009 secret=somesecret
    ProxyPassReverse ajp://localhost:8009
</LocationMatch>
"""

empty_ipa_proxy = """
"""

different_secrets_ipa_proxy = """
<LocationMatch "^/ca/ee/ca/checkRequest">
    SSLOptions +StdEnvVars +ExportCertData +StrictRequire +OptRenegotiate
    SSLVerifyClient none
    ProxyPassMatch ajp://localhost:8009 secret=somesecret
    ProxyPassReverse ajp://localhost:8009
</LocationMatch>
<LocationMatch "^/ca/ee/ca/checkRequest">
    SSLOptions +StdEnvVars +ExportCertData +StrictRequire +OptRenegotiate
    SSLVerifyClient none
    ProxyPassMatch ajp://localhost:8009 secret=othersecret
    ProxyPassReverse ajp://localhost:8009
</LocationMatch>
"""

# server.xml secret won't match Apache secret
mismatch1_xml_input = """
<Server port="8005" shutdown="SHUTDOWN">
   <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" address="127.0.0.1" name="Connector1" secret="badsecret"/>
   <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" address="::1" name="Connector1" secret="badsecret"/>
</Server>
"""  # noqa: E501
mismatch1_xml = lxml.etree.parse(BytesIO(mismatch1_xml_input.encode('utf-8')))

both_secrets_xml_input = """
<Server port="8005" shutdown="SHUTDOWN">
   <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" address="127.0.0.1" name="Connector1" secret="somesecret" requiredSecret="somesecret"/>
   <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" address="::1" name="Connector1" secret="somesecret" requiredSecret="somesecret"/>
</Server>
"""  # noqa: E501
both_secrets_xml = lxml.etree.parse(
    BytesIO(both_secrets_xml_input.encode('utf-8'))
)

both_secrets_mismatch_xml_input = """
<Server port="8005" shutdown="SHUTDOWN">
   <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" address="127.0.0.1" name="Connector1" secret="somesecret" requiredSecret="othersecret"/>
   <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" address="::1" name="Connector1" secret="somesecret" requiredSecret="othersecret"/>
</Server>
"""  # noqa: E501
both_secrets_mismatch_xml = lxml.etree.parse(
    BytesIO(both_secrets_mismatch_xml_input.encode('utf-8'))
)

empty_xml_input = """
<Server port="8005" shutdown="SHUTDOWN">
</Server>
"""
empty_xml = lxml.etree.parse(BytesIO(empty_xml_input.encode('utf-8')))


class TestIPAProxySecretCheck(BaseTest):
    @patch('lxml.etree.parse')
    @patch('ipahealthcheck.ipa.proxy.read_ipa_pki_proxy')
    def test_matching_secrets(self, mock_proxy, mock_ltree):
        """The passwords match"""
        mock_ltree.return_value = good_xml
        mock_proxy.return_value = good_ipa_proxy.split('\n')

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAProxySecretCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS

    @patch('lxml.etree.parse')
    @patch('ipahealthcheck.ipa.proxy.read_ipa_pki_proxy')
    def test_xml_both_secrets(self, mock_proxy, mock_ltree):
        """server.xml defines both secret types and they match"""
        mock_ltree.return_value = both_secrets_xml
        mock_proxy.return_value = good_ipa_proxy.split('\n')

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAProxySecretCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.SUCCESS

    @patch('lxml.etree.parse')
    @patch('ipahealthcheck.ipa.proxy.read_ipa_pki_proxy')
    def test_xml_both_secret_type_mismatch(self, mock_proxy, mock_ltree):
        """XML has both secret attributes and they do not match"""
        mock_ltree.return_value = both_secrets_mismatch_xml
        mock_proxy.return_value = good_ipa_proxy.split('\n')

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAProxySecretCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.WARNING
        assert result.kw.get('msg') == 'The AJP secrets in {server_xml} do '\
                                       'not match'

    @patch('lxml.etree.parse')
    @patch('ipahealthcheck.ipa.proxy.read_ipa_pki_proxy')
    def test_xml_secret_mismatch(self, mock_proxy, mock_ltree):
        """The Apache secret doesn't match the tomcat secret"""
        mock_ltree.return_value = mismatch1_xml
        mock_proxy.return_value = good_ipa_proxy.split('\n')

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAProxySecretCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.kw.get('msg') == 'A ProxyPassMatch secret not found ' \
                                       'in {server_xml}'

    @patch('lxml.etree.parse')
    @patch('ipahealthcheck.ipa.proxy.read_ipa_pki_proxy')
    def test_xml_no_connectors(self, mock_proxy, mock_ltree):
        """No connectors found in server.xml"""
        mock_ltree.return_value = empty_xml
        mock_proxy.return_value = good_ipa_proxy.split('\n')

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAProxySecretCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.kw.get('msg') == 'No AJP/1.3 Connectors defined in ' \
                                       '{server_xml}'

    @patch('lxml.etree.parse')
    @patch('ipahealthcheck.ipa.proxy.read_ipa_pki_proxy')
    def test_no_proxypassmatch(self, mock_proxy, mock_ltree):
        """No connectors found in server.xml"""
        mock_ltree.return_value = good_xml
        mock_proxy.return_value = empty_ipa_proxy.split('\n')

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAProxySecretCheck(registry)

        self.results = capture_results(f)

        assert len(self.results) == 1

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.kw.get('msg') == 'No ProxyPassMatch secrets found ' \
                                       'in {proxy_conf}'

    @patch('lxml.etree.parse')
    @patch('ipahealthcheck.ipa.proxy.read_ipa_pki_proxy')
    def test_proxypassmatch_different_secrets(self, mock_proxy, mock_ltree):
        """No connectors found in server.xml"""
        mock_ltree.return_value = good_xml
        mock_proxy.return_value = different_secrets_ipa_proxy.split('\n')

        framework = object()
        registry.initialize(framework, config.Config())
        f = IPAProxySecretCheck(registry)

        self.results = capture_results(f)

        print(self.results.results)
        assert len(self.results) == 2

        result = self.results.results[0]
        assert result.result == constants.CRITICAL
        assert result.kw.get('msg') == 'Not all ProxyPassMatch secrets ' \
                                       'match in {proxy_conf}'

        result = self.results.results[1]
        assert result.result == constants.CRITICAL
        assert result.kw.get('msg') == 'A ProxyPassMatch secret not found ' \
                                       'in {server_xml}'
