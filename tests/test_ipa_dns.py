#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from dns import (
    rdata,
    rdataclass,
    rdatatype,
    message,
    rrset,
)
from dns.resolver import Answer, NoAnswer

from base import BaseTest
from util import capture_results, m_api
from unittest.mock import patch

from ipahealthcheck.core import config, constants
from ipahealthcheck.ipa.plugin import registry
from ipahealthcheck.ipa.idns import IPADNSSystemRecordsCheck

from ipapython.dnsutil import DNSName
from ipaserver.dns_data_management import (
    IPA_DEFAULT_MASTER_SRV_REC,
    IPA_DEFAULT_ADTRUST_SRV_REC
)


def add_srv_records(qname, port_map, priority=0, weight=100):
    rdlist = []
    for name, port in port_map:
        answerlist = []
        for host in qname:
            hostname = DNSName(host)
            rd = rdata.from_text(
                rdataclass.IN, rdatatype.SRV,
                '{0} {1} {2} {3}'.format(
                    priority, weight, port, hostname.make_absolute()
                )
            )
            answerlist.append(rd)
        rdlist.append(answerlist)
    return rdlist


def query_srv(qname, ad_records=False):
    """
    Return a SRV for each service IPA cares about for all the hosts.

    This is pre-generated as a side-effect for each test.
    """
    rdlist = add_srv_records(qname, IPA_DEFAULT_MASTER_SRV_REC)
    if ad_records:
        rdlist.extend(add_srv_records(qname, IPA_DEFAULT_ADTRUST_SRV_REC))
    return rdlist


class Response:
    """Fake class so that a DNS NoAnswer can be raised"""
    def __init__(self, question=None):
        self.question = question

    @property
    def question(self):
        return self.__question

    @question.setter
    def question(self, question):
        self.__question = question


def gen_addrs(num):
    """Generate sequential IP addresses for the ipa-ca A record lookup"""
    ips = []
    for i in range(num):
        ips.append('192.168.0.%d' % (i + 1))

    return ips


def fake_query(qname, rdtype=rdatatype.A, rdclass=rdataclass.IN, count=1,
               fake_txt=False):
    """Fake a DNS query, returning count responses to the request

       Three kinds of lookups are faked:
       1. A query for A records for a service will return the count
          as requested in the test. This simulates lookups for the
          ipa-ca A record. To force a difference in responses one can
          vary the count.
       2. AAAA records are not yet supported, return no answer
       3. TXT queries will return the Kerberos realm

       fake_txt will set an invalid Kerberos realm entry to provoke a
       warning.
    """
    m = message.Message()
    if rdtype == rdatatype.A:
        fqdn = DNSName(qname)
        fqdn = fqdn.make_absolute()

        answers = Answer(fqdn, rdataclass.IN, rdatatype.A, m,
                         raise_on_no_answer=False)

        rlist = rrset.from_text_list(fqdn, 86400, rdataclass.IN,
                                     rdatatype.A, gen_addrs(count))

        answers.rrset = rlist
    elif rdtype == rdatatype.AAAA:
        raise NoAnswer(response=Response('no AAAA'))
    elif rdtype == rdatatype.TXT:
        if fake_txt:
            realm = 'FAKE_REALM'
        else:
            realm = m_api.env.realm
        qname = DNSName('_kerberos.' + m_api.env.domain)
        qname = qname.make_absolute()

        answers = Answer(qname, rdataclass.IN, rdatatype.TXT, m,
                         raise_on_no_answer=False)

        rlist = rrset.from_text_list(qname, 86400, rdataclass.IN,
                                     rdatatype.TXT, [realm])

        answers.rrset = rlist

    return answers


# Helpers to generate an appropriate number of A records for the
# ipa-ca and Kerberos realm responses. Optionally return a bogus
# TXT record.
def fake_query_one(qname, rdtype=rdatatype.A, rdclass=rdataclass.IN,
                   count=1):
    return fake_query(qname, rdtype, rdclass, count)


def fake_query_two(qname, rdtype=rdatatype.A, rdclass=rdataclass.IN,
                   count=2):
    return fake_query(qname, rdtype, rdclass, count)


def fake_query_three(qname, rdtype=rdatatype.A, rdclass=rdataclass.IN,
                     count=3):
    return fake_query(qname, rdtype, rdclass, count)


def fake_query_one_txt(qname, rdtype=rdatatype.A, rdclass=rdataclass.IN,
                       count=1):
    return fake_query(qname, rdtype, rdclass, count, fake_txt=True)


def get_results_by_severity(results, severity):
    """Return the results with a matching severity"""
    new_results = []
    for result in results:
        if result.result == severity:
            new_results.append(result)
    return new_results


class TestDNSSystemRecords(BaseTest):
    """Test that the SRV records checks are working properly

       The intention was to not override IPASystemRecords since
       this is the core mechanism that IPA uses to determine what
       recoreds should exist.

       Instead the DNS lookups are managed. This is done in two
       ways:

       1. The query_srv() override returns the set of configured
          servers for each type of SRV record.
       2. fake_query() overrides dns.resolver.query to simulate
          A, AAAA and TXT record lookups.
    """
    @patch('ipapython.dnsutil.query_srv')
    @patch('dns.resolver.query')
    def test_dnsrecords_single(self, mock_query, mock_query_srv):
        """Test single CA master, all SRV records"""
        mock_query.side_effect = fake_query_one
        mock_query_srv.side_effect = query_srv([m_api.env.host])

        m_api.Command.server_find.side_effect = [{
            'result': [
                {
                    'cn': [m_api.env.host],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
            ]
        }]
        framework = object()
        registry.initialize(framework)
        f = IPADNSSystemRecordsCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 9

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.idns'
            assert result.check == 'IPADNSSystemRecordsCheck'

    @patch('ipapython.dnsutil.query_srv')
    @patch('dns.resolver.query')
    def test_dnsrecords_two(self, mock_query, mock_query_srv):
        """Test two CA masters, all SRV records"""
        mock_query_srv.side_effect = query_srv([
            m_api.env.host,
            'replica.' + m_api.env.domain
        ])
        mock_query.side_effect = fake_query_two

        m_api.Command.server_find.side_effect = [{
            'result': [
                {
                    'cn': [m_api.env.host],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
            ]
        }]

        framework = object()
        registry.initialize(framework)
        f = IPADNSSystemRecordsCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 17

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.idns'
            assert result.check == 'IPADNSSystemRecordsCheck'

    @patch('ipapython.dnsutil.query_srv')
    @patch('dns.resolver.query')
    def test_dnsrecords_three(self, mock_query, mock_query_srv):
        """Test three CA masters, all SRV records"""
        mock_query_srv.side_effect = query_srv([
            m_api.env.host,
            'replica.' + m_api.env.domain,
            'replica2.' + m_api.env.domain
        ])
        mock_query.side_effect = fake_query_three

        m_api.Command.server_find.side_effect = [{
            'result': [
                {
                    'cn': [m_api.env.host],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica2.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
            ]
        }]

        framework = object()
        registry.initialize(framework)
        f = IPADNSSystemRecordsCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 25

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.idns'
            assert result.check == 'IPADNSSystemRecordsCheck'

    @patch('ipapython.dnsutil.query_srv')
    @patch('dns.resolver.query')
    def test_dnsrecords_three_mixed(self, mock_query, mock_query_srv):
        """Test three masters, only one with a CA, all SRV records"""
        mock_query_srv.side_effect = query_srv([
            m_api.env.host,
            'replica.' + m_api.env.domain,
            'replica2.' + m_api.env.domain
        ])
        mock_query.side_effect = fake_query_one

        m_api.Command.server_find.side_effect = [{
            'result': [
                {
                    'cn': [m_api.env.host],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica2.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'IPA master'
                    ],
                },
            ]
        }]

        framework = object()
        registry.initialize(framework)
        f = IPADNSSystemRecordsCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 23

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.idns'

    @patch('ipapython.dnsutil.query_srv')
    @patch('dns.resolver.query')
    def test_dnsrecords_missing_server(self, mock_query, mock_query_srv):
        """Drop one of the masters from query_srv

           This will simulate missing SRV records and cause a number of
           warnings to be thrown.
        """
        mock_query_srv.side_effect = query_srv([
            m_api.env.host,
            'replica.' + m_api.env.domain
            # replica2 is missing
        ])
        mock_query.side_effect = fake_query_three

        m_api.Command.server_find.side_effect = [{
            'result': [
                {
                    'cn': [m_api.env.host],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica2.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
            ]
        }]

        framework = object()
        registry.initialize(framework)
        f = IPADNSSystemRecordsCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 25

        ok = get_results_by_severity(self.results.results, constants.SUCCESS)
        warn = get_results_by_severity(self.results.results, constants.WARNING)
        assert len(ok) == 18
        assert len(warn) == 7

        for result in warn:
            assert result.kw.get('msg') == 'Expected SRV record missing'

    @patch('ipapython.dnsutil.query_srv')
    @patch('dns.resolver.query')
    def test_dnsrecords_missing_ipa_ca(self, mock_query, mock_query_srv):
        """Drop one of the masters from query_srv

           This will simulate missing SRV records and cause a number of
           warnings to be thrown.
        """
        mock_query_srv.side_effect = query_srv([
            m_api.env.host,
            'replica.' + m_api.env.domain,
            'replica2.' + m_api.env.domain
        ])
        mock_query.side_effect = fake_query_two

        m_api.Command.server_find.side_effect = [{
            'result': [
                {
                    'cn': [m_api.env.host],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica2.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
            ]
        }]

        framework = object()
        registry.initialize(framework)
        f = IPADNSSystemRecordsCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 25

        ok = get_results_by_severity(self.results.results, constants.SUCCESS)
        warn = get_results_by_severity(self.results.results, constants.WARNING)
        assert len(ok) == 24
        assert len(warn) == 1

        for result in warn:
            assert result.kw.get('msg') == \
                'Got {count} ipa-ca A records, expected {expected}'
            assert result.kw.get('count') == 2
            assert result.kw.get('expected') == 3

    @patch('ipapython.dnsutil.query_srv')
    @patch('dns.resolver.query')
    def test_dnsrecords_extra_srv(self, mock_query, mock_query_srv):
        """An extra SRV record set exists, report it.

           Add an extra master to the query_srv() which will generate
           a full extra set of SRV records for the master.
        """
        mock_query_srv.side_effect = query_srv([
            m_api.env.host,
            'replica.' + m_api.env.domain,
            'replica2.' + m_api.env.domain,
            'replica3.' + m_api.env.domain
        ])
        mock_query.side_effect = fake_query_three

        m_api.Command.server_find.side_effect = [{
            'result': [
                {
                    'cn': [m_api.env.host],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
                {
                    'cn': ['replica2.' + m_api.env.domain],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
            ]
        }]

        framework = object()
        registry.initialize(framework)
        f = IPADNSSystemRecordsCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 32

        ok = get_results_by_severity(self.results.results, constants.SUCCESS)
        warn = get_results_by_severity(self.results.results, constants.WARNING)
        assert len(ok) == 25
        assert len(warn) == 7

        for result in warn:
            assert result.kw.get('msg') == \
                'Unexpected SRV entry in DNS'

    @patch('ipapython.dnsutil.query_srv')
    @patch('dns.resolver.query')
    def test_dnsrecords_bad_realm(self, mock_query, mock_query_srv):
        """Unexpected Kerberos TXT record"""
        mock_query.side_effect = fake_query_one_txt
        mock_query_srv.side_effect = query_srv([m_api.env.host])

        m_api.Command.server_find.side_effect = [{
            'result': [
                {
                    'cn': [m_api.env.host],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master'
                    ],
                },
            ]
        }]
        framework = object()
        registry.initialize(framework)
        f = IPADNSSystemRecordsCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 9

        ok = get_results_by_severity(self.results.results, constants.SUCCESS)
        warn = get_results_by_severity(self.results.results, constants.WARNING)
        assert len(ok) == 8
        assert len(warn) == 1

        result = warn[0]
        assert result.kw.get('msg') == 'expected realm missing'
        assert result.kw.get('key') == '\"FAKE_REALM\"'

    @patch('ipapython.dnsutil.query_srv')
    @patch('dns.resolver.query')
    def test_dnsrecords_one_with_ad(self, mock_query, mock_query_srv):
        mock_query.side_effect = fake_query_one
        mock_query_srv.side_effect = query_srv([m_api.env.host], True)

        m_api.Command.server_find.side_effect = [{
            'result': [
                {
                    'cn': [m_api.env.host],
                    'enabled_role_servrole': [
                        'CA server',
                        'IPA master',
                        'AD trust controller'
                    ],
                },
            ]
        }]
        framework = object()
        registry.initialize(framework)
        f = IPADNSSystemRecordsCheck(registry)

        f.config = config.Config()
        self.results = capture_results(f)

        assert len(self.results) == 15

        for result in self.results.results:
            assert result.result == constants.SUCCESS
            assert result.source == 'ipahealthcheck.ipa.idns'
            assert result.check == 'IPADNSSystemRecordsCheck'
