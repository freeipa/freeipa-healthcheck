
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from dns import rdatatype
from dns.exception import DNSException
import logging

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result, duration
from ipahealthcheck.core import constants

from ipalib import api

try:
    from dns.resolver import resolve
except ImportError:
    from dns.resolver import query as resolve


logger = logging.getLogger()


def query_uri(uri):
    try:
        answers = resolve(uri, rdatatype.URI)
    except DNSException as e:
        logger.debug("DNS record not found: %s", e.__class__.__name__)
        answers = []
    return answers


@registry
class IPADNSSystemRecordsCheck(IPAPlugin):
    """
    Verify that the expected DNS service records are resolvable.

    IPA will already provide the values we need to validate with the
    IPASystemRecords class. We just need to pull that and do the
    equivalent DNS lookups.
    """
    requires = ('dirsrv',)

    def srv_to_name(self, srv, target):
        """Combine the SRV record and target into a unique name."""
        return srv + ":" + target

    def uri_to_name(self, uri, target):
        """Combine the SRV record and target into a unique name."""
        return uri + ":" + target

    @duration
    def check(self):
        # pylint: disable=import-outside-toplevel
        from ipapython.dnsutil import query_srv
        from ipaserver.dns_data_management import IPASystemRecords
        # pylint: enable=import-outside-toplevel

        system_records = IPASystemRecords(api)
        base_records = system_records.get_base_records()

        # collect the list of expected values
        txt_rec = dict()
        srv_rec = dict()
        uri_rec = dict()
        a_rec = list()
        aaaa_rec = list()

        for name, node in base_records.items():
            for rdataset in node:
                for rd in rdataset:
                    if rd.rdtype == rdatatype.SRV:
                        if name.ToASCII() in srv_rec:
                            srv_rec[name.ToASCII()].append(rd.target.to_text())
                        else:
                            srv_rec[name.ToASCII()] = [rd.target.to_text()]
                    elif rd.rdtype == rdatatype.TXT:
                        if name.ToASCII() in txt_rec:
                            txt_rec[name.ToASCII()].append(rd.to_text())
                        else:
                            txt_rec[name.ToASCII()] = [rd.to_text()]
                    elif rd.rdtype == rdatatype.A:
                        a_rec.append(rd.to_text())
                    elif rd.rdtype == rdatatype.AAAA:
                        aaaa_rec.append(rd.to_text())
                    elif rd.rdtype == rdatatype.URI:
                        if name.ToASCII() in uri_rec:
                            uri_rec[name.ToASCII()].append(
                                rd.target.decode('utf-8')
                            )
                        else:
                            uri_rec[name.ToASCII()] = [
                                rd.target.decode('utf-8')
                            ]
                    else:
                        logger.error("Unhandled rdtype %d", rd.rdtype)

        # For each SRV record that IPA thinks it should have, do a DNS
        # lookup of it and ensure that DNS has the same set of values
        # that IPA thinks it should.
        for srv in srv_rec:
            logger.debug("Search DNS for SRV record of %s", srv)
            try:
                answers = query_srv(srv)
            except DNSException as e:
                logger.debug("DNS record not found: %s", e.__class__.__name__)
                answers = []
            hosts = srv_rec[srv]
            for answer in answers:
                logger.debug("DNS record found: %s", answer)
                try:
                    hosts.remove(answer.target.to_text())
                    yield Result(
                         self, constants.SUCCESS,
                         key=self.srv_to_name(srv, answer.target.to_text()))
                except ValueError:
                    yield Result(
                        self, constants.WARNING,
                        msg='Unexpected SRV entry in DNS',
                        key=self.srv_to_name(srv, answer.target.to_text()))
            for host in hosts:
                yield Result(
                    self, constants.WARNING,
                    msg='Expected SRV record missing',
                    key=self.srv_to_name(srv, host))

        for uri in uri_rec:
            logger.debug("Search DNS for URI record of %s", uri)
            answers = query_uri(uri)
            hosts = uri_rec[uri]
            for answer in answers:
                logger.debug("DNS record found: %s", answer)
                try:
                    hosts.remove(answer.target.decode('utf-8'))
                    yield Result(
                         self, constants.SUCCESS,
                         key=self.uri_to_name(
                             uri, answer.target.decode('utf-8')
                         )
                    )
                except ValueError:
                    yield Result(
                        self, constants.WARNING,
                        msg='Unexpected URI entry in DNS',
                        key=self.uri_to_name(
                            uri, answer.target.decode('utf-8')
                        )
                    )
            for host in hosts:
                yield Result(
                    self, constants.WARNING,
                    msg='Expected URI record missing',
                    key=self.uri_to_name(uri, host)
                )

        for txt in txt_rec:
            logger.debug("Search DNS for TXT record of %s", txt)
            try:
                answers = resolve(txt, rdatatype.TXT)
            except DNSException as e:
                logger.debug("DNS record not found: %s", e.__class__.__name__)
                answers = []

            realms = txt_rec[txt]
            for answer in answers:
                logger.debug("DNS record found: %s", answer)
                realm = answer.to_text()
                try:
                    realms.remove(realm)
                    yield Result(self, constants.SUCCESS,
                                 key=realm)
                except ValueError:
                    yield Result(self, constants.WARNING,
                                 key=realm,
                                 msg='expected realm missing')

        if a_rec:
            # Look up the ipa-ca records
            qname = "ipa-ca." + api.env.domain + "."
            logger.debug("Search DNS for A record of %s", qname)
            try:
                answers = resolve(qname, rdatatype.A)
            except DNSException as e:
                logger.debug("DNS record not found: %s", e.__class__.__name__)
                answers = []

            for answer in answers:
                logger.debug("DNS record found: %s", answer)
                ipaddr = answer.to_text()
                try:
                    yield Result(self, constants.SUCCESS,
                                 key=ipaddr)
                except ValueError:
                    yield Result(self, constants.WARNING,
                                 key=ipaddr,
                                 msg='expected ipa-ca IPv4 address missing')

            ca_count = 0
            for server in system_records.servers_data:
                master = system_records.servers_data.get(server)
                if 'CA server' in master.get('roles'):
                    ca_count += 1

            if len(answers) != ca_count:
                yield Result(
                    self, constants.WARNING,
                    msg='Got {count} ipa-ca A records, expected {expected}',
                    count=len(answers),
                    expected=ca_count)

        if aaaa_rec:
            # Look up the ipa-ca records
            qname = "ipa-ca." + api.env.domain + "."
            logger.debug("Search DNS for AAAA record of %s", qname)
            try:
                answers = resolve(qname, rdatatype.AAAA)
            except DNSException as e:
                logger.debug("DNS record not found: %s", e.__class__.__name__)
                answers = []

            for answer in answers:
                logger.debug("DNS record found: %s", answer)
                ipaddr = answer.to_text()
                try:
                    yield Result(self, constants.SUCCESS,
                                 key=ipaddr)
                except ValueError:
                    yield Result(self, constants.WARNING,
                                 key=ipaddr,
                                 msg='expected ipa-ca IPv6 address missing')

            ca_count = 0
            for server in system_records.servers_data:
                master = system_records.servers_data.get(server)
                if 'CA server' in master.get('roles'):
                    ca_count += 1

            if len(answers) != ca_count:
                yield Result(
                    self, constants.WARNING,
                    msg='Got {count} ipa-ca AAAA records, expected {expected}',
                    count=len(answers),
                    expected=ca_count)
