
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
        for srv, hosts in srv_rec.items():
            logger.debug("Search DNS for SRV record of %s", srv)
            try:
                answers = query_srv(srv)
            except DNSException as e:
                logger.debug("DNS record not found: %s", e.__class__.__name__)
                answers = []
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

        for uri, hosts in uri_rec.items():
            logger.debug("Search DNS for URI record of %s", uri)
            answers = query_uri(uri)
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

        for txt, realms in txt_rec.items():
            logger.debug("Search DNS for TXT record of %s", txt)
            try:
                answers = resolve(txt, rdatatype.TXT)
            except DNSException as e:
                logger.debug("DNS record not found: %s", e.__class__.__name__)
                answers = []

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

        # Verify that all of the ipa-ca record IPs match those of
        # servers with a CA role. Report any missing or unexpected.
        qname = "ipa-ca." + api.env.domain + "."
        ipa_ca_records = []
        for dtype in (rdatatype.A, rdatatype.AAAA):
            logger.debug("Search DNS for %s records of %s", dtype.name, qname)
            try:
                answers = resolve(qname, dtype)
            except DNSException as e:
                logger.debug("DNS record not found: %s", e.__class__.__name__)
                answers = []
            for answer in answers:
                ipa_ca_records.append(answer.to_text())

        # Get the set of servers with the 'CA server' role
        ca_servers = {}
        for server in system_records.servers_data:
            host = system_records.servers_data.get(server)
            if 'CA server' in host.get('roles'):
                for dtype in (rdatatype.A, rdatatype.AAAA):
                    try:
                        a = resolve(server + '.', dtype)
                    except DNSException as e:
                        logger.debug("DNS lookup of %s failed: %s",
                                     server, e)
                        if server not in ca_servers:
                            ca_servers[server] = ['']
                    else:
                        for answer in a:
                            if server in ca_servers:
                                ca_servers[server].append(answer.to_text())
                            else:
                                ca_servers[server] = [answer.to_text()]

        # If no DNS records for ipa-ca were found at all short circuit
        # looping through the CA and IP-addr list since the latter will
        # be empty by definition and just report them all missing.
        if len(ca_servers) > 0 and len(ipa_ca_records) == 0:
            for server in ca_servers:
                yield Result(self, constants.WARNING,
                             key='ipa_ca_missing_%s' % server,
                             server=server,
                             msg='missing IP address for ipa-ca server '
                                 '{server}')
            return

        all_ca_ipaddr = []
        for server, ipaddrs in ca_servers.items():
            for ipaddr in ipaddrs:
                all_ca_ipaddr.append(ipaddr)

        # Loop through the ipa-ca records to determine if any are not
        # in the collection of all the reported CA server IPs.
        errors = 0
        for ipaddr in ipa_ca_records:
            if ipaddr not in all_ca_ipaddr:
                errors += 1
                yield Result(self, constants.WARNING,
                             key='ipa_ca_non_server_%s' % ipaddr,
                             ipaddr=ipaddr,
                             msg='Unexpected ipa-ca address {ipaddr}')

        # Remove any IP addresses we found for ipa-ca from the set of
        # IP addresses for all the IPA servers. Any remaining ones
        # are not in the ipa-ca A/AAAA record. We're only looking at
        # the DNS advertised servers so hidden ones should not be
        # here.
        for server, ipaddrs in ca_servers.items():
            for ipaddr in ipa_ca_records:
                if ipaddr in ipaddrs:
                    ipaddrs.remove(ipaddr)

        for server, ipaddrs in ca_servers.items():
            if ipaddrs:
                errors += 1
                yield Result(self, constants.WARNING,
                             key='ipa_ca_missing_%s' % server,
                             server=server,
                             ipaddr=', '.join(ipaddrs),
                             msg='expected ipa-ca to contain {ipaddr} for '
                                 '{server}')

        if errors == 0:
            yield Result(self, constants.SUCCESS, key='ipa_ca_check')
