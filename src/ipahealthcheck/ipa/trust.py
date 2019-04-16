#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

import logging
import os
import SSSDConfig

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

from ipalib import api
from ipaplatform.paths import paths
from ipapython import ipautil
from ipapython.dn import DN

try:
    from ipaserver.masters import ENABLED_SERVICE
except ImportError:
    from ipaserver.install.service import ENABLED_SERVICE
try:
    from ipapython.ipaldap import realm_to_serverid
except ImportError:
    from ipaserver.install.installutils import realm_to_serverid
from ipaserver.install.adtrust import retrieve_netbios_name
from ipaserver.install.adtrustinstance import make_netbios_name

logger = logging.getLogger()


def get_trust_domains():
    """
    Get the list of AD trust domains from IPA

    The caller is expected to catch any exceptions.
    """
    result = api.Command.trust_find()
    results = result['result']
    trust_domains = []
    for result in results:
        if result.get('trusttype')[0] == 'Active Directory domain':
            trust_domains.append(result.get('cn')[0])
    return trust_domains


@registry
class IPATrustAgentCheck(IPAPlugin):
    """
    Check the values that should be set when configures as a trust agent.
    """
    @duration
    def check(self):
        if not self.registry.trust_agent:
            logger.debug('Not a trust agent, skipping')
            return

        try:
            sssdconfig = SSSDConfig.SSSDConfig()
            sssdconfig.import_config()
        except Exception as e:
            logger.debug('Failed to parse sssd.conf: %s', e)
            yield Result(self, constants.CRITICAL, error=str(e),
                         msg='Unable to parse sssd.conf: {error}')
            return
        else:
            domains = sssdconfig.list_active_domains()

        errors = False
        for name in domains:
            domain = sssdconfig.get_domain(name)
            try:
                provider = domain.get_option('id_provider')
            except SSSDConfig.NoOptionError:
                continue
            if provider == "ipa":
                try:
                    mode = domain.get_option('ipa_server_mode')
                except SSSDConfig.NoOptionError:
                    yield Result(self, constants.ERROR,
                                 key='ipa_server_mode_missing',
                                 attr='ipa_server_mode',
                                 domain=name,
                                 sssd_config=paths.SSSD_CONF,
                                 msg='{sssd_config} is missing {attr} '
                                     'in the domain {domain}')
                    errors = True
                else:
                    if not mode:
                        yield Result(self, constants.ERROR,
                                     key='ipa_server_mode_false',
                                     attr='ipa_server_mode',
                                     domain=name,
                                     sssd_config=paths.SSSD_CONF,
                                     msg='{attr} is not True in {sssd_config} '
                                         'in the domain {domain}')
                        errors = True

            if not errors:
                yield Result(self, constants.SUCCESS)


@registry
class IPATrustDomainsCheck(IPAPlugin):
    """
    Check the trust domains
    """
    @duration
    def check(self):
        if not self.registry.trust_agent:
            logger.debug('Not a trust agent, skipping')
            return

        result = ipautil.run([paths.SSSCTL, "domain-list"], raiseonerr=False,
                             capture_output=True)
        if result.returncode != 0:
            yield Result(self, constants.ERROR,
                         key='domain_list_error',
                         sslctl=paths.SSSCTL,
                         error=result.error_log,
                         msg='Execution of {sslctl} failed: {error}')
            return
        sssd_domains = result.output.strip().split('\n')
        if 'implicit_files' not in sssd_domains:
            yield Result(self, constants.WARNING,
                         key='implicit_files',
                         sslctl=paths.SSSCTL,
                         msg='{key} not in {sslctl} output')
        else:
            sssd_domains.remove('implicit_files')

        try:
            trust_domains = get_trust_domains()
        except Exception as e:
            yield Result(self, constants.WARNING,
                         key='trust-find',
                         error=str(e),
                         msg='Execution of {key} failed: {error}')
            trust_domains = []

        if api.env.domain in sssd_domains:
            sssd_domains.remove(api.env.domain)
        else:
            yield Result(self, constants.ERROR,
                         key=api.env.domain,
                         sslctl=paths.SSSCTL,
                         msg='{key} not in {sslctl} domain-list')

        trust_domains_out = ', '.join(trust_domains)
        sssd_domains_out = ', '.join(sssd_domains)

        if set(trust_domains).symmetric_difference(set(sssd_domains)):
            yield Result(self, constants.ERROR,
                         key='domain-list',
                         sslctl=paths.SSSCTL,
                         sssd_domains=sssd_domains_out,
                         trust_domains=trust_domains_out,
                         msg='{sslctl} {key} reports mismatch: '
                         'sssd domains {sssd_domains} '
                         'trust domains {trust_domains}')
        else:
            yield Result(self, constants.SUCCESS,
                         key='domain-list',
                         sssd_domains=sssd_domains_out,
                         trust_domains=trust_domains_out)

        for domain in sssd_domains:
            args = [paths.SSSCTL, "domain-status", domain, "--online"]
            try:
                result = ipautil.run(args, capture_output=True)
            except Exception as e:
                yield Result(self, constants.WARNING,
                             key='domain-status',
                             error=str(e),
                             msg='Execution of {key} failed: {error}')
                continue
            else:
                if result.output.strip() != 'Online status: Online':
                    yield Result(self, constants.WARNING,
                                 key='domain-status',
                                 domain=domain,
                                 msg='Domain {domain} is not online')
                else:
                    yield Result(self, constants.SUCCESS,
                                 key='domain-status',
                                 domain=domain)


@registry
class IPATrustCatalogCheck(IPAPlugin):
    """
    Resolve an AD user

    This should populate the 'AD Global catalog' and 'AD Domain Controller'
    fields in 'sssctl domain-status' output (means SSSD actually talks to AD
    DCs)
    """
    @duration
    def check(self):
        if not self.registry.trust_agent:
            logger.debug('Not a trust agent, skipping')
            return

        try:
            trust_domains = get_trust_domains()
        except Exception as e:
            yield Result(self, constants.WARNING,
                         key='trust-find',
                         error=str(e),
                         msg='Execution of {key} failed: {error}')
            trust_domains = []

        for domain in trust_domains:
            try:
                ipautil.run(['/bin/id', "Administrator@%s" % domain],
                            capture_output=True)
            except Exception as e:
                yield Result(self, constants.WARNING,
                             key='/bin/id',
                             error=str(e),
                             msg='Execution of {key} failed: {error}')
                continue

            args = [paths.SSSCTL, "domain-status", domain, "--active-server"]
            try:
                result = ipautil.run(args, capture_output=True)
            except Exception as e:
                yield Result(self, constants.ERROR,
                             key='domain-status',
                             error=str(e),
                             msg='Execution of {key} failed: {error}')
                continue
            else:
                for txt in ['AD Global Catalog', 'AD Domain Controller']:
                    if txt not in result.output:
                        yield Result(self, constants.ERROR,
                                     key=txt,
                                     output=result.output.strip(),
                                     sssctl=paths.SSSCTL,
                                     domain=domain,
                                     msg='{key} not found in {sssctl} '
                                     '\'domain-status\' output: {output}')
                    else:
                        yield Result(self, constants.SUCCESS,
                                     key=txt,
                                     domain=domain)


@registry
class IPAsidgenpluginCheck(IPAPlugin):
    """
    Verify that the sidgen 389-ds plugins are enabled
    """
    @duration
    def check(self):
        if not self.registry.trust_agent:
            logger.debug('Not a trust agent, skipping')
            return

        for plugin in ['IPA SIDGEN', 'ipa-sidgen-task']:
            sidgen_dn = DN(('cn', plugin), "cn=plugins,cn=config")
            try:
                entry = self.conn.get_entry(
                    sidgen_dn,
                    attrs_list=['nsslapd-pluginEnabled'])
            except Exception as e:
                yield Result(self, constants.ERROR,
                             key=plugin,
                             error=str(e),
                             msg='Error retrieving 389-ds plugin {key}: '
                             '{error}')
            else:
                enabled = entry.get('nsslapd-pluginEnabled', [])
                if len(enabled) != 1:
                    yield Result(self, constants.ERROR,
                                 key=plugin,
                                 dn=str(sidgen_dn),
                                 attr=enabled,
                                 msg='{key}: unexpected value in '
                                 'nsslapd-pluginEnabled in entry {dn}'
                                 '{attr}')
                    continue
                if entry.get('nsslapd-pluginEnabled', [])[0].lower() != 'on':
                    yield Result(self, constants.ERROR,
                                 key=plugin,
                                 msg='389-ds plugin {key} is not enabled')
                else:
                    yield Result(self, constants.SUCCESS,
                                 key=plugin)


@registry
class IPATrustAgentMemberCheck(IPAPlugin):
    """
    Verify that the current host is a member of adtrust agents
    """
    @duration
    def check(self):
        if not self.registry.trust_agent:
            logger.debug('Not a trust agent, skipping')
            return

        agent_dn = DN(('fqdn', api.env.host), api.env.container_host,
                      api.env.basedn)
        group_dn = DN(('cn', 'adtrust agents'), api.env.container_sysaccounts,
                      api.env.basedn)
        try:
            entry = self.conn.get_entry(
                agent_dn,
                attrs_list=['memberOf'])
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key=str(agent_dn),
                         error=str(e),
                         msg='Error retrieving ldap entry {key}: '
                         '{error}')
        else:
            memberof = entry.get('memberof', [])
            for member in memberof:
                if DN(member) == group_dn:
                    yield Result(self, constants.SUCCESS,
                                 key=api.env.host)
                    return

            yield Result(self, constants.ERROR,
                         key=api.env.host,
                         group='adtrust agents',
                         msg='{key} is not a member of {group}')


@registry
class IPATrustControllerPrincipalCheck(IPAPlugin):
    """
    Verify that the current host cifs principal is a member of adtrust agents
    """
    @duration
    def check(self):
        if not self.registry.trust_controller:
            logger.debug('Not a trust controller, skipping')
            return

        agent_dn = DN(('krbprincipalname',
                      'cifs/%s@%s' % (api.env.host, api.env.realm)),
                      api.env.container_service, api.env.basedn)
        group_dn = DN(('cn', 'adtrust agents'), api.env.container_sysaccounts,
                      api.env.basedn)
        try:
            entry = self.conn.get_entry(
                agent_dn,
                attrs_list=['memberOf'])
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key=str(agent_dn),
                         error=str(e),
                         msg='Error retrieving ldap entry {key}: '
                         '{error}')
        else:
            memberof = entry.get('memberof', [])
            for member in memberof:
                if DN(member) == group_dn:
                    yield Result(self, constants.SUCCESS,
                                 key='cifs/%s@%s' %
                                 (api.env.host, api.env.realm))
                    return

            yield Result(self, constants.ERROR,
                         key='cifs/%s@%s' % (api.env.host, api.env.realm),
                         group='adtrust agents',
                         msg='{key} is not a member of {group}')


@registry
class IPATrustControllerServiceCheck(IPAPlugin):
    """
    Verify that the current host starts the ADTRUST service.
    """
    @duration
    def check(self):
        if not self.registry.trust_controller:
            logger.debug('Not a trust controller, skipping')
            return

        service_dn = DN(('cn', 'ADTRUST'), ('cn', api.env.host),
                        api.env.container_masters, api.env.basedn)

        try:
            entry = self.conn.get_entry(
                service_dn,
                attrs_list=['ipaconfigstring'])
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key=str(service_dn),
                         error=str(e),
                         msg='Error retrieving ldap entry {key}: '
                         '{error}')
        else:
            configs = entry.get('ipaconfigstring', [])
            enabled = False
            for config in configs:
                if config == ENABLED_SERVICE:
                    enabled = True
                    break

            if enabled:
                yield Result(self, constants.SUCCESS,
                             key='ADTRUST')
            else:
                yield Result(self, constants.ERROR,
                             key='ADTRUST',
                             msg='{key} service is not enabled')


@registry
class IPATrustControllerConfCheck(IPAPlugin):
    """
    Verify that smb.conf matches the template
    """
    @duration
    def check(self):
        if not self.registry.trust_controller:
            logger.debug('Not a trust controller, skipping')
            return

        netbios_name = retrieve_netbios_name(api)
        host_netbios_name = make_netbios_name(api.env.host)
        ldapi_socket = "%%2fvar%%2frun%%2fslapd-%s.socket" % \
                       realm_to_serverid(api.env.realm)

        sub_dict = dict(REALM=api.env.realm,
                        SUFFIX=api.env.basedn,
                        NETBIOS_NAME=netbios_name,
                        HOST_NETBIOS_NAME=host_netbios_name,
                        LDAPI_SOCKET=ldapi_socket)

        template = os.path.join(paths.USR_SHARE_IPA_DIR, "smb.conf.template")
        expected_conf = ipautil.template_file(template, sub_dict)

        try:
            result = ipautil.run(['net', 'conf', 'list'], capture_output=True)
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key='net_conf_list',
                         error=str(e),
                         msg='Execution of {key} failed: {error}')
        else:
            conf = result.output.replace('\n', '')
            conf = conf.replace('\t', '')
            conf = conf.replace(' ', '')
            expected_conf = expected_conf.replace('\n', '')
            expected_conf = expected_conf.replace(' ', '')

            if conf != expected_conf:
                yield Result(self, constants.ERROR,
                             key='net_conf_list',
                             template=template,
                             msg='net conf list output doesn\'t match '
                             '{template}')
            else:
                yield Result(self, constants.SUCCESS,
                             key='net_conf_list')


@registry
class IPATrustControllerGroupSIDCheck(IPAPlugin):
    """
    Verify that the admins group's SID ends with 512 (Domain Admins RID)
    """
    @duration
    def check(self):
        if not self.registry.trust_controller:
            logger.debug('Not a trust controller, skipping')
            return

        admins_dn = DN(('cn', 'admins'),
                       api.env.container_group, api.env.basedn)

        try:
            entry = self.conn.get_entry(
                admins_dn,
                attrs_list=['ipantsecurityidentifier'])
        except Exception as e:
            yield Result(self, constants.ERROR,
                         key=str(admins_dn),
                         error=str(e),
                         msg='Error retrieving ldap entry {key}: '
                         '{error}')
            return

        identifier = entry.get('ipantsecurityidentifier', [None])[0]
        if not identifier or not identifier.endswith('512'):
            yield Result(self, constants.ERROR,
                         key='ipantsecurityidentifier',
                         rid=identifier,
                         msg='{key} is not a Domain Admins RID')
        else:
            yield Result(self, constants.SUCCESS,
                         rid=identifier,
                         key='ipantsecurityidentifier')
