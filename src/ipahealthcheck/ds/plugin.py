#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

from ipalib import api
from ipahealthcheck.core import constants
from ipahealthcheck.core.plugin import Plugin, Result, Registry, duration
from ipaserver.install import dsinstance, installutils
try:
    from ipapython.ipaldap import realm_to_serverid
except ImportError:
    from ipaserver.install.installutils import realm_to_serverid
from lib389.cli_base import disconnect_instance, connect_instance
from lib389.properties import SER_LDAP_URL, SER_ROOT_DN


class DSArgs(dict):
    """
    Prepare the args to make a dirsrv connection that is compatible with
    lib389's Dirsrv object.
    """
    def __init__(self, inst):
        self.pwdfile = None
        self.bindpw = None
        self.prompt = False
        self.instance = inst


class DSPlugin(Plugin):
    requires = ('dirsrv',)
    check_class = None
    many = False

    def __init__(self, registry):
        super().__init__(registry)
        self.ds = self.ds = dsinstance.DsInstance()
        self.conn = api.Backend.ldap2
        self.serverid = realm_to_serverid(api.env.realm)

    def convertSev(self, ds_severity):
        """Convert lib389 HC severity level to IDM's HC level"""
        sev = ds_severity.lower()
        if sev == 'high':
            return constants.CRITICAL
        elif sev == 'medium':
            return constants.ERROR
        else:
            return constants.WARNING

    def doCheck(self, DSObj, many=False):
        """Perform a healthcheck on a specific DS/lib389 class.  First
        we need to set up the proper args and dicts to properly connect
        to the LDAP server via lib389.  Then run the classes' lint
        functions.

        :param DSObj: a class from lib389 that has built-in lint functions
                      like: Backends, Replica, Encryption, NssSsl, Config, etc
        :returns: a list of Result objects
        """
        args = DSArgs(self.serverid)
        dsrc_inst = {
            'uri': args.instance,
            'basedn': None,
            'binddn': None,
            'bindpw': None,
            'saslmech': None,
            'tls_cacertdir': None,
            'tls_cert': None,
            'tls_key': None,
            'tls_reqcert': 1,
            'starttls': False,
            'prompt': False,
            'pwdfile': None,
            'args': {}
        }
        dsrc_inst['args'][SER_LDAP_URL] = dsrc_inst['uri']
        dsrc_inst['args'][SER_ROOT_DN] = dsrc_inst['binddn']

        inst = connect_instance(dsrc_inst=dsrc_inst, verbose=False, args=args)
        ds_obj = DSObj(inst)
        results = []
        if many:
            # DS class that has many instances of itself (e.g. Backends)
            for clo in ds_obj.list():
                result = clo.lint()
                if result is not None:
                    # DS result could be a single or multiple results
                    if isinstance(result, list):
                        for single_result in result:
                            results += single_result
                    else:
                        results += result
        else:
            # Single object always returns a list of results
            results = ds_obj.lint()
        hc_results = []
        if results is not None:
            for result in results:
                hc_results.append(Result(self,
                                         self.convertSev(result['severity']),
                                         key=result['dsle'],
                                         items=result['items'],
                                         msg=result['detail']))
        disconnect_instance(inst)
        return hc_results

    @duration
    def check(self):
        results = self.doCheck(self.check_class, self.many)
        if len(results) > 0:
            for result in results:
                yield result
        else:
            yield Result(self, constants.SUCCESS)


class DSRegistry(Registry):
    def initialize(self, framework, config, options=None):
        super().initialize(framework, config)
        installutils.check_server_configuration()
        if not api.isdone('bootstrap'):
            api.bootstrap(in_server=True,
                          context='ipahealthcheck',
                          log=None)
        if not api.isdone('finalize'):
            api.finalize()


registry = DSRegistry()
