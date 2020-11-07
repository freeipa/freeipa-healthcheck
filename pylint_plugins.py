""" Plugin to teach Pylint about FreeIPA API
"""

import textwrap

from astroid import MANAGER, register_module_extender
from astroid.builder import AstroidBuilder


def register(linter):
    pass


AstroidBuilder(MANAGER).string_build(
    textwrap.dedent(
        """
    from ipalib import api
    from ipalib import plugable

    api.Backend = plugable.APINameSpace(api, None)
    api.Command = plugable.APINameSpace(api, None)
    """
    )
)


# dnspython 2.x RR types
AstroidBuilder(MANAGER).string_build(textwrap.dedent(
    """
    import dns.flags
    import dns.rdataclass
    import dns.rdatatype

    dns.flags.AD = 0
    dns.flags.CD = 0
    dns.flags.DO = 0
    dns.flags.RD = 0

    dns.rdataclass.IN = 0

    dns.rdatatype.A = 0
    dns.rdatatype.AAAA = 0
    dns.rdatatype.CNAME = 0
    dns.rdatatype.DNSKEY = 0
    dns.rdatatype.MX = 0
    dns.rdatatype.NS = 0
    dns.rdatatype.PTR = 0
    dns.rdatatype.RRSIG = 0
    dns.rdatatype.SOA = 0
    dns.rdatatype.SRV = 0
    dns.rdatatype.TXT = 0
    dns.rdatatype.URI = 0
    """
))


def ipaplatform_paths_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.paths import paths
    __all__ = ('paths',)
    '''))


def ipaplatform_services_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.services import knownservices
    from ipaplatform.base.services import timedate_services
    from ipaplatform.base.services import service
    from ipaplatform.base.services import wellknownservices
    from ipaplatform.base.services import wellknownports
    __all__ = ('knownservices', 'timedate_services', 'service',
               'wellknownservices', 'wellknownports')
    '''))


def ipaplatform_constants_transform():
    return AstroidBuilder(MANAGER).string_build(textwrap.dedent('''
    from ipaplatform.base.constants import constants
    __all__ = ('constants',)
    '''))

register_module_extender(MANAGER, 'ipaplatform.paths',
                         ipaplatform_paths_transform)
register_module_extender(MANAGER, 'ipaplatform.services',
                         ipaplatform_services_transform)
register_module_extender(MANAGER, 'ipaplatform.constants',
                         ipaplatform_constants_transform)
