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
