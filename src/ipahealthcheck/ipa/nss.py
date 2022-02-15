#
# Copyright (C) 2021 FreeIPA Contributors see COPYING for license
#

import grp
import logging

from ipaplatform.constants import constants as platform_constants

from ipahealthcheck.ipa.plugin import IPAPlugin, registry
from ipahealthcheck.core.plugin import Result
from ipahealthcheck.core.plugin import duration
from ipahealthcheck.core import constants

logger = logging.getLogger()

# A tuple of groups and a tuple of expected members
#
# For example the apache user needs to be in the ipaapi group so
# the tuple would look like: 'ipaapi', ('apache',).
#
# The second value is a tuple so that we can more easily extend if
# multiple users need to be a member of a group.
#
# (group_name, (members,))
GROUP_MEMBERS = (
    (platform_constants.IPAAPI_GROUP, (platform_constants.HTTPD_USER,)),
)


@registry
class IPAGroupMemberCheck(IPAPlugin):
    """
    Ensure that nss/POSIX group membership is as expected.

    This can be critical for security and/or proper access control and
    is primarily being checked for privilege separation. The ipaapi
    user needs to be able to read ccaches created by Apache.
    """
    @duration
    def check(self):
        for (group, members) in GROUP_MEMBERS:
            try:
                grp_group = grp.getgrnam(group)
            except KeyError:
                yield Result(self, constants.ERROR,
                             key=group,
                             msg='group {key} does not exist')
                continue
            for member in members:
                if member not in grp_group.gr_mem:
                    yield Result(self, constants.ERROR,
                                 key=group,
                                 member=member,
                                 msg='{member} is not a member of group {key}')
                else:
                    yield Result(self, constants.SUCCESS,
                                 key=group,
                                 member=member)
