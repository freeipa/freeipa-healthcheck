#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#
from unittest import mock, TestCase
from util import no_exceptions
from util import ADtrustBasedRole, ServiceBasedRole


class BaseTest(TestCase):
    """
    Base class for tests.

    Most tests use the same set of mocks so centralize and apply them
    once when the class of tests is created.

    A child class defines self.patches as a dictionary of functions
    and Mock values. These are applied once when the class starts up.

    If a test needs a particular value then it will need to use
    @patch individually.

    A default set of Mock patches is set because they apply to all or
    nearly all test cases.
    """
    default_patches = {
        'ipaserver.install.installutils.check_server_configuration':
        mock.Mock(return_value=None),
        'ipaserver.servroles.ServiceBasedRole':
        mock.Mock(return_value=ServiceBasedRole()),
        'ipaserver.servroles.ADtrustBasedRole':
        mock.Mock(return_value=ADtrustBasedRole()),
    }
    patches = {}
    results = None
    applied_patches = None

    def setup_class(self):
        # collect the list of patches to be applied for this class of
        # tests
        self.default_patches.update(self.patches)

        self.applied_patches = [
            mock.patch(patch, data) for patch, data in
            self.default_patches.items()
        ]

        for patch in self.applied_patches:
            patch.start()

    def teardown_class(self):
        mock.patch.stopall()

    def tearDown(self):
        """
        Ensure that no exceptions snuck into the results which might not
        be noticed because an exception may have the same result as
        the expected result.
        """
        no_exceptions(self.results)
