#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#
from unittest import mock, TestCase
from util import no_exceptions


class BaseTest(TestCase):
    """
    Base class for tests.

    Most tests use the same set of mocks so centralize and apply them
    once when the class of tests is created.

    A child class defines self.patches as a dictionary of functions
    and Mock values. These are applied once when the class starts up.

    If a test needs a particular value then it will need to use
    @patch individually.
    """

    def setup_class(self):
        # collect the list of patches to be applied for this class of
        # tests
        self.applied_patches = [
            mock.patch(patch, data) for patch, data in self.patches.items()
        ]

        for patch in self.applied_patches:
            patch.start()

    def teardown_class(self):
        mock.patch.stopall()

    def tearDown(self):
        """
        Ensure that no exceptions snuck into the results which might not
        be noticed because an exception may have the same severity as
        the expected result.
        """
        no_exceptions(self.results)
