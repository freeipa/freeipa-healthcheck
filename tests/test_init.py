#
# Copyright (C) 2020 FreeIPA Contributors see COPYING for license
#

import argparse

from ipahealthcheck.core.output import output_registry


class RunChecks:
    def run_healthcheck(self):
        options = argparse.Namespace(check=None, debug=False, indent=2,
                                     list_sources=False, outfile=None,
                                     output='json', source=None,
                                     verbose=False)

        for out in output_registry.plugins:
            if out.__name__.lower() == options.output:
                out(options)
                break


def test_run_healthcheck():
    """
    Test typical initialization in run_healthcheck (based ok pki-healthcheck)
    """
    run = RunChecks()
    run.run_healthcheck()
