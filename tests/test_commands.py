#
# Copyright (C) 2021 FreeIPA Contributors see COPYING for license
#

import os

from ipapython.ipautil import run
import pytest


def test_version():
    """
    Test the --version option
    """
    output = run(['ipa-healthcheck', '--version'], env=os.environ)
    assert 'ipahealthcheck' in output.raw_output.decode('utf-8')


@pytest.fixture
def python_ipalib_dir(tmpdir):
    ipalib_dir = tmpdir.mkdir("ipalib")
    ipalib_dir.join("__init__.py").write("")

    def _make_facts(configured=None):
        if configured is None:
            module_text = ""
        elif isinstance(configured, bool):
            module_text = f"def is_ipa_configured(): return {configured}"
        else:
            raise TypeError(
                f"'configured' must be None or bool, got '{configured!r}'"
            )

        ipalib_dir.join("facts.py").write(module_text)
        return str(tmpdir)

    return _make_facts


def test_ipa_notinstalled(python_ipalib_dir, monkeypatch):
    """
    Test ipa-healthcheck handles the missing IPA stuff
    """
    monkeypatch.setenv("PYTHONPATH", python_ipalib_dir(configured=None))
    output = run(["ipa-healthcheck"], raiseonerr=False, env=os.environ)
    assert output.returncode == 1
    assert "IPA server is not installed" in output.raw_output.decode("utf-8")


def test_ipa_unconfigured(python_ipalib_dir, monkeypatch):
    """
    Test ipa-healthcheck handles the unconfigured IPA server
    """
    monkeypatch.setenv("PYTHONPATH", python_ipalib_dir(configured=False))
    output = run(["ipa-healthcheck"], raiseonerr=False, env=os.environ)
    assert output.returncode == 1
    assert "IPA server is not configured" in output.raw_output.decode("utf-8")
