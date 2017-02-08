#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
from __future__ import print_function

from ipalib import api
from ipalib.cli import cli_plugins
try:
    import ipaserver
except ImportError:
    ipaserver = None


pytest_plugins = [
    'ipatests.pytest_plugins.additional_config',
    'ipatests.pytest_plugins.beakerlib',
    'ipatests.pytest_plugins.declarative',
    'ipatests.pytest_plugins.nose_compat',
]
# The integration plugin is not available in client-only builds.
if ipaserver is not None:
    pytest_plugins.append('ipatests.pytest_plugins.integration')


MARKERS = [
    'tier0: basic unit tests and critical functionality',
    'tier1: functional API tests',
    'cs_acceptance: Acceptance test suite for Dogtag Certificate Server',
    'ds_acceptance: Acceptance test suite for 389 Directory Server',
]


NO_RECURSE_DIRS = [
    # build directories
    'ipaclient/build',
    'ipalib/build',
    'ipaplatform/build',
    'ipapython/build',
    'ipaserver/build',
    'ipatests/build',
    # install/share/wsgi.py
    'install/share'
]

INIVALUES = {
    'python_classes': ['test_', 'Test'],
    'python_files': ['test_*.py'],
    'python_functions': ['test_*'],
}


def pytest_configure(config):
    # add pytest markers
    for marker in MARKERS:
        config.addinivalue_line('markers', marker)

    # do not recurse into build directories or install/share directory.
    for norecursedir in NO_RECURSE_DIRS:
        config.addinivalue_line('norecursedirs', norecursedir)

    # addinivalue_line() adds duplicated entries and does not remove existing.
    for name, values in INIVALUES.items():
        current = config.getini(name)
        current[:] = values

    # set default JUnit prefix
    if config.option.junitprefix is None:
        config.option.junitprefix = 'ipa'

    # always run doc tests
    config.option.doctestmodules = True


def pytest_addoption(parser):
    def truefalse(arg):
        if arg.lower() == 'true':
            return True
        if arg.lower() == 'false':
            return False
        return arg  # triggers an error later

    group = parser.getgroup("IPA integration tests")
    group.addoption(
        '--in-server',
        dest="ipa_in_server",
        type=truefalse,
        choices=(True, False),
        default=False,
        help="Run IPA tests with in-server API (talk directly to LDAP, avoid "
             "http communications). Requires to run test on "
             "installed server (default: False)"
    )


def pytest_cmdline_main(config):
    api.bootstrap(
        context=u'cli', in_server=config.option.ipa_in_server,
        in_tree=True, fallback=False
    )
    for klass in cli_plugins:
        api.add_plugin(klass)
    api.finalize()
