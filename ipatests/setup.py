# Copyright (C) 2007  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""FreeIPA tests

FreeIPA is a server for identity, policy, and audit.
"""
from os.path import abspath, dirname
import sys

if __name__ == '__main__':
    # include ../ for ipasetup.py
    sys.path.append(dirname(dirname(abspath(__file__))))
    from ipasetup import ipasetup  # noqa: E402

    ipasetup(
        name="ipatests",
        doc=__doc__,
        package_dir={'ipatests': ''},
        packages=[
            "ipatests",
            "ipatests.pytest_ipa",
            "ipatests.pytest_ipa.integration",
            "ipatests.test_cmdline",
            "ipatests.test_custodia",
            "ipatests.test_install",
            "ipatests.test_integration",
            "ipatests.test_ipaclient",
            "ipatests.test_ipalib",
            "ipatests.test_ipalib_install",
            "ipatests.test_ipaplatform",
            "ipatests.test_ipapython",
            "ipatests.test_ipaserver",
            "ipatests.test_ipaserver.test_install",
            "ipatests.test_ipatests_plugins",
            "ipatests.test_webui",
            "ipatests.test_xmlrpc",
            "ipatests.test_xmlrpc.tracker"
        ],
        scripts=['ipa-run-tests', 'ipa-test-config', 'ipa-test-task'],
        package_data={
            'ipatests': ['prci_definitions/*'],
            'ipatests.test_custodia': ['*.conf', 'empty.conf.d/*.conf'],
            'ipatests.test_install': ['*.update'],
            'ipatests.test_integration': ['scripts/*', 'data/*'],
            'ipatests.test_ipaclient': ['data/*/*/*'],
            'ipatests.test_ipalib': ['data/*'],
            'ipatests.test_ipaplatform': ['data/*'],
            "ipatests.test_ipaserver": ['data/*'],
            'ipatests.test_xmlrpc': ['data/*'],
        },
        install_requires=[
            "cryptography",
            "dnspython",
            "gssapi",
            "ipaclient",
            "ipalib",
            "ipaplatform",
            "ipapython",
            "polib",
            "pytest",
            "pytest_multihost",
            "python-ldap",
            "six",
            "pexpect",
        ],
        extras_require={
            "integration": ["dbus-python", "pyyaml", "ipaserver"],
            "ipaserver": ["ipaserver"],
            "webui": ["selenium", "pyyaml", "ipaserver"],
            "xmlrpc": ["ipaserver"],
            ":python_version<'3'": ["mock"],
        }
    )
