# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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

"""
Python-level packaging using setuptools
"""
from os.path import abspath, dirname
import sys

custodia_authenticators = [
    'IPAInterface = ipaserver.custodia.ipa.interface:IPAInterface',
    ('SimpleCredsAuth = '
     'ipaserver.custodia.httpd.authenticators:SimpleCredsAuth'),
]

custodia_authorizers = [
    'SimplePathAuthz = ipaserver.custodia.httpd.authorizers:SimplePathAuthz',
    'UserNameSpace = ipaserver.custodia.httpd.authorizers:UserNameSpace',
    'KEMKeysStore = ipaserver.custodia.message.kem:KEMKeysStore',
    'IPAKEMKeys = ipaserver.secrets.kem:IPAKEMKeys',
]

custodia_clients = [
    'KEMClient = ipaserver.custodia.client:CustodiaKEMClient',
    'SimpleClient = ipaserver.custodia.client:CustodiaSimpleClient',
]

custodia_consumers = [
    'Forwarder = ipaserver.custodia.forwarder:Forwarder',
    'Secrets = ipaserver.custodia.secrets:Secrets',
    'Root = ipaserver.custodia.root:Root',
]


if __name__ == '__main__':
    # include ../ for ipasetup.py
    sys.path.append(dirname(dirname(abspath(__file__))))
    from ipasetup import ipasetup  # noqa: E402

    ipasetup(
        name='ipaserver',
        doc=__doc__,
        package_dir={'ipaserver': ''},
        packages=[
            'ipaserver',
            'ipaserver.advise',
            'ipaserver.advise.plugins',
            'ipaserver.custodia',
            'ipaserver.custodia.httpd',
            'ipaserver.custodia.message',
            'ipaserver.custodia.server',
            'ipaserver.dnssec',
            'ipaserver.plugins',
            'ipaserver.secrets',
            'ipaserver.secrets.handlers',
            'ipaserver.install',
            'ipaserver.install.plugins',
            'ipaserver.install.server',
        ],
        install_requires=[
            "cryptography",
            "dbus-python",
            "dnspython",
            # dogtag-pki is just the client package on PyPI. ipaserver
            # requires the full pki package.
            # "dogtag-pki",
            "ipaclient",
            "ipalib",
            "ipaplatform",
            "ipapython",
            "jwcrypto",
            "lxml",
            "netaddr",
            "psutil",
            "pyasn1",
            "requests",
            "six",
            "python-augeas",
            "python-ldap",
        ],
        entry_points={
            'ipaserver.custodia.authenticators': custodia_authenticators,
            'ipaserver.custodia.authorizers': custodia_authorizers,
            'ipaserver.custodia.clients': custodia_clients,
            'ipaserver.custodia.consumers': custodia_consumers,
            'ipaserver.custodia.stores': [
                'IPASecStore = ipaserver.secrets.store:IPASecStore',
            ],
        },
        extras_require={
            # These packages are currently not available on PyPI.
            "dcerpc": ["samba", "pysss", "pysss_nss_idmap"],
            "hbactest": ["pyhbac"],
            "install": ["SSSDConfig"],
            "trust": ["pysss_murmur", "pysss_nss_idmap"],
        }
    )
