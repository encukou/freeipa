#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This Fedora base platform module exports platform related constants.
'''

# Fallback to default constant definitions
from __future__ import absolute_import

from ipaplatform.redhat.constants import (
    RedHatConstantsNamespace, User, Group
)
from ipaplatform.osinfo import osinfo

# Fedora 28 and earlier use /etc/sysconfig/nfs
# Fedora 30 and later use /etc/nfs.conf
# Fedora 29 has both
HAS_NFS_CONF = osinfo.version_number >= (30,)

# Fedora 40 and later deprecated OpenSSL engine and recommend using OpenSSL
# provider API.
HAS_OPENSSL_PROVIDER = osinfo.version_number >= (40,)


__all__ = ("constants", "User", "Group")


class FedoraConstantsNamespace(RedHatConstantsNamespace):
    # Fedora allows installation of Python 2 and 3 mod_wsgi, but the modules
    # can't coexist. For Apache to load correct module.
    MOD_WSGI_PYTHON2 = "modules/mod_wsgi.so"
    MOD_WSGI_PYTHON3 = "modules/mod_wsgi_python3.so"

    if HAS_NFS_CONF:
        SECURE_NFS_VAR = None

    if HAS_OPENSSL_PROVIDER:
        NAMED_OPENSSL_PROVIDER = True
    else:
        NAMED_OPENSSL_ENGINE = "pkcs11"

constants = FedoraConstantsNamespace()
