#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This RHEL base platform module exports platform related constants.
'''

# Fallback to default constant definitions
from __future__ import absolute_import

from ipaplatform.redhat.constants import (
    RedHatConstantsNamespace, User, Group
)
from ipaplatform.osinfo import osinfo

# RHEL 7 and earlier use /etc/sysconfig/nfs
# RHEL 8 uses /etc/nfs.conf
HAS_NFS_CONF = osinfo.version_number >= (8,)
# RHEL 9 uses pkcs11 as openssl engine
HAS_PKCS11_OPENSSL_ENGINE = osinfo.version_number == (9,)

# RHEL 10 and later deprecated OpenSSL engine and recommend using OpenSSL
# provider API.
HAS_OPENSSL_PROVIDER = osinfo.version_number >= (10,)

__all__ = ("constants", "User", "Group")


class RHELConstantsNamespace(RedHatConstantsNamespace):
    IPA_ADTRUST_PACKAGE_NAME = "ipa-server-trust-ad"
    IPA_DNS_PACKAGE_NAME = "ipa-server-dns"
    if HAS_NFS_CONF:
        SECURE_NFS_VAR = None
    if HAS_PKCS11_OPENSSL_ENGINE:
        NAMED_OPENSSL_ENGINE = "pkcs11"
    if HAS_OPENSSL_PROVIDER:
        NAMED_OPENSSL_PROVIDER = True

constants = RHELConstantsNamespace()
