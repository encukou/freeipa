#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

'''
This base platform module exports platform dependant constants.
'''
import grp
import os
import pwd
import sys


class _Entity(str):
    __slots__ = ("_entity", )

    def __new__(cls, name):
        # if 'name' is already an instance of cls, return identical name
        if isinstance(name, cls):
            return name
        else:
            return super().__new__(cls, name)

    def __init__(self, name):
        super().__init__()
        self._entity = None

    def __str__(self):
        return super().__str__()

    def __repr__(self):
        return f'<{self.__class__.__name__} "{self!s}">'


class User(_Entity):
    __slots__ = ()

    @property
    def entity(self):
        """User information struct

        :return: pwd.struct_passwd instance
        """
        entity = self._entity
        if entity is None:
            try:
                self._entity = entity = pwd.getpwnam(self)
            except KeyError:
                raise ValueError(f"user '{self!s}' not found") from None
        return entity

    @property
    def uid(self):
        """Numeric user id (int)
        """
        return self.entity.pw_uid

    @property
    def pgid(self):
        """Primary group id (int)"""
        return self.entity.pw_gid

    def chown(self, path, gid=None, **kwargs):
        """chown() file by path or file descriptor

        gid defaults to user's primary gid. Use -1 to keep gid.
        """
        if gid is None:
            gid = self.pgid
        elif isinstance(gid, Group):
            gid = gid.gid
        os.chown(path, self.uid, gid, **kwargs)


class Group(_Entity):
    __slots__ = ()

    @property
    def entity(self):
        """Group information

        :return: grp.struct_group instance
        """
        entity = self._entity
        if entity is None:
            try:
                self._entity = entity = grp.getgrnam(self)
            except KeyError:
                try:
                    self._entity = entity = grp.getgrgid(int(self))
                except (TypeError, ValueError):
                    raise ValueError(f"group '{self!s}' not found") from None
        return entity

    @property
    def gid(self):
        """Numeric group id (int)
        """
        return self.entity.gr_gid

    def chgrp(self, path, **kwargs):
        """change group owner file by path or file descriptor
        """
        os.chown(path, -1, self.gid, **kwargs)


class BaseConstantsNamespace:
    IS_64BITS = sys.maxsize > 2 ** 32
    DEFAULT_ADMIN_SHELL = '/bin/bash'
    DEFAULT_SHELL = '/bin/sh'
    IPAAPI_USER = User("ipaapi")
    IPAAPI_GROUP = Group("ipaapi")
    DS_USER = User("dirsrv")
    DS_GROUP = Group("dirsrv")
    HTTPD_USER = User("apache")
    HTTPD_GROUP = Group("apache")
    GSSPROXY_USER = User("root")
    IPA_ADTRUST_PACKAGE_NAME = "freeipa-server-trust-ad"
    IPA_DNS_PACKAGE_NAME = "freeipa-server-dns"
    KDCPROXY_USER = User("kdcproxy")
    NAMED_USER = User("named")
    NAMED_GROUP = Group("named")
    NAMED_DATA_DIR = "data/"
    NAMED_OPTIONS_VAR = "OPTIONS"
    NAMED_OPENSSL_ENGINE = None
    NAMED_OPENSSL_PROVIDER = None
    NAMED_ZONE_COMMENT = ""
    PKI_USER = User("pkiuser")
    PKI_GROUP = Group("pkiuser")
    # ntpd init variable used for daemon options
    NTPD_OPTS_VAR = "OPTIONS"
    # quote used for daemon options
    NTPD_OPTS_QUOTE = "\""
    ODS_USER = User("ods")
    ODS_GROUP = Group("ods")
    # nfsd init variable used to enable kerberized NFS
    SECURE_NFS_VAR = "SECURE_NFS"
    SELINUX_BOOLEAN_ADTRUST = {
        'samba_portmapper': 'on',
    }
    SELINUX_BOOLEAN_HTTPD = {
        'httpd_can_network_connect': 'on',
        'httpd_manage_ipa': 'on',
        'httpd_run_ipa': 'on',
        'httpd_dbus_sssd': 'on',
    }
    # Unlike above, there are multiple use cases for SMB sharing
    # SELINUX_BOOLEAN_SMBSERVICE is a dictionary of dictionaries
    # to define set of booleans for each use case
    SELINUX_BOOLEAN_SMBSERVICE = {
        'share_home_dirs': {
            'samba_enable_home_dirs': 'on',
        },
        'reshare_nfs_with_samba': {
            'samba_share_nfs': 'on',
        },
    }
    SELINUX_BOOLEAN_SSSD = {
        'sssd_use_usb': 'on',
    }
    SELINUX_MCS_MAX = 1023
    SELINUX_MCS_REGEX = r"^c(\d+)([.,-]c(\d+))*$"
    SELINUX_MLS_MAX = 15
    SELINUX_MLS_REGEX = r"^s(\d+)(-s(\d+))?$"
    SELINUX_USER_REGEX = r"^[a-zA-Z][a-zA-Z_\.]*$"
    SELINUX_USERMAP_DEFAULT = "unconfined_u:s0-s0:c0.c1023"
    SELINUX_USERMAP_ORDER = (
        "guest_u:s0"
        "$xguest_u:s0"
        "$user_u:s0"
        "$staff_u:s0-s0:c0.c1023"
        "$sysadm_u:s0-s0:c0.c1023"
        "$unconfined_u:s0-s0:c0.c1023"
    )
    SSSD_USER = User("sssd")
    # WSGI module override, only used on Fedora
    MOD_WSGI_PYTHON2 = None
    MOD_WSGI_PYTHON3 = None
    # WSGIDaemonProcess process count. On 64bit platforms, each process
    # consumes about 110 MB RSS, from which are about 35 MB shared.
    WSGI_PROCESSES = 4 if IS_64BITS else 2
    # high ciphers without RC4, MD5, TripleDES, pre-shared key, secure
    # remote password, and DSA cert authentication.
    TLS_HIGH_CIPHERS = "HIGH:!aNULL:!eNULL:!MD5:!RC4:!3DES:!PSK:!SRP:!aDSS"


constants = BaseConstantsNamespace()
