#
# Copyright (C) 2017  FreeIPA Contributors see COPYING for license
#

"""
This module contains default Debian-specific implementations of system tasks.
"""

from __future__ import absolute_import

import logging
import os
import shutil
from pathlib import Path

from ipaplatform.base.tasks import BaseTaskNamespace
from ipaplatform.redhat.tasks import RedHatTaskNamespace
from ipaplatform.paths import paths

from ipapython import directivesetter
from ipapython import ipautil
from ipapython.dn import DN

logger = logging.getLogger(__name__)


class DebianTaskNamespace(RedHatTaskNamespace):
    @staticmethod
    def restore_pre_ipa_client_configuration(fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        try:
            ipautil.run(["pam-auth-update",
                         "--package", "--remove", "mkhomedir"])
        except ipautil.CalledProcessError:
            return False
        return True

    @staticmethod
    def set_nisdomain(nisdomain):
        # Debian doesn't use authconfig, nothing to set
        return True

    @staticmethod
    def modify_nsswitch_pam_stack(sssd, mkhomedir, statestore, sudo=True,
                                  subid=False):
        if mkhomedir:
            try:
                ipautil.run(["pam-auth-update",
                             "--package", "--enable", "mkhomedir"])
            except ipautil.CalledProcessError:
                return False
            return True
        else:
            return True

    @staticmethod
    def modify_pam_to_use_krb5(statestore):
        # Debian doesn't use authconfig, this is handled by pam-auth-update
        return True

    @staticmethod
    def backup_auth_configuration(path):
        # Debian doesn't use authconfig, nothing to backup
        return True

    @staticmethod
    def restore_auth_configuration(path):
        # Debian doesn't use authconfig, nothing to restore
        return True

    def migrate_auth_configuration(self, statestore):
        # Debian doesn't have authselect
        return True

    def configure_httpd_wsgi_conf(self):
        # Debian doesn't require special mod_wsgi configuration
        pass

    def configure_httpd_protocol(self):
        # TLS 1.3 is not yet supported
        directivesetter.set_directive(paths.HTTPD_SSL_CONF,
                                      'SSLProtocol',
                                      'TLSv1.2', False)

    def setup_httpd_logging(self):
        # Debian handles httpd logging differently
        pass

    def configure_pkcs11_modules(self, fstore):
        # Debian doesn't use p11-kit
        pass

    def restore_pkcs11_modules(self, fstore):
        pass

    def platform_insert_ca_certs(self, ca_certs):
        # ca-certificates does not use this file, so it doesn't matter if we
        # fail to create it.
        try:
            self.write_p11kit_certs(paths.IPA_P11_KIT, ca_certs),
        except Exception:
            logger.exception("""\
Could not create p11-kit anchor trust file. On Debian this file is not
used by ca-certificates and is provided for information only.\
""")

        return any([
            self.write_ca_certificates_dir(
                paths.CA_CERTIFICATES_DIR, ca_certs
            ),
            self.remove_ca_certificates_bundle(
                paths.CA_CERTIFICATES_BUNDLE_PEM
            ),
        ])

    def write_ca_certificates_dir(self, directory, ca_certs):
        # pylint: disable=ipa-forbidden-import
        from ipalib import x509  # FixMe: break import cycle
        # pylint: enable=ipa-forbidden-import

        path = Path(directory)
        try:
            path.mkdir(mode=0o755, exist_ok=True)
        except Exception:
            logger.error("Could not create %s", path)
            raise

        for cert, nickname, trusted, _ext_key_usage, _serial in ca_certs:
            if not trusted:
                continue

            # I'm not handling errors here because they have already
            # been checked by the time we get here
            subject = DN(cert.subject)
            issuer = DN(cert.issuer)

            # Construct the certificate filename using the Subject DN so that
            # the user can see which CA a particular file is for, and include
            # the serial number to disambiguate clashes where a subordinate CA
            # had a new certificate issued.
            #
            # Strictly speaking, certificates are uniquely idenified by (Issuer
            # DN, Serial Number). Do we care about the possibility of a clash
            # where a subordinate CA had two certificates issued by different
            # CAs who used the same serial number?)
            filename = f'{subject.ldap_text()} {cert.serial_number}.crt'

            # pylint: disable=old-division
            cert_path = path / filename
            # pylint: enable=old-division
            try:
                f = open(cert_path, 'w')
            except Exception:
                logger.error("Could not create %s", cert_path)
                raise

            with f:
                try:
                    os.fchmod(f.fileno(), 0o644)
                except Exception:
                    logger.error("Could not set mode of %s", cert_path)
                    raise

                try:
                    f.write(f"""\
This file was created by IPA. Do not edit.

Description: {nickname}
Subject: {subject.ldap_text()}
Issuer: {issuer.ldap_text()}
Serial Number (dec): {cert.serial_number}
Serial Number (hex): {cert.serial_number:#x}

""")
                    pem = cert.public_bytes(x509.Encoding.PEM).decode('ascii')
                    f.write(pem)
                except Exception:
                    logger.error("Could not write to %s", cert_path)
                    raise

        return True

    def platform_remove_ca_certs(self):
        return any([
            self.remove_ca_certificates_dir(paths.CA_CERTIFICATES_DIR),
            self.remove_ca_certificates_bundle(paths.IPA_P11_KIT),
            self.remove_ca_certificates_bundle(
                paths.CA_CERTIFICATES_BUNDLE_PEM
            ),
        ])

    def remove_ca_certificates_dir(self, directory):
        path = Path(paths.CA_CERTIFICATES_DIR)
        if not path.exists():
            return False

        try:
            shutil.rmtree(path)
        except Exception:
            logger.error("Could not remove %s", path)
            raise

        return True

    # Debian doesn't use authselect, so call disable_ldap_automount
    def disable_ldap_automount(self, statestore):
        return BaseTaskNamespace.disable_ldap_automount(self, statestore)

tasks = DebianTaskNamespace()
