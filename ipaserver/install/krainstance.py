# Authors: Ade Lee <alee@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

from __future__ import absolute_import

import logging
import os
import shutil
import tempfile

from ipalib import api
from ipalib import x509
from ipalib.constants import KRA_TRACKING_REQS
from ipaplatform.paths import paths
from ipapython import directivesetter
from ipapython import ipautil
from ipapython.dn import DN
from ipaserver.install import cainstance
from ipaserver.install import installutils
from ipaserver.install.dogtaginstance import DogtagInstance
from ipaserver.install.ca import (
    lookup_random_serial_number_version,
    lookup_hsm_configuration
)


logger = logging.getLogger(__name__)

# When IPA is installed with DNS support, this CNAME should hold all IPA
# replicas with KRA configured
IPA_KRA_RECORD = "ipa-kra"

ADMIN_GROUPS = [
    'Enterprise CA Administrators',
    'Enterprise KRA Administrators',
    'Security Domain Administrators'
]

KRA_BASEDN = DN(('o', 'kra'), ('o', 'ipaca'))
KRA_AGENT_DN = DN(('uid', 'ipakra'), ('ou', 'people'), KRA_BASEDN)


class KRAInstance(DogtagInstance):
    """
    We assume that the CA has already been installed, and we use the
    same tomcat instance to host both the CA and KRA.
    The same RA agent certificate used with the CA will be used for the
    KRA.
    """

    # Mapping of nicknames for tracking requests, and the profile to
    # use for that certificate.  'configure_renewal()' reads this
    # dict.  The profile MUST be specified.
    tracking_reqs = KRA_TRACKING_REQS

    def __init__(self, realm):
        super(KRAInstance, self).__init__(
            realm=realm,
            subsystem="KRA",
            service_desc="KRA server",
            config=paths.KRA_CS_CFG_PATH,
        )

    def uninstall(self):
        DogtagInstance.uninstall(self)

        ipautil.remove_file(paths.KRACERT_P12)

    def configure_instance(self, realm_name, host_name, dm_password,
                           admin_password, pkcs12_info=None, master_host=None,
                           subject_base=None, ca_subject=None,
                           promote=False, pki_config_override=None,
                           token_password=None):
        """Create a KRA instance.

           To create a clone, pass in pkcs12_info.
        """
        self.fqdn = host_name
        self.dm_password = dm_password
        self.admin_groups = ADMIN_GROUPS
        self.admin_password = admin_password
        self.pkcs12_info = pkcs12_info
        if self.pkcs12_info is not None or promote:
            self.clone = True
        self.master_host = master_host
        self.pki_config_override = pki_config_override
        # The remaining token values are available via sysrestore
        self.token_password = token_password

        self.subject_base = \
            subject_base or installutils.default_subject_base(realm_name)

        # eagerly convert to DN to ensure validity
        self.ca_subject = DN(ca_subject)

        self.realm = realm_name
        self.suffix = ipautil.realm_to_suffix(realm_name)

        # Confirm that a KRA does not already exist
        if self.is_installed():
            raise RuntimeError(
                "KRA already installed.")
        # Confirm that a Dogtag 10 CA instance already exists
        ca = cainstance.CAInstance(self.realm)
        if not ca.is_installed():
            raise RuntimeError(
                "KRA configuration failed.  "
                "A Dogtag CA must be installed first")

        if promote:
            self.step("creating ACIs for admin", self.add_ipaca_aci)
            self.step("creating installation admin user", self.setup_admin)
        self.step("configuring KRA instance", self.__spawn_instance)
        if not self.clone:
            self.step("create KRA agent",
                      self.__create_kra_agent)
        if promote:
            self.step("destroying installation admin user",
                      self.teardown_admin)
        self.step("enabling ephemeral requests", self.enable_ephemeral)
        self.step("restarting KRA", self.restart_instance)
        self.step("configure certmonger for renewals",
                  self.configure_certmonger_renewal_helpers)
        self.step("configure certificate renewals", self.configure_renewal)
        if not self.clone:
            self.step("add vault container", self.__add_vault_container)
        self.step("apply LDAP updates", self.__apply_updates)

        self.step("enabling KRA instance", self.__enable_instance)

        try:
            self.start_creation(runtime=120)
        finally:
            self.clean_pkispawn_files()

    def __spawn_instance(self):
        """
        Create and configure a new KRA instance using pkispawn.
        Creates a configuration file with IPA-specific
        parameters and passes it to the base class to call pkispawn
        """

        self.tmp_agent_db = tempfile.mkdtemp(
                prefix="tmp-", dir=paths.VAR_LIB_IPA)
        tmp_agent_pwd = ipautil.ipa_generate_password()

        # Create a temporary file for the admin PKCS #12 file
        (admin_p12_fd, admin_p12_file) = tempfile.mkstemp()
        os.close(admin_p12_fd)

        cfg = dict(
            pki_issuing_ca_uri="https://{}".format(
                ipautil.format_netloc(self.fqdn, 443)),
            # Client security database
            pki_client_database_dir=self.tmp_agent_db,
            pki_client_database_password=tmp_agent_pwd,
            pki_client_database_purge=True,
            pki_client_pkcs12_password=self.admin_password,
            pki_import_admin_cert=False,
            pki_client_admin_cert_p12=admin_p12_file,
        )
        if lookup_random_serial_number_version(api) > 0:
            cfg['pki_key_id_generator'] = 'random'
            cfg['pki_request_id_generator'] = 'random'
        else:
            cfg['pki_key_id_generator'] = 'legacy'
            cfg['pki_request_id_generator'] = 'legacy'

        if not (os.path.isdir(paths.PKI_TOMCAT_ALIAS_DIR) and
                os.path.isfile(paths.PKI_TOMCAT_PASSWORD_CONF)):
            # generate pin which we know can be used for FIPS NSS database
            pki_pin = ipautil.ipa_generate_password()
            cfg['pki_server_database_password'] = pki_pin
        else:
            pki_pin = None

        ca = cainstance.CAInstance(self.realm)
        if ca.hsm_enabled:
            cfg['pki_hsm_enable'] = True
            cfg['pki_token_name'] = ca.token_name
            cfg['pki_token_password'] = self.token_password
            cfg['pki_sslserver_token'] = 'internal'
            # Require OAEP for nfast devices as they do not support
            # PKCS1v15.
            (_unused, token_library_path) = lookup_hsm_configuration(api)
            if 'nfast' in token_library_path:
                cfg['pki_use_oaep_rsa_keywrap'] = True

        p12_tmpfile_name = None

        if self.clone:
            krafile = self.pkcs12_info[0]
            if krafile:
                _p12_tmpfile_handle, p12_tmpfile_name = tempfile.mkstemp(
                    dir=paths.TMP
                )
                shutil.copy(krafile, p12_tmpfile_name)
                self.service_user.chown(p12_tmpfile_name)

            self._configure_clone(
                cfg,
                security_domain_hostname=self.fqdn,
                clone_pkcs12_path=p12_tmpfile_name,
            )
            cfg.update(
                pki_clone_setup_replication=False,
            )
        else:
            # the admin cert file is needed for the first instance of KRA
            cert = self.get_admin_cert()
            # First make sure that the directory exists
            parentdir = os.path.dirname(paths.ADMIN_CERT_PATH)
            if not os.path.exists(parentdir):
                os.makedirs(parentdir)
            x509.write_certificate(cert, paths.ADMIN_CERT_PATH)

        # Generate configuration file
        config = self._create_spawn_config(cfg)
        with tempfile.NamedTemporaryFile('w', delete=False) as f:
            config.write(f)
            self.service_user.chown(f.fileno())
            cfg_file = f.name

        nolog_list = [
            self.dm_password, self.admin_password, pki_pin, tmp_agent_pwd
        ]

        try:
            DogtagInstance.spawn_instance(
                self, cfg_file,
                nolog_list=nolog_list
            )
        finally:
            if p12_tmpfile_name:
                os.remove(p12_tmpfile_name)
            os.remove(cfg_file)
            os.remove(admin_p12_file)

        if config.getboolean(
            self.subsystem, 'pki_backup_keys', fallback=True
        ):
            shutil.move(paths.KRA_BACKUP_KEYS_P12, paths.KRACERT_P12)
        logger.debug("completed creating KRA instance")

    def __create_kra_agent(self):
        """
        Create KRA agent, assign a certificate, and add the user to
        the appropriate groups for accessing KRA services.
        """
        conn = api.Backend.ldap2

        # get RA agent certificate
        cert = x509.load_certificate_from_file(paths.RA_AGENT_PEM)

        # create ipakra user with RA agent certificate
        entry = conn.make_entry(
            KRA_AGENT_DN,
            objectClass=['top', 'person', 'organizationalPerson',
                         'inetOrgPerson', 'cmsuser'],
            uid=["ipakra"],
            sn=["IPA KRA User"],
            cn=["IPA KRA User"],
            usertype=["undefined"],
            userCertificate=[cert],
            description=['2;%s;%s;%s' % (
                cert.serial_number,
                self.ca_subject,
                DN(('CN', 'IPA RA'), self.subject_base))])
        conn.add_entry(entry)

        # add ipakra user to Data Recovery Manager Agents group
        group_dn = DN(
            ('cn', 'Data Recovery Manager Agents'), ('ou', 'groups'),
            KRA_BASEDN)
        conn.add_entry_to_group(KRA_AGENT_DN, group_dn, 'uniqueMember')

    def __add_vault_container(self):
        self._ldap_mod(
            'vault.ldif', {'SUFFIX': self.suffix}, raise_on_err=True)

    def __apply_updates(self):
        self._ldap_update(['40-vault.update'])

    def enable_ephemeral(self):
        """
        Enable ephemeral KRA requests to reduce the number of LDAP
        write operations.
        """
        with installutils.stopped_service('pki-tomcatd', 'pki-tomcat'):
            directivesetter.set_directive(
                self.config,
                'kra.ephemeralRequests',
                'true', quotes=False, separator='=')

        # A restart is required

    def enable_oaep_wrap_algo(self):
        """
        Enable KRA OAEP key wrap algorithm
        """
        with installutils.stopped_service('pki-tomcatd', 'pki-tomcat'):
            directivesetter.set_directive(
                self.config,
                'keyWrap.useOAEP',
                'true', quotes=False, separator='=')

        # A restart is required

    def update_cert_config(self, nickname, cert):
        """
        When renewing a KRA subsystem certificate the configuration file
        needs to get the new certificate as well.

        nickname is one of the known nicknames.
        cert is a DER-encoded certificate.
        """

        # The cert directive to update per nickname
        directives = {
            'auditSigningCert cert-pki-kra': 'kra.audit_signing.cert',
            'storageCert cert-pki-kra': 'kra.storage.cert',
            'transportCert cert-pki-kra': 'kra.transport.cert',
            'subsystemCert cert-pki-kra': 'kra.subsystem.cert',
            'Server-Cert cert-pki-ca': 'kra.sslserver.cert'}

        if nickname in directives:
            super(KRAInstance, self).update_cert_cs_cfg(
                directives[nickname], cert)

    def __enable_instance(self):
        self.ldap_configure('KRA', self.fqdn, None, self.suffix)
