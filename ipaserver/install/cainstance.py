# Authors: Rob Crittenden <rcritten@redhat.com>
#          Ade Lee <alee@redhat.com>
#          Andrew Wnuk <awnuk@redhat.com>
#
# Copyright (C) 2009  Red Hat
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

from __future__ import print_function, absolute_import

import base64
import binascii
import enum
import logging

import dbus
import os
import re
import shutil
import sys
import syslog
import time
import tempfile
from configparser import RawConfigParser
from pkg_resources import parse_version

from ipalib import api
from ipalib import x509
from ipalib import errors
import ipalib.constants
from ipalib.install import certmonger
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks

from ipapython import directivesetter
from ipapython import dogtag
from ipapython import ipautil
from ipapython.certdb import (
    get_ca_nickname,
    IPA_CA_TRUST_FLAGS,
    EMPTY_TRUST_FLAGS)
from ipapython.dn import DN, RDN
from ipapython.ipa_log_manager import standard_logging_setup
from ipaserver.secrets.kem import IPAKEMKeys

from ipaserver.install import certs
from ipaserver.install import dsinstance
from ipaserver.install import installutils
from ipaserver.install import replication
from ipaserver.install import sysupgrade
from ipaserver.install.dogtaginstance import DogtagInstance, INTERNAL_TOKEN
from ipaserver.masters import ENABLED_SERVICE

logger = logging.getLogger(__name__)


ADMIN_GROUPS = [
    'Enterprise CA Administrators',
    'Enterprise KRA Administrators',
    'Security Domain Administrators'
]

ACME_AGENT_GROUP = 'Enterprise ACME Administrators'

PROFILES_DN = DN(('ou', 'certificateProfiles'), ('ou', 'ca'), ('o', 'ipaca'))

ACME_CONFIG_FILES = (
    ('pki-acme-configsources.conf.template',
        paths.PKI_ACME_CONFIGSOURCES_CONF),
    ('pki-acme-database.conf.template', paths.PKI_ACME_DATABASE_CONF),
    ('pki-acme-engine.conf.template', paths.PKI_ACME_ENGINE_CONF),
    ('pki-acme-issuer.conf.template', paths.PKI_ACME_ISSUER_CONF),
    ('pki-acme-realm.conf.template', paths.PKI_ACME_REALM_CONF),
)


def check_ports():
    """Check that dogtag ports (8080, 8443) are available.

    Returns True when ports are free, False if they are taken.
    """
    return all([ipautil.check_port_bindable(8443),
                ipautil.check_port_bindable(8080)])


def get_preop_pin(instance_root, instance_name):
    # Only used for Dogtag 9
    preop_pin = None

    filename = instance_root + "/" + instance_name + "/conf/CS.cfg"

    # read the config file and get the preop pin
    try:
        f = open(filename)
    except IOError as e:
        logger.error("Cannot open configuration file.%s", str(e))
        raise e
    data = f.read()
    data = data.split('\n')
    pattern = re.compile("preop.pin=(.*)")
    for line in data:
        match = re.search(pattern, line)
        if match:
            preop_pin = match.group(1)
            break

    if preop_pin is None:
        raise RuntimeError(
            "Unable to find preop.pin in %s. Is your CA already configured?" %
            filename)

    return preop_pin


def import_pkcs12(input_file, input_passwd, cert_database,
                  cert_passwd):
    ipautil.run([paths.PK12UTIL, "-d", cert_database,
                 "-i", input_file,
                 "-k", cert_passwd,
                 "-w", input_passwd])


def get_value(s):
    """
    Parse out a name/value pair from a Javascript variable.
    """
    try:
        expr = s.split('=', 1)
        value = expr[1]
        value = value.replace('\"', '')
        value = value.replace(';', '')
        value = value.replace('\\n', '\n')
        value = value.replace('\\r', '\r')
        return value
    except IndexError:
        return None


def find_substring(data, value):
    """
    Scan through a list looking for a string that starts with value.
    """
    for d in data:
        if d.startswith(value):
            return get_value(d)
    return None


def get_defList(data):
    """
    Return a dictionary of defList name/value pairs.

    A certificate signing request is specified as a series of these.
    """
    varname = None
    value = None
    skip = False
    defdict = {}
    for d in data:
        if d.startswith("defList = new Object"):
            varname = None
            value = None
            skip = False
        if d.startswith("defList.defId"):
            varname = get_value(d)
        if d.startswith("defList.defVal"):
            value = get_value(d)
            if skip:
                varname = None
                value = None
                skip = False
        if d.startswith("defList.defConstraint"):
            ctype = get_value(d)
            if ctype == "readonly":
                skip = True

        if varname and value:
            defdict[varname] = value
            varname = None
            value = None

    return defdict


def get_outputList(data):
    """
    Return a dictionary of outputList name/value pairs.

    The output from issuing a certificate is a series of these.
    """
    varname = None
    value = None
    outputdict = {}
    for d in data:
        if d.startswith("outputList = new"):
            varname = None
            value = None
        if d.startswith("outputList.outputId"):
            varname = get_value(d)
        if d.startswith("outputList.outputVal"):
            value = get_value(d)

        if varname and value:
            outputdict[varname] = value
            varname = None
            value = None

    return outputdict


def get_crl_files(path=None):
    """
    Traverse dogtag's CRL files in default CRL publish directory or in chosen
    target directory.

    @param path Custom target directory
    """
    if path is None:
        path = paths.PKI_CA_PUBLISH_DIR

    if not os.path.exists(path):
        return

    files = os.listdir(path)
    for f in files:
        if f == "MasterCRL.bin":
            yield os.path.join(path, f)
        elif f.endswith(".der"):
            yield os.path.join(path, f)


def is_step_one_done():
    """Read CS.cfg and determine if step one of an external CA install is done
    """
    path = paths.CA_CS_CFG_PATH
    if not os.path.exists(path):
        return False
    test = directivesetter.get_directive(path, 'preop.ca.type', '=')
    if test == "otherca":
        return True
    return False


def is_ca_installed_locally():
    """Check if CA is installed locally by checking for existence of CS.cfg
    :return:True/False
    """
    return os.path.exists(paths.CA_CS_CFG_PATH)


def lookup_ldap_backend(api):
    """Look up the LDAP backend database value and return it"""
    dn = DN("cn=config,cn=ldbm database,cn=plugins,cn=config")
    try:
        entry = api.Backend.ldap2.get_entry(dn)
    except errors.NotFound:
        ldap_backend = 'bdb'
    else:
        ldap_backend = entry.get('nsslapd-backend-implement', ['bdb'])[0]
    return ldap_backend


class InconsistentCRLGenConfigException(Exception):
    pass


class CAInstance(DogtagInstance):
    """
    When using a dogtag CA the DS database contains just the
    server cert for DS. The mod_nss database will contain the RA agent
    cert that will be used to do authenticated requests against dogtag.

    This is done because we use python-nss and will inherit the opened
    NSS database in mod_python. In nsslib.py we do an nssinit but this will
    return success if the database is already initialized. It doesn't care
    if the database is different or not.

    external is a state machine:
       0 = not an externally signed CA
       1 = generating CSR to be signed
       2 = have signed cert, continue installation
    """

    server_cert_name = 'Server-Cert cert-pki-ca'

    # Mapping of nicknames for tracking requests, and the profile to
    # use for that certificate.  'configure_renewal()' reads this
    # dict.  The profile MUST be specified.
    tracking_reqs = {
        'auditSigningCert cert-pki-ca': 'caSignedLogCert',
        'ocspSigningCert cert-pki-ca': 'caOCSPCert',
        'subsystemCert cert-pki-ca': 'caSubsystemCert',
        'caSigningCert cert-pki-ca': 'caCACert',
        server_cert_name: 'caServerCert',
    }
    token_names = {
        # Server-Cert always on internal token
        server_cert_name: INTERNAL_TOKEN,
    }

    # The following must be aligned with the RewriteRule defined in
    # install/share/ipa-pki-proxy.conf.template
    crl_rewrite_pattern = r"^\s*(RewriteRule\s+\^/ipa/crl/MasterCRL.bin\s.*)$"
    crl_rewrite_comment = r"^#\s*RewriteRule\s+\^/ipa/crl/MasterCRL.bin\s.*$"
    crl_rewriterule = "\nRewriteRule ^/ipa/crl/MasterCRL.bin " \
        "http://{}/ca/ee/ca/getCRL?" \
        "op=getCRL&crlIssuingPoint=MasterCRL " \
        "[L,R=301,NC]"

    def __init__(self, realm=None, host_name=None, custodia=None):
        super(CAInstance, self).__init__(
            realm=realm,
            subsystem="CA",
            service_desc="certificate server",
            host_name=host_name,
            service_prefix=ipalib.constants.PKI_GSSAPI_SERVICE_NAME,
            config=paths.CA_CS_CFG_PATH,
        )

        # for external CAs
        self.external = 0
        self.csr_file = None
        self.cert_file = None
        self.cert_chain_file = None
        self.basedn = DN(('o', 'ipaca'))

        if realm is not None:
            self.canickname = get_ca_nickname(realm)
        else:
            self.canickname = None
        self.ra_cert = None
        self.requestId = None
        self.no_db_setup = False
        self.keytab = os.path.join(
            paths.PKI_TOMCAT, self.service_prefix + '.keytab')
        # Custodia instance for RA key retrieval
        self._custodia = custodia

    def configure_instance(self, host_name, dm_password, admin_password,
                           pkcs12_info=None, master_host=None, csr_file=None,
                           cert_file=None, cert_chain_file=None,
                           master_replication_port=389,
                           subject_base=None, ca_subject=None,
                           ca_signing_algorithm=None,
                           ca_type=None, external_ca_profile=None,
                           ra_p12=None, ra_only=False,
                           promote=False, use_ldaps=False,
                           pki_config_override=None,
                           random_serial_numbers=False,
                           token_name=None, token_library_path=None,
                           token_password=None):
        """Create a CA instance.

           To create a clone, pass in pkcs12_info.

           Creating a CA with an external signer is a 2-step process. In
           step 1 we generate a CSR. In step 2 we are given the cert and
           chain and actually proceed to create the CA. For step 1 set
           csr_file. For step 2 set cert_file and cert_chain_file.
        """
        self.fqdn = host_name
        self.dm_password = dm_password
        self.admin_user = "admin"
        self.admin_groups = ADMIN_GROUPS

        # NOTE: "admin_password" refers to the password for PKI
        # "admin" account.  This is not necessarily the same as
        # the IPA admin password.  Indeed, ca.configure_instance
        # gets called with admin_password=dm_password.
        #
        self.admin_password = admin_password

        self.pkcs12_info = pkcs12_info
        if self.pkcs12_info is not None:
            self.clone = True
        self.master_host = master_host
        self.master_replication_port = master_replication_port
        self.ra_p12 = ra_p12

        self.subject_base = \
            subject_base or installutils.default_subject_base(self.realm)
        self.ca_subject = \
            ca_subject or installutils.default_ca_subject_dn(self.subject_base)

        self.ca_signing_algorithm = ca_signing_algorithm
        if ca_type is not None:
            self.ca_type = ca_type
        else:
            self.ca_type = x509.ExternalCAType.GENERIC.value
        self.external_ca_profile = external_ca_profile
        self.random_serial_numbers = random_serial_numbers
        ldap_backend = lookup_ldap_backend(api)

        if ldap_backend != 'bdb' and not random_serial_numbers:
            # override selection for lmdb due to VLV performance issues.
            logger.info(
                'Forcing random serial numbers to be enabled for the %s '
                'backend', ldap_backend
            )
            self.random_serial_numbers = True

        self.no_db_setup = promote
        self.use_ldaps = use_ldaps
        self.pki_config_override = pki_config_override

        self.tokenname = token_name
        self.token_library_path = token_library_path
        self.token_password = token_password

        # Determine if we are installing as an externally-signed CA and
        # what stage we're in.
        if csr_file is not None:
            self.csr_file = csr_file
            self.external = 1
        elif cert_file is not None:
            self.cert_file = cert_file
            self.cert_chain_file = cert_chain_file
            self.external = 2

        if self.clone:
            has_ra_cert = os.path.exists(paths.RA_AGENT_PEM)
        else:
            has_ra_cert = False

        if not ra_only:
            if promote:
                # Setup Database
                self.step("creating certificate server db", self.__create_ds_db)
                self.step("ignore time skew for initial replication",
                          self.replica_ignore_initial_time_skew)
                self.step("setting up initial replication", self.__setup_replication)
                self.step("revert time skew after initial replication",
                          self.replica_revert_time_skew)
                self.step("creating ACIs for admin", self.add_ipaca_aci)
                self.step("creating installation admin user", self.setup_admin)
            self.step("configuring certificate server instance",
                      self.__spawn_instance)
            # Config file and ACL modifications require either restart or
            # offline update of Dogtag.
            self.step("stopping certificate server instance to update CS.cfg",
                      self.stop_instance)
            self.step("backing up CS.cfg", self.safe_backup_config)
            self.step("Add ipa-pki-wait-running", self.add_ipa_wait)
            self.step("secure AJP connector", self.secure_ajp_connector)
            self.step("reindex attributes", self.reindex_task)
            self.step("exporting Dogtag certificate store pin",
                      self.create_certstore_passwdfile)
            self.step("disabling nonces", self.__disable_nonce)
            self.step("set up CRL publishing", self.__enable_crl_publish)
            self.step("enable PKIX certificate path discovery and validation",
                      self.enable_pkix)
            self.step("authorizing RA to modify profiles",
                      configure_profiles_acl)
            self.step("authorizing RA to manage lightweight CAs",
                      configure_lightweight_ca_acls)
            self.step("Ensure lightweight CAs container exists",
                      ensure_lightweight_cas_container)
            self.step("Enable lightweight CA monitor",
                      enable_lightweight_ca_monitor)
            self.step(
                "Ensuring backward compatibility",
                self.__dogtag10_migration)
            if self.random_serial_numbers:
                self.step("enable certificate pruning", self.enable_pruning)
            if promote:
                self.step("destroying installation admin user",
                          self.teardown_admin)
            # Materialize config changes and new ACLs
            self.step("starting certificate server instance",
                      self.start_instance)
            if promote:
                self.step("Finalize replication settings",
                          self.finalize_replica_config)
        # Step 1 of external is getting a CSR so we don't need to do these
        # steps until we get a cert back from the external CA.
        if self.external != 1:
            if not has_ra_cert:
                self.step("configure certmonger for renewals",
                          self.configure_certmonger_renewal_helpers)
                if not self.clone:
                    self.step("requesting RA certificate from CA", self.__request_ra_certificate)
                elif promote:
                    self.step("Importing RA key", self.__import_ra_key)
                else:
                    self.step("importing RA certificate from PKCS #12 file",
                              self.__import_ra_cert)
            if not ra_only:
                if not self.clone:
                    self.step("publishing the CA certificate",
                              self.__export_ca_chain)
                    self.step("adding RA agent as a trusted user", self.__create_ca_agent)
                self.step("configure certificate renewals", self.configure_renewal)
                self.step("Configure HTTP to proxy connections",
                          self.http_proxy)
                self.step("updating IPA configuration", update_ipa_conf)
                self.step("enabling CA instance", self.__enable_instance)
                if not promote:
                    if self.clone:
                        # DL0 workaround; see docstring of __expose_ca_in_ldap
                        self.step("exposing CA instance on LDAP",
                                  self.__expose_ca_in_ldap)

                    self.step("importing IPA certificate profiles",
                              import_included_profiles)
                    self.step("migrating certificate profiles to LDAP",
                              migrate_profiles_to_ldap)
                    self.step("adding default CA ACL", ensure_default_caacl)
                    self.step("adding 'ipa' CA entry", ensure_ipa_authority_entry)
                    if not self.clone:
                        self.step("Recording random serial number state",
                                  self.__store_random_serial_number_state)
                        self.step("Recording HSM configuration state",
                                  self.__store_hsm_configuration_state)
                else:
                    # Re-import profiles in the promote case to pick up any
                    # that will only be triggered by an upgrade.
                    self.step("importing IPA certificate profiles",
                              import_included_profiles)

                self.step("configuring certmonger renewal for lightweight CAs",
                          self.add_lightweight_ca_tracking_requests)
                if self.clone and self.random_serial_numbers:
                    self.step("Recording random serial number state",
                              self.__store_random_serial_number_state)
                if minimum_acme_support():
                    self.step("deploying ACME service", self.setup_acme)

        if ra_only:
            runtime = None
        else:
            if self.tokenname:
                runtime = "HSM dependent"
            else:
                runtime = 180

        try:
            self.start_creation(runtime=runtime)
        finally:
            if self.external == 1:
                # Don't remove client DB in external CA step 1
                # https://pagure.io/freeipa/issue/7742
                logger.debug("Keep pkispawn files for step 2")
            else:
                self.clean_pkispawn_files()

    def __spawn_instance(self):
        """
        Create and configure a new CA instance using pkispawn.
        Creates the config file with IPA specific parameters
        and passes it to the base class to call pkispawn
        """
        cfg = dict(
            pki_ds_secure_connection=self.use_ldaps
        )

        if self.tokenname:
            module_name = os.path.basename(
                self.token_library_path
            ).split('.', 1)[0]
            cfg['pki_hsm_enable'] = True
            cfg['pki_hsm_modulename'] = module_name
            cfg['pki_hsm_libfile'] = self.token_library_path
            cfg['pki_token_name'] = self.tokenname
            cfg['pki_token_password'] = self.token_password
            cfg['pki_sslserver_token'] = 'internal'

        if self.ca_signing_algorithm is not None:
            cfg['ipa_ca_signing_algorithm'] = self.ca_signing_algorithm

        cfg['pki_random_serial_numbers_enable'] = self.random_serial_numbers
        if self.random_serial_numbers:
            cfg['pki_request_id_generator'] = 'random'
            cfg['pki_cert_id_generator'] = 'random'
        else:
            cfg['pki_request_id_generator'] = 'legacy'
            cfg['pki_cert_id_generator'] = 'legacy'

        if not (os.path.isdir(paths.PKI_TOMCAT_ALIAS_DIR) and
                os.path.isfile(paths.PKI_TOMCAT_PASSWORD_CONF)):
            # generate pin which we know can be used for FIPS NSS database
            pki_pin = ipautil.ipa_generate_password()
            cfg['pki_server_database_password'] = pki_pin
        else:
            pki_pin = None

        # When spawning a CA instance, always point to IPA_CA_CRT if it
        # exists. Later, when we're performing step 2 of an external CA
        # installation, we'll overwrite this key to point to the real
        # external CA.
        if os.path.exists(paths.IPA_CA_CRT):
            cfg['pki_cert_chain_path'] = paths.IPA_CA_CRT

        # Use IP address instead of default localhost4 and localhost6
        # because /etc/hosts does not always define them
        cfg['pki_ajp_host_ipv4'] = "127.0.0.1"
        cfg['pki_ajp_host_ipv6'] = "::1"

        if self.clone:
            if self.no_db_setup:
                cfg.update(
                    pki_ds_create_new_db=False,
                    pki_clone_setup_replication=False,
                    pki_clone_reindex_data=True,
                )

            cafile = self.pkcs12_info[0]

            # if paths.TMP_CA_P12 exists and is not owned by root,
            # shutil.copy will fail if when fs.protected_regular=1
            # so remove the file first
            if cafile:
                ipautil.remove_file(paths.TMP_CA_P12)
                shutil.copy(cafile, paths.TMP_CA_P12)
                self.service_user.chown(paths.TMP_CA_P12)
                clone_pkcs12_path = paths.TMP_CA_P12
            else:
                clone_pkcs12_path = None

            if self.random_serial_numbers:
                cfg.update(
                    pki_random_serial_numbers_enable=True,
                    pki_request_id_generator="random",
                    pki_cert_id_generator="random",
                )
            else:
                cfg.update(
                    pki_random_serial_numbers_enable=False,
                    pki_request_id_generator="legacy",
                    pki_cert_id_generator="legacy",
                )

            self._configure_clone(
                cfg,
                security_domain_hostname=self.master_host,
                clone_pkcs12_path=clone_pkcs12_path,
            )

        # External CA
        if self.external == 1:
            cfg.update(
                pki_external=True,
                pki_ca_signing_csr_path=self.csr_file,
            )

            if self.ca_type == x509.ExternalCAType.MS_CS.value:
                # Include MS template name extension in the CSR
                template = self.external_ca_profile
                if template is None:
                    # default template name
                    template = x509.MSCSTemplateV1(u"SubCA")

                ext_data = binascii.hexlify(template.get_ext_data())
                cfg.update(
                    pki_req_ext_add=True,
                    pki_req_ext_oid=template.ext_oid,
                    pki_req_ext_critical=False,
                    pki_req_ext_data=ext_data.decode('ascii'),
                )
        elif self.external == 2:
            cert_file = tempfile.NamedTemporaryFile()
            with open(self.cert_file, 'rb') as f:
                ext_cert = x509.load_unknown_x509_certificate(f.read())
            cert_file.write(ext_cert.public_bytes(x509.Encoding.PEM))
            ipautil.flush_sync(cert_file)
            self.service_user.chown(cert_file.name)

            result = ipautil.run(
                [paths.OPENSSL, 'crl2pkcs7',
                 '-certfile', self.cert_chain_file,
                 '-nocrl'],
                capture_output=True)
            cert_chain = result.output
            # Dogtag chokes on the header and footer, remove them
            # https://bugzilla.redhat.com/show_bug.cgi?id=1127838
            cert_chain = re.search(
                r'(?<=-----BEGIN PKCS7-----).*?(?=-----END PKCS7-----)',
                cert_chain, re.DOTALL).group(0)
            cert_chain_file = ipautil.write_tmp_file(cert_chain)

            cfg.update(
                pki_external=True,
                pki_ca_signing_cert_path=cert_file.name,
                pki_cert_chain_path=cert_chain_file.name,
                pki_external_step_two=True,
            )

        nolog_list = [self.dm_password, self.admin_password, pki_pin]
        if self.token_password:
            nolog_list.append(self.token_password)

        config = self._create_spawn_config(cfg)
        self.set_hsm_state(config)
        with tempfile.NamedTemporaryFile('w') as f:
            config.write(f)
            f.flush()
            self.service_user.chown(f.fileno())

            self.backup_state('installed', True)

            DogtagInstance.spawn_instance(
                self, f.name,
                nolog_list=nolog_list
            )

        if self.external == 1:
            print("The next step is to get %s signed by your CA and re-run %s as:" % (self.csr_file, sys.argv[0]))
            print("%s --external-cert-file=/path/to/signed_certificate --external-cert-file=/path/to/external_ca_certificate" % sys.argv[0])
            sys.exit(0)
        else:
            if config.getboolean(
                    self.subsystem, 'pki_backup_keys', fallback=True
            ):
                shutil.move(
                    paths.CA_BACKUP_KEYS_P12, paths.CACERT_P12
                )

        logger.debug("completed creating ca instance")

    def add_ipa_wait(self):
        """Add ipa-pki-wait-running to pki-tomcatd service
        """
        conf = paths.SYSTEMD_PKI_TOMCAT_IPA_CONF
        directory = os.path.dirname(conf)
        if not os.path.isdir(directory):
            os.mkdir(directory)
        with open(conf, 'w') as f:
            os.fchmod(f.fileno(), 0o644)
            f.write('[Service]\n')
            f.write('Environment=LC_ALL=C.UTF-8\n')
            f.write('ExecStartPost={}\n'.format(paths.IPA_PKI_WAIT_RUNNING))
        tasks.systemd_daemon_reload()

    def safe_backup_config(self):
        """
        Safely handle exceptions if backup_config fails

        The parent class raises an exception if the configuration
        cannot be backed up. Catch that and log the message but
        don't stop the current installer.
        """
        try:
            super(CAInstance, self).backup_config()
        except Exception as e:
            logger.warning("Failed to backup CS.cfg: %s", e)

    def create_certstore_passwdfile(self):
        """
        This method creates a 'pwdfile.txt' file in the Dogtag certificate
        store so that this file can be assumed and used for NSSDatabase/CertDB
        operations in 'certutil' calls.
        """
        passwd = None
        token = INTERNAL_TOKEN
        with open(paths.PKI_TOMCAT_PASSWORD_CONF, 'r') as f:
            for line in f:
                (tok, pin) = line.split('=', 1)
                if token == tok:
                    passwd = pin.strip()
                    break
            else:
                raise RuntimeError(
                    "The password to the 'internal' token of the Dogtag "
                    "certificate store was not found.")
        db = certs.CertDB(self.realm, nssdir=paths.PKI_TOMCAT_ALIAS_DIR)
        db.create_passwd_file(passwd)

    def __update_topology(self):
        self._ldap_update(
            [paths.CA_TOPOLOGY_ULDIF],
            basedir=None,
        )

    def __disable_nonce(self):
        # Turn off Nonces
        update_result = installutils.update_file(
            self.config, 'ca.enableNonces=true',
            'ca.enableNonces=false')
        if update_result != 0:
            raise RuntimeError("Disabling nonces failed")
        self.service_user.chown(self.config)

    def enable_pkix(self):
        directivesetter.set_directive(paths.SYSCONFIG_PKI_TOMCAT,
                                   'NSS_ENABLE_PKIX_VERIFY', '1',
                                   quotes=False, separator='=')

    def enable_pruning(self):
        directivesetter.set_directive(paths.CA_CS_CFG_PATH,
                                      'jobsScheduler.enabled', 'true',
                                      quotes=False, separator='=')
        directivesetter.set_directive(paths.CA_CS_CFG_PATH,
                                      'jobsScheduler.job.pruning.enabled',
                                      'true', quotes=False, separator='=')
        directivesetter.set_directive(paths.CA_CS_CFG_PATH,
                                      'jobsScheduler.job.pruning.owner',
                                      'ipara', quotes=False, separator='=')

    def __import_ra_cert(self):
        """
        Helper method for IPA domain level 0 replica install
        """
        self.import_ra_cert(self.ra_p12, self.dm_password)

    def import_ra_cert(self, rafile, password=''):
        """
        Cloned RAs will use the same RA agent cert as the master so we
        need to import from a PKCS#12 file.

        Used when setting up replication
        """
        with ipautil.write_tmp_file(password + '\n') as f:
            pwdarg = 'file:{file}'.format(file=f.name)
            # get the private key from the file
            ipautil.run([paths.OPENSSL,
                         "pkcs12",
                         "-in", rafile,
                         "-nocerts", "-nodes",
                         "-out", paths.RA_AGENT_KEY,
                         "-passin", pwdarg])

            # get the certificate from the pkcs12 file
            ipautil.run([paths.OPENSSL,
                         "pkcs12",
                         "-in", rafile,
                         "-clcerts", "-nokeys",
                         "-out", paths.RA_AGENT_PEM,
                         "-passin", pwdarg])
        self._set_ra_cert_perms()

        self.configure_agent_renewal()

    def __import_ra_key(self):
        import_ra_key(self._custodia)

    @staticmethod
    def _set_ra_cert_perms():
        """
        Sets the correct permissions for the RA_AGENT_PEM, RA_AGENT_KEY files
        """
        group = ipalib.constants.IPAAPI_GROUP
        for fname in (paths.RA_AGENT_PEM, paths.RA_AGENT_KEY):
            group.chgrp(fname)
            os.chmod(fname, 0o440)
            tasks.restore_context(fname)

    def __create_ca_agent(self):
        """
        Create CA agent, assign a certificate, and add the user to
        the appropriate groups for accessing CA services.
        """
        conn = api.Backend.ldap2

        # create ipara user with RA certificate
        user_dn = DN(('uid', "ipara"), ('ou', 'People'), self.basedn)
        entry = conn.make_entry(
            user_dn,
            objectClass=['top', 'person', 'organizationalPerson',
                         'inetOrgPerson', 'cmsuser'],
            uid=["ipara"],
            sn=["ipara"],
            cn=["ipara"],
            usertype=["agentType"],
            userstate=["1"],
            userCertificate=[self.ra_cert],
            description=['2;%s;%s;%s' % (
                self.ra_cert.serial_number,
                DN(self.ca_subject),
                DN(('CN', 'IPA RA'), self.subject_base))])
        conn.add_entry(entry)

        # add ipara user to Certificate Manager Agents group
        group_dn = DN(('cn', 'Certificate Manager Agents'), ('ou', 'groups'),
            self.basedn)
        conn.add_entry_to_group(user_dn, group_dn, 'uniqueMember')

        # add ipara user to Registration Manager Agents group
        group_dn = DN(('cn', 'Registration Manager Agents'), ('ou', 'groups'),
            self.basedn)
        conn.add_entry_to_group(user_dn, group_dn, 'uniqueMember')

        # add ipara user to Security Domain Administrators group
        group_dn = DN(('cn', 'Security Domain Administrators'),
                      ('ou', 'groups'), self.basedn)
        conn.add_entry_to_group(user_dn, group_dn, 'uniqueMember')

    def __get_ca_chain(self):
        try:
            return dogtag.get_ca_certchain(ca_host=self.fqdn)
        except Exception as e:
            raise RuntimeError("Unable to retrieve CA chain: %s" % str(e))

    def __export_ca_chain(self):
        """
        Get the CA chain from Dogtag NSS DB and write it to paths.IPA_CA_CRT
        """
        # Getting Dogtag CA chain
        chain = self.__get_ca_chain()

        # Convert to DER because the chain comes back as one long string which
        # makes openssl throw up.
        data = base64.b64decode(chain)

        # Get list of PEM certificates
        certlist = x509.pkcs7_to_certs(data, x509.DER)

        # We need to append the certs to the existing file, so start by
        # reading the file
        if os.path.isfile(paths.IPA_CA_CRT):
            ca_certs = x509.load_certificate_list_from_file(paths.IPA_CA_CRT)
            certlist.extend(ca_certs)

        # We have all the certificates in certlist, write them to a PEM file
        for path in [paths.IPA_CA_CRT,
                     paths.KDC_CA_BUNDLE_PEM,
                     paths.CA_BUNDLE_PEM]:
            x509.write_certificate_list(certlist, path, mode=0o644)

    def __request_ra_certificate(self):
        """
        Request the IPA RA certificate from dogtag.

        dogtag automatically generates an admin certificate that
        in a usual deployment would be used in the UI to handle
        administrative duties. IPA does not use this certificate
        except as a bootstrap to generate the RA.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdb = certs.CertDB(self.realm, nssdir=tmpdir)
            chain_file = os.path.join(tmpdir, "chain.pem")

            chain = self.__get_ca_chain()
            data = base64.b64decode(chain)
            ipautil.run(
                [paths.OPENSSL,
                 "pkcs7",
                 "-inform",
                 "DER",
                 "-print_certs",
                 "-out", chain_file,
                 ], stdin=data, capture_output=False)

            tmpdb.create_noise_file()
            tmpdb.create_passwd_file()
            tmpdb.create_certdbs()
            tmpdb.load_cacert(chain_file, IPA_CA_TRUST_FLAGS)

            tmpdb.import_pkcs12(
                paths.DOGTAG_ADMIN_P12, pkcs12_passwd=self.dm_password)

            ipautil.run(
                [paths.CERTUTIL,
                 "-d", tmpdb.secdir,
                 "-R", "-s", str(DN(('CN', 'IPA RA'), self.subject_base)),
                 "-g", "2048",
                 "-z", os.path.join(tmpdb.secdir, tmpdb.noise_fname),
                 "-f", tmpdb.passwd_fname,
                 "-o", os.path.join(tmpdb.secdir, "csr"),
                 "-a",]
            )

            tmpdb.pki_issue_certificate(
                service=None,
                profile="caSubsystemCert",
                subject="CN=IPA RA",
                keyfile=None,
                certfile=paths.RA_AGENT_PEM,
                key_passwd_file=None,
                use_admin=True)

            self.ra_cert = x509.load_certificate_from_file(
                paths.RA_AGENT_PEM)
            tmpdb.add_cert(self.ra_cert, 'IPA RA', EMPTY_TRUST_FLAGS)
            pk12_pwdfile = ipautil.write_tmp_file(self.dm_password)
            tmpdb.export_pkcs12(
                os.path.join(tmpdb.secdir, "ra.p12"),
                pk12_pwdfile.name,
                'IPA RA')
            certs.install_key_from_p12(
                os.path.join(tmpdb.secdir, "ra.p12"),
                self.dm_password, paths.RA_AGENT_KEY)
        self._set_ra_cert_perms()
        update_people_entry(self.ra_cert)
        certmonger.start_tracking(
            certpath=(paths.RA_AGENT_PEM, paths.RA_AGENT_KEY),
            ca=ipalib.constants.RENEWAL_CA_NAME,
            profile=ipalib.constants.RA_AGENT_PROFILE,
            pre_command='renew_ra_cert_pre',
            post_command='renew_ra_cert',
            storage='FILE',
        )

    def prepare_crl_publish_dir(self):
        """
        Prepare target directory for CRL publishing

        Returns a path to the CRL publishing directory
        """
        publishdir = paths.PKI_CA_PUBLISH_DIR

        if not os.path.exists(publishdir):
            os.mkdir(publishdir)

        os.chmod(publishdir, 0o775)
        os.chown(publishdir, 0, self.service_user.pgid)

        tasks.restore_context(publishdir)

        return publishdir


    def __enable_crl_publish(self):
        """
        Enable file-based CRL publishing and disable LDAP publishing.

        https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Certificate_System/8.0/html/Admin_Guide/Setting_up_Publishing.html
        """
        with directivesetter.DirectiveSetter(
                self.config, quotes=False, separator='=') as ds:
            # Enable file publishing, disable LDAP
            ds.set('ca.publish.enable', 'true')
            ds.set('ca.publish.cert.enable', 'false')
            ds.set('ca.publish.ldappublish.enable', 'false')

            # Create the file publisher, der only, not b64
            ds.set(
                'ca.publish.publisher.impl.FileBasedPublisher.class',
                'com.netscape.cms.publish.publishers.FileBasedPublisher'
            )
            prefix = 'ca.publish.publisher.instance.FileBaseCRLPublisher.'
            ds.set(prefix + 'crlLinkExt', 'bin')
            ds.set(prefix + 'directory', self.prepare_crl_publish_dir())
            ds.set(prefix + 'latestCrlLink', 'true')
            ds.set(prefix + 'pluginName', 'FileBasedPublisher')
            ds.set(prefix + 'timeStamp', 'LocalTime')
            ds.set(prefix + 'zipCRLs', 'false')
            ds.set(prefix + 'zipLevel', '9')
            ds.set(prefix + 'Filename.b64', 'false')
            ds.set(prefix + 'Filename.der', 'true')

            # The publishing rule
            ds.set('ca.publish.rule.instance.FileCrlRule.enable', 'true')
            ds.set('ca.publish.rule.instance.FileCrlRule.mapper', 'NoMap')
            ds.set('ca.publish.rule.instance.FileCrlRule.pluginName', 'Rule')
            ds.set('ca.publish.rule.instance.FileCrlRule.predicate', '')
            ds.set(
                'ca.publish.rule.instance.FileCrlRule.publisher',
                'FileBaseCRLPublisher'
            )
            ds.set('ca.publish.rule.instance.FileCrlRule.type', 'crl')

            # Now disable LDAP publishing
            ds.set('ca.publish.rule.instance.LdapCaCertRule.enable', 'false')
            ds.set('ca.publish.rule.instance.LdapCrlRule.enable', 'false')
            ds.set(
                'ca.publish.rule.instance.LdapUserCertRule.enable',
                'false'
            )
            ds.set('ca.publish.rule.instance.LdapXCertRule.enable', 'false')

            # If we are the initial master then we are the CRL generator,
            # otherwise we point to that master for CRLs.
            if not self.clone:
                # These next two are defaults, but I want to be explicit
                # that the initial master is the CRL generator.
                ds.set('ca.crl.MasterCRL.enableCRLCache', 'true')
                ds.set('ca.crl.MasterCRL.enableCRLUpdates', 'true')
                ds.set('ca.listenToCloneModifications', 'true')
            else:
                ds.set('ca.crl.MasterCRL.enableCRLCache', 'false')
                ds.set('ca.crl.MasterCRL.enableCRLUpdates', 'false')
                ds.set('ca.listenToCloneModifications', 'false')

    def uninstall(self):
        # just eat state
        self.restore_state("enabled")
        self.restore_hsm_state()

        DogtagInstance.uninstall(self)

        self.restore_state("installed")

        # At one time we removed this user on uninstall. That can potentially
        # orphan files, or worse, if another useradd runs in the interim,
        # cause files to have a new owner.
        self.restore_state("user_exists")

        if not services.knownservices.dbus.is_running():
            # some platforms protect dbus with RefuseManualStart=True
            services.knownservices.dbus.start()
        cmonger = services.knownservices.certmonger
        cmonger.start()

        bus = dbus.SystemBus()
        obj = bus.get_object('org.fedorahosted.certmonger',
                             '/org/fedorahosted/certmonger')
        iface = dbus.Interface(obj, 'org.fedorahosted.certmonger')
        for suffix in ['', '-reuse', '-selfsigned']:
            name = ipalib.constants.RENEWAL_CA_NAME + suffix
            path = iface.find_ca_by_nickname(name)
            if path:
                iface.remove_known_ca(path)

        cmonger.stop()

        # remove ipa-pki-wait-running config
        ipautil.remove_file(paths.SYSTEMD_PKI_TOMCAT_IPA_CONF)
        try:
            os.rmdir(os.path.dirname(paths.SYSTEMD_PKI_TOMCAT_IPA_CONF))
        except OSError:
            pass
        tasks.systemd_daemon_reload()

        # remove CRL files
        logger.debug("Remove old CRL files")
        try:
            for f in get_crl_files():
                logger.debug("Remove %s", f)
                ipautil.remove_file(f)
        except OSError as e:
            logger.warning("Error while removing old CRL files: %s", e)

        # remove CRL directory
        logger.debug("Remove CRL directory")
        if os.path.exists(paths.PKI_CA_PUBLISH_DIR):
            try:
                shutil.rmtree(paths.PKI_CA_PUBLISH_DIR)
            except OSError as e:
                logger.warning("Error while removing CRL publish "
                               "directory: %s", e)

        ipautil.remove_file(paths.DOGTAG_ADMIN_P12)
        ipautil.remove_file(paths.CACERT_P12)
        ipautil.remove_file(paths.ADMIN_CERT_PATH)

    def unconfigure_certmonger_renewal_guard(self):
        if not self.is_configured():
            return

        helper = self.restore_state('certmonger_dogtag_helper')
        if helper:
            bus = dbus.SystemBus()
            obj = bus.get_object('org.fedorahosted.certmonger',
                                 '/org/fedorahosted/certmonger')
            iface = dbus.Interface(obj, 'org.fedorahosted.certmonger')
            path = iface.find_ca_by_nickname('dogtag-ipa-renew-agent')
            if path:
                ca_obj = bus.get_object('org.fedorahosted.certmonger', path)
                ca_iface = dbus.Interface(ca_obj,
                                          'org.freedesktop.DBus.Properties')
                ca_iface.Set('org.fedorahosted.certmonger.ca',
                             'external-helper', helper)

    @staticmethod
    def configure_agent_renewal():
        try:
            certmonger.start_tracking(
                certpath=(paths.RA_AGENT_PEM, paths.RA_AGENT_KEY),
                ca=ipalib.constants.RENEWAL_CA_NAME,
                profile=ipalib.constants.RA_AGENT_PROFILE,
                pre_command='renew_ra_cert_pre',
                post_command='renew_ra_cert',
                storage='FILE')
        except RuntimeError as e:
            logger.error(
                "certmonger failed to start tracking certificate: %s", e)

    def stop_tracking_certificates(self):
        """
        Stop tracking our certificates. Called on uninstall.  Also called
        during upgrade to fix discrepancies.

        """
        super(CAInstance, self).stop_tracking_certificates()

        # stop tracking lightweight CA signing certs
        for request_id in certmonger.get_requests_for_dir(self.nss_db):
            nickname = certmonger.get_request_value(request_id, 'key-nickname')
            if nickname.startswith('caSigningCert cert-pki-ca '):
                certmonger.stop_tracking(self.nss_db, nickname=nickname)

        try:
            certmonger.stop_tracking(certfile=paths.RA_AGENT_PEM)
        except RuntimeError as e:
            logger.error(
                "certmonger failed to stop tracking certificate: %s", e)

    def is_renewal_master(self, fqdn=None):
        if fqdn is None:
            fqdn = api.env.host

        dn = DN(('cn', 'CA'), ('cn', fqdn), api.env.container_masters,
                api.env.basedn)
        renewal_filter = '(ipaConfigString=caRenewalMaster)'
        try:
            api.Backend.ldap2.get_entries(base_dn=dn, filter=renewal_filter,
                                          attrs_list=[])
        except errors.NotFound:
            return False

        return True

    def set_renewal_master(self, fqdn=None):
        if fqdn is None:
            fqdn = api.env.host

        base_dn = DN(api.env.container_masters, api.env.basedn)
        filter = '(&(cn=CA)(ipaConfigString=caRenewalMaster))'
        try:
            entries = api.Backend.ldap2.get_entries(
                base_dn=base_dn, filter=filter, attrs_list=['ipaConfigString'])
        except errors.NotFound:
            entries = []

        dn = DN(('cn', 'CA'), ('cn', fqdn), base_dn)
        master_entry = api.Backend.ldap2.get_entry(dn, ['ipaConfigString'])

        for entry in entries:
            if master_entry is not None and entry.dn == master_entry.dn:
                master_entry = None
                continue

            entry['ipaConfigString'] = [x for x in entry['ipaConfigString']
                                        if x.lower() != 'carenewalmaster']
            api.Backend.ldap2.update_entry(entry)

        if master_entry is not None:
            master_entry['ipaConfigString'].append('caRenewalMaster')
            api.Backend.ldap2.update_entry(master_entry)

    def update_cert_config(self, nickname, cert):
        """
        When renewing a CA subsystem certificate the configuration file
        needs to get the new certificate as well.

        nickname is one of the known nicknames.
        cert is a DER-encoded certificate.
        """

        # The cert directive to update per nickname
        directives = {
            'auditSigningCert cert-pki-ca': 'ca.audit_signing.cert',
            'ocspSigningCert cert-pki-ca': 'ca.ocsp_signing.cert',
            'caSigningCert cert-pki-ca': 'ca.signing.cert',
            'subsystemCert cert-pki-ca': 'ca.subsystem.cert',
            'Server-Cert cert-pki-ca': 'ca.sslserver.cert',
            'transportCert cert-pki-kra': 'ca.connector.KRA.transportCert'
        }

        try:
            self.backup_config()
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, "Failed to backup CS.cfg: %s" % e)

        if nickname in directives:
            super(CAInstance, self).update_cert_cs_cfg(
                directives[nickname], cert)

    def __create_ds_db(self):
        '''
        Create PKI database. Is needed when pkispawn option
        pki_ds_create_new_db is set to False
        '''

        backend = 'ipaca'
        suffix = DN(('o', 'ipaca'))

        # database
        dn = DN(('cn', 'ipaca'), ('cn', 'ldbm database'), ('cn', 'plugins'),
                ('cn', 'config'))
        entry = api.Backend.ldap2.make_entry(
            dn,
            objectclass=["top", "extensibleObject", "nsBackendInstance"],
            cn=[backend],
        )
        entry['nsslapd-suffix'] = [suffix]
        api.Backend.ldap2.add_entry(entry)

        # replication
        dn = DN(('cn', str(suffix)), ('cn', 'mapping tree'), ('cn', 'config'))
        entry = api.Backend.ldap2.make_entry(
            dn,
            objectclass=["top", "extensibleObject", "nsMappingTree"],
            cn=[suffix],
        )
        entry['nsslapd-state'] = ['Backend']
        entry['nsslapd-backend'] = [backend]
        api.Backend.ldap2.add_entry(entry)

    def __setup_replication(self):
        repl = replication.CAReplicationManager(self.realm, self.fqdn)
        repl.setup_cs_replication(self.master_host)

        # Activate Topology for o=ipaca segments
        self.__update_topology()

    def finalize_replica_config(self):
        repl = replication.CAReplicationManager(self.realm, self.fqdn)
        repl.finalize_replica_config(self.master_host)

    def __enable_instance(self):
        basedn = ipautil.realm_to_suffix(self.realm)
        if not self.clone:
            config = ['caRenewalMaster']
        else:
            config = []
        self.ldap_configure('CA', self.fqdn, None, basedn, config)

    def __expose_ca_in_ldap(self):
        """
        In a case when replica is created on DL0 we need to make
        sure that query for CA service record of this replica in
        ldap will succeed in time of installation.
        This method is needed for sucessfull replica installation
        on DL0 and should be removed alongside with code for DL0.

        To suppress deprecation warning message this method is
        not invoking ldap_enable() but _ldap_enable() method.
        """

        basedn = ipautil.realm_to_suffix(self.realm)
        if not self.clone:
            config = ['caRenewalMaster']
        else:
            config = []
        self._ldap_enable(ENABLED_SERVICE, "CA", self.fqdn, basedn, config)

    def setup_lightweight_ca_key_retrieval(self):
        # Important: there is a typo in the below string, which is known
        # and should not be fixed as existing installations already use it
        LWCA_KEY_RETRIEVAL = 'setup_lwca_key_retieval'
        if sysupgrade.get_upgrade_state('dogtag', LWCA_KEY_RETRIEVAL):
            return

        logger.debug('Set up lightweight CA key retrieval')

        self.__setup_lightweight_ca_key_retrieval_kerberos()
        self.__setup_lightweight_ca_key_retrieval_custodia()

        logger.debug('Configuring key retriever')
        directives = [
            ('features.authority.keyRetrieverClass',
                'com.netscape.ca.ExternalProcessKeyRetriever'),
            ('features.authority.keyRetrieverConfig.executable',
                paths.IPA_PKI_RETRIEVE_KEY),
        ]
        for k, v in directives:
            directivesetter.set_directive(
                self.config, k, v, quotes=False, separator='=')

        sysupgrade.set_upgrade_state('dogtag', LWCA_KEY_RETRIEVAL, True)

    def __setup_lightweight_ca_key_retrieval_kerberos(self):
        logger.debug('Creating principal')
        installutils.kadmin_addprinc(self.principal)
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.move_service(self.principal)

        logger.debug('Retrieving keytab')
        installutils.create_keytab(self.keytab, self.principal)
        os.chmod(self.keytab, 0o600)
        self.service_user.chown(self.keytab)

    def __setup_lightweight_ca_key_retrieval_custodia(self):
        logger.debug('Creating Custodia keys')
        custodia_basedn = DN(
            ('cn', 'custodia'), ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)
        ensure_entry(
            custodia_basedn,
            objectclass=['top', 'nsContainer'],
            cn=['custodia'],
        )
        ensure_entry(
            DN(('cn', 'dogtag'), custodia_basedn),
            objectclass=['top', 'nsContainer'],
            cn=['dogtag'],
        )
        keyfile = os.path.join(paths.PKI_TOMCAT, self.service_prefix + '.keys')
        keystore = IPAKEMKeys({'server_keys': keyfile})
        keystore.generate_keys(self.service_prefix)
        os.chmod(keyfile, 0o600)
        self.service_user.chown(keyfile)

    def add_lightweight_ca_tracking_requests(self):
        try:
            lwcas = api.Backend.ldap2.get_entries(
                base_dn=api.env.basedn,
                filter='(objectclass=ipaca)',
                attrs_list=['cn', 'ipacaid'],
            )
            add_lightweight_ca_tracking_requests(lwcas)
        except errors.NotFound:
            # shouldn't happen, but don't fail if it does
            logger.warning(
                "Did not find any lightweight CAs; nothing to track")

    def __dogtag10_migration(self):
        self._ldap_update(['50-dogtag10-migration.update'])

    def is_crlgen_enabled(self):
        """Check if the local CA instance is generating CRL

        Three conditions must be met to consider that the local CA is CRL
        generation master:
        - in CS.cfg ca.crl.MasterCRL.enableCRLCache=true
        - in CS.cfg ca.crl.MasterCRL.enableCRLUpdates=true
        - in CS.cfg ca.listenToCloneModifications=true
        - in CS.cfg ca.certStatusUpdateInterval != 0
        - in /etc/httpd/conf.d/ipa-pki-proxy.conf the RewriteRule
        ^/ipa/crl/MasterCRL.bin is disabled (commented or removed)

        If the values are inconsistent, an exception is raised
        :returns: True/False
        :raises: InconsistentCRLGenConfigException if the config is
                 inconsistent
        """
        try:
            cache = directivesetter.get_directive(
                self.config, 'ca.crl.MasterCRL.enableCRLCache', '=')
            enableCRLCache = cache.lower() == 'true'
            updates = directivesetter.get_directive(
                self.config, 'ca.crl.MasterCRL.enableCRLUpdates', '=')
            enableCRLUpdates = updates.lower() == 'true'
            listen = directivesetter.get_directive(
                self.config, 'ca.listenToCloneModifications', '=')
            enableToClone = listen.lower() == 'true'
            updateinterval = directivesetter.get_directive(
                self.config, 'ca.certStatusUpdateInterval', '=')

            # If the values are different, the config is inconsistent
            if not (enableCRLCache == enableCRLUpdates == enableToClone):
                raise InconsistentCRLGenConfigException(
                    "Configuration is inconsistent, please check "
                    "ca.crl.MasterCRL.enableCRLCache, "
                    "ca.crl.MasterCRL.enableCRLUpdates and "
                    "ca.listenToCloneModifications in {} and "
                    "run ipa-crlgen-manage [enable|disable] to repair".format(
                        self.config))
            # If they are the same then we are the CRL renewal master. Ensure
            # the update task is configured.
            if enableCRLCache and updateinterval == '0':
                raise InconsistentCRLGenConfigException(
                    "Configuration is inconsistent, please check "
                    "ca.certStatusUpdateInterval in {}. It should "
                    "be either not present or not zero. Run "
                    "ipa-crlgen-manage [enable|disable] to repair".format(
                        self.config))
        except IOError:
            raise RuntimeError(
                "Unable to read {}".format(self.config))

        # At this point enableCRLCache and enableCRLUpdates have the same value
        try:
            rewriteRuleDisabled = True
            p = re.compile(self.crl_rewrite_pattern)
            with open(paths.HTTPD_IPA_PKI_PROXY_CONF) as f:
                for line in f.readlines():
                    if p.search(line):
                        rewriteRuleDisabled = False
                        break
        except IOError:
            raise InconsistentCRLGenConfigException(
                "Unable to read {}".format(paths.HTTPD_IPA_PKI_PROXY_CONF))

        # if enableCRLUpdates and rewriteRuleDisabled are different, the config
        # is inconsistent
        if enableCRLUpdates != rewriteRuleDisabled:
            raise InconsistentCRLGenConfigException(
                "Configuration is inconsistent, please check "
                "ca.crl.MasterCRL.enableCRLCache in {} and the "
                "RewriteRule ^/ipa/crl/MasterCRL.bin in {} and "
                "run ipa-crlgen-manage [enable|disable] to repair".format(
                    self.config, paths.HTTPD_IPA_PKI_PROXY_CONF))
        return enableCRLUpdates

    def setup_crlgen(self, setup_crlgen):
        """Configure the local host for CRL generation

        :param setup_crlgen: if True enable CRL generation, if False, disable
        """
        try:
            crlgen_enabled = self.is_crlgen_enabled()
            if crlgen_enabled == setup_crlgen:
                logger.info(
                    "Nothing to do, CRL generation already %s",
                    "enabled" if crlgen_enabled else "disabled")
                return
        except InconsistentCRLGenConfigException:
            logger.warning("CRL generation is partially enabled, repairing...")

        # Stop PKI
        logger.info("Stopping %s", self.service_name)
        self.stop_instance()
        logger.debug("%s successfully stopped", self.service_name)

        # Edit the CS.cfg directives
        logger.info("Editing %s", self.config)
        with directivesetter.DirectiveSetter(
                self.config, quotes=False, separator='=') as ds:
            # Convert the bool setup_crlgen to a lowercase string
            str_value = str(setup_crlgen).lower()
            ds.set('ca.crl.MasterCRL.enableCRLCache', str_value)
            ds.set('ca.crl.MasterCRL.enableCRLUpdates', str_value)
            ds.set('ca.listenToCloneModifications', str_value)
            if setup_crlgen:
                ds.set('ca.certStatusUpdateInterval', None)
            else:
                ds.set('ca.certStatusUpdateInterval', '0')

        # Start pki-tomcat
        logger.info("Starting %s", self.service_name)
        self.start_instance()
        logger.debug("%s successfully started", self.service_name)

        # Edit the RewriteRule
        def comment_rewriterule():
            logger.info("Editing %s", paths.HTTPD_IPA_PKI_PROXY_CONF)
            # look for the pattern RewriteRule ^/ipa/crl/MasterCRL.bin ..
            # and comment out
            p = re.compile(self.crl_rewrite_pattern, re.MULTILINE)
            with open(paths.HTTPD_IPA_PKI_PROXY_CONF) as f:
                content = f.read()
            new_content = p.sub(r"#\1", content)
            with open(paths.HTTPD_IPA_PKI_PROXY_CONF, 'w') as f:
                f.write(new_content)

        def uncomment_rewriterule():
            logger.info("Editing %s", paths.HTTPD_IPA_PKI_PROXY_CONF)
            # check if the pattern RewriteRule ^/ipa/crl/MasterCRL.bin ..
            # is already present
            present = False
            p = re.compile(self.crl_rewrite_pattern, re.MULTILINE)
            with open(paths.HTTPD_IPA_PKI_PROXY_CONF) as f:
                content = f.read()
            present = p.search(content)
            # Remove the comment
            p_comment = re.compile(self.crl_rewrite_comment, re.MULTILINE)
            new_content = p_comment.sub("", content)
            # If not already present, add RewriteRule
            if not present:
                new_content += self.crl_rewriterule.format(api.env.host)
            # Finally write the file
            with open(paths.HTTPD_IPA_PKI_PROXY_CONF, 'w') as f:
                f.write(new_content)

        try:
            if setup_crlgen:
                comment_rewriterule()
            else:
                uncomment_rewriterule()

        except IOError:
            raise RuntimeError(
                "Unable to access {}".format(paths.HTTPD_IPA_PKI_PROXY_CONF))

        # Restart httpd
        http_service = services.knownservices.httpd
        logger.info("Restarting %s", http_service.service_name)
        http_service.restart()
        logger.debug("%s successfully restarted", http_service.service_name)

        # make sure a CRL is generated if setup_crl is True
        if setup_crlgen:
            logger.info("Forcing CRL update")
            api.Backend.ra.override_port = 8443
            result = api.Backend.ra.updateCRL(wait='true')
            if result.get('crlUpdate', 'Failure') == 'Success':
                logger.debug("Successfully updated CRL")
            api.Backend.ra.override_port = None

    @staticmethod
    def acme_uid(fqdn: str) -> str:
        """Compute ACME RA account uid."""
        return f'acme-{fqdn}'

    def setup_acme(self) -> bool:
        """
        Set up ACME service, if needed.

        Return False if ACME service was already set up, otherwise True.

        """

        # ACME LDAP database schema will be added by ipa-server-upgrade.
        # It is fine if this subroutine runs *before* the schema update,
        # because we only create the container objects.

        if os.path.isdir(os.path.join(paths.PKI_TOMCAT, 'acme')):
            logger.debug('ACME service is already deployed')
            return False

        if not minimum_acme_support():
            logger.debug('Minimum ACME support not available')
            return False

        logger.debug('Deploying ACME')
        self._ldap_mod('/usr/share/pki/acme/database/ds/schema.ldif')

        configure_acme_acls()

        # create ACME agent group (if not exist already) and user
        self.ensure_group(ACME_AGENT_GROUP, "ACME RA accounts")
        acme_user = self.acme_uid(self.fqdn)
        result = self.create_user(
            uid=acme_user,
            cn=acme_user,
            sn=acme_user,
            user_type='agentType',
            groups=[ACME_AGENT_GROUP],
            force=True,
        )
        if result is None:
            raise RuntimeError("Failed to add ACME RA user")
        else:
            password = result

        # Add the IPA RA user as a member of the ACME admins for
        # ipa-acme-manage.
        user_dn = DN(('uid', "ipara"), ('ou', 'People'), self.basedn)
        conn = api.Backend.ldap2
        group_dn = DN(('cn', ACME_AGENT_GROUP), ('ou', 'groups'),
                      self.basedn)
        try:
            conn.add_entry_to_group(user_dn, group_dn, 'uniqueMember')
        except errors.AlreadyGroupMember:
            pass

        # create container object heirarchy in LDAP
        ensure_acme_containers()

        # create ACME service instance
        ipautil.run(['pki-server', 'acme-create'])

        # write configuration files
        sub_dict = dict(
            FQDN=self.fqdn,
            USER=acme_user,
            PASSWORD=password,
        )
        for template_name, target in ACME_CONFIG_FILES:
            template_filename = \
                os.path.join(paths.USR_SHARE_IPA_DIR, template_name)
            filled = ipautil.template_file(template_filename, sub_dict)
            with open(target, 'w') as f:
                f.write(filled)
                os.fchmod(f.fileno(), 0o600)
                self.service_user.chown(f.fileno())

        # deploy ACME Tomcat application
        ipautil.run(['pki-server', 'acme-deploy'])

        return True

    def __store_random_serial_number_state(self):
        """
        Save the Random Serial Number (RSN) version.

        This is intended to add flexibility in case RSN bumps
        another version in dogtag. For now we only support v3
        or no randomization (0).
        """
        if self.random_serial_numbers:
            value = 3
        else:
            value = 0
        dn = DN(('cn', ipalib.constants.IPA_CA_CN), api.env.container_ca,
                api.env.basedn)
        entry_attrs = api.Backend.ldap2.get_entry(dn)
        version = entry_attrs.single_value.get(
            "ipaCaRandomSerialNumberVersion", "0"
        )
        if str(version) == str(value):
            return
        entry_attrs['ipaCaRandomSerialNumberVersion'] = value
        api.Backend.ldap2.update_entry(entry_attrs)

    def __store_hsm_configuration_state(self):
        """
        Save the HSM token configuration.

        This data is used during replica install to determine whether
        the remote server uses an HSM.
        """
        if not self.token_name or self.token_name == 'internal':
            return
        dn = DN(('cn', ipalib.constants.IPA_CA_CN), api.env.container_ca,
                api.env.basedn)
        entry_attrs = api.Backend.ldap2.get_entry(dn)
        entry_attrs['ipaCaHSMConfiguration'] = '{};{}'.format(
            self.token_name, self.token_library_path)
        api.Backend.ldap2.update_entry(entry_attrs)


def __update_entry_from_cert(make_filter, make_entry, cert):
    """
    Given a certificate and functions to make a filter based on the
    cert, and make a new entry based on the cert, update database
    accordingly.

    :param make_filter:
        function that takes a certificate in DER format and
        returns an LDAP search filter

    :param make_entry:
        function that takes a certificate in DER format and an
        LDAP entry, and returns the new state of the LDAP entry.
        Return the input unchanged to skip an entry.

    :param cert:
        An IPACertificate object

    Logging is done via syslog.

    Return ``True`` if all updates were successful (zero updates is
    vacuously successful) otherwise ``False``.

    """
    base_dn = DN(('o', 'ipaca'))
    conn = api.Backend.ldap2

    attempts = 0
    updated = False

    while attempts < 10:
        try:
            db_filter = make_filter(cert)
            try:
                entries = conn.get_entries(base_dn, conn.SCOPE_SUBTREE, db_filter)
            except errors.NotFound:
                entries = []

            updated = True

            for entry in entries:
                syslog.syslog(
                    syslog.LOG_NOTICE, 'Updating entry %s' % str(entry.dn))

                try:
                    entry = make_entry(cert, entry)
                    conn.update_entry(entry)
                except errors.EmptyModlist:
                    pass
                except Exception as e:
                    syslog.syslog(
                        syslog.LOG_ERR,
                        'Updating entry %s failed: %s' % (str(entry.dn), e))
                    updated = False

            break
        except errors.NetworkError:
            syslog.syslog(
                syslog.LOG_ERR,
                'Connection to %s failed, sleeping 30s' % api.env.ldap_uri)
            time.sleep(30)
            attempts += 1
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, 'Caught unhandled exception: %s' % e)
            break

    if not updated:
        syslog.syslog(syslog.LOG_ERR, 'Update failed.')
        return False

    return True

def update_people_entry(cert):
    """
    Update the userCerticate for an entry in the dogtag ou=People. This
    is needed when a certificate is renewed.
    """
    def make_filter(cert):
        ldap = api.Backend.ldap2
        subject = DN(cert.subject)
        issuer = DN(cert.issuer)
        return ldap.combine_filters(
            [
                ldap.make_filter({'objectClass': 'inetOrgPerson'}),
                ldap.make_filter(
                    {'description': ';%s;%s' % (issuer, subject)},
                    exact=False, trailing_wildcard=False),
            ],
            ldap.MATCH_ALL)

    def make_entry(cert, entry):
        serial_number = cert.serial_number
        subject = DN(cert.subject)
        issuer = DN(cert.issuer)
        entry['usercertificate'].append(cert)
        entry['description'] = '2;%d;%s;%s' % (serial_number, issuer, subject)
        return entry

    return __update_entry_from_cert(make_filter, make_entry, cert)


def update_authority_entry(cert):
    """
    Find the authority entry for the given cert, and update the
    serial number to match the given cert.
    """
    def make_filter(cert):
        ldap = api.Backend.ldap2
        subject = str(DN(cert.subject))
        return ldap.make_filter(
            dict(objectclass='authority', authoritydn=subject),
            rules=ldap.MATCH_ALL,
        )

    def make_entry(cert, entry):
        entry['authoritySerial'] = cert.serial_number
        return entry

    return __update_entry_from_cert(make_filter, make_entry, cert)


def get_ca_renewal_nickname(subject_base, ca_subject_dn, sdn):
    """
    Get the nickname for storage in the cn_renewal container.

    :param subject_base: Certificate subject base
    :param ca_subject_dn: IPA CA subject DN
    :param sdn: Subject DN
    :return: string, or None if nickname cannot be determined.

    """
    assert isinstance(sdn, DN)
    nickname_by_subject_dn = {
        DN(ca_subject_dn): 'caSigningCert cert-pki-ca',
        DN('CN=CA Audit', subject_base): 'auditSigningCert cert-pki-ca',
        DN('CN=OCSP Subsystem', subject_base): 'ocspSigningCert cert-pki-ca',
        DN('CN=CA Subsystem', subject_base): 'subsystemCert cert-pki-ca',
        DN('CN=KRA Audit', subject_base): 'auditSigningCert cert-pki-kra',
        DN('CN=KRA Transport Certificate', subject_base):
            'transportCert cert-pki-kra',
        DN('CN=KRA Storage Certificate', subject_base):
            'storageCert cert-pki-kra',
        DN('CN=IPA RA', subject_base): 'ipaCert',
    }
    return nickname_by_subject_dn.get(sdn)


def update_ca_renewal_entry(conn, nickname, cert):
    """
    Update the ca_renewal entry for the given nickname.

    :param conn: A *connected* LDAP handle
    :param nickname: NSSDB nickname
    :param cert: python-cryptography X509Certificate

    """
    dn = DN(('cn', nickname), api.env.container_ca_renewal, api.env.basedn)
    try:
        entry = conn.get_entry(dn, ['usercertificate'])
        entry['usercertificate'] = [cert]
        conn.update_entry(entry)
    except errors.NotFound:
        entry = conn.make_entry(
            dn,
            objectclass=['top', 'pkiuser', 'nscontainer'],
            cn=[nickname],
            usercertificate=[cert])
        conn.add_entry(entry)
    except errors.EmptyModlist:
        pass


def ensure_ldap_profiles_container():
    ensure_entry(
        PROFILES_DN,
        objectclass=['top', 'organizationalUnit'],
        ou=['certificateProfiles'],
    )

def ensure_lightweight_cas_container():
    return ensure_entry(
        DN(('ou', 'authorities'), ('ou', 'ca'), ('o', 'ipaca')),
        objectclass=['top', 'organizationalUnit'],
        ou=['authorities'],
    )


def enable_lightweight_ca_monitor():

    # Check LWCA monitor
    value = directivesetter.get_directive(
        paths.CA_CS_CFG_PATH,
        'ca.authorityMonitor.enable',
        separator='=')

    if value == 'true':
        return False  # already enabled; restart not needed

    # Enable LWCA monitor
    directivesetter.set_directive(
        paths.CA_CS_CFG_PATH,
        'ca.authorityMonitor.enable',
        'true',
        quotes=False,
        separator='=')

    return True  # restart needed


def minimum_acme_support(data=None):
    """
    ACME with global enable/disable is required.

    This first shipped in dogtag version 10.10.0.

    Parse the version string to determine if the minimum version
    is met. If parsing fails return False.

    :param: data: The string value to parse for version. Defaults to
                  reading from the filesystem.
    """
    if not data:
        with open('/usr/share/pki/VERSION', 'r') as fd:
            data = fd.read()

    groups = re.match(r'.*\nSpecification-Version: ([\d+\.]*)\n.*', data)
    if groups:
        version_string = groups.groups(0)[0]
        minimum_version = parse_version('10.10.0')

        return parse_version(version_string) >= minimum_version
    else:
        logger.debug('Unable to parse version from %s', data)
        return False


def ensure_acme_containers():
    """
    Create the ACME container objects under ou=acme,o=ipaca if
    they do not exist.

    """
    ou_acme = RDN(('ou', 'acme'))
    rdns = [
        DN(ou_acme),
        DN(('ou', 'nonces'), ou_acme),
        DN(('ou', 'accounts'), ou_acme),
        DN(('ou', 'orders'), ou_acme),
        DN(('ou', 'authorizations'), ou_acme),
        DN(('ou', 'challenges'), ou_acme),
        DN(('ou', 'certificates'), ou_acme),
    ]

    extensible_rdns = [
        DN(('ou', 'config'), ou_acme),
    ]

    for rdn in rdns:
        ensure_entry(
            DN(rdn, ('o', 'ipaca')),
            objectclass=['top', 'organizationalUnit'],
            ou=[rdn[0][0].value],
        )

    for rdn in extensible_rdns:
        ensure_entry(
            DN(rdn, ('o', 'ipaca')),
            objectclass=['top', 'organizationalUnit', 'extensibleObject'],
            ou=[rdn[0][0].value],
        )


def ensure_entry(dn, **attrs):
    """Ensure an entry exists.

    If an entry with the given DN already exists, return ``False``,
    otherwise add the entry and return ``True``.

    """
    conn = api.Backend.ldap2
    try:
        conn.get_entry(dn)
        return False
    except errors.NotFound:
        # entry doesn't exist; add it
        entry = conn.make_entry(dn, **attrs)
        conn.add_entry(entry)
        return True


def configure_profiles_acl():
    """Allow the Certificate Manager Agents group to modify profiles."""
    new_rules = [
        'certServer.profile.configuration:read,modify' +
        ':allow (read,modify) group="Certificate Manager Agents"' +
        ':Certificate Manager agents may modify (create/update/delete) ' +
        'and read profiles',

        'certServer.ca.account:login,logout' +
        ':allow (login,logout) user="anybody"' +
        ':Anybody can login and logout',
    ]
    return __add_acls(new_rules)


def configure_lightweight_ca_acls():
    """Allow Certificate Manager Agents to manage lightweight CAs."""
    new_rules = [
        'certServer.ca.authorities:list,read' +
        ':allow (list,read) user="anybody"' +
        ':Anybody may list and read lightweight authorities',

        'certServer.ca.authorities:create,modify' +
        ':allow (create,modify) group="Administrators"' +
        ':Administrators may create and modify lightweight authorities',

        'certServer.ca.authorities:delete' +
        ':allow (delete) group="Administrators"' +
        ':Administrators may delete lightweight authorities',

        'certServer.ca.authorities:create,modify,delete' +
        ':allow (create,modify,delete) group="Certificate Manager Agents"' +
        ':Certificate Manager Agents may manage lightweight authorities',
    ]
    return __add_acls(new_rules)


def configure_acme_acls():
    """Allow the ACME Agents to modify profiles."""

    # The "execute" operation sounds scary, but it actually only allows
    # revocation and unrevocation.  See CertResource.java and
    # base/ca/shared/conf/acl.properties in the Dogtag source.

    new_rules = [
        'certServer.ca.certs:execute'
        f':allow (execute) group="{ACME_AGENT_GROUP}"'
        ':ACME Agents may execute cert operations',
    ]
    return __add_acls(new_rules)


def __add_acls(new_rules):
    """Add the given Dogtag ACLs.

    ``new_rules``
        Iterable of ACL rule values to add

    Return ``True`` if any ACLs were added otherwise ``False``.

    """
    updated = False

    dn = DN(('cn', 'aclResources'), ('o', 'ipaca'))

    conn = api.Backend.ldap2
    entry = conn.get_entry(dn)
    cur_rules = entry.get('resourceACLS', [])
    add_rules = [rule for rule in new_rules if rule not in cur_rules]
    if add_rules:
        cur_rules.extend(add_rules)
        conn.update_entry(entry)
        updated = True

    return updated


def __get_profile_config(profile_id):
    sub_dict = dict(
        DOMAIN=ipautil.format_netloc(api.env.domain),
        IPA_CA_RECORD=ipalib.constants.IPA_CA_RECORD,
        CRL_ISSUER='CN=Certificate Authority,o=ipaca',
        SUBJECT_DN_O=dsinstance.DsInstance().find_subject_base(),
        ACME_AGENT_GROUP=ACME_AGENT_GROUP,
    )

    # To work around lack of proper profile upgrade system, we ship
    # two versions of some profiles - one for new installs only, and
    # the other for upgrading to LDAP-based profiles in an existing
    # deployment.
    #
    # Select UPGRADE version if we are in the 'updates' API context
    # and an upgrade-specific version of the profile exists.
    #
    profile_filename = '/usr/share/ipa/profiles/{}.cfg'.format(profile_id)
    profile_upg_filename = \
        '/usr/share/ipa/profiles/{}.UPGRADE.cfg'.format(profile_id)
    if api.env.context == 'updates' and os.path.isfile(profile_upg_filename):
        profile_filename = profile_upg_filename

    return ipautil.template_file(profile_filename, sub_dict)

def import_included_profiles():
    conn = api.Backend.ldap2

    ensure_entry(
        DN(('cn', 'ca'), api.env.basedn),
        objectclass=['top', 'nsContainer'],
        cn=['ca'],
    )
    ensure_entry(
        DN(api.env.container_certprofile, api.env.basedn),
        objectclass=['top', 'nsContainer'],
        cn=['certprofiles'],
    )

    # At this point Apache may or may not be running with a valid
    # certificate. The local server is not yet recognized as a full
    # CA yet so it isn't discoverable. So try to do some detection
    # on what port to use, 443 (remote) or 8443 (local) for importing
    # the profiles.
    #
    # api.Backend.ra_certprofile invokes the RestClient class
    # which will discover and login to the CA REST API. We can
    # use this information to detect where to import the profiles.
    #
    # If the login is successful (e.g. doesn't raise an exception)
    # and it returns our hostname (it prefers the local host) then
    # we override and talk locally.
    #
    # Otherwise a NetworkError means we can't connect on 443 (perhaps
    # a firewall) or we get an HTTP error (valid TLS certificate on
    # Apache but no CA, login fails with 404) so we override to the
    # local server.
    #
    # When override port was always set to 8443 the RestClient could
    # pick a remote server and since 8443 isn't in our firewall profile
    # setting up a new server would fail.
    try:
        with api.Backend.ra_certprofile as profile_api:
            if profile_api.ca_host == api.env.host:
                api.Backend.ra_certprofile.override_port = 8443
    except (errors.NetworkError, errors.RemoteRetrieveError) as e:
        logger.debug('Overriding CA port: %s', e)
        api.Backend.ra_certprofile.override_port = 8443

    for (profile_id, desc, store_issued) in dogtag.INCLUDED_PROFILES:
        dn = DN(('cn', profile_id),
            api.env.container_certprofile, api.env.basedn)
        try:
            conn.get_entry(dn)
        except errors.NotFound:
            # profile not found; add it
            entry = conn.make_entry(
                dn,
                objectclass=['ipacertprofile'],
                cn=[profile_id],
                description=[desc],
                ipacertprofilestoreissued=[store_issued],
            )
            conn.add_entry(entry)

            # Create the profile, replacing any existing profile of same name
            profile_data = __get_profile_config(profile_id)
            try:
                _create_dogtag_profile(profile_id, profile_data,
                                       overwrite=True)
            except errors.HTTPRequestError as e:
                logger.warning("Failed to import profile '%s': %s. Running "
                               "ipa-server-upgrade when installation is "
                               "completed may resolve this issue.",
                               profile_id, e)
                conn.delete_entry(entry)
            else:
                logger.debug("Imported profile '%s'", profile_id)
        else:
            logger.debug(
                "Profile '%s' is already in LDAP; skipping", profile_id
            )

    api.Backend.ra_certprofile.override_port = None


def repair_profile_caIPAserviceCert():
    """
    A regression caused replica installation to replace the FreeIPA
    version of caIPAserviceCert with the version shipped by Dogtag.

    This function detects and repairs occurrences of this problem.

    """
    api.Backend.ra_certprofile.override_port = 8443

    profile_id = 'caIPAserviceCert'

    with api.Backend.ra_certprofile as profile_api:
        try:
            cur_config = profile_api.read_profile(profile_id).splitlines()
        except errors.RemoteRetrieveError:
            # no profile there to check/repair
            api.Backend.ra_certprofile.override_port = None
            return

    indicators = [
        (
            b"policyset.serverCertSet.1.default.params.name="
            b"CN=$request.req_subject_name.cn$, OU=pki-ipa, O=IPA "
        ),
        (
            b"policyset.serverCertSet.9.default.params."
            b"crlDistPointsPointName_0="
            b"https://ipa.example.com/ipa/crl/MasterCRL.bin"
        ),
    ]
    need_repair = all(l in cur_config for l in indicators)

    if need_repair:
        logger.debug(
            "Detected that profile '%s' has been replaced with "
            "incorrect version; begin repair.", profile_id)
        _create_dogtag_profile(
            profile_id, __get_profile_config(profile_id), overwrite=True)
        logger.debug("Repair of profile '%s' complete.", profile_id)

    api.Backend.ra_certprofile.override_port = None


def migrate_profiles_to_ldap():
    """Migrate profiles from filesystem to LDAP.

    This must be run *after* switching to the LDAPProfileSubsystem
    and restarting the CA.

    The profile might already exist, e.g. if a replica was already
    upgraded, so this case is ignored. New/missing profiles are imported
    into LDAP. Existing profiles are not modified. This means that they are
    neither enabled nor updated when the file on disk has been changed.
    """
    ensure_ldap_profiles_container()
    api.Backend.ra_certprofile.override_port = 8443

    with open(paths.CA_CS_CFG_PATH) as f:
        cs_cfg = f.read()
    match = re.search(r'^profile\.list=(\S*)', cs_cfg, re.MULTILINE)
    profile_ids = match.group(1).split(',')
    profile_states = _get_ldap_profile_states()

    for profile_id in profile_ids:
        state = profile_states.get(profile_id.lower(), ProfileState.MISSING)
        if state != ProfileState.MISSING:
            # We don't reconsile enabled/disabled state.
            logger.debug(
                "Profile '%s' is already in LDAP and %s; skipping",
                profile_id, state.value
            )
            continue

        logger.info("Migrating profile '%s'", profile_id)
        match = re.search(
            r'^profile\.{}\.config=(\S*)'.format(profile_id),
            cs_cfg, re.MULTILINE
        )
        if match is None:
            logger.info("No file for profile '%s'; skipping", profile_id)
            continue
        filename = match.group(1)

        match = re.search(
            r'^profile\.{}\.class_id=(\S*)'.format(profile_id),
            cs_cfg, re.MULTILINE
        )
        if match is None:
            logger.info("No class_id for profile '%s'; skipping", profile_id)
            continue
        class_id = match.group(1)

        with open(filename) as f:
            profile_data = f.read()
            if profile_data[-1] != '\n':
                profile_data += '\n'
            profile_data += 'profileId={}\n'.format(profile_id)
            profile_data += 'classId={}\n'.format(class_id)

            # Import the profile, but do not replace it if it already exists.
            # This prevents replicas from replacing IPA-managed profiles with
            # Dogtag default profiles of same name.
            #
            _create_dogtag_profile(profile_id, profile_data, overwrite=False)

    api.Backend.ra_certprofile.override_port = None


class ProfileState(enum.Enum):
    MISSING = "missing"
    ENABLED = "enabled"
    DISABLED = "disabled"


def _get_ldap_profile_states():
    """Get LDAP profile states

    The function directly access LDAP for performance reasons. It's much
    faster than Dogtag's REST API and it's easier to check profiles for all
    subsystems.

    :return: mapping of lowercase profile id to state enum member
    """
    conn = api.Backend.ldap2
    entries = conn.get_entries(
        base_dn=PROFILES_DN,
        scope=conn.SCOPE_SUBTREE,
        filter="(objectClass=certProfile)",
        attrs_list=["cn", "certProfileConfig"]
    )
    results = {}
    for entry in entries:
        single = entry.single_value
        cn = single["cn"]
        try:
            cfg = single["certProfileConfig"]
        except (ValueError, KeyError):
            # certProfileConfig is neither mandatory nor single value
            # skip entries with incomplete configuration
            state = ProfileState.MISSING
        else:
            if isinstance(cfg, bytes):
                # some profile configurations are marked as binary
                cfg = cfg.decode("utf-8")
            for line in cfg.split("\n"):
                if line.lower() == "enable=true":
                    state = ProfileState.ENABLED
                    break
            else:
                state = ProfileState.DISABLED

        results[cn.lower()] = state

    return results


def _create_dogtag_profile(profile_id, profile_data, overwrite):
    with api.Backend.ra_certprofile as profile_api:
        # import the profile
        try:
            profile_api.create_profile(profile_data)
            logger.debug("Profile '%s' successfully migrated to LDAP",
                         profile_id)
        except errors.RemoteRetrieveError as e:
            logger.debug("Error migrating '%s': %s", profile_id, e)

            # profile already exists
            if overwrite:
                try:
                    profile_api.disable_profile(profile_id)
                except errors.RemoteRetrieveError:
                    logger.debug(
                        "Failed to disable profile '%s' "
                        "(it is probably already disabled)",
                        profile_id)
                profile_api.update_profile(profile_id, profile_data)

        # enable the profile
        try:
            profile_api.enable_profile(profile_id)
        except errors.RemoteRetrieveError:
            logger.debug(
                "Failed to enable profile '%s' "
                "(it is probably already enabled)",
                profile_id)


def ensure_ipa_authority_entry():
    """Add the IPA CA ipaCa object if missing.

    This requires the "host authority" authority entry to have been
    created, which Dogtag will do automatically upon startup, if the
    ou=authorities,ou=ca,o=ipaca container exists.  Therefore, the
    ``ensure_lightweight_cas_container`` function must be executed,
    and Dogtag restarted, before executing this function.

    """

    # find out authority id, issuer DN and subject DN of IPA CA
    api.Backend.ra_lightweight_ca.override_port = 8443
    with api.Backend.ra_lightweight_ca as lwca:
        data = lwca.read_ca('host-authority')
        attrs = dict(
            ipacaid=data['id'],
            ipacaissuerdn=data['issuerDN'],
            ipacasubjectdn=data['dn'],
        )
    api.Backend.ra_lightweight_ca.override_port = None

    ensure_entry(
        DN(api.env.container_ca, api.env.basedn),
        objectclass=['top', 'nsContainer'],
        cn=['cas'],
    )
    ensure_entry(
        DN(('cn', ipalib.constants.IPA_CA_CN), api.env.container_ca, api.env.basedn),
        objectclass=['top', 'ipaca'],
        cn=[ipalib.constants.IPA_CA_CN],
        description=['IPA CA'],
        **attrs
    )


def ensure_default_caacl():
    """Add the default CA ACL if missing."""
    ensure_entry(
        DN(('cn', 'ca'), api.env.basedn),
        objectclass=['top', 'nsContainer'],
        cn=['ca'],
    )
    ensure_entry(
        DN(api.env.container_caacl, api.env.basedn),
        objectclass=['top', 'nsContainer'],
        cn=['certprofiles'],
    )

    if not api.Command.caacl_find()['result']:
        api.Command.caacl_add(u'hosts_services_caIPAserviceCert',
            hostcategory=u'all', servicecategory=u'all')
        api.Command.caacl_add_profile(u'hosts_services_caIPAserviceCert',
            certprofile=(u'caIPAserviceCert',))


def add_lightweight_ca_tracking_requests(lwcas):
    """Add tracking requests for the given lightweight CAs.

    The entries must have the 'cn' and 'ipacaid' attributes.

    The IPA CA, if present, is skipped.

    """
    for entry in lwcas:
        if ipalib.constants.IPA_CA_CN in entry['cn']:
            continue

        nickname = "{} {}".format(
                ipalib.constants.IPA_CA_NICKNAME,
                entry['ipacaid'][0])
        criteria = {
            'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
            'cert-nickname': nickname,
            'ca-name': ipalib.constants.RENEWAL_CA_NAME,
        }
        request_id = certmonger.get_request_id(criteria)
        if request_id is None:
            try:
                certmonger.start_tracking(
                    certpath=paths.PKI_TOMCAT_ALIAS_DIR,
                    pin=certmonger.get_pin(INTERNAL_TOKEN),
                    nickname=nickname,
                    ca=ipalib.constants.RENEWAL_CA_NAME,
                    profile='caCACert',
                    pre_command='stop_pkicad',
                    post_command='renew_ca_cert "%s"' % nickname,
                )
                logger.debug(
                    'Lightweight CA renewal: '
                    'added tracking request for "%s"', nickname)
            except RuntimeError as e:
                logger.error(
                    'Lightweight CA renewal: Certmonger failed to '
                    'start tracking certificate: %s', e)
        else:
            logger.debug(
                'Lightweight CA renewal: '
                'already tracking certificate "%s"', nickname)


def update_ipa_conf(ca_host=None):
    """
    Update IPA configuration file to ensure that RA plugins are enabled and
    that CA host points to specified server (or localhost if ca_host=None).
    """
    parser = RawConfigParser()
    parser.read(paths.IPA_DEFAULT_CONF)
    parser.set('global', 'enable_ra', 'True')
    parser.set('global', 'ra_plugin', 'dogtag')
    parser.set('global', 'dogtag_version', '10')
    if ca_host is None:
        parser.remove_option('global', 'ca_host')
    else:
        parser.set('global', 'ca_host', ca_host)
    with open(paths.IPA_DEFAULT_CONF, 'w') as f:
        parser.write(f)


def import_ra_key(custodia):
    custodia.import_ra_key()
    CAInstance._set_ra_cert_perms()
    CAInstance.configure_agent_renewal()


def check_ipa_ca_san(cert):
    """
    Test whether the certificate has an ipa-ca SAN

    :param cert: x509.IPACertificate

    This SAN is necessary for ACME.

    The caller is responsible for initializing the api.

    On success returns None, on failure raises ValidationError
    """
    expect = f'{ipalib.constants.IPA_CA_RECORD}.' \
             f'{ipautil.format_netloc(api.env.domain)}'

    try:
        cert.match_hostname(expect)
    except x509.ssl_match_hostname.CertificateError:
        raise errors.ValidationError(
            name='certificate',
            error='Does not have a \'{}\' SAN'.format(expect)
        )


if __name__ == "__main__":
    standard_logging_setup("install.log")
    ds = dsinstance.DsInstance()

    ca = CAInstance("EXAMPLE.COM")
    ca.configure_instance("catest.example.com", "password", "password")
