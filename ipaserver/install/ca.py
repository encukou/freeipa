#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
CA installer module
"""

from __future__ import print_function

import enum
import logging
import os.path

import six

from ipalib.constants import IPA_CA_CN
from ipalib.install import certstore
from ipalib.install.service import enroll_only, master_install_only, replica_install_only
from ipaserver.install import sysupgrade
from ipapython.install import typing
from ipapython.install.core import group, knob, extend_knob
from ipaserver.install import (cainstance,
                               custodiainstance,
                               dsinstance,
                               bindinstance)
from ipapython import ipautil, certdb
from ipapython.admintool import ScriptError
from ipaplatform import services
from ipaplatform.paths import paths
from ipaserver.install import installutils, certs
from ipaserver.install.replication import replica_conn_check
from ipalib import api, errors, x509
from ipapython.dn import DN

from . import conncheck, dogtag

if six.PY3:
    unicode = str

VALID_SUBJECT_BASE_ATTRS = {
    'st', 'o', 'ou', 'dnqualifier', 'c', 'serialnumber', 'l', 'title', 'sn',
    'givenname', 'initials', 'generationqualifier', 'dc', 'mail', 'uid',
    'postaladdress', 'postalcode', 'postofficebox', 'houseidentifier', 'e',
    'street', 'pseudonym', 'incorporationlocality', 'incorporationstate',
    'incorporationcountry', 'businesscategory',
}
VALID_SUBJECT_ATTRS = {'cn'} | VALID_SUBJECT_BASE_ATTRS

logger = logging.getLogger(__name__)

external_cert_file = None
external_ca_file = None


def subject_validator(valid_attrs, value):
    v = unicode(value, 'utf-8')
    if any(ord(c) < 0x20 for c in v):
        raise ValueError("must not contain control characters")
    if '&' in v:
        raise ValueError("must not contain an ampersand (\"&\")")
    try:
        dn = DN(v)
        for rdn in dn:
            if rdn.attr.lower() not in valid_attrs:
                raise ValueError("invalid attribute: \"%s\"" % rdn.attr)
    except ValueError as e:
        raise ValueError("invalid DN: %s" % e)


def lookup_ca_subject(api, subject_base):
    dn = DN(('cn', IPA_CA_CN), api.env.container_ca, api.env.basedn)
    try:
        # we do not use api.Command.ca_show because it attempts to
        # talk to the CA (to read certificate / chain), but the RA
        # backend may be unavailable (ipa-replica-install) or unusable
        # due to RA Agent cert not yet created (ipa-ca-install).
        ca_subject = api.Backend.ldap2.get_entry(dn)['ipacasubjectdn'][0]
    except errors.NotFound:
        # if the entry doesn't exist, we are dealing with a pre-v4.4
        # installation, where the default CA subject was always based
        # on the subject_base.
        #
        # installutils.default_ca_subject_dn is NOT used here in
        # case the default changes in the future.
        ca_subject = DN(('CN', 'Certificate Authority'), subject_base)
    return six.text_type(ca_subject)


def set_subject_base_in_config(subject_base):
    entry_attrs = api.Backend.ldap2.get_ipa_config()
    entry_attrs['ipacertificatesubjectbase'] = [str(subject_base)]
    try:
        api.Backend.ldap2.update_entry(entry_attrs)
    except errors.EmptyModlist:
        pass


def install_check(standalone, replica_config, options):
    global external_cert_file
    global external_ca_file

    realm_name = options.realm_name
    host_name = options.host_name

    if replica_config is None:
        options._subject_base = options.subject_base
        options._ca_subject = options.ca_subject
    else:
        # during replica install, this gets invoked before local DS is
        # available, so use the remote api.
        _api = api if standalone else options._remote_api

        # for replica-install the knobs cannot be written, hence leading '_'
        options._subject_base = six.text_type(replica_config.subject_base)
        options._ca_subject = lookup_ca_subject(_api, options._subject_base)

    if replica_config is not None and not replica_config.setup_ca:
        return

    if replica_config is not None:
        if standalone and api.env.ra_plugin == 'selfsign':
            raise ScriptError('A selfsign CA can not be added')

        cafile = os.path.join(replica_config.dir, 'cacert.p12')
        if not options.promote and not ipautil.file_exists(cafile):
            raise ScriptError('CA cannot be installed in CA-less setup.')

        if standalone and not options.skip_conncheck:
            principal = options.principal
            replica_conn_check(
                replica_config.ca_host_name, host_name, realm_name, True,
                replica_config.ca_ds_port, options.admin_password,
                principal=principal, ca_cert_file=options.ca_cert_file)

        if options.skip_schema_check:
            logger.info("Skipping CA DS schema check")
        else:
            cainstance.replica_ca_install_check(replica_config, options.promote)

        return

    if standalone:
        if api.Command.ca_is_enabled()['result']:
            raise ScriptError(
                "One or more CA masters are already present in IPA realm "
                "'%s'.\nIf you wish to replicate CA to this host, please "
                "re-run 'ipa-ca-install'\nwith a replica file generated on "
                "an existing CA master as argument." % realm_name
            )

    if options.external_cert_files:
        if not cainstance.is_step_one_done():
            # This can happen if someone passes external_ca_file without
            # already having done the first stage of the CA install.
            raise ScriptError(
                  "CA is not installed yet. To install with an external CA "
                  "is a two-stage process.\nFirst run the installer with "
                  "--external-ca.")

        external_cert_file, external_ca_file = installutils.load_external_cert(
            options.external_cert_files, options._ca_subject)
    elif options.external_ca:
        if cainstance.is_step_one_done():
            raise ScriptError(
                "CA is already installed.\nRun the installer with "
                "--external-cert-file.")
        if ipautil.file_exists(paths.ROOT_IPA_CSR):
            raise ScriptError(
                "CA CSR file %s already exists.\nIn order to continue "
                "remove the file and run the installer again." %
                paths.ROOT_IPA_CSR)

    if not options.external_cert_files:
        if not cainstance.check_port():
            print("IPA requires port 8443 for PKI but it is currently in use.")
            raise ScriptError("Aborting installation")

    if standalone:
        dirname = dsinstance.config_dirname(
            installutils.realm_to_serverid(realm_name))
        cadb = certs.CertDB(realm_name, nssdir=paths.PKI_TOMCAT_ALIAS_DIR,
                            subject_base=options._subject_base)
        dsdb = certs.CertDB(
            realm_name, nssdir=dirname, subject_base=options._subject_base)

        for db in (cadb, dsdb):
            if not db.exists():
                continue
            for nickname, _trust_flags in db.list_certs():
                if nickname == certdb.get_ca_nickname(realm_name):
                    raise ScriptError(
                        "Certificate with nickname %s is present in %s, "
                        "cannot continue." % (nickname, db.secdir))

                cert = db.get_cert_from_db(nickname)
                if not cert:
                    continue
                subject = DN(x509.load_pem_x509_certificate(cert).subject)
                if subject == DN(options._ca_subject):
                    raise ScriptError(
                        "Certificate with subject %s is present in %s, "
                        "cannot continue." % (subject, db.secdir))


def install(standalone, replica_config, options):
    install_step_0(standalone, replica_config, options)
    install_step_1(standalone, replica_config, options)


def install_step_0(standalone, replica_config, options):
    realm_name = options.realm_name
    dm_password = options.dm_password
    host_name = options.host_name
    ca_subject = options._ca_subject
    subject_base = options._subject_base

    if replica_config is None:
        ca_signing_algorithm = options.ca_signing_algorithm
        if options.external_ca:
            ca_type = options.external_ca_type
            csr_file = paths.ROOT_IPA_CSR
        else:
            ca_type = None
            csr_file = None
        if options.external_cert_files:
            cert_file = external_cert_file.name
            cert_chain_file = external_ca_file.name
        else:
            cert_file = None
            cert_chain_file = None

        pkcs12_info = None
        master_host = None
        master_replication_port = None
        ra_p12 = None
        ra_only = False
        promote = False
    else:
        cafile = os.path.join(replica_config.dir, 'cacert.p12')
        if options.promote:
            custodia = custodiainstance.CustodiaInstance(
                replica_config.host_name,
                replica_config.realm_name)
            custodia.get_ca_keys(
                replica_config.ca_host_name,
                cafile,
                replica_config.dirman_password)

        ca_signing_algorithm = None
        ca_type = None
        csr_file = None
        cert_file = None
        cert_chain_file = None

        pkcs12_info = (cafile,)
        master_host = replica_config.ca_host_name
        master_replication_port = replica_config.ca_ds_port
        ra_p12 = os.path.join(replica_config.dir, 'ra.p12')
        ra_only = not replica_config.setup_ca
        promote = options.promote

    # if upgrading from CA-less to CA-ful, need to rewrite
    # certmap.conf and subject_base configuration
    #
    set_subject_base_in_config(subject_base)
    sysupgrade.set_upgrade_state(
        'certmap.conf', 'subject_base', str(subject_base))
    dsinstance.write_certmap_conf(realm_name, ca_subject)

    ca = cainstance.CAInstance(realm_name, host_name=host_name)
    ca.configure_instance(host_name, dm_password, dm_password,
                          subject_base=subject_base,
                          ca_subject=ca_subject,
                          ca_signing_algorithm=ca_signing_algorithm,
                          ca_type=ca_type,
                          csr_file=csr_file,
                          cert_file=cert_file,
                          cert_chain_file=cert_chain_file,
                          pkcs12_info=pkcs12_info,
                          master_host=master_host,
                          master_replication_port=master_replication_port,
                          ra_p12=ra_p12,
                          ra_only=ra_only,
                          promote=promote,
                          use_ldaps=standalone)


def install_step_1(standalone, replica_config, options):
    if replica_config is not None and not replica_config.setup_ca:
        return

    realm_name = options.realm_name
    host_name = options.host_name
    subject_base = options._subject_base
    basedn = ipautil.realm_to_suffix(realm_name)

    ca = cainstance.CAInstance(realm_name, host_name=host_name)

    ca.stop('pki-tomcat')

    # This is done within stopped_service context, which restarts CA
    ca.enable_client_auth_to_db(paths.CA_CS_CFG_PATH)

    # Lightweight CA key retrieval is configured in step 1 instead
    # of CAInstance.configure_instance (which is invoked from step
    # 0) because kadmin_addprinc fails until krb5.conf is installed
    # by krb.create_instance.
    #
    ca.setup_lightweight_ca_key_retrieval()

    serverid = installutils.realm_to_serverid(realm_name)

    if standalone and replica_config is None:
        dirname = dsinstance.config_dirname(serverid)

        # Store the new IPA CA cert chain in DS NSS database and LDAP
        cadb = certs.CertDB(
            realm_name, nssdir=paths.PKI_TOMCAT_ALIAS_DIR,
            subject_base=subject_base)
        dsdb = certs.CertDB(
            realm_name, nssdir=dirname, subject_base=subject_base)
        cacert = cadb.get_cert_from_db('caSigningCert cert-pki-ca', pem=False)
        nickname = certdb.get_ca_nickname(realm_name)
        trust_flags = certdb.IPA_CA_TRUST_FLAGS
        dsdb.add_cert(cacert, nickname, trust_flags)
        certstore.put_ca_cert_nss(api.Backend.ldap2, api.env.basedn,
                                  cacert, nickname, trust_flags,
                                  config_ipa=True, config_compat=True)

        # Store DS CA cert in Dogtag NSS database
        trust_flags = dict(reversed(dsdb.list_certs()))
        server_certs = dsdb.find_server_certs()
        trust_chain = dsdb.find_root_cert(server_certs[0][0])[:-1]
        nickname = trust_chain[-1]
        cert = dsdb.get_cert_from_db(nickname)
        cadb.add_cert(cert, nickname, trust_flags[nickname])

    installutils.restart_dirsrv()

    ca.start('pki-tomcat')

    if standalone or replica_config is not None:
        # We need to restart apache as we drop a new config file in there
        services.knownservices.httpd.restart(capture_output=True)

    if standalone:
        # Install CA DNS records
        if bindinstance.dns_container_exists(basedn):
            bind = bindinstance.BindInstance()
            bind.update_system_records()


def uninstall():
    ca_instance = cainstance.CAInstance(api.env.realm)
    ca_instance.stop_tracking_certificates()
    installutils.remove_file(paths.RA_AGENT_PEM)
    installutils.remove_file(paths.RA_AGENT_KEY)
    if ca_instance.is_configured():
        ca_instance.uninstall()


class ExternalCAType(enum.Enum):
    GENERIC = 'generic'
    MS_CS = 'ms-cs'


class CASigningAlgorithm(enum.Enum):
    SHA1_WITH_RSA = 'SHA1withRSA'
    SHA_256_WITH_RSA = 'SHA256withRSA'
    SHA_512_WITH_RSA = 'SHA512withRSA'


@group
class CAInstallInterface(dogtag.DogtagInstallInterface,
                         conncheck.ConnCheckInterface):
    """
    Interface of the CA installer

    Knobs defined here will be available in:
    * ipa-server-install
    * ipa-replica-prepare
    * ipa-replica-install
    * ipa-ca-install
    """
    description = "Certificate system"

    principal = conncheck.ConnCheckInterface.principal
    principal = extend_knob(
        principal,
        description="User allowed to manage replicas",
        cli_names=list(principal.cli_names) + ['-P'],
    )
    principal = enroll_only(principal)
    principal = replica_install_only(principal)

    admin_password = conncheck.ConnCheckInterface.admin_password
    admin_password = extend_knob(
        admin_password,
        description="Admin user Kerberos password used for connection check",
        cli_names=list(admin_password.cli_names) + ['-w'],
    )
    admin_password = enroll_only(admin_password)

    external_ca = knob(
        None,
        description=("Generate a CSR for the IPA CA certificate to be signed "
                     "by an external CA"),
    )
    external_ca = master_install_only(external_ca)

    external_ca_type = knob(
        ExternalCAType, None,
        description="Type of the external CA",
    )
    external_ca_type = master_install_only(external_ca_type)

    external_cert_files = knob(
        # pylint: disable=invalid-sequence-index
        typing.List[str], None,
        description=("File containing the IPA CA certificate and the external "
                     "CA certificate chain"),
        cli_names='--external-cert-file',
        cli_deprecated_names=['--external_cert_file', '--external_ca_file'],
        cli_metavar='FILE',
    )
    external_cert_files = master_install_only(external_cert_files)

    @external_cert_files.validator
    def external_cert_files(self, value):
        if any(not os.path.isabs(path) for path in value):
            raise ValueError("must use an absolute path")

    subject_base = knob(
        str, None,
        description=(
            "The certificate subject base (default O=<realm-name>). "
            "RDNs are in LDAP order (most specific RDN first)."
        ),
        cli_deprecated_names=['--subject'],
    )
    subject_base = master_install_only(subject_base)

    @subject_base.validator
    def subject_base(self, value):
        subject_validator(VALID_SUBJECT_BASE_ATTRS, value)

    ca_subject = knob(
        str, None,
        description=(
            "The CA certificate subject DN "
            "(default CN=Certificate Authority,O=<realm-name>). "
            "RDNs are in LDAP order (most specific RDN first)."
        ),
    )
    ca_subject = master_install_only(ca_subject)

    @ca_subject.validator
    def ca_subject(self, value):
        subject_validator(VALID_SUBJECT_ATTRS, value)

    ca_signing_algorithm = knob(
        CASigningAlgorithm, None,
        description="Signing algorithm of the IPA CA certificate",
    )
    ca_signing_algorithm = master_install_only(ca_signing_algorithm)

    skip_schema_check = knob(
        None,
        description="skip check for updated CA DS schema on the remote master",
    )
    skip_schema_check = enroll_only(skip_schema_check)
    skip_schema_check = replica_install_only(skip_schema_check)
