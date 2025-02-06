#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
CA installer module
"""

from __future__ import print_function, absolute_import

import enum
import logging
import os.path
import pki.util

import six

from ipalib.constants import IPA_CA_CN
from ipalib.install import certstore
from ipalib.install.service import enroll_only, master_install_only, replica_install_only
from ipaplatform.constants import constants
from ipaserver.install import sysupgrade
from ipapython.install import typing
from ipapython.install.core import group, knob, extend_knob
from ipaserver.install import acmeinstance, cainstance, bindinstance, dsinstance
from ipapython import ipautil, certdb
from ipapython import ipaldap
from ipapython.admintool import ScriptError
from ipaplatform import services
from ipaplatform.paths import paths
from ipaserver.install import installutils, certs
from ipaserver.install.replication import replica_conn_check
from ipalib import api, errors, x509
from ipapython.dn import DN

from . import conncheck, dogtag, cainstance

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
    if not isinstance(value, unicode):
        v = unicode(value, 'utf-8')
    else:
        v = value
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


def random_serial_numbers_version(enabled):
    """Return True if  PKI supports RSNv3

       The caller is responsible for raising the exception.
    """
    if not enabled:
        return None, None
    pki_version = pki.util.Version(pki.specification_version())
    return pki_version >= pki.util.Version("11.2.0"), pki_version


def random_serial_numbers_validator(enabled):
    val, pki_version = random_serial_numbers_version(enabled)
    if val is False:
        raise ValueError(
            "Random Serial Numbers are not supported in PKI version %s"
            % pki_version
        )


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
    return str(ca_subject)


def lookup_random_serial_number_version(api):
    """
    Retrieve the random serial number version number from the
    remote server.

    If the value is > 0 then RSN was enabled. Return the raw
    value for future-proofing in case version-specific decisions
    need to be made.

    Returns 0 if RSN is not enabled or otherwise not available.
    """
    dn = DN(('cn', IPA_CA_CN), api.env.container_ca, api.env.basedn)
    version = 0
    try:
        # we do not use api.Command.ca_show because it attempts to
        # talk to the CA (to read certificate / chain), but the RA
        # backend may be unavailable (ipa-replica-install) or unusable
        # due to RA Agent cert not yet created (ipa-ca-install).
        entry = api.Backend.ldap2.get_entry(dn)

        # If the attribute doesn't exist then the remote didn't
        # enable RSN.
        if 'ipacarandomserialnumberversion' in entry:
            version = int(entry['ipacarandomserialnumberversion'][0])
    except (errors.NotFound, KeyError):
        # if the entry doesn't exist then the remote doesn't support
        # RSN so there is nothing to do.
        pass

    return version


def lookup_hsm_configuration(api):
    """
    If an HSM was configured on the initial install then return the
    token name and PKCS#11 library path from that install.

    Returns a tuple of (token_name, token_library_path) or (None, None)
    """
    dn = DN(('cn', IPA_CA_CN), api.env.container_ca, api.env.basedn)
    token_name = None
    token_library_path = None
    try:
        # we do not use api.Command.ca_show because it attempts to
        # talk to the CA (to read certificate / chain), but the RA
        # backend may be unavailable (ipa-replica-install) or unusable
        # due to RA Agent cert not yet created (ipa-ca-install).
        entry = api.Backend.ldap2.get_entry(dn)

        # If the attribute doesn't exist then the remote didn't
        # enable RSN.
        if 'ipacahsmconfiguration' in entry:
            val = entry['ipacahsmconfiguration'][0]
            (token_name, token_library_path) = val.split(';')
    except (errors.NotFound, KeyError):
        # if the entry doesn't exist then the remote doesn't support
        # HSM so there is nothing to do.
        pass

    return (token_name, token_library_path)


def hsm_version():
    """Return True if PKI supports working HSM code

       The caller is responsible for raising the exception.
    """
    pki_version = pki.util.Version(pki.specification_version())
    return pki_version >= pki.util.Version("11.5.0"), pki_version


def hsm_validator(token_name, token_library, token_password):
    """Do some basic validation of the HSM information provided.

       - The local PKI server supports IPA HSM
       - The token library exists
       - The token name doesn't have a colon or semi-colon in it
       - The token name exists after loading the library
       - The token password works
       - Super-simple test to see if the SELinux module is loaded
    """
    if not token_name:
        logger.debug("No token name, assuming not an HSM install")
        return
    if not token_password:
        raise ValueError("No token password provided")
    val, pki_version = hsm_version()
    if val is False:
        raise ValueError(
            "HSM is not supported in PKI version %s" % pki_version
        )
    if ':' in token_name or ';' in token_name:
        raise ValueError(
            "Colon and semi-colon are not allowed in a token name."
        )
    if not os.path.exists(token_library):
        raise ValueError(
            "Token library path '%s' does not exist" % token_library
        )
    pkiuser = constants.PKI_USER
    pkigroup = constants.PKI_GROUP
    group_list = os.getgrouplist(pkiuser, pkigroup.gid)
    with certdb.NSSDatabase() as tempnssdb:
        tempnssdb.create_db(user=str(pkiuser), group=str(pkigroup))
        # Try adding the token library to the temporary database in
        # case it isn't already available. Ignore all errors.
        command = [
            paths.MODUTIL,
            '-dbdir', '{}:{}'.format(tempnssdb.dbtype, tempnssdb.secdir),
            '-nocertdb',
            '-add', 'test',
            '-libfile', token_library,
            '-force',
        ]
        # It may fail if p11-kit has already registered the library, that's
        # ok.
        ipautil.run(command, stdin='\n', cwd=tempnssdb.secdir,
                    runas=pkiuser, suplementary_groups=group_list,
                    raiseonerr=False)

        command = [
            paths.MODUTIL,
            '-dbdir', '{}:{}'.format(tempnssdb.dbtype, tempnssdb.secdir),
            '-list',
            '-force'
        ]
        lines = ipautil.run(
            command, cwd=tempnssdb.secdir, capture_output=True,
            runas=pkiuser, suplementary_groups=group_list).output
        found = False
        token_line = f'token: {token_name}'
        for line in lines.split('\n'):
            if token_line in line.strip():
                found = True
                break
        if not found:
            raise ValueError(
                "Token named '%s' was not found. Check permissions"
                % token_name
            )
        pwdfile = ipautil.write_tmp_file(token_password)
        os.fchown(pwdfile.fileno(), pkiuser.uid, pkigroup.gid)
        args = [
            paths.CERTUTIL,
            "-d", '{}:{}'.format(tempnssdb.dbtype, tempnssdb.secdir),
            "-K",
            "-h", token_name,
            "-f", pwdfile.name,
        ]
        result = ipautil.run(args, cwd=tempnssdb.secdir,
                             runas=pkiuser,
                             suplementary_groups=group_list,
                             capture_error=True, raiseonerr=False)
        if result.returncode != 0 and len(result.error_output):
            if 'SEC_ERROR_BAD_PASSWORD' in result.error_output:
                raise ValueError('Invalid HSM token password')
            else:
                raise ValueError(
                    "Validating HSM password failed: %s" % result.error_output
                )
        # validate that the appropriate SELinux module is installed
        # Only warn in case the expected paths don't match.
        if 'nfast' in token_library:
            module = 'ipa-nfast'
        elif 'luna' in token_library:
            module = 'ipa-luna'
        else:
            module = None
        if module:
            args = [paths.SEMODULE, "-l"]
            result = ipautil.run(args, cwd=tempnssdb.secdir,
                                 capture_output=True, raiseonerr=False)
            if module not in result.output:
                logger.info('\nWARNING: The associated SELinux module ,%s, '
                            'for this HSM was not detected.\nVerify '
                            'that the appropriate subpackage is installed '
                            'for this HSM\n', module)


def set_subject_base_in_config(subject_base):
    entry_attrs = api.Backend.ldap2.get_ipa_config()
    entry_attrs['ipacertificatesubjectbase'] = [str(subject_base)]
    try:
        api.Backend.ldap2.update_entry(entry_attrs)
    except errors.EmptyModlist:
        pass


def print_ca_configuration(options):
    """Print info about how the CA will be configured.

    Does not print trailing empty line.

    """
    print("The CA will be configured with:")
    print("Subject DN:   {}".format(options.ca_subject))
    print("Subject base: {}".format(options.subject_base))
    if options.external_ca:
        chaining = "externally signed (two-step installation)"
    elif options.external_cert_files:
        chaining = "externally signed"
    else:
        chaining = "self-signed"
    print("Chaining:     {}".format(chaining))


def uninstall_check(options):
    """IPA needs to be running so pkidestroy can unregister CA"""
    ca = cainstance.CAInstance(api.env.realm)
    if not ca.is_installed():
        return

    result = ipautil.run([paths.IPACTL, 'status'],
                         raiseonerr=False)

    if result.returncode not in [0, 4]:
        try:
            logger.info(
                "Starting services to unregister CA from security domain")
            ipautil.run([paths.IPACTL, 'start'])
        except Exception:
            logger.info("Re-starting IPA failed, continuing uninstall")


def uninstall_crl_check(options):
    """Check if the host is CRL generation master"""
    # Skip the checks if the host is not a CA instance
    ca = cainstance.CAInstance(api.env.realm)
    if not (api.Command.ca_is_enabled()['result'] and
       cainstance.is_ca_installed_locally()):
        return

    # skip the checks if the host is the last master
    ipa_config = api.Command.config_show()['result']
    ipa_masters = ipa_config.get('ipa_master_server', [])
    if len(ipa_masters) <= 1:
        return

    try:
        crlgen_enabled = ca.is_crlgen_enabled()
    except cainstance.InconsistentCRLGenConfigException:
        # If config is inconsistent, let's be safe and act as if
        # crl gen was enabled
        crlgen_enabled = True

    if crlgen_enabled:
        print("Deleting this server will leave your installation "
              "without a CRL generation master.")
        if (options.unattended and not options.ignore_last_of_role) or \
           not (options.unattended or ipautil.user_input(
                "Are you sure you want to continue with the uninstall "
                "procedure?", False)):
            raise ScriptError("Aborting uninstall operation.")


def install_check(standalone, replica_config, options):
    global external_cert_file
    global external_ca_file

    realm_name = options.realm_name
    host_name = options.host_name

    if replica_config is None:
        options._subject_base = options.subject_base
        options._ca_subject = options.ca_subject
        options._random_serial_numbers = options.random_serial_numbers
        token_name = options.token_name
        token_library_path = options.token_library_path
        if "setup_ca" in options.__dict__:
            setup_ca = options.setup_ca
        else:
            # We got here through ipa-ca-install
            setup_ca = True
    else:
        # during replica install, this gets invoked before local DS is
        # available, so use the remote api.
        _api = api if standalone else options._remote_api

        # for replica-install the knobs cannot be written, hence leading '_'
        options._subject_base = str(replica_config.subject_base)
        options._ca_subject = lookup_ca_subject(_api, options._subject_base)

        options._random_serial_numbers = (
            lookup_random_serial_number_version(_api) > 0
        )

        if options._random_serial_numbers and replica_config.setup_ca:
            try:
                random_serial_numbers_validator(
                    options._random_serial_numbers
                )
            except ValueError as e:
                raise ScriptError(str(e))

        (token_name, token_library_path) = lookup_hsm_configuration(_api)
        # IPA version and dependency checking should prevent this but
        # better to be safe and avoid a failed install.
        if replica_config.setup_ca and token_name:
            if not options.token_library_path:
                options.token_library_path = token_library_path
        setup_ca = replica_config.setup_ca

    if setup_ca and token_name:
        if (options.token_password_file and options.token_password):
            raise ScriptError(
                "token-password and token-password-file are mutually exclusive"
            )
        if options.token_password_file:
            with open(options.token_password_file, "r") as fd:
                options.token_password = fd.readline().strip()
        if (
            not options.token_password_file
            and not options.token_password
        ):
            if options.unattended:
                raise ScriptError("HSM token password required")
            token_password = installutils.read_password(
                f"HSM token '{token_name}'", confirm=False
            )
            if token_password is None:
                raise ScriptError("HSM token password required")
            else:
                options.token_password = token_password

        try:
            hsm_validator(
                token_name, token_library_path,
                options.token_password)
        except ValueError as e:
            raise ScriptError(str(e))

    if replica_config is not None and not replica_config.setup_ca:
        return

    if replica_config is not None:
        if standalone and api.env.ra_plugin == 'selfsign':
            raise ScriptError('A selfsign CA can not be added')

        if standalone and not options.skip_conncheck:
            principal = options.principal
            replica_conn_check(
                replica_config.ca_host_name, host_name, realm_name, True,
                replica_config.ca_ds_port, options.admin_password,
                principal=principal, ca_cert_file=options.ca_cert_file)

        if options.skip_schema_check:
            logger.info("Skipping CA DS schema check")

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
        if os.path.isfile(paths.ROOT_IPA_CSR):
            raise ScriptError(
                "CA CSR file %s already exists.\nIn order to continue "
                "remove the file and run the installer again." %
                paths.ROOT_IPA_CSR)

        if not options.external_ca_type:
            options.external_ca_type = x509.ExternalCAType.GENERIC.value

        if options.external_ca_profile is not None:
            # check that profile is valid for the external ca type
            if options.external_ca_type \
                    not in options.external_ca_profile.valid_for:
                raise ScriptError(
                    "External CA profile specification '{}' "
                    "cannot be used with external CA type '{}'."
                    .format(
                        options.external_ca_profile.unparsed_input,
                        options.external_ca_type)
                    )

    if not options.external_cert_files:
        if not cainstance.check_ports():
            print(
                "IPA requires ports 8080 and 8443 for PKI, but one or more "
                "are currently in use."
            )
            raise ScriptError("Aborting installation")

    if standalone:
        dirname = dsinstance.config_dirname(
            ipaldap.realm_to_serverid(realm_name))
        cadb = certs.CertDB(realm_name, nssdir=paths.PKI_TOMCAT_ALIAS_DIR,
                            subject_base=options._subject_base)
        dsdb = certs.CertDB(
            realm_name, nssdir=dirname, subject_base=options._subject_base)

        # Check that we can add our CA cert to DS and PKI NSS databases
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
                subject = DN(cert.subject)
                if subject == DN(options._ca_subject):
                    raise ScriptError(
                        "Certificate with subject %s is present in %s, "
                        "cannot continue." % (subject, db.secdir))


def install(standalone, replica_config, options, custodia):
    install_step_0(standalone, replica_config, options, custodia=custodia)
    install_step_1(standalone, replica_config, options, custodia=custodia)


def install_step_0(standalone, replica_config, options, custodia):
    realm_name = options.realm_name
    dm_password = options.dm_password
    host_name = options.host_name
    ca_subject = options._ca_subject
    subject_base = options._subject_base
    external_ca_profile = None

    if replica_config is None:
        ca_signing_algorithm = options.ca_signing_algorithm
        if options.external_ca:
            ca_type = options.external_ca_type
            external_ca_profile = options.external_ca_profile
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
        token_name = options.token_name

        pkcs12_info = None
        master_host = None
        master_replication_port = None
        ra_p12 = None
        ra_only = False
        promote = False
    else:
        _api = api if standalone else options._remote_api
        (token_name, _token_library_path) = lookup_hsm_configuration(_api)
        if not token_name:
            cafile = os.path.join(replica_config.dir, 'cacert.p12')
            if replica_config.setup_ca:
                custodia.get_ca_keys(
                    cafile,
                    replica_config.dirman_password)
        else:
            cafile = None

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
        promote = True

    # if upgrading from CA-less to CA-ful, need to rewrite
    # certmap.conf and subject_base configuration
    #
    set_subject_base_in_config(subject_base)
    sysupgrade.set_upgrade_state(
        'certmap.conf', 'subject_base', str(subject_base))
    dsinstance.write_certmap_conf(realm_name, ca_subject)

    # use secure ldaps when installing a replica or upgrading to CA-ful
    # In both cases, 389-DS is already configured to have a trusted cert.
    use_ldaps = standalone or replica_config is not None

    ca = cainstance.CAInstance(
        realm=realm_name, host_name=host_name, custodia=custodia
    )
    ca.configure_instance(
        host_name, dm_password, dm_password,
        subject_base=subject_base,
        ca_subject=ca_subject,
        ca_signing_algorithm=ca_signing_algorithm,
        ca_type=ca_type,
        external_ca_profile=external_ca_profile,
        csr_file=csr_file,
        cert_file=cert_file,
        cert_chain_file=cert_chain_file,
        pkcs12_info=pkcs12_info,
        master_host=master_host,
        master_replication_port=master_replication_port,
        ra_p12=ra_p12,
        ra_only=ra_only,
        promote=promote,
        use_ldaps=use_ldaps,
        pki_config_override=options.pki_config_override,
        random_serial_numbers=options._random_serial_numbers,
        token_name=token_name,
        token_library_path=options.token_library_path,
        token_password=options.token_password,
    )


def install_step_1(standalone, replica_config, options, custodia):
    if replica_config is not None and not replica_config.setup_ca:
        return

    realm_name = options.realm_name
    host_name = options.host_name
    subject_base = options._subject_base
    basedn = ipautil.realm_to_suffix(realm_name)

    ca = cainstance.CAInstance(
        realm=realm_name, host_name=host_name, custodia=custodia
    )

    ca.stop('pki-tomcat')

    # This is done within stopped_service context, which restarts CA
    ca.enable_client_auth_to_db()

    # Lightweight CA key retrieval is configured in step 1 instead
    # of CAInstance.configure_instance (which is invoked from step
    # 0) because kadmin_addprinc fails until krb5.conf is installed
    # by krb.create_instance.
    #
    ca.setup_lightweight_ca_key_retrieval()

    serverid = ipaldap.realm_to_serverid(realm_name)

    if standalone and replica_config is None:
        dirname = dsinstance.config_dirname(serverid)

        # Store the new IPA CA cert chain in DS NSS database and LDAP
        cadb = certs.CertDB(
            realm_name, nssdir=paths.PKI_TOMCAT_ALIAS_DIR,
            subject_base=subject_base)
        dsdb = certs.CertDB(
            realm_name, nssdir=dirname, subject_base=subject_base)
        cacert = cadb.get_cert_from_db('caSigningCert cert-pki-ca')
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
    acme = acmeinstance.ACMEInstance(api.env.realm)
    acme.uninstall()

    ca_instance = cainstance.CAInstance(api.env.realm)
    ca_instance.stop_tracking_certificates()
    ipautil.remove_file(paths.RA_AGENT_PEM)
    ipautil.remove_file(paths.RA_AGENT_KEY)
    if ca_instance.is_configured():
        ca_instance.uninstall()


class CASigningAlgorithm(enum.Enum):
    SHA1_WITH_RSA = 'SHA1withRSA'
    SHA_256_WITH_RSA = 'SHA256withRSA'
    SHA_384_WITH_RSA = 'SHA384withRSA'
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
        x509.ExternalCAType, None, description="Type of the external CA")
    external_ca_type = master_install_only(external_ca_type)

    external_ca_profile = knob(
        type=x509.ExternalCAProfile,
        default=None,
        description=(
            "Specify the certificate profile/template to use at the "
            "external CA"),
    )
    external_ca_profile = master_install_only(external_ca_profile)

    external_cert_files = knob(
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

    random_serial_numbers = knob(
        None,
        description="Enable random serial numbers",
    )
    random_serial_numbers = master_install_only(random_serial_numbers)

    @random_serial_numbers.validator
    def random_serial_numbers(self, value):
        random_serial_numbers_validator(value)
