#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
Server installer module
"""
import os.path
import random

from ipaclient.install import client
from ipalib import constants
from ipalib.util import validate_domain_name
from ipalib.install import service
from ipalib.install.service import (enroll_only,
                                    installs_master,
                                    installs_replica,
                                    master_install_only,
                                    prepare_only,
                                    replica_install_only)
from ipapython.install import typing
from ipapython.install.core import group, knob, extend_knob
from ipapython.install.common import step
from ipaplatform import services

from .install import validate_admin_password, validate_dm_password
from .install import get_min_idstart
from .install import init as master_init
from .install import install as master_install
from .install import install_check as master_install_check
from .install import uninstall, uninstall_check
from .replicainstall import init as replica_init
from .replicainstall import install as replica_install
from .replicainstall import promote_check as replica_promote_check
from .upgrade import upgrade_check, upgrade

from .. import adtrust, ca, conncheck, dns, kra


@group
class ServerUninstallInterface(service.ServiceInstallInterface):
    description = "Uninstall"

    ignore_topology_disconnect = knob(
        None,
        description="do not check whether server uninstall disconnects the "
                    "topology (domain level 1+)",
    )
    ignore_topology_disconnect = master_install_only(ignore_topology_disconnect)

    ignore_last_of_role = knob(
        None,
        description="do not check whether server uninstall removes last "
                    "CA/DNS server or DNSSec master (domain level 1+)",
    )
    ignore_last_of_role = master_install_only(ignore_last_of_role)


@group
class ServerCertificateInstallInterface(service.ServiceInstallInterface):
    description = "SSL certificate"

    dirsrv_cert_files = knob(
        typing.List[str], None,
        description=("File containing the Directory Server SSL certificate "
                     "and private key"),
        cli_names='--dirsrv-cert-file',
        cli_deprecated_names='--dirsrv_pkcs12',
        cli_metavar='FILE',
    )
    dirsrv_cert_files = prepare_only(dirsrv_cert_files)

    http_cert_files = knob(
        typing.List[str], None,
        description=("File containing the Apache Server SSL certificate and "
                     "private key"),
        cli_names='--http-cert-file',
        cli_deprecated_names='--http_pkcs12',
        cli_metavar='FILE',
    )
    http_cert_files = prepare_only(http_cert_files)

    pkinit_cert_files = knob(
        typing.List[str], None,
        description=("File containing the Kerberos KDC SSL certificate and "
                     "private key"),
        cli_names='--pkinit-cert-file',
        cli_deprecated_names='--pkinit_pkcs12',
        cli_metavar='FILE',
    )
    pkinit_cert_files = prepare_only(pkinit_cert_files)

    dirsrv_pin = knob(
        str, None,
        sensitive=True,
        description="The password to unlock the Directory Server private key",
        cli_deprecated_names='--dirsrv_pin',
        cli_metavar='PIN',
    )
    dirsrv_pin = prepare_only(dirsrv_pin)

    http_pin = knob(
        str, None,
        sensitive=True,
        description="The password to unlock the Apache Server private key",
        cli_deprecated_names='--http_pin',
        cli_metavar='PIN',
    )
    http_pin = prepare_only(http_pin)

    pkinit_pin = knob(
        str, None,
        sensitive=True,
        description="The password to unlock the Kerberos KDC private key",
        cli_deprecated_names='--pkinit_pin',
        cli_metavar='PIN',
    )
    pkinit_pin = prepare_only(pkinit_pin)

    dirsrv_cert_name = knob(
        str, None,
        description="Name of the Directory Server SSL certificate to install",
        cli_metavar='NAME',
    )
    dirsrv_cert_name = prepare_only(dirsrv_cert_name)

    http_cert_name = knob(
        str, None,
        description="Name of the Apache Server SSL certificate to install",
        cli_metavar='NAME',
    )
    http_cert_name = prepare_only(http_cert_name)

    pkinit_cert_name = knob(
        str, None,
        description="Name of the Kerberos KDC SSL certificate to install",
        cli_metavar='NAME',
    )
    pkinit_cert_name = prepare_only(pkinit_cert_name)


@group
class ServerHSMInstallInterface(service.ServiceInstallInterface):
    description = "HSM"

    token_name = knob(
        str, None,
        description=(
            "The PKCS#11 token name if using an HSM to store and generate "
            "private keys."
        ),
        cli_metavar='NAME',
    )
    token_name = master_install_only(token_name)

    token_library_path = knob(
        str, None,
        description=(
            "The full path to the PKCS#11 shared library needed to"
            "access an HSM device."
        ),
        cli_metavar='NAME',
    )
    token_library_path = prepare_only(token_library_path)

    token_password = knob(
        str, None,
        sensitive=True,
        description=("The PKCS#11 token password for the HSM."),
        cli_metavar='NAME',
    )
    token_password = prepare_only(token_password)

    token_password_file = knob(
        str, None,
        description=("The full path to a file containing the password to "
                     "the PKCS#11 token password."),
        cli_metavar='NAME',
    )
    token_password_file = prepare_only(token_password_file)


@group
class ServerInstallInterface(ServerCertificateInstallInterface,
                             ServerHSMInstallInterface,
                             client.ClientInstallInterface,
                             ca.CAInstallInterface,
                             kra.KRAInstallInterface,
                             dns.DNSInstallInterface,
                             adtrust.ADTrustInstallInterface,
                             conncheck.ConnCheckInterface,
                             ServerUninstallInterface):
    """
    Interface of server installers

    Knobs defined here will be available in:
    * ipa-server-install
    * ipa-replica-prepare
    * ipa-replica-install
    """
    description = "Server"

    kinit_attempts = 1
    fixed_primary = True
    permit = False
    enable_dns_updates = False
    no_krb5_offline_passwords = False
    preserve_sssd = False
    no_sssd = False

    domain_name = client.ClientInstallInterface.domain_name
    domain_name = extend_knob(
        domain_name,
        cli_names=list(domain_name.cli_names) + ['-n'],
    )

    servers = extend_knob(
        client.ClientInstallInterface.servers,
        description="fully qualified name of IPA server to enroll to",
    )
    servers = enroll_only(servers)

    realm_name = client.ClientInstallInterface.realm_name
    realm_name = extend_knob(
        realm_name,
        cli_names=list(realm_name.cli_names) + ['-r'],
    )

    host_name = extend_knob(
        client.ClientInstallInterface.host_name,
        description="fully qualified name of this host",
    )

    ca_cert_files = extend_knob(
        client.ClientInstallInterface.ca_cert_files,
        description="File containing CA certificates for the service "
                    "certificate files",
        cli_deprecated_names='--root-ca-file',
    )
    ca_cert_files = prepare_only(ca_cert_files)

    dm_password = extend_knob(
        client.ClientInstallInterface.dm_password,
        description="Directory Manager password",
    )

    ip_addresses = extend_knob(
        client.ClientInstallInterface.ip_addresses,
        description="Server IP Address. This option can be used multiple "
                    "times",
    )

    principal = client.ClientInstallInterface.principal
    principal = extend_knob(
        principal,
        description="User Principal allowed to promote replicas and join IPA "
                    "realm",
        cli_names=list(principal.cli_names) + ['-P'],
    )
    principal = replica_install_only(principal)

    admin_password = extend_knob(
        client.ClientInstallInterface.admin_password,
    )

    master_password = knob(
        str, None,
        sensitive=True,
        deprecated=True,
        description="kerberos master password (normally autogenerated)",
    )
    master_password = master_install_only(master_password)

    hidden_replica = knob(
        None,
        cli_names='--hidden-replica',
        description="Install a hidden replica",
    )
    hidden_replica = replica_install_only(hidden_replica)

    domain_level = knob(
        int, constants.MAX_DOMAIN_LEVEL,
        description="IPA domain level",
        deprecated=True,
    )
    domain_level = master_install_only(domain_level)

    @domain_level.validator
    def domain_level(self, value):
        # Check that Domain Level is within the allowed range
        if value < constants.MIN_DOMAIN_LEVEL:
            raise ValueError(
                "Domain Level cannot be lower than {0}".format(
                    constants.MIN_DOMAIN_LEVEL))
        elif value > constants.MAX_DOMAIN_LEVEL:
            raise ValueError(
                "Domain Level cannot be higher than {0}".format(
                    constants.MAX_DOMAIN_LEVEL))

    setup_adtrust = knob(
        None,
        description="configure AD trust capability"
    )
    setup_ca = knob(
        None,
        description="configure a dogtag CA",
    )
    setup_ca = enroll_only(setup_ca)

    setup_kra = knob(
        None,
        description="configure a dogtag KRA",
    )
    setup_kra = enroll_only(setup_kra)

    setup_dns = knob(
        None,
        description="configure bind with our zone",
    )
    setup_dns = enroll_only(setup_dns)

    @setup_dns.validator
    def setup_dns(self, value):
        if value:
            dns.package_check(ValueError)

    idstart = knob(
        int, random.randint(1, 10000) * 200000,
        description="The starting value for the IDs range (default random)",
    )
    idstart = master_install_only(idstart)

    idmax = knob(
        int,
        description=("The max value for the IDs range (default: "
                     "idstart+199999)"),
    )
    idmax = master_install_only(idmax)

    @idmax.default_getter
    def idmax(self):
        return self.idstart + 200000 - 1

    no_hbac_allow = knob(
        None,
        description="Don't install allow_all HBAC rule",
        cli_deprecated_names='--no_hbac_allow',
    )
    no_hbac_allow = master_install_only(no_hbac_allow)

    no_pkinit = knob(
        None,
        description="disables pkinit setup steps",
    )
    no_pkinit = prepare_only(no_pkinit)

    no_ui_redirect = knob(
        None,
        description="Do not automatically redirect to the Web UI",
    )
    no_ui_redirect = enroll_only(no_ui_redirect)

    dirsrv_config_file = knob(
        str, None,
        description="The path to LDIF file that will be used to modify "
                    "configuration of dse.ldif during installation of the "
                    "directory server instance",
        cli_metavar='FILE',
    )
    dirsrv_config_file = enroll_only(dirsrv_config_file)

    skip_mem_check = knob(
        None,
        description="Skip checking for minimum required memory",
    )
    skip_mem_check = enroll_only(skip_mem_check)

    @dirsrv_config_file.validator
    def dirsrv_config_file(self, value):
        if not os.path.exists(value):
            raise ValueError("File %s does not exist." % value)

    def __init__(self, **kwargs):
        super(ServerInstallInterface, self).__init__(**kwargs)

        # If any of the key file options are selected, all are required.
        cert_file_req = (self.dirsrv_cert_files, self.http_cert_files)
        cert_file_opt = (self.pkinit_cert_files,)
        if not self.no_pkinit:
            cert_file_req += cert_file_opt
        if self.no_pkinit and self.pkinit_cert_files:
            raise RuntimeError(
                "--no-pkinit and --pkinit-cert-file cannot be specified "
                "together"
            )
        if any(cert_file_req + cert_file_opt) and not all(cert_file_req):
            raise RuntimeError(
                "--dirsrv-cert-file, --http-cert-file, and --pkinit-cert-file "
                "or --no-pkinit are required if any key file options are used."
            )

        if not self.interactive:
            if self.dirsrv_cert_files and self.dirsrv_pin is None:
                raise RuntimeError(
                    "You must specify --dirsrv-pin with --dirsrv-cert-file")
            if self.http_cert_files and self.http_pin is None:
                raise RuntimeError(
                    "You must specify --http-pin with --http-cert-file")
            if self.pkinit_cert_files and self.pkinit_pin is None:
                raise RuntimeError(
                    "You must specify --pkinit-pin with --pkinit-cert-file")

        if not self.setup_dns:
            if self.forwarders:
                raise RuntimeError(
                    "You cannot specify a --forwarder option without the "
                    "--setup-dns option")
            if self.auto_forwarders:
                raise RuntimeError(
                    "You cannot specify a --auto-forwarders option without "
                    "the --setup-dns option")
            if self.no_forwarders:
                raise RuntimeError(
                    "You cannot specify a --no-forwarders option without the "
                    "--setup-dns option")
            if self.forward_policy:
                raise RuntimeError(
                    "You cannot specify a --forward-policy option without the "
                    "--setup-dns option")
            if self.reverse_zones:
                raise RuntimeError(
                    "You cannot specify a --reverse-zone option without the "
                    "--setup-dns option")
            if self.auto_reverse:
                raise RuntimeError(
                    "You cannot specify a --auto-reverse option without the "
                    "--setup-dns option")
            if self.no_reverse:
                raise RuntimeError(
                    "You cannot specify a --no-reverse option without the "
                    "--setup-dns option")
            if self.no_dnssec_validation:
                raise RuntimeError(
                    "You cannot specify a --no-dnssec-validation option "
                    "without the --setup-dns option")
            if self.dot_forwarders:
                raise RuntimeError(
                    "You cannot specify a --dot-forwarder option "
                    "without the --setup-dns option")
            if self.dns_over_tls_cert:
                raise RuntimeError(
                    "You cannot specify a --dns-over-tls-cert option "
                    "without the --setup-dns option")
            if self.dns_over_tls_key:
                raise RuntimeError(
                    "You cannot specify a --dns-over-tls-key option "
                    "without the --setup-dns option")
        elif self.forwarders and self.no_forwarders:
            raise RuntimeError(
                "You cannot specify a --forwarder option together with "
                "--no-forwarders")
        elif self.auto_forwarders and self.no_forwarders:
            raise RuntimeError(
                "You cannot specify a --auto-forwarders option together with "
                "--no-forwarders")
        elif self.reverse_zones and self.no_reverse:
            raise RuntimeError(
                "You cannot specify a --reverse-zone option together with "
                "--no-reverse")
        elif self.auto_reverse and self.no_reverse:
            raise RuntimeError(
                "You cannot specify a --auto-reverse option together with "
                "--no-reverse")
        elif self.dot_forwarders and not self.dns_over_tls:
            raise RuntimeError(
                "You cannot specify a --dot-forwarder option "
                "without the --dns-over-tls option")
        elif (self.dns_over_tls
              and not services.knownservices["unbound"].is_installed()):
            raise RuntimeError(
                "To enable DNS over TLS, package ipa-server-encrypted-dns "
                "must be installed."
            )
        elif self.dns_policy == "enforced" and not self.dns_over_tls:
            raise RuntimeError(
                "You cannot specify a --dns-policy option "
                "without the --dns-over-tls option")
        elif self.dns_over_tls_cert and not self.dns_over_tls:
            raise RuntimeError(
                "You cannot specify a --dns-over-tls-cert option "
                "without the --dns-over-tls option")
        elif self.dns_over_tls_key and not self.dns_over_tls:
            raise RuntimeError(
                "You cannot specify a --dns-over-tls-key option "
                "without the --dns-over-tls option")
        elif bool(self.dns_over_tls_key) != bool(self.dns_over_tls_cert):
            raise RuntimeError(
                "You cannot specify a --dns-over-tls-key option "
                "without the --dns-over-tls-cert option and vice versa")
        if not self.setup_adtrust:
            if self.add_agents:
                raise RuntimeError(
                    "You cannot specify an --add-agents option without the "
                    "--setup-adtrust option")

            if self.enable_compat:
                raise RuntimeError(
                    "You cannot specify an --enable-compat option without the "
                    "--setup-adtrust option")

            if self.no_msdcs:
                raise RuntimeError(
                    "You cannot specify a --no-msdcs option without the "
                    "--setup-adtrust option")

        if not hasattr(self, 'replica_install'):
            if self.external_cert_files and self.dirsrv_cert_files:
                raise RuntimeError(
                    "Service certificate file options cannot be used with the "
                    "external CA options.")

            if self.external_ca_type and not self.external_ca:
                raise RuntimeError(
                    "You cannot specify --external-ca-type without "
                    "--external-ca")

            if self.external_ca_profile and not self.external_ca:
                raise RuntimeError(
                    "You cannot specify --external-ca-profile without "
                    "--external-ca")

            if self.uninstalling:  # pylint: disable=using-constant-test
                if (self.realm_name or self.admin_password or
                        self.master_password):
                    raise RuntimeError(
                        "In uninstall mode, -a, -r and -P options are not "
                        "allowed")
            elif not self.interactive:
                if (not self.realm_name or not self.dm_password or
                        not self.admin_password):
                    raise RuntimeError(
                        "In unattended mode you need to provide at least -r, "
                        "-p and -a options")
                if self.setup_dns:
                    if (not self.forwarders
                            and not self.no_forwarders
                            and not self.auto_forwarders
                            and not self.dot_forwarders):
                        raise RuntimeError(
                            "You must specify at least one of --forwarder, "
                            "--auto-forwarders, --dot-forwarder or "
                            "--no-forwarders options")
                    elif self.dns_over_tls and not self.dot_forwarders:
                        raise RuntimeError(
                            "You must specify --dot-forwarder "
                            "when enabling DNS over TLS")

            any_ignore_option_true = any(
                [self.ignore_topology_disconnect, self.ignore_last_of_role])
            if any_ignore_option_true and not self.uninstalling:
                raise RuntimeError(
                    "'--ignore-topology-disconnect/--ignore-last-of-role' "
                    "options can be used only during uninstallation")

            min_idstart = get_min_idstart()
            if self.idstart < min_idstart:
                raise RuntimeError(
                    "idstart (%i) must be larger than UID_MAX/GID_MAX (%i) "
                    "setting in /etc/login.defs." % (
                        self.idstart, min_idstart
                    )
                )

            if self.idmax < self.idstart:
                raise RuntimeError(
                    "idmax (%s) cannot be smaller than idstart (%s)" %
                    (self.idmax, self.idstart))
        else:
            # replica installers
            if self.servers and not self.domain_name:
                raise RuntimeError(
                    "The --server option cannot be used without providing "
                    "domain via the --domain option")

            if self.setup_dns:
                if (not self.forwarders and
                        not self.no_forwarders and
                        not self.auto_forwarders
                        and not self.dot_forwarders):
                    raise RuntimeError(
                        "You must specify at least one of --forwarder, "
                        "--auto-forwarders, --dot-forwarder, "
                        "or --no-forwarders options")


ServerMasterInstallInterface = installs_master(ServerInstallInterface)


class ServerMasterInstall(ServerMasterInstallInterface):
    """
    Server master installer
    """

    force_join = False
    servers = None
    no_wait_for_dns = True
    host_password = None
    keytab = None
    setup_ca = True

    domain_name = extend_knob(
        ServerMasterInstallInterface.domain_name,
    )

    @domain_name.validator
    def domain_name(self, value):
        # There might be an overlap but at this point we don't have
        # complete installer object to verify that DNS is hosted
        # by the same machine (i.e. we are already installed).
        # Later, DNS.install_check will do its zone overlap check
        # and will make sure to fail if overlap does really exist.
        # At this point we only verify that value is a valid DNS syntax.
        validate_domain_name(value)

    dm_password = extend_knob(
        ServerMasterInstallInterface.dm_password,
    )

    @dm_password.validator
    def dm_password(self, value):
        validate_dm_password(value)

    admin_password = extend_knob(
        ServerMasterInstallInterface.admin_password,
        description="admin user kerberos password",
    )

    @admin_password.validator
    def admin_password(self, value):
        validate_admin_password(value)

    # always run sidgen task and do not allow adding agents on first master
    add_sids = True
    add_agents = False

    def __init__(self, **kwargs):
        super(ServerMasterInstall, self).__init__(**kwargs)
        master_init(self)

    @step()
    def main(self):
        master_install_check(self)
        yield
        master_install(self)

    @main.uninstaller
    def main(self):
        uninstall_check(self)
        yield
        uninstall(self)


ServerReplicaInstallInterface = installs_replica(ServerInstallInterface)


class ServerReplicaInstall(ServerReplicaInstallInterface):
    """
    Server replica installer
    """

    subject_base = None
    ca_subject = None

    admin_password = extend_knob(
        ServerReplicaInstallInterface.admin_password,
        description="Kerberos password for the specified admin principal",
    )

    def __init__(self, **kwargs):
        super(ServerReplicaInstall, self).__init__(**kwargs)
        replica_init(self)

    @step()
    def main(self):
        replica_promote_check(self)
        yield
        replica_install(self)
