#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

"""
DNS installer module
"""

from __future__ import absolute_import
from __future__ import print_function

import enum
import logging
import os
import sys

import six
from subprocess import CalledProcessError

from ipalib import api
from ipalib import errors
from ipalib import util
from ipalib import x509
from ipalib.install import hostname, sysrestore, certmonger
from ipalib.install.service import enroll_only, prepare_only
from ipalib.install import dnsforwarders
from ipalib.constants import FQDN
from ipaplatform.paths import paths
from ipaplatform.constants import constants
from ipaplatform import services
from ipapython import admintool
from ipapython import ipautil
from ipapython import dnsutil
from ipapython.certdb import EXTERNAL_CA_TRUST_FLAGS
from ipapython.dn import DN
from ipapython.dnsutil import check_zone_overlap
from ipapython.install import typing
from ipapython.install.core import group, knob
from ipapython.admintool import ScriptError
from ipapython.ipautil import user_input
from ipaserver.install.installutils import get_server_ip_address
from ipaserver.install.installutils import read_dns_forwarders
from ipaserver.install.installutils import update_hosts_file
from ipaserver.install.installutils import default_subject_base
from ipaserver.install import bindinstance
from ipaserver.install import certs
from ipaserver.install import dnskeysyncinstance
from ipaserver.install import odsexporterinstance
from ipaserver.install import opendnssecinstance
from ipaserver.install import service

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

ip_addresses = []
reverse_zones = []


def _find_dnssec_enabled_zones(conn):
    search_kw = {'idnssecinlinesigning': True}
    dnssec_enabled_filter = conn.make_filter(search_kw)
    dn = DN('cn=dns', api.env.basedn)
    try:
        entries, _truncated = conn.find_entries(
            base_dn=dn, filter=dnssec_enabled_filter, attrs_list=['idnsname'])
    except errors.NotFound:
        return []
    else:
        return [entry.single_value['idnsname'] for entry in entries
                if 'idnsname' in entry]


def _is_master():
    # test if server is DNSSEC key master
    masters = opendnssecinstance.get_dnssec_key_masters(api.Backend.ldap2)
    if api.env.host not in masters:
        raise RuntimeError("Current server is not DNSSEC key master")


def _disable_dnssec():
    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    ods = opendnssecinstance.OpenDNSSECInstance(fstore)
    ods.realm = api.env.realm

    ods_exporter = odsexporterinstance.ODSExporterInstance(fstore)
    ods_exporter.realm = api.env.realm

    # unconfigure services first
    ods.uninstall()  # needs keytab to flush the latest ods database
    ods_exporter.uninstall()

    ods.ldap_disable('DNSSEC', api.env.host, api.env.basedn)
    ods.ldap_remove_service_container('DNSSEC', api.env.host, api.env.basedn)

    ods_exporter.ldap_disable('DNSKeyExporter', api.env.host, api.env.basedn)
    ods_exporter.remove_service()
    ods_exporter.ldap_remove_service_container('DNSKeyExporter', api.env.host,
                                               api.env.basedn)

    conn = api.Backend.ldap2
    dn = DN(('cn', 'DNSSEC'), ('cn', api.env.host),
            api.env.container_masters, api.env.basedn)
    try:
        entry = conn.get_entry(dn)
    except errors.NotFound:
        pass
    else:
        ipa_config = entry.get('ipaConfigString', [])
        if opendnssecinstance.KEYMASTER in ipa_config:
            ipa_config.remove(opendnssecinstance.KEYMASTER)
            conn.update_entry(entry)


def _setup_dns_over_tls(options):
    if os.path.isfile(paths.IPA_CA_CRT) and not options.dns_over_tls_cert:
        # request certificate for DNS over TLS, using IPA CA
        cert = paths.BIND_DNS_OVER_TLS_CRT
        key = paths.BIND_DNS_OVER_TLS_KEY
        certmonger.request_and_wait_for_cert(
            certpath=(cert, key),
            principal='DNS/%s@%s' % (FQDN, api.env.realm),
            subject=str(DN(('CN', FQDN), default_subject_base(api.env.realm))),
            storage="FILE"
        )
        constants.NAMED_USER.chown(cert, gid=constants.NAMED_GROUP.gid)
        constants.NAMED_USER.chown(key, gid=constants.NAMED_GROUP.gid)

    # setup and enable Unbound as resolver
    forward_addrs = ["# forward-addr: specify here forwarders"]
    if options.dot_forwarders:
        forward_addrs = ["forward-addr: %s" % fw
                         for fw in options.dot_forwarders]
    ipautil.copy_template_file(
        paths.UNBOUND_CONF_SRC,
        paths.UNBOUND_CONF,
        dict(
            TLS_CERT_BUNDLE_PATH=os.path.join(
                paths.OPENSSL_CERTS_DIR, "ca-bundle.crt"),
            FORWARD_ADDRS="\n".join(forward_addrs)
        )
    )

    sr = services.knownservices["systemd-resolved"]
    if sr.is_running():
        sr.stop()
        sr.disable()

    api.Command.dnsserver_mod(
        FQDN,
        idnsforwarders="127.0.0.55",
        idnsforwardpolicy="first"
    )

    nm = services.knownservices["NetworkManager"]
    if nm.is_enabled():
        with open(paths.NETWORK_MANAGER_IPA_CONF, "w") as f:
            dns_none = [
                "# auto-generated by IPA installer",
                "[main]",
                "dns=none\n"
            ]
            f.write("\n".join(dns_none))
        nm.reload_or_restart()

    # Overwrite resolv.conf to point to IPA
    cfg = [
        "# auto-generated by IPA installer",
        "search .",
        "nameserver 127.0.0.1\n"
    ]
    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    fstore.backup_file(paths.RESOLV_CONF)
    with open(paths.RESOLV_CONF, 'w') as f:
        f.write('\n'.join(cfg))
        os.chmod(paths.RESOLV_CONF, 0o644)

    services.knownservices.unbound.enable()
    services.knownservices.unbound.restart()


def package_check(exception):
    if not os.path.isfile(paths.IPA_DNS_INSTALL):
        raise exception(
            "Integrated DNS requires '%s' package"
            % constants.IPA_DNS_PACKAGE_NAME
        )


def install_check(standalone, api, replica, options, hostname):
    global ip_addresses
    global reverse_zones
    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    package_check(RuntimeError)

    # when installing first DNS instance we need to check zone overlap
    if replica or standalone:
        already_enabled = api.Command.dns_is_enabled()['result']
    else:
        already_enabled = False

    if not already_enabled:
        domain = dnsutil.DNSName(util.normalize_zone(api.env.domain))
        try:
            dnsutil.check_zone_overlap(domain, raise_on_error=False)
        except dnsutil.DNSZoneAlreadyExists as e:
            if options.force or options.allow_zone_overlap:
                logger.warning("%s Please make sure that the domain is "
                               "properly delegated to this IPA server.",
                               e)
            else:
                hst = dnsutil.DNSName(hostname).make_absolute().to_text()
                if hst not in e.kwargs['ns']:
                    raise ValueError(str(e))

    for reverse_zone in options.reverse_zones:
        try:
            dnsutil.check_zone_overlap(reverse_zone)
        except dnsutil.DNSZoneAlreadyExists as e:
            if options.force or options.allow_zone_overlap:
                logger.warning('%s', str(e))
            else:
                raise e

    if standalone:
        print("==============================================================================")
        print("This program will setup DNS for the IPA Server.")
        print("")
        print("This includes:")
        print("  * Configure DNS (bind)")
        print("  * Configure SoftHSM (required by DNSSEC)")
        print("  * Configure ipa-dnskeysyncd (required by DNSSEC)")
        if options.dnssec_master:
            print("  * Configure ipa-ods-exporter (required by DNSSEC key master)")
            print("  * Configure OpenDNSSEC (required by DNSSEC key master)")
            print("  * Generate DNSSEC master key (required by DNSSEC key master)")
        elif options.disable_dnssec_master:
            print("  * Unconfigure ipa-ods-exporter")
            print("  * Unconfigure OpenDNSSEC")
            print("")
            print("No new zones will be signed without DNSSEC key master IPA server.")
            print("")
            print(("Please copy file from %s after uninstallation. This file is needed "
                   "on new DNSSEC key " % paths.IPA_KASP_DB_BACKUP))
            print("master server")
        print("")
        print("NOTE: DNSSEC zone signing is not enabled by default")
        print("")
        if options.dnssec_master:
            print("Plan carefully, replacing DNSSEC key master is not recommended")
            print("")
        print("")
        print("To accept the default shown in brackets, press the Enter key.")
        print("")

    if (options.dnssec_master and not options.unattended and not
        ipautil.user_input(
            "Do you want to setup this IPA server as DNSSEC key master?",
            False)):
        sys.exit("Aborted")
    elif (options.disable_dnssec_master and not options.unattended and not
          ipautil.user_input(
            "Do you want to disable current DNSSEC key master?",
            False)):
        sys.exit("Aborted")

    if options.disable_dnssec_master:
        _is_master()

    if options.disable_dnssec_master or options.dnssec_master:
        dnssec_zones = _find_dnssec_enabled_zones(api.Backend.ldap2)

    if options.disable_dnssec_master:
        if dnssec_zones and not options.force:
            raise RuntimeError(
                "Cannot disable DNSSEC key master, DNSSEC signing is still "
                "enabled for following zone(s):\n"
                "%s\n"
                "It is possible to move DNSSEC key master role to a different "
                "server by using --force option to skip this check.\n\n"
                "WARNING: You have to immediately copy kasp.db file to a new "
                "server and run command 'ipa-dns-install --dnssec-master "
                "--kasp-db'.\n"
                "Your DNS zones will become unavailable if you "
                "do not reinstall the DNSSEC key master role immediately." %
                ", ".join([str(zone) for zone in dnssec_zones]))

    elif options.dnssec_master:
        ods = opendnssecinstance.OpenDNSSECInstance(fstore)
        ods.realm = api.env.realm
        dnssec_masters = ods.get_masters()
        # we can reinstall current server if it is dnssec master
        if dnssec_masters and api.env.host not in dnssec_masters:
            print("DNSSEC key master(s):", u','.join(dnssec_masters))
            raise ScriptError(
                "Only one DNSSEC key master is supported in current version.")

        if options.kasp_db_file:
            dnskeysyncd = services.service('ipa-dnskeysyncd', api)

            if not dnskeysyncd.is_installed():
                raise RuntimeError("ipa-dnskeysyncd is not configured on this "
                                   "server, you cannot reuse OpenDNSSEC "
                                   "database (kasp.db file)")

            # check if replica can be the DNSSEC master
            cmd = [paths.IPA_DNSKEYSYNCD_REPLICA]
            environment = {
                "SOFTHSM2_CONF": paths.DNSSEC_SOFTHSM2_CONF,
            }

            # stop dnskeysyncd before test
            dnskeysyncd_running = dnskeysyncd.is_running()
            dnskeysyncd.stop()
            try:
                ipautil.run(cmd, env=environment,
                            runas=constants.ODS_USER,
                            suplementary_groups=[constants.NAMED_GROUP])
            except CalledProcessError as e:
                logger.debug("%s", e)
                raise RuntimeError("This IPA server cannot be promoted to "
                                   "DNSSEC master role because some keys were "
                                   "not replicated from the original "
                                   "DNSSEC master server")
            finally:
                if dnskeysyncd_running:
                    dnskeysyncd.start()
        elif dnssec_zones and not options.force:
            # some zones have --dnssec=true, make sure a user really want to
            # install new database
            raise RuntimeError(
                "DNSSEC signing is already enabled for following zone(s): %s\n"
                "Installation cannot continue without the OpenDNSSEC database "
                "file from the original DNSSEC master server.\n"
                "Please use option --kasp-db to specify location "
                "of the kasp.db file copied from the original "
                "DNSSEC master server.\n"
                "WARNING: Zones will become unavailable if you do not provide "
                "the original kasp.db file." %
                ", ".join([str(zone) for zone in dnssec_zones]))

    ip_addresses = get_server_ip_address(hostname, options.unattended,
                                         True, options.ip_addresses)

    util.no_matching_interface_for_ip_address_warning(ip_addresses)

    if not options.forward_policy:
        # user did not specify policy, derive it: default is 'first' but
        # if any of local IP addresses belongs to private ranges use 'only'
        options.forward_policy = 'first'
        for ip in ip_addresses:
            if dnsutil.inside_auto_empty_zone(dnsutil.DNSName(ip.reverse_dns)):
                options.forward_policy = 'only'
                logger.debug('IP address %s belongs to a private range, '
                             'using forward policy only', ip)
                break

    if options.no_forwarders:
        options.forwarders = []
    elif (options.forwarders
          or options.dot_forwarders or options.auto_forwarders):
        if not options.forwarders:
            if options.dot_forwarders:
                options.forwarders = [fw.split("#")[0]
                                      for fw in options.dot_forwarders]
            else:
                options.forwarders = []
        if options.auto_forwarders:
            options.forwarders.extend(dnsforwarders.get_nameservers())
    elif standalone or not replica:
        options.forwarders = read_dns_forwarders()

    # test DNSSEC forwarders
    if options.forwarders:
        if not options.no_dnssec_validation \
                and not bindinstance.check_forwarders(options.forwarders):
            options.no_dnssec_validation = True
            print("WARNING: DNSSEC validation will be disabled")

    logger.debug("will use DNS forwarders: %s\n", options.forwarders)

    if not standalone:
        search_reverse_zones = False
    else:
        search_reverse_zones = True

    if not standalone and replica:
        reverse_zones_unattended_check = True
    else:
        reverse_zones_unattended_check = options.unattended

    reverse_zones = bindinstance.check_reverse_zones(
        ip_addresses, options.reverse_zones, options,
        reverse_zones_unattended_check, search_reverse_zones
    )

    if reverse_zones:
        print("Using reverse zone(s) %s" % ', '.join(reverse_zones))


def install(standalone, replica, options, api=api):
    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    if standalone:
        # otherwise this is done by server/replica installer
        update_hosts_file(ip_addresses, api.env.host, fstore)

    if os.path.isfile(paths.IPA_CA_CRT) and not options.dns_over_tls_cert:
        dot_cert = paths.BIND_DNS_OVER_TLS_CRT
        dot_key = paths.BIND_DNS_OVER_TLS_KEY
    elif options.dns_over_tls_cert and options.dns_over_tls_key:
        # Check certificate validity first
        with certs.NSSDatabase() as tmpdb:
            tmpdb.create_db()
            ca_certs = x509.load_certificate_list_from_file(
                options.dns_over_tls_cert)
            nicknames = []
            for ca_cert in ca_certs:
                nicknames.append(str(DN(ca_cert.subject)))
                tmpdb.add_cert(
                    ca_cert, str(DN(ca_cert.subject)), EXTERNAL_CA_TRUST_FLAGS)
            try:
                for nick in nicknames:
                    tmpdb.verify_ca_cert_validity(nick)
            except ValueError as e:
                raise admintool.ScriptError(
                    "Not a valid CA certificate: %s" % e)
        dot_cert = options.dns_over_tls_cert
        dot_key = options.dns_over_tls_key
    else:
        raise RuntimeError(
            "Certificate for DNS over TLS not specified "
            "and IPA CA is not present."
        )

    if not options.forwarders and options.dot_forwarders:
        options.forwaders = [fw.split("#")[0] for fw in options.dot_forwarders]

    bind = bindinstance.BindInstance(fstore, api=api)
    bind.setup(api.env.host, ip_addresses, api.env.realm, api.env.domain,
               options.forwarders, options.forward_policy,
               reverse_zones, zonemgr=options.zonemgr,
               no_dnssec_validation=options.no_dnssec_validation,
               dns_over_tls=options.dns_over_tls,
               dns_over_tls_cert=dot_cert,
               dns_over_tls_key=dot_key,
               dns_policy=options.dns_policy)

    if standalone and not options.unattended:
        print("")
        print("The following operations may take some minutes to complete.")
        print("Please wait until the prompt is returned.")
        print("")

    bind.create_instance()

    if options.dns_over_tls:
        print("Setting up DNS over TLS")
        _setup_dns_over_tls(options)

    print("Restarting the web server to pick up resolv.conf changes")
    services.knownservices.httpd.restart(capture_output=True)

    # on dnssec master this must be installed last
    dnskeysyncd = dnskeysyncinstance.DNSKeySyncInstance(fstore)
    dnskeysyncd.create_instance(api.env.host, api.env.realm)
    if options.dnssec_master:
        ods = opendnssecinstance.OpenDNSSECInstance(fstore)
        ods_exporter = odsexporterinstance.ODSExporterInstance(fstore)

        ods_exporter.create_instance(api.env.host, api.env.realm)
        ods.create_instance(api.env.host, api.env.realm,
                            kasp_db_file=options.kasp_db_file)
    elif options.disable_dnssec_master:
        _disable_dnssec()

    dnskeysyncd.start_dnskeysyncd()
    bind.start_named()

    # Enable configured services for standalone check_global_configuration()
    if standalone:
        service.enable_services(api.env.host)

    # this must be done when bind is started and operational
    bind.update_system_records()

    if standalone:
        if options.dns_over_tls and options.dns_policy == "enforced":
            dns_port = "853"
        elif options.dns_over_tls:
            dns_port = "53, 853"
        else:
            dns_port = "53"
        print("==============================================================================")
        print("Setup complete")
        print("")
        bind.check_global_configuration()
        print("")
        print("")
        print("\tYou must make sure these network ports are open:")
        print("\t\tTCP Ports:")
        print(f"\t\t  * {dns_port}: bind")
        print("\t\tUDP Ports:")
        print(f"\t\t  * {dns_port}: bind")
    elif not standalone and replica:
        print("")
        bind.check_global_configuration()
        print("")

    if options.dns_over_tls:
        policy = "enforced" if options.dns_policy == "enforced" else "relaxed"
        print("")
        print(("DNS encryption support was enabled "
               "with policy '{}'.".format(policy)))
        print(("Unbound is configured to listen on 127.0.0.55:53 and "
               "forward to upstream DoT servers."))


def uninstall_check(options):
    # test if server is DNSSEC key master
    masters = opendnssecinstance.get_dnssec_key_masters(api.Backend.ldap2)
    if api.env.host in masters:
        print("This server is active DNSSEC key master. Uninstall could break your DNS system.")
        if not (options.unattended or user_input(
                "Are you sure you want to continue with the uninstall "
                "procedure?", False)):
            print("")
            print("Aborting uninstall operation.")
            sys.exit(1)


def uninstall():
    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    ods = opendnssecinstance.OpenDNSSECInstance(fstore)
    if ods.is_configured():
        ods.uninstall()

    ods_exporter = odsexporterinstance.ODSExporterInstance(fstore)
    if ods_exporter.is_configured():
        ods_exporter.uninstall()

    bind = bindinstance.BindInstance(fstore)
    if bind.is_configured():
        bind.uninstall()

    dnskeysync = dnskeysyncinstance.DNSKeySyncInstance(fstore)
    if dnskeysync.is_configured():
        dnskeysync.uninstall()


class DNSForwardPolicy(enum.Enum):
    ONLY = 'only'
    FIRST = 'first'


class EncryptedDNSPolicy(enum.Enum):
    RELAXED = 'relaxed'
    ENFORCED = 'enforced'

@group
class DNSInstallInterface(hostname.HostNameInstallInterface):
    """
    Interface of the DNS installer

    Knobs defined here will be available in:
    * ipa-server-install
    * ipa-replica-prepare
    * ipa-replica-install
    * ipa-dns-install
    """
    description = "DNS"

    allow_zone_overlap = knob(
        None,
        description="Create DNS zone even if it already exists",
    )
    allow_zone_overlap = prepare_only(allow_zone_overlap)

    reverse_zones = knob(
        typing.List[str], [],
        description=("The reverse DNS zone to use. This option can be used "
                     "multiple times"),
        cli_names='--reverse-zone',
        cli_metavar='REVERSE_ZONE',
    )
    reverse_zones = prepare_only(reverse_zones)

    @reverse_zones.validator
    def reverse_zones(self, values):
        if not self.allow_zone_overlap:
            for zone in values:
                check_zone_overlap(zone)

    no_reverse = knob(
        None,
        description="Do not create new reverse DNS zone",
    )
    no_reverse = prepare_only(no_reverse)

    auto_reverse = knob(
        None,
        description="Create necessary reverse zones",
    )
    auto_reverse = prepare_only(auto_reverse)

    zonemgr = knob(
        str, None,
        description=("DNS zone manager e-mail address. Defaults to "
                     "hostmaster@DOMAIN"),
    )
    zonemgr = prepare_only(zonemgr)

    @zonemgr.validator
    def zonemgr(self, value):
        # validate the value first
        if six.PY3:
            bindinstance.validate_zonemgr_str(value)
        else:
            try:
                # IDNA support requires unicode
                encoding = getattr(sys.stdin, 'encoding', None)
                if encoding is None:
                    encoding = 'utf-8'

                # value is string in py2 and py3
                if not isinstance(value, unicode):
                    value = value.decode(encoding)

                bindinstance.validate_zonemgr_str(value)
            except ValueError as e:
                # FIXME we can do this in better way
                # https://fedorahosted.org/freeipa/ticket/4804
                # decode to proper stderr encoding
                stderr_encoding = getattr(sys.stderr, 'encoding', None)
                if stderr_encoding is None:
                    stderr_encoding = 'utf-8'
                error = unicode(e).encode(stderr_encoding)
                raise ValueError(error)

    forwarders = knob(
        typing.List[ipautil.CheckedIPAddressLoopback], None,
        description=("Add a DNS forwarder. This option can be used multiple "
                     "times"),
        cli_names='--forwarder',
    )
    forwarders = enroll_only(forwarders)

    no_forwarders = knob(
        None,
        description="Do not add any DNS forwarders, use root servers instead",
    )
    no_forwarders = enroll_only(no_forwarders)

    auto_forwarders = knob(
        None,
        description="Use DNS forwarders configured in /etc/resolv.conf",
    )
    auto_forwarders = enroll_only(auto_forwarders)

    forward_policy = knob(
        DNSForwardPolicy, None,
        description=("DNS forwarding policy for global forwarders"),
    )
    forward_policy = enroll_only(forward_policy)

    no_dnssec_validation = knob(
        None,
        description="Disable DNSSEC validation",
    )
    no_dnssec_validation = enroll_only(no_dnssec_validation)

    dns_over_tls = knob(
        None,
        description="Configure DNS over TLS",
    )
    dns_over_tls = enroll_only(dns_over_tls)

    dot_forwarders = knob(
        typing.List[ipautil.IPAddressDoTForwarder], None,
        description=("Add a DNS over TLS forwarder. "
                     "This option can be used multiple times"),
        cli_names='--dot-forwarder',
    )
    dot_forwarders = enroll_only(dot_forwarders)

    dns_over_tls_cert = knob(
        str, None,
        description=("Certificate to use for DNS over TLS. "
                     "If empty, a new certificate will be "
                     "requested from IPA CA"),
    )
    dns_over_tls_cert = enroll_only(dns_over_tls_cert)

    dns_over_tls_key = knob(
        str, None,
        description="Key for certificate specified in --dns-over-tls-cert",
    )
    dns_over_tls_key = enroll_only(dns_over_tls_key)

    dns_policy = knob(
        EncryptedDNSPolicy, 'relaxed',
        description=("Encrypted DNS policy"),
    )
    dns_policy = enroll_only(dns_policy)

    dnssec_master = False
    disable_dnssec_master = False
    kasp_db_file = None
    force = False
