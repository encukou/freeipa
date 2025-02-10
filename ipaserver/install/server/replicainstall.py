#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function, absolute_import

import contextlib
import logging

import dns.exception as dnsexception
import dns.name as dnsname
import itertools
import os
import shutil
import socket
import sys
import tempfile
import textwrap
import traceback

from pkg_resources import parse_version
import six

from ipaclient.install.client import check_ldap_conf, sssd_enable_ifp
import ipaclient.install.timeconf
from ipalib.install import sysrestore
from ipalib.kinit import kinit_keytab
from ipapython import ipaldap, ipautil
from ipapython.dn import DN
from ipapython.dnsutil import DNSResolver
from ipapython.admintool import ScriptError
from ipapython.ipachangeconf import IPAChangeConf
from ipaplatform import services
from ipaplatform.tasks import tasks
from ipaplatform.paths import paths
from ipalib import api, constants, create_api, errors, rpc
from ipalib.config import Env
from ipalib.facts import is_ipa_configured, is_ipa_client_configured
from ipalib.util import no_matching_interface_for_ip_address_warning
from ipaclient.install.client import configure_krb5_conf, purge_host_keytab
from ipaserver.install import (
    adtrust, bindinstance, ca, cainstance, dns, dsinstance, httpinstance,
    installutils, kra, krainstance, krbinstance, otpdinstance,
    custodiainstance, service,)
from ipaserver.install import certs
from ipaserver.install.installutils import (
    ReplicaConfig, load_pkcs12, validate_mask)
from ipaserver.install.replication import (
    ReplicationManager, replica_conn_check)
from ipaserver.masters import find_providing_servers, find_providing_server
import SSSDConfig
from subprocess import CalledProcessError

if six.PY3:
    unicode = str

NoneType = type(None)

logger = logging.getLogger(__name__)


def get_dirman_password():
    return installutils.read_password("Directory Manager (existing master)",
                                      confirm=False, validate=False)


def make_pkcs12_info(directory, cert_name, password_name):
    """Make pkcs12_info

    :param directory: Base directory (config.dir)
    :param cert_name: Cert filename (e.g. "dscert.p12")
    :param password_name: Cert filename (e.g. "dirsrv_pin.txt")
    :return: a (full cert path, password) tuple, or None if cert is not found
    """
    cert_path = os.path.join(directory, cert_name)
    if os.path.isfile(cert_path):
        password_file = os.path.join(directory, password_name)
        password = open(password_file).read().strip()
        return cert_path, password
    else:
        return None


def install_replica_ds(config, options, ca_is_configured, remote_api,
                       ca_file, pkcs12_info=None, fstore=None):
    dsinstance.check_ports()

    # if we have a pkcs12 file, create the cert db from
    # that. Otherwise the ds setup will create the CA
    # cert
    if pkcs12_info is None:
        pkcs12_info = make_pkcs12_info(config.dir, "dscert.p12",
                                       "dirsrv_pin.txt")

    if ca_is_configured:
        ca_subject = ca.lookup_ca_subject(remote_api, config.subject_base)
    else:
        ca_subject = installutils.default_ca_subject_dn(config.subject_base)

    ds = dsinstance.DsInstance(
        config_ldif=options.dirsrv_config_file,
        fstore=fstore)
    ds.create_replica(
        realm_name=config.realm_name,
        master_fqdn=config.master_host_name,
        fqdn=config.host_name,
        domain_name=config.domain_name,
        dm_password=config.dirman_password,
        subject_base=config.subject_base,
        ca_subject=ca_subject,
        pkcs12_info=pkcs12_info,
        ca_is_configured=ca_is_configured,
        ca_file=ca_file,
        api=remote_api,
        setup_pkinit=not options.no_pkinit,
    )

    return ds


def install_krb(config, setup_pkinit=False, pkcs12_info=None, fstore=None):
    krb = krbinstance.KrbInstance(fstore=fstore)

    # pkinit files
    if pkcs12_info is None:
        pkcs12_info = make_pkcs12_info(config.dir, "pkinitcert.p12",
                                       "pkinit_pin.txt")

    krb.create_replica(config.realm_name,
                       config.master_host_name, config.host_name,
                       config.domain_name, config.dirman_password,
                       setup_pkinit, pkcs12_info,
                       subject_base=config.subject_base)

    return krb


def install_http(config, auto_redirect, ca_is_configured, ca_file,
                 pkcs12_info=None, fstore=None):
    # if we have a pkcs12 file, create the cert db from
    # that. Otherwise the ds setup will create the CA
    # cert
    if pkcs12_info is None:
        pkcs12_info = make_pkcs12_info(config.dir, "httpcert.p12",
                                       "http_pin.txt")

    http = httpinstance.HTTPInstance(fstore=fstore)
    http.create_instance(
        config.realm_name, config.host_name, config.domain_name,
        config.dirman_password, pkcs12_info,
        auto_redirect=auto_redirect, ca_file=ca_file,
        ca_is_configured=ca_is_configured, promote=True,
        subject_base=config.subject_base, master_fqdn=config.master_host_name)

    return http


def install_dns_records(config, options, remote_api, fstore=None):

    if not bindinstance.dns_container_exists(
            ipautil.realm_to_suffix(config.realm_name)):
        return

    try:
        bind = bindinstance.BindInstance(api=remote_api, fstore=fstore)
        for ip in config.ips:
            reverse_zone = bindinstance.find_reverse_zone(ip, remote_api)

            bind.add_master_dns_records(config.host_name,
                                        [str(ip)],
                                        config.realm_name,
                                        config.domain_name,
                                        reverse_zone)
    except errors.NotFound as e:
        logger.debug('Replica DNS records could not be added '
                     'on master: %s', str(e))

    # we should not fail here no matter what
    except Exception as e:
        logger.info('Replica DNS records could not be added '
                    'on master: %s', str(e))


def create_ipa_conf(fstore, config, ca_enabled, master=None):
    """
    Create /etc/ipa/default.conf master configuration
    :param fstore: sysrestore file store used for backup and restore of
                   the server configuration
    :param config: replica config
    :param ca_enabled: True if the topology includes a CA
    :param master: if set, the xmlrpc_uri parameter will use the provided
                   master instead of this host
    """
    # Save client file on Domain Level 1
    target_fname = paths.IPA_DEFAULT_CONF
    fstore.backup_file(target_fname)

    ipaconf = IPAChangeConf("IPA Replica Install")
    ipaconf.setOptionAssignment(" = ")
    ipaconf.setSectionNameDelimiters(("[", "]"))

    if master:
        xmlrpc_uri = 'https://{0}/ipa/xml'.format(
            ipautil.format_netloc(master))
    else:
        xmlrpc_uri = 'https://{0}/ipa/xml'.format(
                        ipautil.format_netloc(config.host_name))
    ldapi_uri = ipaldap.realm_to_ldapi_uri(config.realm_name)

    # [global] section
    gopts = [
        ipaconf.setOption('basedn', str(config.basedn)),
        ipaconf.setOption('host', config.host_name),
        ipaconf.setOption('realm', config.realm_name),
        ipaconf.setOption('domain', config.domain_name),
        ipaconf.setOption('xmlrpc_uri', xmlrpc_uri),
        ipaconf.setOption('ldap_uri', ldapi_uri),
        ipaconf.setOption('mode', 'production')
    ]

    if ca_enabled:
        gopts.extend([
            ipaconf.setOption('enable_ra', 'True'),
            ipaconf.setOption('ra_plugin', 'dogtag'),
            ipaconf.setOption('dogtag_version', '10')
        ])

        if not config.setup_ca:
            gopts.append(ipaconf.setOption('ca_host', config.ca_host_name))

    else:
        gopts.extend([
            ipaconf.setOption('enable_ra', 'False'),
            ipaconf.setOption('ra_plugin', 'None')
        ])

    opts = [
        ipaconf.setSection('global', gopts),
        {'name': 'empty', 'type': 'empty'}
    ]
    ipaconf.newConf(target_fname, opts)
    # the new file must be readable for httpd
    # Also, umask applies when creating a new file but we want 0o644 here
    os.chmod(target_fname, 0o644)


def check_dirsrv():
    (ds_unsecure, ds_secure) = dsinstance.check_ports()
    if not ds_unsecure or not ds_secure:
        msg = ("IPA requires ports 389 and 636 for the Directory Server.\n"
               "These are currently in use:\n")
        if not ds_unsecure:
            msg += "\t389\n"
        if not ds_secure:
            msg += "\t636\n"
        raise ScriptError(msg)


def check_dns_resolution(host_name, dns_servers):
    """Check forward and reverse resolution of host_name using dns_servers
    """
    # Point the resolver at specified DNS server
    server_ips = []
    for dns_server in dns_servers:
        try:
            server_ips = list(
                a[4][0] for a in socket.getaddrinfo(dns_server, None))
        except socket.error:
            pass
        else:
            break
    if not server_ips:
        logger.error(
            'Could not resolve any DNS server hostname: %s', dns_servers)
        return False
    resolver = DNSResolver()
    resolver.nameservers = server_ips

    logger.debug('Search DNS server %s (%s) for %s',
                 dns_server, server_ips, host_name)

    # Get IP addresses of host_name
    addresses = set()
    for rtype in 'A', 'AAAA':
        try:
            result = resolver.resolve(host_name, rtype)
        except dnsexception.DNSException:
            rrset = []
        else:
            rrset = result.rrset
        if rrset:
            addresses.update(r.address for r in result.rrset)

    if not addresses:
        logger.error(
            'Could not resolve hostname %s using DNS. '
            'Clients may not function properly. '
            'Please check your DNS setup. '
            '(Note that this check queries IPA DNS directly and '
            'ignores /etc/hosts.)',
            host_name)
        return False

    no_errors = True

    # Check each of the IP addresses
    checked = set()
    for address in addresses:
        if address in checked:
            continue
        checked.add(address)
        try:
            logger.debug('Check reverse address %s (%s)', address, host_name)
            rrset = resolver.resolve_address(address).rrset
        except Exception as e:
            logger.debug('Check failed: %s %s', type(e).__name__, e)
            logger.error(
                'Reverse DNS resolution of address %s (%s) failed. '
                'Clients may not function properly. '
                'Please check your DNS setup. '
                '(Note that this check queries IPA DNS directly and '
                'ignores /etc/hosts.)',
                address, host_name)
            no_errors = False
        else:
            host_name_obj = dnsname.from_text(host_name)
            if rrset:
                names = [r.target.to_text() for r in rrset]
            else:
                names = []
            logger.debug(
                'Address %s resolves to: %s. ', address, ', '.join(names))
            if not rrset or not any(
                    r.target == host_name_obj for r in rrset):
                logger.error(
                    'The IP address %s of host %s resolves to: %s. '
                    'Clients may not function properly. '
                    'Please check your DNS setup. '
                    '(Note that this check queries IPA DNS directly and '
                    'ignores /etc/hosts.)',
                    address, host_name, ', '.join(names))
                no_errors = False

    return no_errors


def configure_certmonger():
    dbus = services.knownservices.dbus
    if not dbus.is_running():
        # some platforms protect dbus with RefuseManualStart=True
        try:
            dbus.start()
        except Exception as e:
            raise ScriptError("dbus service unavailable: %s" % str(e),
                              rval=3)

    # Ensure that certmonger has been started at least once to generate the
    # cas files in /var/lib/certmonger/cas.
    cmonger = services.knownservices.certmonger
    try:
        cmonger.restart()
    except Exception as e:
        raise ScriptError("Certmonger service unavailable: %s" % str(e),
                          rval=3)

    try:
        cmonger.enable()
    except Exception as e:
        raise ScriptError("Failed to enable Certmonger: %s" % str(e),
                          rval=3)


def remove_replica_info_dir(installer):
    # always try to remove decrypted replica file
    try:
        if installer._top_dir is not None:
            shutil.rmtree(installer._top_dir)
    except OSError:
        pass


def common_cleanup(func):
    def decorated(installer):
        try:
            try:
                func(installer)
            except BaseException:
                remove_replica_info_dir(installer)
                raise
        except KeyboardInterrupt:
            raise ScriptError()
        except Exception:
            print(
                "Your system may be partly configured.\n"
                "Run /usr/sbin/ipa-server-install --uninstall to clean up.\n")
            raise

    return decorated


def preserve_enrollment_state(func):
    """
    Makes sure the machine is unenrollled if the decorated function
    failed.
    """
    def decorated(installer):
        try:
            func(installer)
        except BaseException:
            if installer._enrollment_performed:
                uninstall_client()
            raise

    return decorated


def uninstall_client():
    """
    Attempts to unenroll the IPA client using the ipa-client-install utility.

    An unsuccessful attempt to uninstall is ignored (no exception raised).
    """

    print("Removing client side components")
    ipautil.run([paths.IPA_CLIENT_INSTALL, "--unattended", "--uninstall"],
                raiseonerr=False, redirect_output=True)
    print()


def promote_sssd(host_name):
    sssdconfig = SSSDConfig.SSSDConfig()
    sssdconfig.import_config()
    domains = sssdconfig.list_active_domains()

    for name in domains:
        domain = sssdconfig.get_domain(name)
        try:
            hostname = domain.get_option('ipa_hostname')
            if hostname == host_name:
                break
        except SSSDConfig.NoOptionError:
            continue
    else:
        raise RuntimeError("Couldn't find IPA domain in sssd.conf")

    domain.set_option('ipa_server', host_name)
    domain.set_option('ipa_server_mode', True)
    sssdconfig.save_domain(domain)

    sssd_enable_ifp(sssdconfig)

    sssdconfig.write()

    sssd = services.service('sssd', api)
    try:
        sssd.restart()
    except CalledProcessError:
        logger.warning("SSSD service restart was unsuccessful.")


def promote_openldap_conf(hostname, master):
    """
    Reset the URI directive in openldap-client configuration file to point to
    newly promoted replica. If this directive was set by third party, then
    replace the added comment with the one pointing to replica

    :param hostname: replica FQDN
    :param master: FQDN of remote master
    """

    ldap_conf = paths.OPENLDAP_LDAP_CONF

    ldap_change_conf = IPAChangeConf("IPA replica installer")
    ldap_change_conf.setOptionAssignment((" ", "\t"))

    new_opts = []

    with open(ldap_conf, 'r') as f:
        old_opts = ldap_change_conf.parse(f)

        for opt in old_opts:
            if opt['type'] == 'comment' and master in opt['value']:
                continue
            if (opt['type'] == 'option' and opt['name'] == 'URI' and
                    master in opt['value']):
                continue
            new_opts.append(opt)

    change_opts = [
        {'action': 'addifnotset',
         'name': 'URI',
         'type': 'option',
         'value': 'ldaps://' + hostname}
    ]

    try:
        ldap_change_conf.newConf(ldap_conf, new_opts)
        ldap_change_conf.changeConf(ldap_conf, change_opts)
    except Exception as e:
        logger.info("Failed to update %s: %s", ldap_conf, e)


@contextlib.contextmanager
def rpc_client(api):
    """
    Context manager for JSON RPC client.

    :param api: api to initiate the RPC client
    """
    client = rpc.jsonclient(api)
    client.finalize()
    client.connect()

    try:
        yield client
    finally:
        client.disconnect()


def check_remote_fips_mode(client, local_fips_mode):
    """
    Verify remote server's fips-mode is the same as this server's fips-mode

    :param client: RPC client
    :param local_fips_mode: boolean indicating whether FIPS mode is turned on
    :raises: ScriptError: if the checks fails
    """
    env = client.forward(u'env', u'fips_mode')['result']
    remote_fips_mode = env.get('fips_mode', False)
    if local_fips_mode != remote_fips_mode:
        if local_fips_mode:
            raise ScriptError(
                "Cannot join FIPS-enabled replica into existing topology: "
                "FIPS is not enabled on the master server.")
        else:
            raise ScriptError(
                "Cannot join replica into existing FIPS-enabled topology: "
                "FIPS has to be enabled locally first.")


def check_remote_version(client, local_version):
    """
    Verify remote server's version is not higher than this server's version

    :param client: RPC client
    :param local_version: API version of local server
    :raises: ScriptError: if the checks fails
    """
    env = client.forward(u'env', u'version')['result']
    remote_version = parse_version(env['version'])
    if remote_version > local_version:
        raise ScriptError(
            "Cannot install replica of a server of higher version ({}) than "
            "the local version ({})".format(remote_version, local_version))


def common_check(no_ntp, skip_mem_check, setup_ca):
    if not skip_mem_check:
        installutils.check_available_memory(ca=setup_ca)
    tasks.check_ipv6_stack_enabled()
    tasks.check_selinux_status()
    check_ldap_conf()

    mask_str = validate_mask()
    if mask_str:
        raise ScriptError(
            "Unexpected system mask: %s, expected 0022" % mask_str)

    if is_ipa_configured():
        raise ScriptError(
            "IPA server is already configured on this system.\n"
            "If you want to reinstall the IPA server, please uninstall "
            "it first using 'ipa-server-install --uninstall'.")

    check_dirsrv()

    if not no_ntp:
        try:
            ipaclient.install.timeconf.check_timedate_services()
        except ipaclient.install.timeconf.NTPConflictingService as e:
            print("WARNING: conflicting time&date synchronization service "
                  "'{svc}' will\nbe disabled in favor of chronyd\n"
                  .format(svc=e.conflicting_service))
        except ipaclient.install.timeconf.NTPConfigurationError:
            pass


def current_domain_level(api):
    """Return the current domain level.

    """
    # Detect the current domain level
    try:
        return api.Command['domainlevel_get']()['result']
    except errors.NotFound:
        # If we're joining an older master, domain entry is not
        # available
        return constants.DOMAIN_LEVEL_0


def check_domain_level_is_supported(current):
    """Check that the given domain level is supported by this server version.

    :raises: ScriptError if DL is out of supported range for this IPA version.

    """
    under_lower_bound = current < constants.MIN_DOMAIN_LEVEL
    above_upper_bound = current > constants.MAX_DOMAIN_LEVEL

    if under_lower_bound or above_upper_bound:
        message = ("This version of IPA does not support "
                   "the Domain Level which is currently set for "
                   "this domain. The Domain Level needs to be "
                   "raised before installing a replica with "
                   "this version is allowed to be installed "
                   "within this domain.")
        logger.error("%s", message)
        raise ScriptError(message, rval=3)


def enroll_dl0_replica(installer, fstore, remote_api, debug=False):
    """
    Do partial host enrollment in DL0:
        * add host entry to remote master
        * request host keytab from remote master
        * configure client-like /etc/krb5.conf to enable GSSAPI auth further
          down the replica installation
    """
    logger.info("Enrolling host to IPA domain")
    config = installer._config
    hostname = config.host_name

    try:
        installer._enrollment_performed = True
        # pylint: disable=E0606
        host_result = remote_api.Command.host_add(
            unicode(config.host_name), force=installer.no_host_dns
        )['result']
        # pylint: enable=E0606

        host_princ = unicode(host_result['krbcanonicalname'][0])
        purge_host_keytab(config.realm_name)

        getkeytab_args = [
            paths.IPA_GETKEYTAB,
            '-s', config.master_host_name,
            '-p', host_princ,
            '-D', unicode(ipaldap.DIRMAN_DN),
            '-w', config.dirman_password,
            '-k', paths.KRB5_KEYTAB,
            '--cacert', os.path.join(config.dir, 'ca.crt')
        ]
        ipautil.run(getkeytab_args, nolog=(config.dirman_password,))

        _hostname, _sep, host_domain = hostname.partition('.')

        fstore.backup_file(paths.KRB5_CONF)
        configure_krb5_conf(
            config.realm_name,
            config.domain_name,
            [config.master_host_name],
            [config.master_host_name],
            False,
            paths.KRB5_CONF,
            host_domain,
            hostname,
            configure_sssd=False
        )

    except CalledProcessError as e:
        raise RuntimeError("Failed to fetch host keytab: {}".format(e))


def ensure_enrolled(installer):
    args = [paths.IPA_CLIENT_INSTALL, "--unattended"]
    stdin = None
    nolog = []

    if installer.domain_name:
        args.extend(["--domain", installer.domain_name])
    if installer.server:
        args.extend(["--server", installer.server])
    if installer.realm_name:
        args.extend(["--realm", installer.realm_name])
    if installer.host_name:
        args.extend(["--hostname", installer.host_name])

    if installer.password:
        args.extend(["--password", installer.password])
        nolog.append(installer.password)
    else:
        if installer.admin_password:
            # Always set principal if password was set explicitly,
            # the password itself gets passed directly via stdin
            args.extend(["--principal", installer.principal or "admin"])
            stdin = installer.admin_password
        if installer.keytab:
            args.extend(["--keytab", installer.keytab])

    if installer.no_dns_sshfp:
        args.append("--no-dns-sshfp")
    if installer.ssh_trust_dns:
        args.append("--ssh-trust-dns")
    if installer.no_ssh:
        args.append("--no-ssh")
    if installer.no_sshd:
        args.append("--no-sshd")
    if installer.mkhomedir:
        args.append("--mkhomedir")
    if installer.subid:
        args.append("--subid")
    if installer.force_join:
        args.append("--force-join")
    if installer.no_ntp:
        args.append("--no-ntp")
    if installer.ip_addresses:
        for ip in installer.ip_addresses:
            # installer.ip_addresses is of type [CheckedIPAddress]
            args.extend(("--ip-address", str(ip)))
    if installer.ntp_servers:
        for server in installer.ntp_servers:
            args.extend(("--ntp-server", server))
    if installer.ntp_pool:
        args.extend(("--ntp-pool", installer.ntp_pool))
    if installer.dns_over_tls and not installer.setup_dns:
        args.append("--dns-over-tls")

    try:
        # Call client install script
        service.print_msg("Configuring client side components")
        installer._enrollment_performed = True
        ipautil.run(args, stdin=stdin, nolog=nolog, redirect_output=True)
        print()
    except ipautil.CalledProcessError:
        raise ScriptError("Configuration of client side components failed!")


def promotion_check_ipa_domain(master_ldap_conn, basedn):
    entry = master_ldap_conn.get_entry(basedn, ['associatedDomain'])
    if 'associatedDomain' not in entry:
        raise RuntimeError('IPA domain not found in LDAP.')

    if len(entry['associatedDomain']) > 1:
        logger.critical(
            "Multiple IPA domains found. We are so sorry :-(, you are "
            "probably experiencing this bug "
            "https://fedorahosted.org/freeipa/ticket/5976. Please contact us "
            "for help.")
        raise RuntimeError(
            'Multiple IPA domains found in LDAP database ({domains}). '
            'Only one domain is allowed.'.format(
                domains=u', '.join(entry['associatedDomain'])
            ))

    if entry['associatedDomain'][0] != api.env.domain:
        raise RuntimeError(
            "Cannot promote this client to a replica. Local domain "
            "'{local}' does not match IPA domain '{ipadomain}'. ".format(
                local=api.env.domain,
                ipadomain=entry['associatedDomain'][0]
        ))


def promotion_check_host_principal_auth_ind(conn, hostdn):
    entry = conn.get_entry(hostdn, ['krbprincipalauthind'])
    if 'krbprincipalauthind' in entry:
        raise RuntimeError(
            "Client cannot be promoted to a replica if the host principal "
            "has an authentication indicator set."
        )


def clean_up_hsm_nicknames(api):
    """Ensure that all of the nicknames on the token are visible on
       the NSS softoken.
    """
    # Hardcode the token names. NSS tooling does not provide a
    # public way to determine it other than scraping modutil
    # output.
    api.Backend.ldap2.connect()
    (token_name, _unused) = ca.lookup_hsm_configuration(api)
    api.Backend.ldap2.disconnect()
    if not token_name:
        return

    cai = cainstance.CAInstance(api.env.realm, host_name=api.env.host)
    dogtag_reqs = cai.tracking_reqs.items()
    kra = krainstance.KRAInstance(api.env.realm)
    if kra.is_installed():
        dogtag_reqs = itertools.chain(dogtag_reqs,
                                      kra.tracking_reqs.items())

    try:
        tmpdir = tempfile.mkdtemp(prefix="tmp-")
        pwd_file = cai.get_token_pwd_file(tmpdir)
        db = certs.CertDB(api.env.realm,
                          nssdir=paths.PKI_TOMCAT_ALIAS_DIR,
                          pwd_file=pwd_file)
        for (nickname, _unused) in dogtag_reqs:
            try:
                if nickname in (
                    'caSigningCert cert-pki-ca',
                    'Server-Cert cert-pki-ca'
                ):
                    continue
                if nickname in (
                    'auditSigningCert cert-pki-ca',
                    'auditSigningCert cert-pki-kra',
                ):
                    trust = ',,P'
                else:
                    trust = ',,'
                db.run_certutil(['-M',
                                 '-n', f"{token_name}:{nickname}",
                                 '-t', trust])
            except CalledProcessError as e:
                logger.debug("Modifying trust on %s failed: %s",
                             nickname, e)

        if db.has_nickname('Directory Server CA certificate'):
            db.run_certutil(['--rename',
                             '-n', 'Directory Server CA certificate',
                             '--new-n', 'caSigningCert cert-pki-ca'],
                            raiseonerr=False)
    finally:
        shutil.rmtree(tmpdir)


def remote_connection(config):
    logger.debug("Creating LDAP connection to %s", config.master_host_name)
    ldapuri = 'ldaps://%s' % ipautil.format_netloc(config.master_host_name)
    xmlrpc_uri = 'https://{}/ipa/xml'.format(
        ipautil.format_netloc(config.master_host_name))
    remote_api = create_api(mode=None)
    remote_api.bootstrap(in_server=True,
                         context='installer',
                         confdir=paths.ETC_IPA,
                         ldap_uri=ldapuri,
                         xmlrpc_uri=xmlrpc_uri)
    remote_api.finalize()
    return remote_api


@common_cleanup
@preserve_enrollment_state
def promote_check(installer):
    options = installer
    installer._enrollment_performed = False
    installer._top_dir = tempfile.mkdtemp("ipa")

    # check selinux status, http and DS ports, NTP conflicting services
    common_check(options.no_ntp, options.skip_mem_check, options.setup_ca)

    if options.setup_ca and any([options.dirsrv_cert_files,
                                 options.http_cert_files,
                                 options.pkinit_cert_files]):
        raise ScriptError("--setup-ca and --*-cert-file options are "
                          "mutually exclusive")

    ipa_client_installed = is_ipa_client_configured(on_master=True)
    if not ipa_client_installed:
        # One-step replica installation
        if options.password and options.admin_password:
            raise ScriptError("--password and --admin-password options are "
                              "mutually exclusive")
        ensure_enrolled(installer)
    else:
        if (options.domain_name or options.server or options.realm_name or
                options.host_name or options.password or options.keytab):
            print("IPA client is already configured on this system, ignoring "
                  "the --domain, --server, --realm, --hostname, --password "
                  "and --keytab options.")
            # Make sure options.server is not used
            options.server = None

        # The NTP configuration can not be touched on pre-installed client:
        if options.no_ntp or options.ntp_servers or options.ntp_pool:
                raise ScriptError(
                    "NTP configuration cannot be updated during promotion")

    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    fstore = sysrestore.FileStore(paths.SYSRESTORE)

    env = Env()
    env._bootstrap(context='installer', confdir=paths.ETC_IPA, log=None)
    env._finalize_core(**dict(constants.DEFAULT_CONFIG))

    xmlrpc_uri = 'https://{}/ipa/xml'.format(ipautil.format_netloc(env.host))
    api.bootstrap(in_server=True,
                  context='installer',
                  confdir=paths.ETC_IPA,
                  ldap_uri=ipaldap.realm_to_ldapi_uri(env.realm),
                  xmlrpc_uri=xmlrpc_uri)
    api.finalize()

    config = ReplicaConfig()
    config.realm_name = api.env.realm
    config.host_name = api.env.host
    config.domain_name = api.env.domain
    config.master_host_name = api.env.server
    if not api.env.ca_host or api.env.ca_host == api.env.host:
        # ca_host has not been configured explicitly, prefer source master
        config.ca_host_name = api.env.server
    else:
        # default to ca_host from IPA config
        config.ca_host_name = api.env.ca_host
    config.kra_host_name = config.ca_host_name
    config.ca_ds_port = 389
    config.setup_ca = options.setup_ca
    config.setup_kra = options.setup_kra
    config.dir = installer._top_dir
    config.basedn = api.env.basedn
    config.hidden_replica = options.hidden_replica

    http_pkcs12_file = None
    http_pkcs12_info = None
    http_ca_cert = None
    dirsrv_pkcs12_file = None
    dirsrv_pkcs12_info = None
    dirsrv_ca_cert = None
    pkinit_pkcs12_file = None
    pkinit_pkcs12_info = None
    pkinit_ca_cert = None

    if options.http_cert_files:
        if options.http_pin is None:
            options.http_pin = installutils.read_password(
                "Enter Apache Server private key unlock",
                confirm=False, validate=False, retry=False)
            if options.http_pin is None:
                raise ScriptError(
                    "Apache Server private key unlock password required")
        http_pkcs12_file, http_pin, http_ca_cert = load_pkcs12(
            cert_files=options.http_cert_files,
            key_password=options.http_pin,
            key_nickname=options.http_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=config.host_name)
        http_pkcs12_info = (http_pkcs12_file.name, http_pin)

    if options.dirsrv_cert_files:
        if options.dirsrv_pin is None:
            options.dirsrv_pin = installutils.read_password(
                "Enter Directory Server private key unlock",
                confirm=False, validate=False, retry=False)
            if options.dirsrv_pin is None:
                raise ScriptError(
                    "Directory Server private key unlock password required")
        dirsrv_pkcs12_file, dirsrv_pin, dirsrv_ca_cert = load_pkcs12(
            cert_files=options.dirsrv_cert_files,
            key_password=options.dirsrv_pin,
            key_nickname=options.dirsrv_cert_name,
            ca_cert_files=options.ca_cert_files,
            host_name=config.host_name)
        dirsrv_pkcs12_info = (dirsrv_pkcs12_file.name, dirsrv_pin)

    if options.pkinit_cert_files:
        if options.pkinit_pin is None:
            options.pkinit_pin = installutils.read_password(
                "Enter Kerberos KDC private key unlock",
                confirm=False, validate=False, retry=False)
            if options.pkinit_pin is None:
                raise ScriptError(
                    "Kerberos KDC private key unlock password required")
        pkinit_pkcs12_file, pkinit_pin, pkinit_ca_cert = load_pkcs12(
            cert_files=options.pkinit_cert_files,
            key_password=options.pkinit_pin,
            key_nickname=options.pkinit_cert_name,
            ca_cert_files=options.ca_cert_files,
            realm_name=config.realm_name)
        pkinit_pkcs12_info = (pkinit_pkcs12_file.name, pkinit_pin)

    if (options.http_cert_files and options.dirsrv_cert_files and
            http_ca_cert != dirsrv_ca_cert):
        raise RuntimeError("Apache Server SSL certificate and Directory "
                           "Server SSL certificate are not signed by the same"
                           " CA certificate")

    if (options.http_cert_files and
            options.pkinit_cert_files and
            http_ca_cert != pkinit_ca_cert):
        raise RuntimeError("Apache Server SSL certificate and PKINIT KDC "
                           "certificate are not signed by the same CA "
                           "certificate")

    installutils.verify_fqdn(config.host_name, options.no_host_dns)
    # Inside the container environment master's IP address does not
    # resolve to its name. See https://pagure.io/freeipa/issue/6210
    container_environment = tasks.detect_container() is not None
    installutils.verify_fqdn(config.master_host_name, options.no_host_dns,
                             local_hostname=not container_environment)

    if config.host_name.lower() == config.domain_name.lower():
        raise ScriptError("hostname cannot be the same as the domain name")

    ccache = os.environ['KRB5CCNAME']
    kinit_keytab('host/{env.host}@{env.realm}'.format(env=api.env),
                 paths.KRB5_KEYTAB,
                 ccache)

    if ipa_client_installed:
        # host was already an IPA client, refresh client cert stores to
        # ensure we have up to date CA certs.
        try:
            ipautil.run([paths.IPA_CERTUPDATE])
        except ipautil.CalledProcessError:
            raise RuntimeError("ipa-certupdate failed to refresh certs.")

    remote_api = remote_connection(config)
    installer._remote_api = remote_api

    with rpc_client(remote_api) as client:
        check_remote_version(client, parse_version(api.env.version))
        check_remote_fips_mode(client, api.env.fips_mode)

    conn = remote_api.Backend.ldap2
    replman = None
    try:
        # Try out authentication
        conn.connect(ccache=ccache)
        replman = ReplicationManager(config.realm_name,
                                     config.master_host_name, None)

        promotion_check_ipa_domain(conn, remote_api.env.basedn)
        hostdn = DN(('fqdn', api.env.host),
                    api.env.container_host,
                    api.env.basedn)
        promotion_check_host_principal_auth_ind(conn, hostdn)

        # Make sure that domain fulfills minimal domain level
        # requirement
        domain_level = current_domain_level(remote_api)
        check_domain_level_is_supported(domain_level)
        if domain_level < constants.MIN_DOMAIN_LEVEL:
            raise RuntimeError(
                "Cannot promote this client to a replica. The domain level "
                "must be raised to {mindomainlevel} before the replica can be "
                "installed".format(
                    mindomainlevel=constants.MIN_DOMAIN_LEVEL
                ))

        # Check authorization
        result = remote_api.Command['hostgroup_find'](
            cn=u'ipaservers',
            host=[unicode(api.env.host)]
        )['result']
        add_to_ipaservers = not result

        if add_to_ipaservers:
            if options.password and not options.admin_password:
                raise errors.ACIError(info="Not authorized")

            if installer._ccache is None:
                os.environ.pop('KRB5CCNAME', None)
            else:
                os.environ['KRB5CCNAME'] = installer._ccache

            try:
                installutils.check_creds(options, config.realm_name)
                installer._ccache = os.environ.get('KRB5CCNAME')
            finally:
                os.environ['KRB5CCNAME'] = ccache

            conn.disconnect()
            conn.connect(ccache=installer._ccache)

            try:
                result = remote_api.Command['hostgroup_show'](
                    u'ipaservers',
                    all=True,
                    rights=True
                )['result']

                if 'w' not in result['attributelevelrights']['member']:
                    raise errors.ACIError(info="Not authorized")
            finally:
                conn.disconnect()
                conn.connect(ccache=ccache)


        # Check that we don't already have a replication agreement
        if replman.get_replication_agreement(config.host_name):
            msg = ("A replication agreement for this host already exists. "
                   "It needs to be removed.\n"
                   "Run this command on any working server:\n"
                   "    %% ipa server-del {host} --force"
                   .format(host=config.host_name))
            raise ScriptError(msg, rval=3)

        # Detect if the other master can handle replication managers
        # cn=replication managers,cn=sysaccounts,cn=etc,$SUFFIX
        dn = DN(('cn', 'replication managers'),
                api.env.container_sysaccounts,
                ipautil.realm_to_suffix(config.realm_name))
        try:
            conn.get_entry(dn)
        except errors.NotFound:
            msg = ("The Replication Managers group is not available in "
                   "the domain. Replica promotion requires the use of "
                   "Replication Managers to be able to replicate data. "
                   "Upgrade the peer master or use the ipa-replica-prepare "
                   "command on the master and use a prep file to install "
                   "this replica.")
            logger.error("%s", msg)
            raise ScriptError(rval=3)

        dns_masters = remote_api.Object['dnsrecord'].get_dns_masters()
        if dns_masters:
            if not options.no_host_dns:
                logger.debug('Check forward/reverse DNS resolution')
                resolution_ok = (
                    check_dns_resolution(config.master_host_name,
                                         dns_masters) and
                    check_dns_resolution(config.host_name, dns_masters))
                if not resolution_ok and installer.interactive:
                    if not ipautil.user_input("Continue?", False):
                        raise ScriptError(rval=0)
        else:
            logger.debug('No IPA DNS servers, '
                         'skipping forward/reverse resolution check')

        entry_attrs = conn.get_ipa_config()
        subject_base = entry_attrs.get('ipacertificatesubjectbase', [None])[0]
        if subject_base is not None:
            config.subject_base = DN(subject_base)

        # Find any server with a CA
        # The order of preference is
        # 1. the first server specified in --server, if any
        # 2. the server specified in the config file
        # 3. any other
        preferred_cas = [config.ca_host_name]
        if options.server:
            preferred_cas.insert(0, options.server)
        ca_host = find_providing_server(
            'CA', conn, preferred_cas
        )
        if ca_host is not None:
            if options.setup_ca and config.master_host_name != ca_host:
                conn.disconnect()
                del remote_api
                config.master_host_name = ca_host
                remote_api = remote_connection(config)
                installer._remote_api = remote_api
                conn = remote_api.Backend.ldap2
                conn.connect(ccache=installer._ccache)
            config.ca_host_name = ca_host
            ca_enabled = True  # There is a CA somewhere in the topology
            if options.dirsrv_cert_files:
                logger.error("Certificates could not be provided when "
                             "CA is present on some master.")
                raise ScriptError(rval=3)
            if options.setup_ca and options.server and \
               ca_host != options.server:
                # Installer was provided with a specific master
                # but this one doesn't provide CA
                logger.error("The specified --server %s does not provide CA, "
                             "please provide a server with the CA role",
                             options.server)
                raise ScriptError(rval=4)
        else:
            if options.setup_ca:
                logger.error("The remote master does not have a CA "
                             "installed, can't set up CA")
                raise ScriptError(rval=3)
            ca_enabled = False
            if not options.dirsrv_cert_files:
                logger.error("Cannot issue certificates: a CA is not "
                             "installed. Use the --http-cert-file, "
                             "--dirsrv-cert-file options to provide "
                             "custom certificates.")
                raise ScriptError(rval=3)

        # Find any server with a KRA
        # The order of preference is
        # 1. the first server specified in --server, if any
        # 2. the server specified in the config file
        # 3. any other
        preferred_kras = [config.kra_host_name]
        if options.server:
            preferred_kras.insert(0, options.server)
        kra_host = find_providing_server(
            'KRA', conn, preferred_kras
        )
        if kra_host is not None:
            if options.setup_kra and config.master_host_name != kra_host:
                conn.disconnect()
                del remote_api
                config.master_host_name = kra_host
                remote_api = remote_connection(config)
                installer._remote_api = remote_api
                conn = remote_api.Backend.ldap2
                conn.connect(ccache=installer._ccache)
            config.kra_host_name = kra_host
            if options.setup_kra:  # only reset ca_host if KRA is requested
                config.ca_host_name = kra_host
            kra_enabled = True  # There is a KRA somewhere in the topology
            if options.setup_kra and options.server and \
               kra_host != options.server:
                # Installer was provided with a specific master
                # but this one doesn't provide KRA
                logger.error("The specified --server %s does not provide KRA, "
                             "please provide a server with the KRA role",
                             options.server)
                raise ScriptError(rval=4)
        else:
            if options.setup_kra:
                logger.error("There is no active KRA server in the domain, "
                             "can't setup a KRA clone")
                raise ScriptError(rval=3)
            kra_enabled = False

        if ca_enabled:
            options.realm_name = config.realm_name
            options.host_name = config.host_name
            ca.install_check(False, config, options)

        if kra_enabled:
            try:
                kra.install_check(remote_api, config, options)
            except RuntimeError as e:
                raise ScriptError(e)

        if options.setup_dns:
            dns.install_check(False, remote_api, True, options,
                              config.host_name)
            config.ips = dns.ip_addresses
        else:
            config.ips = installutils.get_server_ip_address(
                config.host_name, not installer.interactive,
                False, options.ip_addresses)

            # check addresses here, dns module is doing own check
            no_matching_interface_for_ip_address_warning(config.ips)

        # Always call adtrust.install_check
        # if --setup-adtrust is not specified, only the SID part is executed
        adtrust.install_check(False, options, remote_api)

    except errors.ACIError:
        logger.debug("%s", traceback.format_exc())
        raise ScriptError("\nInsufficient privileges to promote the server."
                          "\nPossible issues:"
                          "\n- A user has insufficient privileges"
                          "\n- This client has insufficient privileges "
                          "to become an IPA replica")
    except errors.LDAPError:
        logger.debug("%s", traceback.format_exc())
        raise ScriptError("\nUnable to connect to LDAP server %s" %
                          config.master_host_name)
    finally:
        if replman and replman.conn:
            replman.conn.unbind()
        if conn.isconnected():
            conn.disconnect()

    # check connection
    if not options.skip_conncheck:
        if add_to_ipaservers:
            # use user's credentials when the server host is not ipaservers
            if installer._ccache is None:
                os.environ.pop('KRB5CCNAME', None)
            else:
                os.environ['KRB5CCNAME'] = installer._ccache

        try:
            replica_conn_check(
                config.master_host_name, config.host_name, config.realm_name,
                options.setup_ca, 389,
                options.admin_password, principal=options.principal,
                ca_cert_file=paths.IPA_CA_CRT)
        finally:
            if add_to_ipaservers:
                os.environ['KRB5CCNAME'] = ccache

    installer._ca_enabled = ca_enabled
    installer._kra_enabled = kra_enabled
    installer._ca_file = paths.IPA_CA_CRT
    installer._fstore = fstore
    installer._sstore = sstore
    installer._config = config
    installer._add_to_ipaservers = add_to_ipaservers
    installer._dirsrv_pkcs12_file = dirsrv_pkcs12_file
    installer._dirsrv_pkcs12_info = dirsrv_pkcs12_info
    installer._http_pkcs12_file = http_pkcs12_file
    installer._http_pkcs12_info = http_pkcs12_info
    installer._pkinit_pkcs12_file = pkinit_pkcs12_file
    installer._pkinit_pkcs12_info = pkinit_pkcs12_info


@common_cleanup
def install(installer):
    options = installer
    ca_enabled = installer._ca_enabled
    kra_enabled = installer._kra_enabled
    fstore = installer._fstore
    sstore = installer._sstore
    config = installer._config
    dirsrv_pkcs12_info = installer._dirsrv_pkcs12_info
    http_pkcs12_info = installer._http_pkcs12_info
    pkinit_pkcs12_info = installer._pkinit_pkcs12_info

    remote_api = installer._remote_api
    conn = remote_api.Backend.ldap2
    ccache = os.environ['KRB5CCNAME']

    # Be clear that the installation process is beginning but not done
    sstore.backup_state('installation', 'complete', False)

    if tasks.configure_pkcs11_modules(fstore):
        print("Disabled p11-kit-proxy")

    _hostname, _sep, host_domain = config.host_name.partition('.')
    fstore.backup_file(paths.KRB5_CONF)

    # Write a new krb5.conf in case any values changed finding the
    # right server to configure against (for CA, KRA).
    logger.debug("Installing against server %s", config.master_host_name)
    configure_krb5_conf(
        cli_realm=api.env.realm,
        cli_domain=api.env.domain,
        cli_server=[config.master_host_name],
        cli_kdc=[config.master_host_name],
        dnsok=False,
        filename=paths.KRB5_CONF,
        client_domain=host_domain,
        client_hostname=config.host_name,
        configure_sssd=False
    )

    if installer._add_to_ipaservers:
        try:
            conn.connect(ccache=installer._ccache)
            remote_api.Command['hostgroup_add_member'](
                u'ipaservers',
                host=[unicode(api.env.host)],
            )
        finally:
            if conn.isconnected():
                conn.disconnect()
            os.environ['KRB5CCNAME'] = ccache
    config.dirman_password = ipautil.ipa_generate_password()

    # FIXME: allow to use passed in certs instead
    if ca_enabled:
        configure_certmonger()

    try:
        conn.connect(ccache=ccache)
        # Configure dirsrv
        ds = install_replica_ds(config, options, ca_enabled,
                                remote_api,
                                ca_file=paths.IPA_CA_CRT,
                                pkcs12_info=dirsrv_pkcs12_info,
                                fstore=fstore)

        # Always try to install DNS records
        install_dns_records(config, options, remote_api, fstore=fstore)

    finally:
        if conn.isconnected():
            conn.disconnect()

        # Create the management framework config file. Do this irregardless
        # of the state of DS installation. Even if it fails,
        # we need to have master-like configuration in order to perform a
        # successful uninstallation
        # The configuration creation has to be here otherwise previous call
        # To config certmonger would try to connect to local server
        create_ipa_conf(fstore, config, ca_enabled)

    krb = install_krb(
        config,
        setup_pkinit=not options.no_pkinit,
        pkcs12_info=pkinit_pkcs12_info,
        fstore=fstore)

    # We need to point to the master when certmonger asks for
    # a DS or HTTP certificate.
    # During http installation, the <service>/hostname principal is
    # created locally then the installer waits for the entry to appear
    # on the master selected for the installation.
    # In a later step, the installer requests a SSL certificate through
    # Certmonger (and the op adds the principal if it does not exist yet).
    # If xmlrpc_uri points to the soon-to-be replica,
    # the httpd service is not ready yet to handle certmonger requests
    # and certmonger tries to find another master. The master can be
    # different from the one selected for the installation, and it is
    # possible that the principal has not been replicated yet. This
    # may lead to a replication conflict.
    # This is why we need to force the use of the same master by
    # setting xmlrpc_uri
    create_ipa_conf(fstore, config, ca_enabled,
                    master=config.master_host_name)

    # we now need to enable ssl on the ds
    ds.enable_ssl()

    install_http(
        config,
        auto_redirect=not options.no_ui_redirect,
        pkcs12_info=http_pkcs12_info,
        ca_is_configured=ca_enabled,
        ca_file=paths.IPA_CA_CRT,
        fstore=fstore)

    # Need to point back to ourself after the cert for HTTP is obtained
    create_ipa_conf(fstore, config, ca_enabled)

    otpd = otpdinstance.OtpdInstance()
    otpd.create_instance('OTPD', config.host_name,
                         ipautil.realm_to_suffix(config.realm_name))

    if options.setup_kra and kra_enabled:
        # A KRA peer always provides a CA, too.
        mode = custodiainstance.CustodiaModes.KRA_PEER
    elif options.setup_ca and ca_enabled:
        mode = custodiainstance.CustodiaModes.CA_PEER
    else:
        mode = custodiainstance.CustodiaModes.MASTER_PEER
    custodia = custodiainstance.get_custodia_instance(config, mode)
    custodia.create_instance()

    if ca_enabled:
        options.realm_name = config.realm_name
        options.domain_name = config.domain_name
        options.host_name = config.host_name
        options.dm_password = config.dirman_password
        # Always call ca.install() if there is a CA in the topology
        # to ensure the RA agent is present.
        ca.install(False, config, options, custodia=custodia)

    # configure PKINIT now that all required services are in place
    krb.enable_ssl()

    # Apply any LDAP updates. Needs to be done after the replica is synced-up
    service.print_msg("Applying LDAP updates")
    ds.apply_updates()
    service.print_msg("Finalize replication settings")
    ds.finalize_replica_config()

    if kra_enabled:
        # The KRA installer checks for itself the status of setup_kra
        kra.install(api, config, options, custodia=custodia)

    service.print_msg("Restarting the KDC")
    krb.restart()

    custodia.import_dm_password()
    promote_sssd(config.host_name)
    promote_openldap_conf(config.host_name, config.master_host_name)

    if options.setup_dns:
        dns.install(False, True, options, api)

    # Always call adtrust.install
    # if --setup-adtrust is not specified, only the SID part is executed
    adtrust.install(False, options, fstore, api)

    if options.hidden_replica:
        # Set services to hidden
        service.hide_services(config.host_name)
    else:
        # Enable configured services
        service.enable_services(config.host_name)
    # update DNS SRV records. Although it's only really necessary in
    # enabled-service case, also perform update in hidden replica case.
    api.Command.dns_update_system_records()

    if options.setup_adtrust:
        dns_help = adtrust.generate_dns_service_records_help(api)
        if dns_help:
            for line in dns_help:
                service.print_msg(line, sys.stdout)

    ca_servers = find_providing_servers('CA', api.Backend.ldap2, api=api)
    api.Backend.ldap2.disconnect()

    # Everything installed properly, activate ipa service.
    sstore.delete_state('installation', 'complete')
    sstore.backup_state('installation', 'complete', True)
    services.knownservices.ipa.enable()

    # Print a warning if CA role is only installed on one server
    if len(ca_servers) == 1:
        msg = textwrap.dedent(u'''
            WARNING: The CA service is only installed on one server ({}).
            It is strongly recommended to install it on another server.
            Run ipa-ca-install(1) on another master to accomplish this.
        '''.format(ca_servers[0]))
        print(msg, file=sys.stderr)

    if options.setup_ca:
        clean_up_hsm_nicknames(api)


def init(installer):
    installer.unattended = not installer.interactive

    if installer.servers:
        installer.server = installer.servers[0]
    else:
        installer.server = None
    installer.password = installer.host_password

    installer._ccache = os.environ.get('KRB5CCNAME')

    installer._top_dir = None
    installer._config = None
    installer._update_hosts_file = False
    installer._dirsrv_pkcs12_file = None
    installer._http_pkcs12_file = None
    installer._pkinit_pkcs12_file = None
    installer._dirsrv_pkcs12_info = None
    installer._http_pkcs12_info = None
    installer._pkinit_pkcs12_info = None
