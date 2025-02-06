#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

"""
IPA client install module

Provides methods for installation, uninstallation of IPA client
"""

from __future__ import (
    print_function,
    absolute_import,
)

import logging

import dns
import getpass
import gssapi
import ifaddr
import os
import re
import SSSDConfig
import shutil
import socket
import sys
import tempfile
import textwrap
import time
import traceback
import warnings

from configparser import RawConfigParser
from urllib.parse import urlparse, urlunparse

from ipalib import api, errors, x509
from ipalib import sysrestore
from ipalib.constants import FQDN, IPAAPI_USER, MAXHOSTNAMELEN
from ipalib.install import certmonger, certstore, service
from ipalib.install import hostname as hostname_
from ipalib.facts import is_ipa_client_configured, is_ipa_configured
from ipalib.kinit import kinit_keytab, kinit_password, kinit_pkinit
from ipalib.install.service import enroll_only, prepare_only
from ipalib.rpc import delete_persistent_client_session_data
from ipalib.util import (
    normalize_hostname,
    no_matching_interface_for_ip_address_warning,
    validate_hostname,
    verify_host_resolvable,
)
from ipaplatform import services
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipapython import certdb, kernel_keyring, ipaldap, ipautil, dnsutil
from ipapython.admintool import ScriptError
from ipapython.dn import DN
from ipapython.install import typing
from ipapython.install.core import group, knob, extend_knob
from ipapython.install.common import step
from ipapython.ipautil import (
    CalledProcessError,
    realm_to_suffix,
    run,
    user_input,
)
from ipapython.ssh import SSHPublicKey
from ipapython import version
from ipapython.errors import SetseboolError

from . import automount, timeconf, sssd
from ipaclient import discovery
from ipapython.ipachangeconf import IPAChangeConf

NoneType = type(None)

logger = logging.getLogger(__name__)

SUCCESS = 0
CLIENT_INSTALL_ERROR = 1
CLIENT_NOT_CONFIGURED = 2
CLIENT_ALREADY_CONFIGURED = 3
CLIENT_UNINSTALL_ERROR = 4  # error after restoring files/state

SECURE_PATH = (
    "/bin:/sbin:/usr/kerberos/bin:/usr/kerberos/sbin:/usr/bin:/usr/sbin"
)

# global variables
hostname = None
hostname_source = None
nosssd_files = None
dnsok = False
cli_domain = None
cli_server = None
subject_base = None
cli_realm = None
cli_kdc = None
client_domain = None
cli_basedn = None
selinux_works = None
# end of global variables


def cleanup(func):
    def inner(options, tdict):
        # Add some additional options which contain the temporary files
        # needed during installation.
        fd, krb_name = tempfile.mkstemp()
        os.close(fd)
        ccache_dir = tempfile.mkdtemp(prefix='krbcc')

        tdict['krb_name'] = krb_name
        tdict['ccache_dir'] = ccache_dir

        func(options, tdict)

        os.environ.pop('KRB5_CONFIG', None)

        try:
            os.remove(krb_name)
        except OSError:
            logger.error("Could not remove %s", krb_name)
        try:
            os.rmdir(ccache_dir)
        except OSError:
            pass
        # During master installation, the .ipabkp file is not created
        # Ignore the delete error if it is "file does not exist"
        remove_file(krb_name + ".ipabkp")

    return inner


def remove_file(filename):
    """
    Deletes a file. If the file does not exist (OSError 2) does nothing.
    Otherwise logs an error message and instructs the user to remove the
    offending file manually
    :param filename: name of the file to be removed
    """

    try:
        os.remove(filename)
    except OSError as e:
        if e.errno == 2:
            return

        logger.error("Failed to remove file %s: %s", filename, e)
        logger.error('Please remove %s manually, as it can cause '
                     'subsequent installation to fail.', filename)


def log_service_error(name, action, error):
    logger.error("%s failed to %s: %s", name, action, str(error))


def get_cert_path(cert_path):
    """
    If a CA certificate is passed in on the command line, use that.

    Else if a CA file exists in paths.IPA_CA_CRT then use that.

    Otherwise return None.
    """
    if cert_path is not None:
        return cert_path

    if os.path.exists(paths.IPA_CA_CRT) and \
            os.stat(paths.IPA_CA_CRT).st_size != 0:
        return paths.IPA_CA_CRT

    return None


def save_state(service, statestore):
    enabled = service.is_enabled()
    running = service.is_running()

    if enabled or running:
        statestore.backup_state(service.service_name, 'enabled', enabled)
        statestore.backup_state(service.service_name, 'running', running)


def restore_state(service, statestore):
    enabled = statestore.restore_state(service.service_name, 'enabled')
    running = statestore.restore_state(service.service_name, 'running')

    if enabled:
        try:
            service.enable()
        except Exception:
            logger.warning(
                "Failed to configure automatic startup of the %s daemon",
                service.service_name
            )
    if running:
        try:
            service.start()
        except Exception:
            logger.warning(
                "Failed to restart the %s daemon",
                service.service_name
            )


def nssldap_exists():
    """Checks whether nss_ldap or nss-pam-ldapd is installed.
     If anyone of mandatory files was found returns True and list of all files
     found.
    """
    files_to_check = [
        {
            'function': 'configure_ldap_conf',
            'mandatory': [
                paths.LDAP_CONF,
                paths.NSS_LDAP_CONF,
                paths.LIBNSS_LDAP_CONF],
            'optional':[paths.PAM_LDAP_CONF]
        },
        {
            'function': 'configure_nslcd_conf',
            'mandatory': [paths.NSLCD_CONF]
        }
    ]
    files_found = {}
    retval = False

    for function in files_to_check:
        files_found[function['function']] = []
        for file_type in ['mandatory', 'optional']:
            try:
                for filename in function[file_type]:
                    if os.path.isfile(filename):
                        files_found[function['function']].append(filename)
                        if file_type == 'mandatory':
                            retval = True
            except KeyError:
                pass

    return (retval, files_found)


def check_ldap_conf(conf=paths.OPENLDAP_LDAP_CONF,
                    error_rval=CLIENT_INSTALL_ERROR):
    if not os.path.isfile(conf):
        return False

    pat = re.compile(r"^\s*(PORT|HOST).*")
    unsupported = set()

    with open(conf) as f:
        for line in f:
            mo = pat.match(line)
            if mo is not None:
                unsupported.add(mo.group(1))

    if unsupported:
        raise ScriptError(
            "'{}' contains deprecated and unsupported entries: {}".format(
                conf, ", ".join(sorted(unsupported))
            ),
            rval=error_rval
        )
    else:
        return True


def delete_ipa_domain():
    """Helper function for uninstall.
    Deletes IPA domain from sssd.conf
    """
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
        domains = sssdconfig.list_active_domains()

        ipa_domain_name = None

        for name in domains:
            domain = sssdconfig.get_domain(name)
            try:
                provider = domain.get_option('id_provider')
                if provider == "ipa":
                    ipa_domain_name = name
                    break
            except SSSDConfig.NoOptionError:
                continue

        if ipa_domain_name is not None:
            sssdconfig.delete_domain(ipa_domain_name)
            sssdconfig.write()
        else:
            logger.warning(
                "IPA domain could not be found in "
                "/etc/sssd/sssd.conf and therefore not deleted")
    except IOError:
        logger.warning(
            "IPA domain could not be deleted. "
            "No access to the /etc/sssd/sssd.conf file.")


def is_ipa_client_installed(on_master=False):
    """
    Consider IPA client not installed if nothing is backed up
    and default.conf file does not exist. If on_master is set to True,
    the existence of default.conf file is not taken into consideration,
    since it has been already created by ipa-server-install.
    """
    warnings.warn(
        "Use 'ipalib.facts.is_ipa_client_configured'",
        DeprecationWarning,
        stacklevel=2
    )
    return is_ipa_client_configured(on_master)


def configure_nsswitch_database(fstore, database, services, preserve=True,
                                append=True, default_value=()):
    """
    This function was deprecated. Use ipaplatform.tasks.

    Edits the specified nsswitch.conf database (e.g. passwd, group, sudoers)
    to use the specified service(s).

    Arguments:
        fstore - FileStore to backup the nsswitch.conf
        database - database configuration that should be ammended,
                    e.g. 'sudoers'
        service - list of services that should be added, e.g. ['sss']
        preserve - if True, the already configured services will be preserved

    The next arguments modify the behaviour if preserve=True:
        append - if True, the services will be appended, if False, prepended
        default_value - list of services that are considered as default (if
                        the database is not mentioned in nsswitch.conf), e.g.
                        ['files']
    """
    warnings.warn(
        "Use ipaplatform.tasks.tasks.configure_nsswitch_database",
        DeprecationWarning,
        stacklevel=2
    )
    return tasks.configure_nsswitch_database(fstore, database, services,
                                             preserve, append, default_value)


def configure_ipa_conf(
        fstore, cli_basedn, cli_realm, cli_domain, cli_server, hostname):
    ipaconf = IPAChangeConf("IPA Installer")
    ipaconf.setOptionAssignment(" = ")
    ipaconf.setSectionNameDelimiters(("[", "]"))

    opts = [
        {
            'name': 'comment',
            'type': 'comment',
            'value': 'File modified by ipa-client-install'
        },
        ipaconf.emptyLine(),
    ]

    # [global]
    defopts = [
        ipaconf.setOption('basedn', cli_basedn),
        ipaconf.setOption('realm', cli_realm),
        ipaconf.setOption('domain', cli_domain),
        ipaconf.setOption('server', cli_server[0]),
        ipaconf.setOption('host', hostname),
        ipaconf.setOption('xmlrpc_uri',
                          'https://{}/ipa/xml'.format(
                                ipautil.format_netloc(cli_server[0]))),
        ipaconf.setOption('enable_ra', 'True')
    ]

    opts.extend([
        ipaconf.setSection('global', defopts),
        ipaconf.emptyLine(),
    ])

    target_fname = paths.IPA_DEFAULT_CONF
    fstore.backup_file(target_fname)
    ipaconf.newConf(target_fname, opts)
    # umask applies when creating a new file but we want 0o644 here
    os.chmod(target_fname, 0o644)


def disable_ra():
    """Set the enable_ra option in /etc/ipa/default.conf to False

    Note that api.env will retain the old value (it is readonly).
    """
    parser = RawConfigParser()
    parser.read(paths.IPA_DEFAULT_CONF)
    parser.set('global', 'enable_ra', 'False')
    fp = open(paths.IPA_DEFAULT_CONF, 'w')
    parser.write(fp)
    fp.close()


def configure_ldap_conf(
        fstore, cli_basedn, cli_realm, cli_domain, cli_server, dnsok, options,
        files):
    ldapconf = IPAChangeConf("IPA Installer")
    ldapconf.setOptionAssignment(" ")

    opts = [
        {
            'name': 'comment',
            'type': 'comment',
            'value': 'File modified by ipa-client-install'
        },
        ldapconf.emptyLine(),

        ldapconf.setOption('ldap_version', '3'),
        ldapconf.setOption('base', cli_basedn),
        ldapconf.emptyLine(),

        ldapconf.setOption(
            'nss_base_passwd', '{dn}{suffix}'
            .format(dn=DN(('cn', 'users'), ('cn', 'accounts'), cli_basedn),
                    suffix='?sub')),
        ldapconf.setOption(
            'nss_base_group', '{dn}{suffix}'
            .format(dn=DN(('cn', 'groups'), ('cn', 'accounts'), cli_basedn),
                    suffix='?sub')),
        ldapconf.setOption('nss_schema', 'rfc2307bis'),
        ldapconf.setOption('nss_map_attribute', 'uniqueMember member'),
        ldapconf.setOption('nss_initgroups_ignoreusers', 'root,dirsrv'),
        ldapconf.emptyLine(),

        ldapconf.setOption('nss_reconnect_maxsleeptime', '8'),
        ldapconf.setOption('nss_reconnect_sleeptime', '1'),
        ldapconf.setOption('bind_timelimit', '5'),
        ldapconf.setOption('timelimit', '15'),
        ldapconf.emptyLine(),
    ]
    if not dnsok or options.force or options.on_master:
        if options.on_master:
            opts.append(ldapconf.setOption('uri', 'ldap://localhost'))
        else:
            opts.append(ldapconf.setOption('uri', 'ldap://{}'.format(
                            ipautil.format_netloc(cli_server[0]))))
    else:
        opts.append(ldapconf.setOption('nss_srv_domain', cli_domain))

    opts.append(ldapconf.emptyLine())

    # Depending on the release and distribution this may exist in any
    # number of different file names, update what we find
    for filename in files:
        try:
            fstore.backup_file(filename)
            ldapconf.newConf(filename, opts)
        except Exception as e:
            logger.error("Creation of %s failed: %s", filename, str(e))
            return (1, 'LDAP', filename)

    if files:
        return (0, 'LDAP', ', '.join(files))

    return 0, None, None


def configure_nslcd_conf(
        fstore, cli_basedn, cli_realm, cli_domain, cli_server, dnsok, options,
        files):
    nslcdconf = IPAChangeConf("IPA Installer")
    nslcdconf.setOptionAssignment(" ")

    opts = [
        {
            'name': 'comment',
            'type': 'comment',
            'value': 'File modified by ipa-client-install'
        },
        nslcdconf.emptyLine(),

        nslcdconf.setOption('ldap_version', '3'),
        nslcdconf.setOption('base', cli_basedn),
        nslcdconf.emptyLine(),

        nslcdconf.setOption('base passwd', str(
                DN(('cn', 'users'), ('cn', 'accounts'), cli_basedn))),
        nslcdconf.setOption('base group', str(
                DN(('cn', 'groups'), ('cn', 'accounts'), cli_basedn))),
        nslcdconf.setOption('timelimit', '15'),
        nslcdconf.emptyLine(),
    ]

    if not dnsok or options.force or options.on_master:
        if options.on_master:
            opts.append(nslcdconf.setOption('uri', 'ldap://localhost'))
        else:
            opts.append(nslcdconf.setOption('uri', 'ldap://{}'.format(
                    ipautil.format_netloc(cli_server[0]))))
    else:
        opts.append(nslcdconf.setOption('uri', 'DNS'))

    opts.append(nslcdconf.emptyLine())

    for filename in files:
        try:
            fstore.backup_file(filename)
            nslcdconf.newConf(filename, opts)
        except Exception as e:
            logger.error("Creation of %s failed: %s", filename, str(e))
            return (1, None, None)

    nslcd = services.knownservices.nslcd
    if nslcd.is_installed():
        try:
            nslcd.restart()
        except Exception as e:
            log_service_error(nslcd.service_name, 'restart', e)

        try:
            nslcd.enable()
        except Exception as e:
            logger.error(
                "Failed to enable automatic startup of the %s daemon: %s",
                nslcd.service_name, str(e))
    else:
        logger.debug(
            "%s daemon is not installed, skip configuration",
            nslcd.service_name)
        return (0, None, None)

    return (0, 'NSLCD', ', '.join(files))


def configure_openldap_conf(fstore, cli_basedn, cli_server):
    ldapconf = IPAChangeConf("IPA Installer")
    ldapconf.setOptionAssignment((" ", "\t"))

    opts = [
        {
            'name': 'comment',
            'type': 'comment',
            'value': ' File modified by ipa-client-install'
        },
        ldapconf.emptyLine(),
        {
            'name': 'comment',
            'type': 'comment',
            'value': ' We do not want to break your existing configuration, '
                     'hence:'
        },
        # this needs to be kept updated if we change more options
        {
            'name': 'comment',
            'type': 'comment',
            'value': '   URI, BASE, and SASL_MECH'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': '   have been added if they were not set.'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': '   In case any of them were set, a comment has been '
                     'inserted and'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': '   "# CONF_NAME modified by IPA" added to the line '
                     'above.'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': ' To use IPA server with openLDAP tools, please comment '
                     'out your'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': ' existing configuration for these options and '
                     'uncomment the'
        },
        {
            'name': 'comment',
            'type': 'comment',
            'value': ' corresponding lines generated by IPA.'
        },
        ldapconf.emptyLine(),
        ldapconf.emptyLine(),
        {
            'action': 'addifnotset',
            'name': 'URI',
            'type': 'option',
            'value': 'ldaps://{}'.format(cli_server[0])
        },
        {
            'action': 'addifnotset',
            'name': 'BASE',
            'type': 'option',
            'value': str(cli_basedn)
        },
        {
            'action': 'addifnotset',
            'name': 'SASL_MECH',
            'type': 'option',
            'value': 'GSSAPI'
        },
    ]

    target_fname = paths.OPENLDAP_LDAP_CONF
    fstore.backup_file(target_fname)

    error_msg = "Configuring {path} failed with: {err}"

    try:
        ldapconf.changeConf(target_fname, opts)
    except SyntaxError as e:
        logger.info("Could not parse %s", target_fname)
        logger.debug('%s', error_msg.format(path=target_fname, err=str(e)))
        return False
    except IOError as e:
        logger.info("%s does not exist.", target_fname)
        logger.debug('%s', error_msg.format(path=target_fname, err=str(e)))
        return False
    except Exception as e:  # we do not want to fail in an optional step
        logger.debug('%s', error_msg.format(path=target_fname, err=str(e)))
        return False

    os.chmod(target_fname, 0o644)
    return True


def hardcode_ldap_server(cli_server):
    """
    DNS Discovery didn't return a valid IPA server, hardcode a value into
    the file instead.
    """
    if not os.path.isfile(paths.LDAP_CONF):
        return

    ldapconf = IPAChangeConf("IPA Installer")
    ldapconf.setOptionAssignment(" ")

    opts = [
        ldapconf.setOption('uri', 'ldap://{}'.format(
            ipautil.format_netloc(cli_server[0]))),
        ldapconf.emptyLine(),
    ]

    # Errors raised by this should be caught by the caller
    ldapconf.changeConf(paths.LDAP_CONF, opts)
    logger.info(
        "Changed configuration of /etc/ldap.conf to use "
        "hardcoded server name: %s", cli_server[0])


# Currently this doesn't support templating, but that could be changed in the
# future.  Note that this function is also called from %post.
def configure_krb5_snippet():
    template = os.path.join(
        paths.USR_SHARE_IPA_CLIENT_DIR,
        os.path.basename(paths.KRB5_FREEIPA) + ".template"
    )
    shutil.copy(template, paths.KRB5_FREEIPA)
    os.chmod(paths.KRB5_FREEIPA, 0o644)

    tasks.restore_context(paths.KRB5_FREEIPA)


def configure_krb5_conf(
        cli_realm, cli_domain, cli_server, cli_kdc, dnsok,
        filename, client_domain, client_hostname, force=False,
        configure_sssd=True):
    # First, write a snippet to krb5.conf.d.
    configure_krb5_snippet()

    # Then, perform the rest of our configuration into krb5.conf itself.
    krbconf = IPAChangeConf("IPA Installer")
    krbconf.setOptionAssignment((" = ", " "))
    krbconf.setSectionNameDelimiters(("[", "]"))
    krbconf.setSubSectionDelimiters(("{", "}"))
    krbconf.setIndent(("", "  ", "    "))

    opts = [
        {
            'name': 'comment',
            'type': 'comment',
            'value': 'File modified by ipa-client-install'
        },
        krbconf.emptyLine(),
    ]

    if os.path.exists(paths.COMMON_KRB5_CONF_DIR):
        opts.extend([
            {
                'name': 'includedir',
                'type': 'option',
                'value': paths.COMMON_KRB5_CONF_DIR,
                'delim': ' '
            }
        ])

    # [libdefaults]
    libopts = [
        krbconf.setOption('default_realm', cli_realm)
    ]
    if not dnsok or not cli_kdc or force:
        libopts.extend([
            krbconf.setOption('dns_lookup_realm', 'false'),
        ])
    else:
        libopts.extend([
            krbconf.setOption('dns_lookup_realm', 'true'),
        ])
    libopts.extend([
        krbconf.setOption('rdns', 'false'),
        krbconf.setOption('dns_canonicalize_hostname', 'false'),
        krbconf.setOption('dns_lookup_kdc', 'true'),
        krbconf.setOption('ticket_lifetime', '24h'),
        krbconf.setOption('forwardable', 'true'),
        krbconf.setOption('udp_preference_limit', '0')
    ])

    # Configure KEYRING CCACHE if supported
    if kernel_keyring.is_persistent_keyring_supported():
        logger.debug("Enabling persistent keyring CCACHE")
        libopts.append(krbconf.setOption('default_ccache_name',
                                         'KEYRING:persistent:%{uid}'))

    opts.extend([
        krbconf.setSection('libdefaults', libopts),
        krbconf.emptyLine()
    ])

    # the following are necessary only if DNS discovery does not work
    kropts = []
    if not dnsok or not cli_kdc or force:
        # [realms]
        for server in cli_server:
            kropts.extend([
                krbconf.setOption('kdc', ipautil.format_netloc(server, 88)),
                krbconf.setOption('master_kdc',
                                  ipautil.format_netloc(server, 88)),
                krbconf.setOption('admin_server',
                                  ipautil.format_netloc(server, 749)),
                krbconf.setOption('kpasswd_server',
                                  ipautil.format_netloc(server, 464))
            ])
        kropts.append(krbconf.setOption('default_domain', cli_domain))

    kropts.append(
        krbconf.setOption('pkinit_anchors',
                          'FILE:%s' % paths.KDC_CA_BUNDLE_PEM))
    kropts.append(
        krbconf.setOption('pkinit_pool',
                          'FILE:%s' % paths.CA_BUNDLE_PEM))
    ropts = [{
        'name': cli_realm,
        'type': 'subsection',
        'value': kropts
    }]

    opts.append(krbconf.setSection('realms', ropts))
    opts.append(krbconf.emptyLine())

    # [domain_realm]
    dropts = [
        krbconf.setOption('.{}'.format(cli_domain), cli_realm),
        krbconf.setOption(cli_domain, cli_realm),
        krbconf.setOption(client_hostname, cli_realm)
    ]

    # add client domain mapping if different from server domain
    if cli_domain != client_domain:
        dropts.extend([
            krbconf.setOption('.{}'.format(client_domain), cli_realm),
            krbconf.setOption(client_domain, cli_realm)
        ])

    opts.extend([
        krbconf.setSection('domain_realm', dropts),
        krbconf.emptyLine()
    ])

    logger.debug("Writing Kerberos configuration to %s:", filename)
    logger.debug("%s", krbconf.dump(opts))

    krbconf.newConf(filename, opts)
    # umask applies when creating a new file but we want 0o644 here
    os.chmod(filename, 0o644)


def configure_certmonger(
        fstore, subject_base, cli_realm, hostname, options, ca_enabled):

    cmonger = services.knownservices.certmonger
    if not options.request_cert:
        # Conditionally restart certmonger to pick up the new IPA
        # configuration.
        try:
            cmonger.try_restart()
        except Exception as e:
            logger.error(
                "Failed to conditionally restart the %s daemon: %s",
                cmonger.service_name, str(e))
        return

    if not ca_enabled:
        logger.warning("An RA is not configured on the server. "
                       "Not requesting host certificate.")
        return

    principal = 'host/%s@%s' % (hostname, cli_realm)

    if options.hostname:
        # If the hostname is explicitly set then we need to tell certmonger
        # which principal name to use when requesting certs.
        certmonger.add_principal_to_cas(principal)

    try:
        cmonger.enable()
        cmonger.start()
    except Exception as e:
        logger.error(
            "Failed to configure automatic startup of the %s daemon: %s",
            cmonger.service_name, str(e))
        logger.warning(
            "Automatic certificate management will not be available")

    # Request our host cert
    subject = str(DN(('CN', hostname), subject_base))
    passwd_fname = os.path.join(paths.IPA_NSSDB_DIR, 'pwdfile.txt')
    try:
        certmonger.request_and_wait_for_cert(
            certpath=paths.IPA_NSSDB_DIR,
            storage='NSSDB',
            nickname='Local IPA host',
            subject=subject,
            dns=[hostname],
            principal=principal,
            passwd_fname=passwd_fname,
            resubmit_timeout=120,
        )
    except Exception as e:
        logger.exception("certmonger request failed")
        raise ScriptError(
            "{} request for host certificate failed: {}".format(
                cmonger.service_name, e
            ),
            rval=CLIENT_INSTALL_ERROR
        )


def configure_sssd_conf(
        fstore, cli_realm, cli_domain, cli_server, options,
        client_domain, client_hostname):
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
    except Exception as e:
        if os.path.exists(paths.SSSD_CONF) and options.preserve_sssd:
            # SSSD config is in place but we are unable to read it
            # In addition, we are instructed to preserve it
            # This all means we can't use it and have to bail out
            logger.error(
                "SSSD config exists but cannot be parsed: %s", str(e))
            logger.error(
                "Was instructed to preserve existing SSSD config")
            logger.info(
                "Correct errors in /etc/sssd/sssd.conf and re-run "
                "installation")
            return 1

        # SSSD configuration does not exist or we are not asked to preserve it,
        # create new one
        # We do make new SSSDConfig instance because IPAChangeConf-derived
        # classes have no means to reset their state and ParseError exception
        # could come due to parsing error from older version which cannot be
        # upgraded anymore, leaving sssdconfig instance practically unusable
        # Note that we already backed up sssd.conf before going into this
        # routine
        if isinstance(e, IOError):
            pass
        else:
            # It was not IOError so it must have been parsing error
            logger.error(
                "Unable to parse existing SSSD config. "
                "As option --preserve-sssd was not specified, new config "
                "will override the old one.")
            logger.info(
                "The old /etc/sssd/sssd.conf is backed up and "
                "will be restored during uninstall.")
        logger.debug("New SSSD config will be created")
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.new_config()

    try:
        domain = sssdconfig.new_domain(cli_domain)
    except SSSDConfig.DomainAlreadyExistsError:
        logger.info(
            "Domain %s is already configured in existing SSSD "
            "config, creating a new one.",
            cli_domain)
        logger.info(
            "The old /etc/sssd/sssd.conf is backed up and will be restored "
            "during uninstall.")
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.new_config()
        domain = sssdconfig.new_domain(cli_domain)

    if options.on_master:
        sssd_enable_ifp(sssdconfig)

    if (
        (options.conf_ssh and os.path.isfile(paths.SSH_CONFIG)) or
        (options.conf_sshd and os.path.isfile(paths.SSHD_CONFIG))
    ):
        try:
            sssdconfig.new_service('ssh')
        except SSSDConfig.ServiceAlreadyExists:
            pass
        except SSSDConfig.ServiceNotRecognizedError:
            logger.error(
                "Unable to activate the SSH service in SSSD config.")
            logger.info(
                "Please make sure you have SSSD built with SSH support "
                "installed.")
            logger.info(
                "Configure SSH support manually in /etc/sssd/sssd.conf.")

        sssdconfig.activate_service('ssh')

    if options.conf_sudo:
        # Activate the service in the SSSD config
        try:
            sssdconfig.new_service('sudo')
        except SSSDConfig.ServiceAlreadyExists:
            pass
        except SSSDConfig.ServiceNotRecognizedError:
            logger.error(
                "Unable to activate the SUDO service in SSSD config.")

        sssdconfig.activate_service('sudo')
        tasks.enable_sssd_sudo(fstore)

    domain.add_provider('ipa', 'id')

    # add discovery domain if client domain different from server domain
    # do not set this config in server mode (#3947)
    if not options.on_master and cli_domain != client_domain:
        domain.set_option('dns_discovery_domain', cli_domain)

    if not options.on_master:
        if options.primary:
            domain.set_option('ipa_server', ', '.join(cli_server))
        else:
            domain.set_option(
                'ipa_server', '_srv_, %s' % ', '.join(cli_server))
    else:
        domain.set_option('ipa_server_mode', 'True')
        # the master should only use itself for Kerberos
        domain.set_option('ipa_server', cli_server[0])

        # increase memcache timeout to 10 minutes when in server mode
        try:
            nss_service = sssdconfig.get_service('nss')
        except SSSDConfig.NoServiceError:
            nss_service = sssdconfig.new_service('nss')

        nss_service.set_option('memcache_timeout', 600)
        sssdconfig.save_service(nss_service)

    sssd_enable_service(sssdconfig, 'nss')
    sssd_enable_service(sssdconfig, 'pam')
    if options.conf_ssh:
        sssd_enable_service(sssdconfig, 'ssh')

    domain.set_option('ipa_domain', cli_domain)
    domain.set_option('ipa_hostname', client_hostname)
    if cli_domain.lower() != cli_realm.lower():
        domain.set_option('krb5_realm', cli_realm)

    # Might need this if /bin/hostname doesn't return a FQDN
    # domain.set_option('ipa_hostname', 'client.example.com')

    domain.add_provider('ipa', 'auth')
    domain.add_provider('ipa', 'chpass')
    if not options.permit:
        domain.add_provider('ipa', 'access')
    else:
        domain.add_provider('permit', 'access')

    domain.set_option('cache_credentials', True)

    # SSSD will need TLS for checking if ipaMigrationEnabled attribute is set
    # Note that SSSD will force StartTLS because the channel is later used for
    # authentication as well if password migration is enabled. Thus set
    # the option unconditionally.
    domain.set_option('ldap_tls_cacert', paths.IPA_CA_CRT)

    if options.dns_updates:
        domain.set_option('dyndns_update', True)
        if options.all_ip_addresses:
            domain.set_option('dyndns_iface', '*')
        else:
            iface = get_server_connection_interface(cli_server[0])
            domain.set_option('dyndns_iface', iface)
    if options.krb5_offline_passwords:
        domain.set_option('krb5_store_password_if_offline', True)

    domain.set_active(True)

    sssdconfig.save_domain(domain)
    sssdconfig.write(paths.SSSD_CONF)

    return 0


def sssd_enable_service(sssdconfig, name):
    try:
        sssdconfig.new_service(name)
    except SSSDConfig.ServiceAlreadyExists:
        pass
    except SSSDConfig.ServiceNotRecognizedError:
        logger.error(
            "Unable to activate the '%s' service in SSSD config.", name)
        logger.info(
            "Please make sure you have SSSD built with %s support "
            "installed.", name)
        logger.info(
            "Configure %s support manually in /etc/sssd/sssd.conf.", name)
        return None

    sssdconfig.activate_service(name)
    return sssdconfig.get_service(name)


def sssd_enable_ifp(sssdconfig, allow_httpd=False):
    """Enable and configure libsss_simpleifp plugin

    Allow the ``ipaapi`` user to access IFP. In case allow_httpd is true,
    the Apache HTTPd user is also allowed to access IFP. For smart card
    authentication, mod_lookup_identity must be allowed to access user
    information.
    """
    service = sssd_enable_service(sssdconfig, 'ifp')
    if service is None:
        # unrecognized service
        return

    try:
        uids = service.get_option('allowed_uids')
    except SSSDConfig.NoOptionError:
        uids = set()
    else:
        uids = {s.strip() for s in uids.split(',') if s.strip()}
    # SSSD supports numeric and string UIDs
    # ensure that root is allowed to access IFP, might be 0 or root
    if uids.isdisjoint({'0', 'root'}):
        uids.add('root')
    # allow IPA API to access IFP
    uids.add(IPAAPI_USER)
    if allow_httpd:
        uids.add(constants.HTTPD_USER)
    service.set_option('allowed_uids', ', '.join(sorted(uids)))
    sssdconfig.save_service(service)


def change_ssh_config(filename, changes, sections):
    if not changes:
        return True

    try:
        f = open(filename, 'r')
    except IOError as e:
        logger.error("Failed to open '%s': %s", filename, str(e))
        return False

    change_keys = tuple(key.lower() for key in changes)
    section_keys = tuple(key.lower() for key in sections)

    lines = []
    in_section = False
    for line in f:
        line = line.rstrip('\n')
        pline = line.strip()
        if not pline or pline.startswith('#'):
            lines.append(line)
            continue
        option = pline.split()[0].lower()
        if option in section_keys:
            in_section = True
            break
        if option in change_keys:
            line = '#' + line
        lines.append(line)
    for option, value in changes.items():
        if value is not None:
            lines.append('%s %s' % (option, value))
    if in_section:
        lines.append('')
        lines.append(line)
    for line in f:
        line = line.rstrip('\n')
        lines.append(line)
    lines.append('')

    f.close()

    try:
        f = open(filename, 'w')
    except IOError as e:
        logger.error("Failed to open '%s': %s", filename, str(e))
        return False

    f.write('\n'.join(lines))

    f.close()

    return True


def configure_ssh_config(fstore, options):
    if not os.path.isfile(paths.SSH_CONFIG):
        logger.info("%s not found, skipping configuration", paths.SSH_CONFIG)
        return

    fstore.backup_file(paths.SSH_CONFIG)

    def ssh_version_supports_include():
        with open(paths.SSH_CONFIG, 'r') as f:
            for line in f:
                if re.match(r"^Include\s", line):
                    return True
        return False

    if ssh_version_supports_include():
        create_ssh_ipa_config(options)
    else:
        modify_ssh_config(options)

    logger.info('Configured %s', paths.SSH_CONFIG)


def modify_ssh_config(options):
    changes = {'PubkeyAuthentication': 'yes'}

    # sss_ssh_knownhostsproxy is deprecated in favor of sss_ssh_knownhosts
    # use sss_ssh_knownhosts when possible
    enableknownhosts = bool(
        options.sssd and os.path.isfile(paths.SSS_SSH_KNOWNHOSTS)
    )

    enableproxy = bool(
        options.sssd and os.path.isfile(paths.SSS_SSH_KNOWNHOSTSPROXY)
        and not enableknownhosts
    )

    if options.sssd and enableknownhosts:
        changes[
            'KnownHostsCommand'] = '%s %%H' % paths.SSS_SSH_KNOWNHOSTS
    if options.sssd and enableproxy:
        changes[
            'ProxyCommand'] = '%s -p %%p %%h' % paths.SSS_SSH_KNOWNHOSTSPROXY
        changes['GlobalKnownHostsFile'] = paths.SSSD_PUBCONF_KNOWN_HOSTS
    if options.trust_sshfp:
        changes['VerifyHostKeyDNS'] = 'yes'

    change_ssh_config(paths.SSH_CONFIG, changes, ['Host', 'Match'])


def create_ssh_ipa_config(options):
    """Add the IPA snippet for ssh"""
    # sss_ssh_knownhostsproxy is deprecated in favor of sss_ssh_knownhosts
    # use sss_ssh_knownhosts when possible
    enableknownhosts = bool(
        options.sssd and os.path.isfile(paths.SSS_SSH_KNOWNHOSTS)
    )

    enableproxy = bool(
        options.sssd and os.path.isfile(paths.SSS_SSH_KNOWNHOSTSPROXY)
        and not enableknownhosts
    )

    ipautil.copy_template_file(
        os.path.join(paths.SSH_IPA_CONFIG_TEMPLATE),
        paths.SSH_IPA_CONFIG,
        dict(
            ENABLEKNOWNHOSTS='' if enableknownhosts else '#',
            KNOWNHOSTSCOMMAND=paths.SSS_SSH_KNOWNHOSTS,
            ENABLEPROXY='' if enableproxy else '#',
            KNOWNHOSTSPROXY=paths.SSS_SSH_KNOWNHOSTSPROXY,
            KNOWNHOSTS=paths.SSSD_PUBCONF_KNOWN_HOSTS,
            VERIFYHOSTKEYDNS='' if options.trust_sshfp else '#'
        )
    )
    os.chmod(paths.SSH_IPA_CONFIG, 0o644)


def configure_sshd_config(fstore, options):
    sshd = services.knownservices.sshd

    if not os.path.isfile(paths.SSHD_CONFIG):
        logger.info("%s not found, skipping configuration", paths.SSHD_CONFIG)
        return

    fstore.backup_file(paths.SSHD_CONFIG)

    # If openssh-server >= 8.2, the config needs to go in a new snippet
    # in /etc/ssh/sshd_config.d/04-ipa.conf
    # instead of /etc/ssh/sshd_config file
    def sshd_version_supports_include():
        with open(paths.SSHD_CONFIG, 'r') as f:
            for line in f:
                if re.match(r"^Include\s", line):
                    return True
        return False

    if sshd_version_supports_include():
        create_sshd_ipa_config(options)
    else:
        modify_sshd_config(options)

    if sshd.is_running():
        try:
            sshd.restart()
        except Exception as e:
            log_service_error(sshd.service_name, 'restart', e)


def modify_sshd_config(options):
    changes = {
        'PubkeyAuthentication': 'yes',
        'KerberosAuthentication': 'no',
        'GSSAPIAuthentication': 'yes',
        'UsePAM': 'yes',
        'ChallengeResponseAuthentication': 'yes',
    }

    if options.sssd and os.path.isfile(paths.SSS_SSH_AUTHORIZEDKEYS):
        authorized_keys_changes = None

        candidates = (
            {
                'AuthorizedKeysCommand': paths.SSS_SSH_AUTHORIZEDKEYS,
                'AuthorizedKeysCommandUser': 'nobody',
            },
            {
                'AuthorizedKeysCommand': paths.SSS_SSH_AUTHORIZEDKEYS,
                'AuthorizedKeysCommandRunAs': 'nobody',
            },
            {
                'PubKeyAgent': '%s %%u' % paths.SSS_SSH_AUTHORIZEDKEYS,
                'PubKeyAgentRunAs': 'nobody',
            },
        )

        for candidate in candidates:
            args = [paths.SSHD, '-t', '-f', os.devnull]
            for item in candidate.items():
                args.append('-o')
                args.append('%s=%s' % item)

            result = ipautil.run(args, raiseonerr=False)
            if result.returncode == 0:
                authorized_keys_changes = candidate
                break

        if authorized_keys_changes is not None:
            changes.update(authorized_keys_changes)
        else:
            logger.warning(
                "Installed OpenSSH server does not support dynamically "
                "loading authorized user keys. Public key authentication of "
                "IPA users will not be available.")

    change_ssh_config(paths.SSHD_CONFIG, changes, ['Match'])
    logger.info('Configured %s', paths.SSHD_CONFIG)


def create_sshd_ipa_config(options):
    """Add the IPA snippet for sshd"""
    sssd_sshd_options = ""
    if options.sssd and os.path.isfile(paths.SSS_SSH_AUTHORIZEDKEYS):
        sssd_sshd_options = textwrap.dedent("""\
            AuthorizedKeysCommand {}
            AuthorizedKeysCommandUser nobody
        """).format(paths.SSS_SSH_AUTHORIZEDKEYS)

    ipautil.copy_template_file(
        os.path.join(paths.SSHD_IPA_CONFIG_TEMPLATE),
        paths.SSHD_IPA_CONFIG,
        dict(
            SSSD_SSHD_OPTIONS=sssd_sshd_options,
        )
    )
    logger.info('Configured %s', paths.SSHD_IPA_CONFIG)


def configure_automount(options, statestore):
    logger.info('\nConfiguring automount:')

    args = [
        paths.IPA_CLIENT_AUTOMOUNT, '--debug', '-U', '--location',
        options.location
    ]

    if options.server:
        args.extend(['--server', options.server[0]])
    if not options.sssd:
        args.append('--no-sssd')

    statestore.backup_state('installation', 'automount', True)
    try:
        result = run(args)
    except Exception as e:
        logger.error('Automount configuration failed: %s', str(e))
    else:
        logger.info('%s', result.output_log)
    finally:
        statestore.delete_state('installation', 'automount')


def configure_nisdomain(options, domain, statestore):
    domain = options.nisdomain or domain
    logger.info('Configuring %s as NIS domain.', domain)

    nis_domain_name = ''

    # First backup the old NIS domain name
    if os.path.exists(paths.BIN_NISDOMAINNAME):
        try:
            result = ipautil.run(
                [paths.BIN_NISDOMAINNAME],
                capture_output=True)
        except CalledProcessError:
            pass
        else:
            nis_domain_name = result.output

    statestore.backup_state('network', 'nisdomain', nis_domain_name)

    # Backup the state of the domainname service
    statestore.backup_state(
        "domainname", "enabled",
        services.knownservices.domainname.is_enabled())

    # Set the new NIS domain name
    tasks.set_nisdomain(domain)

    # Enable and start the domainname service
    services.knownservices.domainname.enable()
    # Restart rather than start so that new NIS domain name is loaded
    # if the service is already running
    services.knownservices.domainname.restart()


def unconfigure_nisdomain(statestore):
    # Set the nisdomain permanent and current nisdomain configuration as it was
    if statestore.has_state('network'):
        old_nisdomain = statestore.restore_state('network', 'nisdomain') or ''

        if old_nisdomain:
            logger.info('Restoring %s as NIS domain.', old_nisdomain)
        else:
            logger.info('Unconfiguring the NIS domain.')

        tasks.set_nisdomain(old_nisdomain)

    # Restore the configuration of the domainname service
    enabled = statestore.restore_state('domainname', 'enabled')
    if not enabled:
        services.knownservices.domainname.disable()


def get_iface_from_ip(ip_addr):
    for adapter in ifaddr.get_adapters():
        for ips in adapter.ips:
            # IPv6 is reported as a tuple, IPv4 is reported as str
            if ip_addr in (ips.ip[0], ips.ip):
                return adapter.name
    raise RuntimeError("IP %s not assigned to any interface." % ip_addr)


def __get_ifaddr_adapters(iface=None):
    if iface:
        interfaces = set(iface if isinstance(iface, (list, tuple)) else [iface])
    else:
        interfaces = set(adapter.name for adapter in ifaddr.get_adapters())
    return [
        adapter
        for adapter in ifaddr.get_adapters()
        if adapter.name in interfaces or adapter.nice_name in interfaces
    ]


def get_local_ipaddresses(iface=None):
    ips = []
    for adapter in __get_ifaddr_adapters(iface):
        for ifip in adapter.ips:
            try:
                ip_addr = ifip.ip[0] if isinstance(ifip.ip, tuple) else ifip.ip
                ips.append(ipautil.CheckedIPAddress(ip_addr))
                logger.debug('IP check successful: %s', ip_addr)
            except ValueError as e:
                logger.debug('IP check failed: %s', e)
    return ips


def do_nsupdate(update_txt):
    logger.debug("Writing nsupdate commands to %s:", UPDATE_FILE)
    logger.debug("%s", update_txt)

    with open(UPDATE_FILE, "w") as f:
        f.write(update_txt)

    result = False
    try:
        ipautil.run([paths.NSUPDATE, '-g', UPDATE_FILE])
        result = True
    except CalledProcessError as e:
        logger.debug('nsupdate (GSS-TSIG) failed: %s', str(e))
        try:
            ipautil.run([paths.NSUPDATE, UPDATE_FILE])
            try:
                sssdconfig = SSSDConfig.SSSDConfig()
                sssdconfig.import_config()
                domains = sssdconfig.list_active_domains()
                for name in domains:
                    domain = sssdconfig.get_domain(name)
                    try:
                        provider = domain.get_option('id_provider')
                    except SSSDConfig.NoOptionError:
                        continue
                    if name == api.env.domain and provider == "ipa":
                        try:
                            if domain.get_option('dyndns_update') is True:
                                domain.set_option('dyndns_auth', 'none')
                                sssdconfig.save_domain(domain)
                                sssdconfig.write(paths.SSSD_CONF)
                                break
                        except SSSDConfig.NoOptionError:
                            break
            except Exception as e:
                logger.debug('Unable to update SSSD configuration: %s', str(e))
                logger.info(
                    'Failed to configure SSSD for unauthenticated DNS '
                    'dynamic updates. SSSD might be unable to update DNS '
                    'entries for this host.'
                )
            result = True
        except CalledProcessError as e:
            logger.debug('Unauthenticated nsupdate failed: %s', str(e))

    try:
        os.remove(UPDATE_FILE)
    except Exception:
        pass

    return result


DELETE_TEMPLATE_A = """
update delete $HOSTNAME. IN A
show
send
"""

DELETE_TEMPLATE_AAAA = """
update delete $HOSTNAME. IN AAAA
show
send
"""

ADD_TEMPLATE_A = """
update add $HOSTNAME. $TTL IN A $IPADDRESS
show
send
"""

ADD_TEMPLATE_AAAA = """
update add $HOSTNAME. $TTL IN AAAA $IPADDRESS
show
send
"""

UPDATE_FILE = paths.IPA_DNS_UPDATE_TXT
CCACHE_FILE = paths.IPA_DNS_CCACHE


def update_dns(server, hostname, options):

    try:
        ips = get_local_ipaddresses()
    except CalledProcessError as e:
        logger.error("Cannot update DNS records. %s", e)
        ips = None

    if options.all_ip_addresses:
        if ips is None:
            raise RuntimeError("Unable to get local IP addresses.")
        update_ips = ips
    elif options.ip_addresses:
        update_ips = []
        for ip in options.ip_addresses:
            update_ips.append(ipautil.CheckedIPAddress(ip))
    else:
        try:
            iface = get_server_connection_interface(server)
        except RuntimeError as e:
            logger.error("Cannot update DNS records. %s", e)
            return
        try:
            update_ips = get_local_ipaddresses(iface)
        except CalledProcessError as e:
            logger.error("Cannot update DNS records. %s", e)
            return

    if not update_ips:
        logger.info("Failed to determine this machine's ip address(es).")
        return

    no_matching_interface_for_ip_address_warning(update_ips)

    update_txt = "debug\n"
    update_txt += ipautil.template_str(DELETE_TEMPLATE_A,
                                       dict(HOSTNAME=hostname))
    update_txt += ipautil.template_str(DELETE_TEMPLATE_AAAA,
                                       dict(HOSTNAME=hostname))

    for ip in update_ips:
        sub_dict = dict(HOSTNAME=hostname, IPADDRESS=ip, TTL=1200)
        if ip.version == 4:
            template = ADD_TEMPLATE_A
        elif ip.version == 6:
            template = ADD_TEMPLATE_AAAA
        update_txt += ipautil.template_str(template, sub_dict)

    if not do_nsupdate(update_txt):
        logger.error("Failed to update DNS records.")
    verify_dns_update(hostname, update_ips)


def verify_dns_update(fqdn, ips):
    """
    Verify that the fqdn resolves to all IP addresses and
    that there's matching PTR record for every IP address.
    """
    # verify A/AAAA records
    missing_ips = [str(ip) for ip in ips]
    extra_ips = []
    for record_type in [dns.rdatatype.A, dns.rdatatype.AAAA]:
        logger.debug('DNS resolver: Query: %s IN %s',
                     fqdn, dns.rdatatype.to_text(record_type))
        try:
            answers = dnsutil.resolve(fqdn, record_type)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.debug('DNS resolver: No record.')
        except dns.resolver.NoNameservers:
            logger.debug('DNS resolver: No nameservers answered the query.')
        except dns.exception.DNSException:
            logger.debug('DNS resolver error.')
        else:
            for rdata in answers:
                try:
                    missing_ips.remove(rdata.address)
                except ValueError:
                    extra_ips.append(rdata.address)

    # verify PTR records
    fqdn_name = dns.name.from_text(fqdn)
    wrong_reverse = {}
    missing_reverse = [str(ip) for ip in ips]
    for ip in ips:
        ip_str = str(ip)
        logger.debug('DNS resolver: Query: %s IN PTR', ip_str)
        try:
            answers = dnsutil.resolve_address(ip_str)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            logger.debug('DNS resolver: No record.')
        except dns.resolver.NoNameservers:
            logger.debug('DNS resolver: No nameservers answered thequery.')
        except dns.exception.DNSException:
            logger.debug('DNS resolver error.')
        else:
            missing_reverse.remove(ip_str)
            for rdata in answers:
                if not rdata.target == fqdn_name:
                    wrong_reverse.setdefault(ip_str, []).append(rdata.target)

    if missing_ips:
        logger.warning('Missing A/AAAA record(s) for host %s: %s.',
                       fqdn, ', '.join(missing_ips))
    if extra_ips:
        logger.warning('Extra A/AAAA record(s) for host %s: %s.',
                       fqdn, ', '.join(extra_ips))
    if missing_reverse:
        logger.warning('Missing reverse record(s) for address(es): %s.',
                       ', '.join(missing_reverse))
    if wrong_reverse:
        logger.warning('Incorrect reverse record(s):')
        for ip, targets in wrong_reverse.items():
            for target in targets:
                logger.warning('%s is pointing to %s instead of %s',
                               ip, target, fqdn_name)


def get_server_connection_interface(server):
    """Connect to IPA server, get all ip addresses of interface used to connect
    """
    last_error = None
    for res in socket.getaddrinfo(
            server, 389, socket.AF_UNSPEC, socket.SOCK_STREAM):
        af, socktype, proto, _canonname, sa = res
        try:
            s = socket.socket(af, socktype, proto)
        except socket.error as e:
            last_error = e
            continue
        try:
            s.connect(sa)
            sockname = s.getsockname()
            ip = sockname[0]
        except socket.error as e:
            last_error = e
            continue
        finally:
            if s:
                s.close()
        try:
            return get_iface_from_ip(ip)
        except (CalledProcessError, RuntimeError) as e:
            last_error = e

    msg = "Cannot get server connection interface"
    if last_error:
        msg += ": %s" % last_error
    raise RuntimeError(msg)


def client_dns(server, hostname, options):

    try:
        verify_host_resolvable(hostname)
        dns_ok = True
    except errors.DNSNotARecordError:
        logger.warning("Hostname (%s) does not have A/AAAA record.",
                       hostname)
        dns_ok = False
    except errors.DNSResolverError as ex:
        logger.warning("DNS resolution for hostname %s failed: %s",
                       hostname, ex)
        dns_ok = False

    if (
        options.dns_updates or options.all_ip_addresses or
        options.ip_addresses or not dns_ok
    ):
        update_dns(server, hostname, options)


def check_ip_addresses(options):
    if options.ip_addresses:
        for ip in options.ip_addresses:
            try:
                ipautil.CheckedIPAddress(ip)
            except ValueError as e:
                logger.error('%s', e)
                return False
    return True


def update_ssh_keys(hostname, ssh_dir, create_sshfp):
    if not os.path.isdir(ssh_dir):
        return

    pubkeys = []
    for basename in os.listdir(ssh_dir):
        if not basename.endswith('.pub'):
            continue
        filename = os.path.join(ssh_dir, basename)

        try:
            f = open(filename, 'r')
        except IOError as e:
            logger.warning("Failed to open '%s': %s", filename, str(e))
            continue

        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                pubkey = SSHPublicKey(line)
            except (ValueError, UnicodeDecodeError) as e:
                logger.debug("Decoding line '%s' failed: %s", line, e)
                continue
            logger.info("Adding SSH public key from %s", filename)
            pubkeys.append(pubkey)

        f.close()

    try:
        # Use the RPC directly so older servers are supported
        api.Backend.rpcclient.forward(
            'host_mod',
            ipautil.fsdecode(hostname),
            ipasshpubkey=[pk.openssh() for pk in pubkeys],
            updatedns=False,
            version=u'2.26',  # this version adds support for SSH public keys
        )
    except errors.EmptyModlist:
        pass
    except Exception as e:
        logger.info("host_mod: %s", str(e))
        logger.warning("Failed to upload host SSH public keys.")
        return

    if create_sshfp:
        ttl = 1200

        update_txt = 'debug\n'
        update_txt += 'update delete %s. IN SSHFP\nshow\nsend\n' % hostname
        for pubkey in pubkeys:
            sshfp = pubkey.fingerprint_dns_sha1()
            if sshfp is not None:
                update_txt += 'update add %s. %s IN SSHFP %s\n' % (
                    hostname, ttl, sshfp)
            sshfp = pubkey.fingerprint_dns_sha256()
            if sshfp is not None:
                update_txt += 'update add %s. %s IN SSHFP %s\n' % (
                    hostname, ttl, sshfp)
        update_txt += 'show\nsend\n'

        if not do_nsupdate(update_txt):
            logger.warning("Could not update DNS SSHFP records.")


def print_port_conf_info():
    logger.info(
        "Please make sure the following ports are opened "
        "in the firewall settings:\n"
        "     TCP: 80, 88, 389\n"
        "     UDP: 88 (at least one of TCP/UDP ports 88 has to be open)\n"
        "Also note that following ports are necessary for ipa-client "
        "working properly after enrollment:\n"
        "     TCP: 464\n"
        "     UDP: 464, 123 (if NTP enabled)")


def cert_summary(msg, certs, indent='    '):
    if msg:
        s = '%s\n' % msg
    else:
        s = ''
    for cert in certs:
        s += '%sSubject:     %s\n' % (indent, DN(cert.subject))
        s += '%sIssuer:      %s\n' % (indent, DN(cert.issuer))
        s += '%sValid From:  %s\n' % (indent, cert.not_valid_before_utc)
        s += '%sValid Until: %s\n' % (indent, cert.not_valid_after_utc)
        s += '\n'
    s = s[:-1]

    return s


def get_certs_from_ldap(server, base_dn, realm, ca_enabled):
    conn = ipaldap.LDAPClient.from_hostname_plain(server)
    try:
        conn.gssapi_bind()
        certs = certstore.get_ca_certs(conn, base_dn, realm, ca_enabled)
    except errors.NotFound:
        raise errors.NoCertificateError(entry=server)
    except errors.NetworkError as e:
        raise errors.NetworkError(uri=conn.ldap_uri, error=str(e))
    except Exception as e:
        raise errors.LDAPError(str(e))
    finally:
        conn.unbind()

    return certs


def get_ca_certs_from_file(url):
    """
    Get the CA cert from a user supplied file and write it into the
    paths.IPA_CA_CRT file.

    Raises errors.NoCertificateError if unable to read cert.
    Raises errors.FileError if unable to write cert.
    """

    try:
        parsed = urlparse(url, 'file')
    except Exception:
        raise errors.FileError(reason="unable to parse file url '%s'" % url)

    if parsed.scheme != 'file':
        raise errors.FileError(reason="url is not a file scheme '%s'" % url)

    filename = parsed.path

    if not os.path.exists(filename):
        raise errors.FileError(reason="file '%s' does not exist" % filename)

    if not os.path.isfile(filename):
        raise errors.FileError(reason="file '%s' is not a file" % filename)

    logger.debug("trying to retrieve CA cert from file %s", filename)
    try:
        certs = x509.load_certificate_list_from_file(filename)
    except Exception:
        raise errors.NoCertificateError(entry=filename)

    return certs


def get_ca_certs_from_http(url, warn=True):
    """
    Use HTTP to retrieve the CA cert and write it into the paths.IPA_CA_CRT
    file. This is insecure and should be avoided.

    Raises errors.NoCertificateError if unable to retrieve and write cert.
    """

    if warn:
        logger.warning("Downloading the CA certificate via HTTP, "
                       "this is INSECURE")

    logger.debug("trying to retrieve CA cert via HTTP from %s", url)
    try:

        result = run([paths.BIN_CURL, "-o", "-", url], capture_output=True)
    except CalledProcessError:
        raise errors.NoCertificateError(entry=url)
    stdout = result.raw_output

    try:
        certs = x509.load_certificate_list(stdout)
    except Exception:
        raise errors.NoCertificateError(entry=url)

    return certs


def get_ca_certs_from_ldap(server, basedn, realm):
    """
    Retrieve th CA cert from the LDAP server by binding to the
    server with GSSAPI using the current Kerberos credentials.
    Write the retrieved cert into the paths.IPA_CA_CRT file.

    Raises errors.NoCertificateError if cert is not found.
    Raises errors.NetworkError if LDAP connection can't be established.
    Raises errors.LDAPError for any other generic LDAP error.
    Raises errors.OnlyOneValueAllowed if more than one cert is found.
    Raises errors.FileError if unable to write cert.
    """

    logger.debug("trying to retrieve CA cert via LDAP from %s", server)

    try:
        certs = get_certs_from_ldap(server, basedn, realm, False)
    except Exception as e:
        logger.debug("get_ca_certs_from_ldap() error: %s", e)
        raise

    certs = [c[0] for c in certs if c[2] is not False]
    return certs


def validate_new_ca_certs(existing_ca_certs, new_ca_certs, ask,
                          override=False):
    if existing_ca_certs is None:
        logger.info(
            "%s",
            cert_summary("Successfully retrieved CA cert", new_ca_certs))
        return

    existing_ca_certs = set(existing_ca_certs)
    new_ca_certs = set(new_ca_certs)
    if existing_ca_certs > new_ca_certs:
        logger.warning(
            "The CA cert available from the IPA server does not match the\n"
            "local certificate available at %s", paths.IPA_CA_CRT)
        logger.warning(
            "%s",
            cert_summary("Existing CA cert:", existing_ca_certs))
        logger.warning(
            "%s",
            cert_summary("Retrieved CA cert:", new_ca_certs))
        if override:
            logger.warning("Overriding existing CA cert\n")
        elif not ask or not user_input(
                "Do you want to replace the local certificate with the CA\n"
                "certificate retrieved from the IPA server?", True):
            raise errors.CertificateInvalidError(name='Retrieved CA')
    else:
        logger.debug(
                "Existing CA cert and Retrieved CA cert are identical")


def get_ca_certs(fstore, options, server, basedn, realm):
    """
    Examine the different options and determine a method for obtaining
    the CA cert.

    If successful the CA cert will have been written into paths.IPA_CA_CRT.

    Raises errors.NoCertificateError if not successful.

    The logic for determining how to load the CA cert is as follow:

    In the OTP case (not -p and -w):

    1. load from user supplied cert file
    2. else load from HTTP

    In the 'user_auth' case ((-p and -w) or interactive):

    1. load from user supplied cert file
    2. load from LDAP using SASL/GSS/Krb5 auth
       (provides mutual authentication, integrity and security)
    3. if LDAP failed and interactive ask for permission to
       use insecure HTTP (default: No)

    In the unattended case:

    1. load from user supplied cert file
    2. load from HTTP if --force specified else fail

    In all cases if HTTP is used emit warning message
    """

    ca_file = paths.IPA_CA_CRT + ".new"

    def ldap_url():
        return urlunparse(('ldap', ipautil.format_netloc(server),
                           '', '', '', ''))

    def file_url():
        return urlunparse(('file', '', options.ca_cert_file,
                           '', '', ''))

    def http_url():
        return urlunparse(('http', ipautil.format_netloc(server),
                           '/ipa/config/ca.crt', '', '', ''))

    interactive = not options.unattended
    otp_auth = options.principal is None and options.password is not None
    existing_ca_certs = None
    ca_certs = None

    if options.ca_cert_file:
        url = file_url()
        try:
            ca_certs = get_ca_certs_from_file(url)
        except errors.FileError as e:
            logger.debug("%s", e)
            raise
        except Exception as e:
            logger.debug("%s", e)
            raise errors.NoCertificateError(entry=url)
        logger.debug("CA cert provided by user, use it!")
    else:
        if os.path.exists(paths.IPA_CA_CRT):
            if os.path.isfile(paths.IPA_CA_CRT):
                try:
                    existing_ca_certs = x509.load_certificate_list_from_file(
                        paths.IPA_CA_CRT)
                except Exception as e:
                    raise errors.FileError(
                        reason=u"Unable to load existing CA cert '%s': %s" %
                               (paths.IPA_CA_CRT, e))
            else:
                raise errors.FileError(
                    reason=(
                        f"Existing ca cert '{paths.IPA_CA_CRT}' is not a plain "
                        "file"
                    ),
                )

        if otp_auth:
            if existing_ca_certs:
                logger.info("OTP case, CA cert preexisted, use it")
            else:
                url = http_url()
                override = not interactive
                if interactive and not user_input(
                    "Do you want to download the CA cert from " + url + " ?\n"
                    "(this is INSECURE)", False
                ):
                    raise errors.NoCertificateError(
                        message=u"HTTP certificate download declined by user")
                try:
                    ca_certs = get_ca_certs_from_http(url, override)
                except Exception as e:
                    logger.debug("%s", e)
                    raise errors.NoCertificateError(entry=url)

                validate_new_ca_certs(existing_ca_certs, ca_certs, False,
                                      override)
        else:
            # Auth with user credentials
            url = ldap_url()
            try:
                ca_certs = get_ca_certs_from_ldap(server, basedn, realm)
                validate_new_ca_certs(existing_ca_certs, ca_certs, interactive)
            except errors.FileError as e:
                logger.debug("%s", e)
                raise
            except (errors.NoCertificateError, errors.LDAPError) as e:
                logger.debug("%s", str(e))
                url = http_url()
                if existing_ca_certs:
                    logger.warning(
                        "Unable to download CA cert from LDAP\n"
                        "but found preexisting cert, using it.\n")
                elif interactive and not user_input(
                    "Unable to download CA cert from LDAP.\n"
                    "Do you want to download the CA cert from " + url + "?\n"
                    "(this is INSECURE)", False
                ):
                    raise errors.NoCertificateError(
                        message=u"HTTP "
                        "certificate download declined by user")
                elif not interactive and not options.force:
                    logger.error(
                        "In unattended mode without a One Time Password "
                        "(OTP) or without --ca-cert-file\nYou must specify"
                        " --force to retrieve the CA cert using HTTP")
                    raise errors.NoCertificateError(
                        message=u"HTTP "
                        "certificate download requires --force")
                else:
                    try:
                        ca_certs = get_ca_certs_from_http(url)
                    except Exception as e:
                        logger.debug("%s", e)
                        raise errors.NoCertificateError(entry=url)
                    validate_new_ca_certs(existing_ca_certs, ca_certs,
                                          interactive)
            except Exception as e:
                logger.debug("%s", str(e))
                raise errors.NoCertificateError(entry=url)

        if ca_certs is None and existing_ca_certs is None:
            raise errors.InternalError(u"expected CA cert file '%s' to "
                                       u"exist, but it's absent" % ca_file)

    if ca_certs is not None:
        try:
            x509.write_certificate_list(ca_certs, ca_file, mode=0o644)
        except Exception as e:
            if os.path.exists(ca_file):
                try:
                    os.unlink(ca_file)
                except OSError as e2:
                    logger.error(
                        "Failed to remove '%s': %s", ca_file, e2)
            raise errors.FileError(
                reason=u"cannot write certificate file '%s': %s" % (
                    ca_file, e)
            )

        os.rename(ca_file, paths.IPA_CA_CRT)

    # Make sure the file permissions are correct
    try:
        os.chmod(paths.IPA_CA_CRT, 0o644)
    except Exception as e:
        raise errors.FileError(reason=u"Unable set permissions on ca "
                               u"cert '%s': %s" % (paths.IPA_CA_CRT, e))

# IMPORTANT: First line of FF config file is ignored
FIREFOX_CONFIG_TEMPLATE = """

/* Kerberos SSO configuration */
pref("network.negotiate-auth.trusted-uris", ".$DOMAIN");

/* These are the defaults */
pref("network.negotiate-auth.gsslib", "");
pref("network.negotiate-auth.using-native-gsslib", true);
pref("network.negotiate-auth.allow-proxies", true);
"""

FIREFOX_PREFERENCES_FILENAME = "all-ipa.js"
FIREFOX_PREFERENCES_REL_PATH = "browser/defaults/preferences"


def configure_firefox(options, statestore, domain):
    try:
        logger.debug("Setting up Firefox configuration.")

        preferences_dir = None

        # Check user specified location of firefox install directory
        if options.firefox_dir is not None:
            pref_path = os.path.join(options.firefox_dir,
                                     FIREFOX_PREFERENCES_REL_PATH)
            if os.path.isdir(pref_path):
                preferences_dir = pref_path
            else:
                logger.error("Directory '%s' does not exists.", pref_path)
        else:
            # test if firefox is installed
            if os.path.isfile(paths.FIREFOX):

                # find valid preferences path
                for path in [paths.LIB_FIREFOX, paths.LIB64_FIREFOX]:
                    pref_path = os.path.join(path,
                                             FIREFOX_PREFERENCES_REL_PATH)
                    if os.path.isdir(pref_path):
                        preferences_dir = pref_path
                        break
            else:
                logger.error(
                    "Firefox configuration skipped (Firefox not found).")
                return

        # setting up firefox
        if preferences_dir is not None:

            # user could specify relative path, we need to store absolute
            preferences_dir = os.path.abspath(preferences_dir)
            logger.debug(
                "Firefox preferences directory found '%s'.", preferences_dir)
            preferences_fname = os.path.join(
                preferences_dir, FIREFOX_PREFERENCES_FILENAME)
            update_txt = ipautil.template_str(
                FIREFOX_CONFIG_TEMPLATE, dict(DOMAIN=domain))
            logger.debug(
                "Firefox trusted uris will be set as '.%s' domain.", domain)
            logger.debug(
                "Firefox configuration will be stored in '%s' file.",
                preferences_fname)

            try:
                with open(preferences_fname, 'w') as f:
                    f.write(update_txt)
                logger.info("Firefox sucessfully configured.")
                statestore.backup_state(
                    'firefox', 'preferences_fname', preferences_fname)
            except Exception as e:
                logger.debug(
                    "An error occured during creating preferences file: %s.",
                    e)
                logger.error("Firefox configuration failed.")
        else:
            logger.debug("Firefox preferences directory not found.")
            logger.error("Firefox configuration failed.")

    except Exception as e:
        logger.debug("%s", str(e))
        logger.error("Firefox configuration failed.")


def purge_host_keytab(realm):
    try:
        ipautil.run([
            paths.IPA_RMKEYTAB,
            '-k', paths.KRB5_KEYTAB, '-r', realm
        ])
    except CalledProcessError as e:
        if e.returncode not in (3, 5, 7):
            # 3 - Unable to open keytab
            # 5 - Principal name or realm not found in keytab
            # 7 - Failed to set cursor, typically when errcode
            #     would be issued in past
            logger.error(
                "Error trying to clean keytab: "
                "/usr/sbin/ipa-rmkeytab returned %s", e.returncode)
    else:
        logger.info(
            "Removed old keys for realm %s from %s",
            realm, paths.KRB5_KEYTAB)


def install_check(options):
    global hostname
    global hostname_source
    global nosssd_files
    global dnsok
    global cli_domain
    global cli_server
    global subject_base
    global cli_realm
    global cli_kdc
    global client_domain
    global cli_basedn
    global selinux_works

    print("This program will set up IPA client.")
    print("Version {}".format(version.VERSION))
    print("")

    cli_domain_source = 'Unknown source'
    cli_server_source = 'Unknown source'

    if not os.getegid() == 0:
        raise ScriptError(
            "You must be root to run ipa-client-install.",
            rval=CLIENT_INSTALL_ERROR)

    selinux_works = tasks.check_selinux_status()

    if is_ipa_client_configured(on_master=options.on_master):
        logger.error("IPA client is already configured on this system.")
        logger.info(
            "If you want to reinstall the IPA client, uninstall it first "
            "using 'ipa-client-install --uninstall'.")
        raise ScriptError(rval=CLIENT_ALREADY_CONFIGURED)

    check_ldap_conf()

    if options.conf_ntp:
        try:
            timeconf.check_timedate_services()
        except timeconf.NTPConflictingService as e:
            print(
                "WARNING: conflicting time&date synchronization service "
                "'{}' will be disabled in favor of chronyd\n".format(
                    e.conflicting_service
                )
            )

        except timeconf.NTPConfigurationError:
            pass

    if options.unattended and (
        options.password is None
        and options.principal is None
        and options.keytab is None
        and options.pkinit_identity is None
        and options.prompt_password is False
        and not options.on_master
    ):
        raise ScriptError(
            "One of password / principal / keytab is required.",
            rval=CLIENT_INSTALL_ERROR)

    if options.pkinit_identity is not None and (
        options.password is not None
        or options.keytab is not None
    ):
        raise ScriptError(
            "pkinit_identity is mutually exclusive with password / keytab.",
            rval=CLIENT_INSTALL_ERROR
        )

    if options.hostname:
        hostname = options.hostname
        hostname_source = 'Provided as option'
    else:
        hostname = FQDN
        hostname_source = "Machine's FQDN"
    if hostname != hostname.lower():
        raise ScriptError(
            "Invalid hostname '{}', must be lower-case.".format(hostname),
            rval=CLIENT_INSTALL_ERROR
        )

    if hostname in ('localhost', 'localhost.localdomain'):
        raise ScriptError(
            "Invalid hostname, '{}' must not be used.".format(hostname),
            rval=CLIENT_INSTALL_ERROR)

    try:
        validate_hostname(hostname, maxlen=MAXHOSTNAMELEN)
    except ValueError as e:
        raise ScriptError(
            'invalid hostname: {}'.format(e),
            rval=CLIENT_INSTALL_ERROR)

    # --no-sssd is not supported any more for rhel-based distros
    if not tasks.is_nosssd_supported() and not options.sssd:
        raise ScriptError(
            "Option '--no-sssd' is incompatible with the 'authselect' tool "
            "provided by this distribution for configuring system "
            "authentication resources",
            rval=CLIENT_INSTALL_ERROR)

    # --noac is not supported any more for rhel-based distros
    if not tasks.is_nosssd_supported() and options.no_ac:
        raise ScriptError(
            "Option '--noac' is incompatible with the 'authselect' tool "
            "provided by this distribution for configuring system "
            "authentication resources",
            rval=CLIENT_INSTALL_ERROR)

    # --mkhomedir is not supported by fedora_container and rhel_container
    if not tasks.is_mkhomedir_supported() and options.mkhomedir:
        raise ScriptError(
            "Option '--mkhomedir' is incompatible with the 'authselect' tool "
            "provided by this distribution for configuring system "
            "authentication resources",
            rval=CLIENT_INSTALL_ERROR)

    # When installing without the "--no-sudo" option, check whether sudo is
    # available.
    if options.conf_sudo:
        try:
            ipautil.run(['sudo', '-V'])
        except FileNotFoundError:
            logger.info(
                "The sudo binary does not seem to be present on this "
                "system. Please consider installing sudo if required."
            )

    # when installing with the '--no-sssd' option, check whether nss-ldap is
    # installed
    if not options.sssd:
        if not os.path.exists(paths.PAM_KRB5_SO):
            raise ScriptError(
                "The pam_krb5 package must be installed",
                rval=CLIENT_INSTALL_ERROR)

        (nssldap_installed, nosssd_files) = nssldap_exists()
        if not nssldap_installed:
            raise ScriptError(
                "One of these packages must be installed: nss_ldap or "
                "nss-pam-ldapd",
                rval=CLIENT_INSTALL_ERROR)

    if options.keytab and options.principal:
        raise ScriptError(
            "Options 'principal' and 'keytab' cannot be used together.",
            rval=CLIENT_INSTALL_ERROR)

    if options.keytab and options.force_join:
        logger.warning("Option 'force-join' has no additional effect "
                       "when used with together with option 'keytab'.")

    # Remove invalid keytab file
    try:
        gssapi.Credentials(
            store={'keytab': paths.KRB5_KEYTAB},
            usage='accept',
        )
    except gssapi.exceptions.GSSError:
        logger.debug("Deleting invalid keytab: '%s'.", paths.KRB5_KEYTAB)
        remove_file(paths.KRB5_KEYTAB)

    # Check if old certificate exist and show warning
    if (
        not options.ca_cert_file and
        get_cert_path(options.ca_cert_file) == paths.IPA_CA_CRT
    ):
        logger.warning("Using existing certificate '%s'.", paths.IPA_CA_CRT)

    if not check_ip_addresses(options):
        raise ScriptError(rval=CLIENT_INSTALL_ERROR)

    # Create the discovery instance
    ds = discovery.IPADiscovery()

    ret = ds.search(
        domain=options.domain,
        servers=options.server,
        realm=options.realm_name,
        hostname=hostname,
        ca_cert_path=get_cert_path(options.ca_cert_file)
    )

    if options.server and ret != 0:
        # There is no point to continue with installation as server list was
        # passed as a fixed list of server and thus we cannot discover any
        # better result
        logger.error(
            "Failed to verify that %s is an IPA Server.",
            ', '.join(options.server))
        logger.error(
            "This may mean that the remote server is not up "
            "or is not reachable due to network or firewall settings.")
        print_port_conf_info()
        raise ScriptError(rval=CLIENT_INSTALL_ERROR)

    if ret == discovery.BAD_HOST_CONFIG:
        logger.error("Can't get the fully qualified name of this host")
        logger.info("Check that the client is properly configured")
        raise ScriptError(rval=CLIENT_INSTALL_ERROR)
    if ret == discovery.NOT_FQDN:
        raise ScriptError(
            "{} is not a fully-qualified hostname".format(hostname),
            rval=CLIENT_INSTALL_ERROR)
    if ret in (discovery.NO_LDAP_SERVER, discovery.NOT_IPA_SERVER) \
            or not ds.domain:
        if ret == discovery.NO_LDAP_SERVER:
            if ds.server:
                logger.debug("%s is not an LDAP server", ds.server)
            else:
                logger.debug("No LDAP server found")
        elif ret == discovery.NOT_IPA_SERVER:
            if ds.server:
                logger.debug("%s is not an IPA server", ds.server)
            else:
                logger.debug("No IPA server found")
        else:
            logger.debug("Domain not found")
        if options.domain:
            cli_domain = options.domain
            cli_domain_source = 'Provided as option'
        elif options.unattended:
            raise ScriptError(
                "Unable to discover domain, not provided on command line",
                rval=CLIENT_INSTALL_ERROR)
        else:
            logger.info(
                "DNS discovery failed to determine your DNS domain")
            cli_domain = user_input(
                "Provide the domain name of your IPA server (ex: example.com)",
                allow_empty=False)
            cli_domain_source = 'Provided interactively'
            logger.debug(
                "will use interactively provided domain: %s", cli_domain)
        ret = ds.search(
            domain=cli_domain,
            servers=options.server,
            hostname=hostname,
            ca_cert_path=get_cert_path(options.ca_cert_file))

    if not cli_domain:
        if ds.domain:
            cli_domain = ds.domain
            cli_domain_source = ds.domain_source
            logger.debug("will use discovered domain: %s", cli_domain)

    client_domain = hostname[hostname.find(".")+1:]

    if ret in (discovery.NO_LDAP_SERVER, discovery.NOT_IPA_SERVER) \
            or not ds.server:
        logger.debug("IPA Server not found")
        if options.server:
            cli_server = options.server
            cli_server_source = 'Provided as option'
        elif options.unattended:
            raise ScriptError(
                "Unable to find IPA Server to join",
                rval=CLIENT_INSTALL_ERROR)
        else:
            logger.debug("DNS discovery failed to find the IPA Server")
            cli_server = [
                user_input(
                    "Provide your IPA server name (ex: ipa.example.com)",
                    allow_empty=False)
            ]
            cli_server_source = 'Provided interactively'
            logger.debug(
                "will use interactively provided server: %s", cli_server[0])
        ret = ds.search(
            domain=cli_domain,
            servers=cli_server,
            hostname=hostname,
            ca_cert_path=get_cert_path(options.ca_cert_file))

    else:
        # Only set dnsok to True if we were not passed in one or more servers
        # and if DNS discovery actually worked.
        if not options.server:
            (server, domain) = ds.check_domain(
                ds.domain, set(), "Validating DNS Discovery")
            if server and domain:
                logger.debug("DNS validated, enabling discovery")
                dnsok = True
            else:
                logger.debug("DNS discovery failed, disabling discovery")
        else:
            logger.debug(
                "Using servers from command line, disabling DNS discovery")

    if not cli_server:
        if options.server:
            cli_server = ds.servers
            cli_server_source = 'Provided as option'
            logger.debug(
                "will use provided server: %s", ', '.join(options.server))
        elif ds.server:
            cli_server = ds.servers
            cli_server_source = ds.server_source
            logger.debug("will use discovered server: %s", cli_server[0])

    if ret == discovery.NOT_IPA_SERVER:
        logger.error("%s is not an IPA v2 Server.", cli_server[0])
        print_port_conf_info()
        logger.debug("(%s: %s)", cli_server[0], cli_server_source)
        raise ScriptError(rval=CLIENT_INSTALL_ERROR)

    if ret == discovery.NO_ACCESS_TO_LDAP:
        logger.warning("Anonymous access to the LDAP server is disabled.")
        logger.info("Proceeding without strict verification.")
        logger.info(
            "Note: This is not an error if anonymous access "
            "has been explicitly restricted.")
        ret = 0

    if ret == discovery.NO_TLS_LDAP:
        logger.warning(
            "The LDAP server requires TLS is but we do not have the CA.")
        logger.info("Proceeding without strict verification.")
        ret = 0

    if ret != 0:
        logger.error(
            "Failed to verify that %s is an IPA Server.",
            cli_server[0])
        logger.error(
            "This may mean that the remote server is not up "
            "or is not reachable due to network or firewall settings.")
        print_port_conf_info()
        logger.debug("(%s: %s)", cli_server[0], cli_server_source)
        raise ScriptError(rval=CLIENT_INSTALL_ERROR)

    cli_kdc = ds.kdc
    if dnsok and not cli_kdc:
        logger.error(
            "DNS domain '%s' is not configured for automatic "
            "KDC address lookup.", ds.realm.lower())
        logger.debug("(%s: %s)", ds.realm, ds.realm_source)
        logger.error("KDC address will be set to fixed value.")

    if dnsok:
        logger.info("Discovery was successful!")
    elif not options.unattended:
        if not options.server:
            logger.warning(
                "The failure to use DNS to find your IPA "
                "server indicates that your resolv.conf file is not properly "
                "configured.")
        logger.info(
            "Autodiscovery of servers for failover cannot work "
            "with this configuration.")
        logger.info(
            "If you proceed with the installation, services "
            "will be configured to always access the discovered server for "
            "all operations and will not fail over to other servers in case "
            "of failure.")
        if not user_input(
                "Proceed with fixed values and no DNS discovery?", False):
            raise ScriptError(rval=CLIENT_INSTALL_ERROR)

    if options.conf_ntp:
        if not options.on_master and not options.unattended and not (
                options.ntp_servers or options.ntp_pool):
            options.ntp_servers, options.ntp_pool = timeconf.get_time_source()

    cli_realm = ds.realm
    cli_realm_source = ds.realm_source
    logger.debug("will use discovered realm: %s", cli_realm)

    if options.realm_name and options.realm_name != cli_realm:
        logger.error(
            "The provided realm name [%s] does not match discovered one [%s]",
            options.realm_name, cli_realm)
        logger.debug("(%s: %s)", cli_realm, cli_realm_source)
        raise ScriptError(rval=CLIENT_INSTALL_ERROR)

    cli_basedn = ds.basedn
    cli_basedn_source = ds.basedn_source
    logger.debug("will use discovered basedn: %s", cli_basedn)
    subject_base = DN(('O', cli_realm))

    logger.info("Client hostname: %s", hostname)
    logger.debug("Hostname source: %s", hostname_source)
    logger.info("Realm: %s", cli_realm)
    logger.debug("Realm source: %s", cli_realm_source)
    logger.info("DNS Domain: %s", cli_domain)
    logger.debug("DNS Domain source: %s", cli_domain_source)
    logger.info("IPA Server: %s", ', '.join(cli_server))
    logger.debug("IPA Server source: %s", cli_server_source)
    logger.info("BaseDN: %s", cli_basedn)
    logger.debug("BaseDN source: %s", cli_basedn_source)

    if not options.on_master:
        if options.ntp_servers:
            for server in options.ntp_servers:
                logger.info("NTP server: %s", server)

        if options.ntp_pool:
            logger.info("NTP pool: %s", options.ntp_pool)

    # ipa-join would fail with IP address instead of a FQDN
    for srv in cli_server:
        try:
            socket.inet_pton(socket.AF_INET, srv)
            is_ipaddr = True
        except socket.error:
            try:
                socket.inet_pton(socket.AF_INET6, srv)
                is_ipaddr = True
            except socket.error:
                is_ipaddr = False

        if is_ipaddr:
            print()
            logger.warning(
                "It seems that you are using an IP address "
                "instead of FQDN as an argument to --server. The "
                "installation may fail.")
            break

    print()
    if not options.unattended and not user_input(
            "Continue to configure the system with these values?", False):
        raise ScriptError(rval=CLIENT_INSTALL_ERROR)


def create_ipa_nssdb(db=None):
    if db is None:
        db = certdb.NSSDatabase(paths.IPA_NSSDB_DIR)
    db.create_db(mode=0o755, backup=True)
    os.chmod(db.pwd_file, 0o600)


def update_ipa_nssdb():
    ipa_db = certdb.NSSDatabase(paths.IPA_NSSDB_DIR)
    sys_db = certdb.NSSDatabase(paths.NSS_DB_DIR)

    if not ipa_db.exists():
        create_ipa_nssdb(ipa_db)
    if ipa_db.dbtype == 'dbm':
        ipa_db.convert_db(rename_old=False)

    for nickname, trust_flags in (
            ('IPA CA', certdb.IPA_CA_TRUST_FLAGS),
            ('External CA cert', certdb.EXTERNAL_CA_TRUST_FLAGS)):
        try:
            cert = sys_db.get_cert(nickname)
        except RuntimeError:
            continue
        try:
            ipa_db.add_cert(cert, nickname, trust_flags)
        except ipautil.CalledProcessError as e:
            raise RuntimeError("Failed to add %s to %s: %s" %
                               (nickname, ipa_db.secdir, e))

    # Remove IPA certs from /etc/pki/nssdb
    for nickname, trust_flags in ipa_db.list_certs():
        while sys_db.has_nickname(nickname):
            try:
                sys_db.delete_cert(nickname)
            except ipautil.CalledProcessError as e:
                raise RuntimeError("Failed to remove %s from %s: %s" %
                                   (nickname, sys_db.secdir, e))


def sync_time(ntp_servers, ntp_pool, fstore, statestore):
    """
    Will disable any other time synchronization service and configure chrony
    with given ntp(chrony) server and/or pool using Augeas.
    If there is no option --ntp-server set IPADiscovery will try to find ntp
    server in DNS records.
    """
    # We assume that NTP servers are discoverable through SRV records in DNS.

    # disable other time&date services first
    timeconf.force_chrony(statestore)

    if not ntp_servers and not ntp_pool:
        # autodiscovery happens in case that NTP configuration isn't explicitly
        # disabled and user did not provide any NTP server addresses or
        # NTP pool address to the installer interactively or as an cli argument
        ds = discovery.IPADiscovery()
        ntp_servers = ds.ipadns_search_srv(
            cli_domain, '_ntp._udp', None, break_on_first=False
        )
        if ntp_servers:
            for server in ntp_servers:
                # when autodiscovery found server records
                logger.debug("Found DNS record for NTP server: \t%s", server)

    logger.info('Synchronizing time')

    configured = False
    if ntp_servers or ntp_pool:
        configured = timeconf.configure_chrony(ntp_servers, ntp_pool,
                                               fstore, statestore)
    else:
        logger.warning("No SRV records of NTP servers found and no NTP server "
                       "or pool address was provided.")

    if not configured:
        print("Using default chrony configuration.")

    return timeconf.sync_chrony()


def restore_time_sync(statestore, fstore):
    if statestore.has_state('chrony'):
        chrony_enabled = statestore.restore_state('chrony', 'enabled')
        restored = False

        try:
            # Restore might fail due to missing file(s) in backup.
            # One example is if the client was updated from a previous version
            # not configured with chrony. In such a cast it is OK to fail.
            restored = fstore.restore_file(paths.CHRONY_CONF)
        except ValueError:  # this will not handle possivble IOError
            logger.debug("Configuration file %s was not restored.",
                         paths.CHRONY_CONF)

        if not chrony_enabled:
            services.knownservices.chronyd.stop()
            services.knownservices.chronyd.disable()
        elif restored:
            services.knownservices.chronyd.restart()

    try:
        timeconf.restore_forced_timeservices(statestore)
    except CalledProcessError as e:
        logger.error('Failed to restore time synchronization service: %s', e)


def configure_selinux_for_client(statestore):
    def backup_state(key, value):
        statestore.backup_state('selinux', key, value)

    try:
        tasks.set_selinux_booleans(constants.SELINUX_BOOLEAN_SSSD,
                                   backup_state)
    except SetseboolError as e:
        for c in constants.SELINUX_BOOLEAN_SSSD:
            if c in e.failed:
                logger.warning(
                    "SELinux does not support SSSD boolean %s, ignoring", c)


def install(options):
    try:
        _install(options, dict())
    except ScriptError as e:
        if e.rval == CLIENT_INSTALL_ERROR:
            if options.force:
                logger.warning(
                    "Installation failed. Force set so not rolling back "
                    "changes.")
            elif options.on_master:
                logger.warning(
                    "Installation failed. As this is IPA server, changes will "
                    "not be rolled back.")
            else:
                logger.error("Installation failed. Rolling back changes.")
                options.unattended = True
                try:
                    uninstall(options)
                except Exception as ex:
                    logger.debug("%s", traceback.format_exc())
                    logger.error("%s", ex)
        raise
    finally:
        try:
            os.remove(CCACHE_FILE)
        except Exception:
            pass


@cleanup
def _install(options, tdict):
    env = {'PATH': SECURE_PATH}

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    statestore.backup_state('installation', 'complete', False)

    krb_name = tdict['krb_name']
    ccache_dir = tdict['ccache_dir']

    if not options.on_master:
        # Try removing old principals from the keytab
        purge_host_keytab(cli_realm)

    if options.hostname and not options.on_master:
        # skip this step when run by ipa-server-install as it always configures
        # hostname
        tasks.backup_hostname(fstore, statestore)
        tasks.set_hostname(options.hostname)

    if options.conf_ntp:
        # Attempt to configure and sync time with NTP server (chrony).
        sync_time(options.ntp_servers, options.ntp_pool, fstore, statestore)
    elif options.on_master:
        # If we're on master skipping the time sync here because it was done
        # in ipa-server-install
        logger.debug("Skipping attempt to configure and synchronize time with"
                     " chrony server as it has been already done on master.")
    else:
        logger.info("Skipping chrony configuration")

    if not options.unattended:
        if (options.principal is None and options.password is None and
                options.prompt_password is False and options.keytab is None
                and options.pkinit_identity is None):
            options.principal = user_input("User authorized to enroll "
                                           "computers", allow_empty=False)
            logger.debug(
                "will use principal provided as option: %s", options.principal)

    host_principal = 'host/%s@%s' % (hostname, cli_realm)
    if not options.on_master:
        nolog = tuple()
        configure_krb5_conf(
            cli_realm=cli_realm,
            cli_domain=cli_domain,
            cli_server=cli_server,
            cli_kdc=cli_kdc,
            dnsok=False,
            filename=krb_name,
            client_domain=client_domain,
            client_hostname=hostname,
            configure_sssd=options.sssd,
            force=options.force)
        env['KRB5_CONFIG'] = krb_name
        ccache_name = os.path.join(ccache_dir, 'ccache')
        join_args = [
            paths.SBIN_IPA_JOIN,
            "-s", cli_server[0],
            "-b", str(realm_to_suffix(cli_realm)),
            "-h", hostname,
            "-k", paths.KRB5_KEYTAB
        ]
        if options.debug:
            join_args.append("-d")
            env['XMLRPC_TRACE_CURL'] = 'yes'
        if options.force_join:
            join_args.append("-f")

        if options.principal is not None:
            stdin = None
            principal = options.principal
            if principal.find('@') == -1:
                principal = '%s@%s' % (principal, cli_realm)
            if options.password is not None:
                stdin = options.password
            else:
                if not options.unattended:
                    try:
                        stdin = getpass.getpass(
                            "Password for %s: " % principal)
                    except EOFError:
                        stdin = None
                    if not stdin:
                        raise ScriptError(
                            "Password must be provided for {}.".format(
                                principal),
                            rval=CLIENT_INSTALL_ERROR)
                else:
                    if sys.stdin.isatty():
                        logger.error(
                            "Password must be provided in "
                            "non-interactive mode.")
                        logger.info(
                            "This can be done via "
                            "echo password | ipa-client-install ... "
                            "or with the -w option.")
                        raise ScriptError(rval=CLIENT_INSTALL_ERROR)
                    else:
                        stdin = sys.stdin.readline()

            try:
                kinit_password(principal, stdin, ccache_name,
                               config=krb_name)
            except RuntimeError as e:
                print_port_conf_info()
                raise ScriptError(
                    "Kerberos authentication failed: {}".format(e),
                    rval=CLIENT_INSTALL_ERROR)
        elif options.keytab:
            join_args.append("-f")
            if os.path.exists(options.keytab):
                try:
                    kinit_keytab(host_principal,
                                 options.keytab,
                                 ccache_name,
                                 config=krb_name,
                                 attempts=options.kinit_attempts)
                except gssapi.exceptions.GSSError as e:
                    print_port_conf_info()
                    raise ScriptError(
                        "Kerberos authentication failed: {}".format(e),
                        rval=CLIENT_INSTALL_ERROR)
            else:
                raise ScriptError(
                    "Keytab file could not be found: {}".format(
                        options.keytab),
                    rval=CLIENT_INSTALL_ERROR)
        elif options.pkinit_identity:
            join_args.append("-f")
            with open(paths.CA_BUNDLE_PEM, "w"):
                # HACK: kinit fails when "pkinit_pool" file is missing.
                # Create an empty file and remove it after PKINIT.
                pass
            # if no principal is set, use host principal
            if options.principal is None:
                pkinit_principal = host_principal
            else:
                pkinit_principal = options.principal
            try:
                kinit_pkinit(
                    pkinit_principal,
                    options.pkinit_identity,
                    ccache_name=ccache_name,
                    config=krb_name,
                    pkinit_anchors=options.pkinit_anchors
                )
            except CalledProcessError as e:
                print_port_conf_info()
                raise ScriptError(
                    f"Kerberos PKINIT authentication failed: {e}",
                    rval=CLIENT_INSTALL_ERROR
                )
            finally:
                remove_file(paths.CA_BUNDLE_PEM)
        elif options.password:
            nolog = (options.password,)
            join_args.append("-w")
            join_args.append(options.password)
        elif options.prompt_password:
            if options.unattended:
                raise ScriptError(
                    "Password must be provided in non-interactive mode",
                    rval=CLIENT_INSTALL_ERROR)
            try:
                password = getpass.getpass("Password: ")
            except EOFError:
                password = None
            if not password:
                raise ScriptError(
                    "Password must be provided.",
                    rval=CLIENT_INSTALL_ERROR)
            join_args.append("-w")
            join_args.append(password)
            nolog = (password,)

        env['KRB5CCNAME'] = os.environ['KRB5CCNAME'] = ccache_name
        # Get the CA certificate
        try:
            os.environ['KRB5_CONFIG'] = env['KRB5_CONFIG']
            get_ca_certs(fstore, options, cli_server[0], cli_basedn,
                         cli_realm)
        except errors.FileError as e:
            logger.error('%s', e)
            raise ScriptError(rval=CLIENT_INSTALL_ERROR)
        except Exception as e:
            logger.error("Cannot obtain CA certificate\n%s", e)
            raise ScriptError(rval=CLIENT_INSTALL_ERROR)

        # Now join the domain
        result = run(
            join_args, raiseonerr=False, env=env, nolog=nolog,
            capture_error=True)
        stderr = result.error_output

        if result.returncode != 0:
            logger.error("Joining realm failed: %s", stderr)
            if not options.force:
                if result.returncode == 13:
                    logger.info(
                        "Use --force-join option to override the host "
                        "entry on the server and force client enrollment.")
                raise ScriptError(rval=CLIENT_INSTALL_ERROR)
            logger.info(
                "Use ipa-getkeytab to obtain a host "
                "principal for this server.")
        else:
            logger.info("Enrolled in IPA realm %s", cli_realm)

        if options.principal is not None:
            run([paths.KDESTROY], raiseonerr=False, env=env)

        # Obtain the TGT. We do it with the temporary krb5.conf, so that
        # only the KDC we're installing under is contacted.
        # Other KDCs might not have replicated the principal yet.
        # Once we have the TGT, it's usable on any server.
        try:
            kinit_keytab(host_principal, paths.KRB5_KEYTAB, CCACHE_FILE,
                         config=krb_name,
                         attempts=options.kinit_attempts)
            env['KRB5CCNAME'] = os.environ['KRB5CCNAME'] = CCACHE_FILE
        except gssapi.exceptions.GSSError as e:
            print_port_conf_info()
            logger.error("Failed to obtain host TGT: %s", e)
            # failure to get ticket makes it impossible to login and bind
            # from sssd to LDAP, abort installation and rollback changes
            raise ScriptError(rval=CLIENT_INSTALL_ERROR)

    # Configure ipa.conf
    if not options.on_master:
        configure_ipa_conf(fstore, cli_basedn, cli_realm, cli_domain,
                           cli_server, hostname)
        logger.info("Created /etc/ipa/default.conf")

    with certdb.NSSDatabase() as tmp_db:
        api.bootstrap(context='cli_installer',
                      confdir=paths.ETC_IPA,
                      debug=options.debug,
                      delegate=False,
                      nss_dir=tmp_db.secdir)
        if 'config_loaded' not in api.env:
            raise ScriptError(
                "Failed to initialize IPA API.",
                rval=CLIENT_INSTALL_ERROR)

        # Always back up sssd.conf. It gets updated by authconfig --enablekrb5.
        fstore.backup_file(paths.SSSD_CONF)
        if options.sssd:
            if configure_sssd_conf(fstore, cli_realm, cli_domain, cli_server,
                                   options, client_domain, hostname):
                raise ScriptError(rval=CLIENT_INSTALL_ERROR)
            logger.info("Configured /etc/sssd/sssd.conf")

        if options.on_master:
            # If on master assume kerberos is already configured properly.
            # Get the host TGT.
            try:
                kinit_keytab(host_principal, paths.KRB5_KEYTAB, CCACHE_FILE,
                             attempts=options.kinit_attempts)
                os.environ['KRB5CCNAME'] = CCACHE_FILE
            except gssapi.exceptions.GSSError as e:
                logger.error("Failed to obtain host TGT: %s", e)
                raise ScriptError(rval=CLIENT_INSTALL_ERROR)

        # Clear out any current session keyring information
        try:
            delete_persistent_client_session_data(host_principal)
        except ValueError:
            pass

        # Add CA certs to a temporary NSS database
        ca_certs = x509.load_certificate_list_from_file(paths.IPA_CA_CRT)
        try:
            tmp_db.create_db()

            for i, cert in enumerate(ca_certs):
                tmp_db.add_cert(cert,
                                'CA certificate %d' % (i + 1),
                                certdb.EXTERNAL_CA_TRUST_FLAGS)
        except CalledProcessError:
            raise ScriptError(
                "Failed to add CA to temporary NSS database.",
                rval=CLIENT_INSTALL_ERROR)

        api.finalize()

        # Now, let's try to connect to the server's RPC interface
        connected = False
        try:
            api.Backend.rpcclient.connect()
            connected = True
            logger.debug("Try RPC connection")
            api.Backend.rpcclient.forward('ping')
        except errors.KerberosError as e:
            if connected:
                api.Backend.rpcclient.disconnect()
            logger.info(
                "Cannot connect to the server due to Kerberos error: %s. "
                "Trying with delegate=True", e)
            try:
                api.Backend.rpcclient.connect(delegate=True)
                logger.debug("Try RPC connection")
                api.Backend.rpcclient.forward('ping')

                logger.info("Connection with delegate=True successful")

                # The remote server is not capable of Kerberos S4U2Proxy
                # delegation. This features is implemented in IPA server
                # version 2.2 and higher
                logger.warning(
                    "Target IPA server has a lower version than the enrolled "
                    "client")
                logger.warning(
                    "Some capabilities including the ipa command capability "
                    "may not be available")
            except errors.PublicError as e2:
                logger.warning(
                    "Second connect with delegate=True also failed: %s", e2)
                raise ScriptError(
                    "Cannot connect to the IPA server RPC interface: %s" % e2,
                    rval=CLIENT_INSTALL_ERROR)
        except errors.PublicError as e:
            raise ScriptError(
                "Cannot connect to the server due to generic error: %s" % e,
                rval=CLIENT_INSTALL_ERROR)

    # Use the RPC directly so older servers are supported
    try:
        result = api.Backend.rpcclient.forward(
            'ca_is_enabled',
            version=u'2.107',
        )
        ca_enabled = result['result']
    except (errors.CommandError, errors.NetworkError):
        result = api.Backend.rpcclient.forward(
            'env',
            server=True,
            version=u'2.0',
        )
        ca_enabled = result['result']['enable_ra']
    if not ca_enabled:
        disable_ra()

    try:
        result = api.Backend.rpcclient.forward(
            'config_show',
            raw=True,  # so that servroles are not queried
            version=u'2.0'
        )
    except Exception as e:
        logger.debug("config_show failed %s", e, exc_info=True)
        raise ScriptError(
            "Failed to retrieve CA certificate subject base: {}".format(e),
            rval=CLIENT_INSTALL_ERROR)
    else:
        subject_base = DN(result['result']['ipacertificatesubjectbase'][0])

    # Create IPA NSS database
    try:
        create_ipa_nssdb()
    except ipautil.CalledProcessError as e:
        raise ScriptError(
            "Failed to create IPA NSS database: %s" % e,
            rval=CLIENT_INSTALL_ERROR)

    # Get CA certificates from the certificate store
    try:
        ca_certs = get_certs_from_ldap(cli_server[0], cli_basedn, cli_realm,
                                       ca_enabled)
    except errors.NoCertificateError:
        if ca_enabled:
            ca_subject = DN(('CN', 'Certificate Authority'), subject_base)
        else:
            ca_subject = None
        ca_certs = certstore.make_compat_ca_certs(ca_certs, cli_realm,
                                                  ca_subject)
    ca_certs_trust = [(c, n, certstore.key_policy_to_trust_flags(t, True, u))
                      for (c, n, t, u, s) in ca_certs]

    x509.write_certificate_list(
        [c for c, n, t, u, s in ca_certs if t is not False],
        paths.KDC_CA_BUNDLE_PEM,
        mode=0o644
    )
    x509.write_certificate_list(
        [c for c, n, t, u, s in ca_certs if t is not False],
        paths.CA_BUNDLE_PEM,
        mode=0o644
    )

    # Add the CA certificates to the IPA NSS database
    logger.debug("Adding CA certificates to the IPA NSS database.")
    ipa_db = certdb.NSSDatabase(paths.IPA_NSSDB_DIR)
    for cert, nickname, trust_flags in ca_certs_trust:
        try:
            ipa_db.add_cert(cert, nickname, trust_flags)
        except CalledProcessError as e:
            raise ScriptError(
                "Failed to add %s to the IPA NSS database." % nickname,
                rval=CLIENT_INSTALL_ERROR)

    # Add the CA certificates to the platform-dependant systemwide CA store
    tasks.insert_ca_certs_into_systemwide_ca_store(ca_certs)

    if not options.on_master:
        client_dns(cli_server[0], hostname, options)

    update_ssh_keys(hostname, paths.SSH_CONFIG_DIR, options.create_sshfp)

    try:
        os.remove(CCACHE_FILE)
    except Exception:
        pass

    # Name Server Caching Daemon. Disable for SSSD, use otherwise
    # (if installed)
    nscd = services.knownservices.nscd
    if nscd.is_installed():
        save_state(nscd, statestore)
        nscd_service_action = None
        try:
            if options.sssd:
                nscd_service_action = 'stop'
                nscd.stop()
            else:
                nscd_service_action = 'restart'
                nscd.restart()
        except Exception:
            logger.warning(
                "Failed to %s the %s daemon",
                nscd_service_action, nscd.service_name)
            if not options.sssd:
                logger.warning(
                    "Caching of users/groups will not be available")

        try:
            if options.sssd:
                nscd.disable()
            else:
                nscd.enable()
        except Exception:
            if not options.sssd:
                logger.warning(
                    "Failed to configure automatic startup of the %s daemon",
                    nscd.service_name)
                logger.info(
                    "Caching of users/groups will not be "
                    "available after reboot")
            else:
                logger.warning(
                    "Failed to disable %s daemon. Disable it manually.",
                    nscd.service_name)

    else:
        # this is optional service, just log
        if not options.sssd:
            logger.info(
                "%s daemon is not installed, skip configuration",
                nscd.service_name)

    nslcd = services.knownservices.nslcd
    if nslcd.is_installed():
        save_state(nslcd, statestore)

    retcode, conf = (0, None)

    if not options.no_ac:
        # Modify nsswitch/pam stack
        tasks.modify_nsswitch_pam_stack(
            sssd=options.sssd,
            mkhomedir=options.mkhomedir,
            statestore=statestore,
            sudo=options.conf_sudo,
            subid=options.subid
        )
        # if mkhomedir, make sure oddjobd is enabled and started
        if options.mkhomedir:
            oddjobd = services.service('oddjobd', api)
            running = oddjobd.is_running()
            enabled = oddjobd.is_enabled()
            statestore.backup_state('oddjobd', 'running', running)
            statestore.backup_state('oddjobd', 'enabled', enabled)
            try:
                if not enabled:
                    oddjobd.enable()
                if not running:
                    oddjobd.start()
            except Exception as e:
                logger.critical("Unable to start oddjobd: %s", str(e))

        logger.info("%s enabled", "SSSD" if options.sssd else "LDAP")

        if options.sssd:
            if selinux_works:
                configure_selinux_for_client(statestore)

            sssd = services.service('sssd', api)
            try:
                sssd.restart()
            except CalledProcessError:
                logger.warning("SSSD service restart was unsuccessful.")

            try:
                sssd.enable()
            except CalledProcessError as e:
                logger.warning(
                    "Failed to enable automatic startup of the SSSD daemon: "
                    "%s", e)

        if not options.sssd:
            tasks.modify_pam_to_use_krb5(statestore)
            logger.info("Kerberos 5 enabled")

        # Update non-SSSD LDAP configuration after authconfig calls as it would
        # change its configuration otherways
        if not options.sssd:
            for configurer in [configure_ldap_conf, configure_nslcd_conf]:
                (retcode, conf, filenames) = configurer(
                    fstore, cli_basedn, cli_realm,
                    cli_domain, cli_server, dnsok,
                    options, nosssd_files[configurer.__name__])
                if retcode:
                    raise ScriptError(rval=CLIENT_INSTALL_ERROR)
                if conf:
                    logger.info(
                        "%s configured using configuration file(s) %s",
                        conf, filenames)

        if configure_openldap_conf(fstore, cli_basedn, cli_server):
            logger.info("Configured /etc/openldap/ldap.conf")
        else:
            logger.info("Failed to configure /etc/openldap/ldap.conf")

        # Check that nss is working properly
        if not options.on_master:
            user = options.principal
            if user is None:
                user = "admin@%s" % cli_domain
                logger.info(
                    "Principal is not set when enrolling with OTP "
                    "or PKINIT; using principal '%s' for 'getent passwd'.",
                    user
                )
            elif '@' not in user:
                user = "%s@%s" % (user, cli_domain)
            n = 0
            found = False
            # Loop for up to 10 seconds to see if nss is working properly.
            # It can sometimes take a few seconds to connect to the remote
            # provider.
            # Particulary, SSSD might take longer than 6-8 seconds.
            while n < 10 and not found:
                try:
                    ipautil.run([paths.GETENT, "passwd", user])
                    found = True
                except Exception as e:
                    time.sleep(1)
                    n = n + 1

            if not found:
                logger.error("Unable to find '%s' user with 'getent "
                             "passwd %s'!", user.split("@")[0], user)
                if conf:
                    logger.info("Recognized configuration: %s", conf)
                else:
                    logger.error(
                        "Unable to reliably detect "
                        "configuration. Check NSS setup manually.")

                try:
                    hardcode_ldap_server(cli_server)
                except Exception as e:
                    logger.error(
                        "Adding hardcoded server name to "
                        "/etc/ldap.conf failed: %s", str(e))

    if options.conf_ssh:
        configure_ssh_config(fstore, options)

    if options.conf_sshd:
        configure_sshd_config(fstore, options)

    if options.location:
        configure_automount(options, statestore)

        # Reload the state as automount install may have modified it
        fstore._load()
        statestore._load()

    if options.configure_firefox:
        configure_firefox(options, statestore, cli_domain)

    if not options.no_nisdomain:
        configure_nisdomain(
            options=options, domain=cli_domain, statestore=statestore)

    # Configure the final krb5.conf
    if not options.on_master:
        fstore.backup_file(paths.KRB5_CONF)
        configure_krb5_conf(
            cli_realm=cli_realm,
            cli_domain=cli_domain,
            cli_server=cli_server,
            cli_kdc=cli_kdc,
            dnsok=dnsok,
            filename=paths.KRB5_CONF,
            client_domain=client_domain,
            client_hostname=hostname,
            configure_sssd=options.sssd,
            force=options.force)

        logger.info("Configured /etc/krb5.conf for IPA realm %s", cli_realm)

        # Configure certmonger after krb5.conf is created and last
        # to give higher chance that the new client is replicated.
        configure_certmonger(fstore, subject_base, cli_realm, hostname,
                             options, ca_enabled)

    statestore.delete_state('installation', 'complete')
    statestore.backup_state('installation', 'complete', True)
    logger.info('Client configuration complete.')


def uninstall_check(options):
    global selinux_works

    if not is_ipa_client_configured():
        if options.on_master:
            rval = SUCCESS
        else:
            rval = CLIENT_NOT_CONFIGURED
        raise ScriptError(
            "IPA client is not configured on this system.",
            rval=rval)

    if is_ipa_configured() and not options.on_master:
        logger.error(
            "IPA client is configured as a part of IPA server on this system.")
        logger.info("Refer to ipa-server-install for uninstallation.")
        raise ScriptError(rval=CLIENT_NOT_CONFIGURED)

    selinux_works = tasks.check_selinux_status()


def uninstall(options):
    env = {'PATH': SECURE_PATH}

    fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)

    statestore.backup_state('installation', 'automount', True)
    try:
        run([paths.IPA_CLIENT_AUTOMOUNT, "--uninstall", "--debug"])
    except CalledProcessError as e:
        if e.returncode != CLIENT_NOT_CONFIGURED:
            logger.error(
                "Unconfigured automount client failed: %s", str(e))
    finally:
        statestore.delete_state('installation', 'automount')

    # Reload the state as automount unconfigure may have modified it
    fstore._load()
    statestore._load()

    hostname = None
    ipa_domain = None
    was_sssd_configured = False
    try:
        sssdconfig = SSSDConfig.SSSDConfig()
        sssdconfig.import_config()
        domains = sssdconfig.list_active_domains()
        all_domains = sssdconfig.list_domains()

        # we consider all the domains, because handling sssd.conf
        # during uninstall is dependant on was_sssd_configured flag
        # so the user does not lose info about inactive domains
        if len(all_domains) > 1:
            # There was more than IPA domain configured
            was_sssd_configured = True
        for name in domains:
            domain = sssdconfig.get_domain(name)
            try:
                provider = domain.get_option('id_provider')
            except SSSDConfig.NoOptionError:
                continue
            if provider == "ipa":
                try:
                    hostname = domain.get_option('ipa_hostname')
                except SSSDConfig.NoOptionError:
                    continue
                try:
                    ipa_domain = domain.get_option('ipa_domain')
                except SSSDConfig.NoOptionError:
                    pass
    except Exception:
        # We were unable to read existing SSSD config. This might mean few
        # things:
        # - sssd wasn't installed
        # - sssd was removed after install and before uninstall
        # - there are no active domains
        # in both cases we cannot continue with SSSD
        all_domains = []

    if hostname is None:
        hostname = FQDN

    ipa_db = certdb.NSSDatabase(paths.IPA_NSSDB_DIR)
    sys_db = certdb.NSSDatabase(paths.NSS_DB_DIR)

    cmonger = services.knownservices.certmonger
    if ipa_db.has_nickname('Local IPA host'):
        try:
            certmonger.stop_tracking(paths.IPA_NSSDB_DIR,
                                     nickname='Local IPA host')
        except RuntimeError as e:
            logger.error("%s failed to stop tracking certificate: %s",
                         cmonger.service_name, e)

    client_nss_nickname = 'IPA Machine Certificate - %s' % hostname
    if sys_db.has_nickname(client_nss_nickname):
        try:
            certmonger.stop_tracking(paths.NSS_DB_DIR,
                                     nickname=client_nss_nickname)
        except RuntimeError as e:
            logger.error("%s failed to stop tracking certificate: %s",
                         cmonger.service_name, e)

    for filename in certdb.NSS_FILES:
        remove_file(os.path.join(ipa_db.secdir, filename))

    # Remove any special principal names we added to the IPA CA helper
    certmonger.remove_principal_from_cas()

    try:
        cmonger.stop()
    except Exception as e:
        log_service_error(cmonger.service_name, 'stop', e)

    try:
        cmonger.disable()
    except Exception as e:
        logger.error(
            "Failed to disable automatic startup of the %s service: %s",
            cmonger.service_name, str(e))

    if not options.on_master and os.path.exists(paths.IPA_DEFAULT_CONF):
        logger.info("Unenrolling client from IPA server")
        join_args = [
            paths.SBIN_IPA_JOIN,
            "--unenroll",
            "-h", hostname,
            "-k", paths.KRB5_KEYTAB
        ]
        if options.debug:
            join_args.append("-d")
            env['XMLRPC_TRACE_CURL'] = 'yes'
        result = run(join_args, raiseonerr=False, env=env)
        if result.returncode != 0:
            logger.error("Unenrolling host failed: %s", result.error_log)

    if os.path.exists(paths.IPA_DEFAULT_CONF) and os.path.exists(
        paths.KRB5_KEYTAB
    ):
        logger.info(
            "Removing Kerberos service principals from /etc/krb5.keytab")
        try:
            parser = RawConfigParser()
            parser.read(paths.IPA_DEFAULT_CONF)
            realm = parser.get('global', 'realm')
            run([paths.IPA_RMKEYTAB, "-k", paths.KRB5_KEYTAB, "-r", realm])
        except CalledProcessError as err:
            if err.returncode != 5:
                # 5 means Principal name or realm not found in keytab
                # and can be ignored
                logger.error(
                    "Failed to remove Kerberos service principals: %s",
                    str(err))
        except Exception as e:
            logger.error(
                "Failed to remove Kerberos service principals: %s", str(e))

    # Restore oddjobd to its original state
    oddjobd = services.service('oddjobd', api)
    if not statestore.restore_state('oddjobd', 'running'):
        try:
            oddjobd.stop()
        except Exception:
            pass

    if not statestore.restore_state('oddjobd', 'enabled'):
        try:
            oddjobd.disable()
        except Exception:
            pass

    logger.info("Disabling client Kerberos and LDAP configurations")
    was_sssd_installed = False
    was_sshd_configured = False
    if fstore.has_files():
        was_sssd_installed = fstore.has_file(paths.SSSD_CONF)
        was_sshd_configured = fstore.has_file(paths.SSHD_CONFIG)
    try:
        tasks.restore_pre_ipa_client_configuration(fstore,
                                                   statestore,
                                                   was_sssd_installed,
                                                   was_sssd_configured)
    except Exception as e:
        raise ScriptError(
            "Failed to remove krb5/LDAP configuration: {}".format(e),
            rval=CLIENT_INSTALL_ERROR)

    # Clean up the SSSD cache before SSSD service is stopped or restarted
    remove_file(paths.SSSD_MC_GROUP)
    remove_file(paths.SSSD_MC_PASSWD)
    remove_file(paths.SSSD_MC_INITGROUPS)
    remove_file(paths.SSSD_MC_SID)

    for root, _dirs, files in os.walk(paths.SSSD_PIPES):
        for file in files:
            remove_file(os.path.join(root, file))

    for domain in all_domains:
        name = f"domain_realm_{domain.replace('.', '_')}"
        filename = os.path.join(paths.SSSD_PUBCONF_KRB5_INCLUDE_D_DIR, name)
        if os.path.exists(filename):
            remove_file(filename)

    if was_sssd_installed:
        try:
            run([paths.SSSCTL, "cache-remove", "-o", "--stop", "--start"])
        except Exception:
            logger.info(
                "An error occurred while removing SSSD's cache."
                "Please remove the cache manually by executing "
                "sssctl cache-remove -o.")

    if ipa_domain:
        sssd_domain_ldb = "cache_" + ipa_domain + ".ldb"
        sssd_ldb_file = os.path.join(paths.SSSD_DB, sssd_domain_ldb)
        remove_file(sssd_ldb_file)

        sssd_domain_ccache = "ccache_" + ipa_domain.upper()
        sssd_ccache_file = os.path.join(paths.SSSD_DB, sssd_domain_ccache)
        remove_file(sssd_ccache_file)

        remove_file(paths.SSSD_LDB)
        remove_file(paths.SSSD_CONFIG_LDB)
        # Stop sssd-kcm.service before removing the KCM ccaches database
        # it is socket-activated and will be restarted whenever needed
        try:
            services.service('sssd-kcm', api).stop()
        except Exception as e:
            logger.warning("Failed to stop sssd-kcm: %s", e)
        remove_file(paths.SSSD_SECRETS)

        sssd_timestamps = "timestamps_" + ipa_domain + ".ldb"
        sssd_timestamps_file = os.path.join(paths.SSSD_DB, sssd_timestamps)
        remove_file(sssd_timestamps_file)

    # Next if-elif-elif construction deals with sssd.conf file.
    # Old pre-IPA domains are preserved due merging the old sssd.conf
    # during the installation of ipa-client but any new domains are
    # only present in sssd.conf now, so we don't want to delete them
    # by rewriting sssd.conf file. IPA domain is removed gracefully.

    # SSSD was installed before our installation and other non-IPA domains
    # found, restore backed up sssd.conf to sssd.conf.bkp and remove IPA
    # domain from the current sssd.conf
    if was_sssd_installed and was_sssd_configured:
        logger.info(
            "The original configuration of SSSD included other domains than "
            "the IPA-based one.")

        delete_ipa_domain()

        restored = False
        try:
            restored = fstore.restore_file(
                paths.SSSD_CONF, paths.SSSD_CONF_BKP)
        except OSError:
            logger.debug(
                "Error while restoring pre-IPA /etc/sssd/sssd.conf.")

        if restored:
            logger.info(
                "Original pre-IPA SSSD configuration file was "
                "restored to /etc/sssd/sssd.conf.bkp.")

        logger.info(
            "IPA domain removed from current one, restarting SSSD service")
        sssd = services.service('sssd', api)
        try:
            sssd.restart()
        except CalledProcessError:
            logger.warning("SSSD service restart was unsuccessful.")

    # SSSD was not installed before our installation, but other domains found,
    # delete IPA domain, but leave other domains intact
    elif not was_sssd_installed and was_sssd_configured:
        delete_ipa_domain()
        logger.info(
            "Other domains than IPA domain found, IPA domain was removed "
            "from /etc/sssd/sssd.conf.")

        sssd = services.service('sssd', api)
        try:
            sssd.restart()
        except CalledProcessError:
            logger.warning("SSSD service restart was unsuccessful.")

    # SSSD was not installed before our installation, and no other domains
    # than IPA are configured in sssd.conf - make sure config file is removed
    elif not was_sssd_installed and not was_sssd_configured \
            and os.path.exists(paths.SSSD_CONF):
        try:
            os.rename(paths.SSSD_CONF, paths.SSSD_CONF_DELETED)
        except OSError:
            logger.debug("Error while moving /etc/sssd/sssd.conf to %s",
                         paths.SSSD_CONF_DELETED)

        logger.info(
            "Redundant SSSD configuration file "
            "/etc/sssd/sssd.conf was moved to /etc/sssd/sssd.conf.deleted")

        sssd = services.service('sssd', api)
        try:
            sssd.stop()
        except CalledProcessError:
            logger.warning("SSSD service could not be stopped")

        try:
            sssd.disable()
        except CalledProcessError as e:
            logger.warning(
                "Failed to disable automatic startup of the SSSD daemon: %s",
                e)

    if statestore.has_state('selinux'):
        # Restore SELinux boolean states
        boolean_states = {name: statestore.restore_state('selinux', name)
                          for name in constants.SELINUX_BOOLEAN_SSSD}
        try:
            tasks.set_selinux_booleans(boolean_states)
        except SetseboolError as e:
            logger.warning("Unable to reset SELinux variable: %s", str(e))

    tasks.restore_hostname(fstore, statestore)

    if fstore.has_files():
        logger.info("Restoring client configuration files")
        fstore.restore_all_files()

    unconfigure_nisdomain(statestore)

    nscd = services.knownservices.nscd
    nslcd = services.knownservices.nslcd

    for service in (nscd, nslcd):
        if service.is_installed():
            restore_state(service, statestore)
        else:
            # this is an optional service, just log
            logger.info(
                "%s daemon is not installed, skip configuration",
                service.service_name
            )

    restore_time_sync(statestore, fstore)

    if was_sshd_configured and services.knownservices.sshd.is_running():
        remove_file(paths.SSHD_IPA_CONFIG)
        remove_file(paths.SSH_IPA_CONFIG)
        services.knownservices.sshd.restart()

    # Remove the Firefox configuration
    if statestore.has_state('firefox'):
        logger.info("Removing Firefox configuration.")
        preferences_fname = statestore.restore_state(
            'firefox', 'preferences_fname')
        if preferences_fname is not None:
            if os.path.isfile(preferences_fname):
                try:
                    os.remove(preferences_fname)
                except Exception as e:
                    logger.warning(
                        "'%s' could not be removed: %s.",
                        preferences_fname, str(e))
                    logger.warning(
                        "Please remove file '%s' manually.", preferences_fname)

    rv = SUCCESS

    if fstore.has_files():
        logger.error('Some files have not been restored, see %s',
                     paths.SYSRESTORE_INDEX)

    statestore.delete_state('installation', 'complete')
    has_state = False
    for module in statestore.modules:
            logger.error(
                'Some installation state for %s has not been '
                'restored, see /var/lib/ipa/sysrestore/sysrestore.state',
                module)
            has_state = True
            rv = CLIENT_UNINSTALL_ERROR

    if has_state:
        logger.warning(
            'Some installation state has not been restored.\n'
            'This may cause re-installation to fail.\n'
            'It should be safe to remove %s '
            'but it may\n mean your system hasn\'t been restored '
            'to its pre-installation state.',
            os.path.join(paths.IPA_CLIENT_SYSRESTORE,
                         sysrestore.SYSRESTORE_STATEFILE)
        )

    # Remove the IPA configuration file
    remove_file(paths.IPA_DEFAULT_CONF)
    remove_file(paths.IPA_DEFAULT_CONF + '.ipabkp')

    # Remove misc backups
    remove_file(paths.OPENLDAP_LDAP_CONF + '.ipabkp')
    remove_file(paths.NSSWITCH_CONF + '.ipabkp')

    # Remove the CA cert from the systemwide certificate store
    tasks.remove_ca_certs_from_systemwide_ca_store()

    # Remove the CA cert
    remove_file(paths.IPA_CA_CRT)
    remove_file(paths.KDC_CA_BUNDLE_PEM)
    remove_file(paths.CA_BUNDLE_PEM)

    logger.info("Client uninstall complete.")

    # The next block of code prompts for reboot, therefore all uninstall
    # logic has to be done before

    if not options.unattended:
        logger.info(
            "The original nsswitch.conf configuration has been restored.")
        logger.info(
            "You may need to restart services or reboot the machine.")
        if not options.on_master:
            if user_input("Do you want to reboot the machine?", False):
                try:
                    run([paths.SBIN_REBOOT])
                except Exception as e:
                    raise ScriptError(
                        "Reboot command failed to execute: {}".format(e),
                         rval=CLIENT_UNINSTALL_ERROR)

    # IMPORTANT: Do not put any client uninstall logic after the block above

    if rv:
        raise ScriptError(rval=rv)


def init(installer):
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        if (isinstance(handler, logging.StreamHandler) and
                handler.stream is sys.stderr):
            installer.debug = handler.level == logging.DEBUG
            break
    else:
        installer.debug = True
    installer.unattended = not installer.interactive

    if installer.domain_name:
        installer.domain = normalize_hostname(installer.domain_name)
    else:
        installer.domain = None
    installer.server = installer.servers
    installer.realm = installer.realm_name
    installer.primary = installer.fixed_primary
    if installer.principal:
        installer.password = installer.admin_password
    else:
        installer.password = installer.host_password
    installer.hostname = installer.host_name
    installer.conf_ntp = not installer.no_ntp
    installer.trust_sshfp = installer.ssh_trust_dns
    installer.conf_ssh = not installer.no_ssh
    installer.conf_sshd = not installer.no_sshd
    installer.conf_sudo = not installer.no_sudo
    installer.create_sshfp = not installer.no_dns_sshfp
    if installer.ca_cert_files:
        installer.ca_cert_file = installer.ca_cert_files[-1]
    else:
        installer.ca_cert_file = None
    installer.location = installer.automount_location
    installer.dns_updates = installer.enable_dns_updates
    installer.krb5_offline_passwords = not installer.no_krb5_offline_passwords
    installer.sssd = not installer.no_sssd


@group
class ClientInstallInterface(hostname_.HostNameInstallInterface,
                             service.ServiceAdminInstallInterface,
                             sssd.SSSDInstallInterface):
    """
    Interface of the client installer

    Knobs defined here will be available in:
    * ipa-client-install
    * ipa-server-install
    * ipa-replica-prepare
    * ipa-replica-install
    """
    description = "Client"

    principal = extend_knob(
        service.ServiceAdminInstallInterface.principal,
        description="principal to use to join the IPA realm",
    )
    principal = enroll_only(principal)

    host_password = knob(
        str, None,
        sensitive=True,
    )
    host_password = enroll_only(host_password)

    keytab = knob(
        str, None,
        description="path to backed up keytab from previous enrollment",
        cli_names=[None, '-k'],
    )
    keytab = enroll_only(keytab)

    mkhomedir = knob(
        None,
        description="create home directories for users on their first login",
    )
    mkhomedir = enroll_only(mkhomedir)

    force_join = knob(
        None,
        description="Force client enrollment even if already enrolled",
    )
    force_join = enroll_only(force_join)

    ntp_servers = knob(
        typing.List[str], None,
        description="ntp server to use. This option can be used multiple "
                    "times",
        cli_names='--ntp-server',
        cli_metavar='NTP_SERVER',
    )
    ntp_servers = enroll_only(ntp_servers)

    ntp_pool = knob(
        str, None,
        description="ntp server pool to use",
    )
    ntp_pool = enroll_only(ntp_pool)

    no_ntp = knob(
        None,
        description="do not configure ntp",
        cli_names=[None, '-N'],
    )
    no_ntp = enroll_only(no_ntp)

    force_ntpd = knob(
        None, False,
        deprecated=True,
        description="Stop and disable any time&date synchronization services "
                    "besides ntpd. This option has been deprecated",
    )
    force_ntpd = enroll_only(force_ntpd)

    nisdomain = knob(
        str, None,
        description="NIS domain name",
    )
    nisdomain = enroll_only(nisdomain)

    no_nisdomain = knob(
        None,
        description="do not configure NIS domain name",
    )
    no_nisdomain = enroll_only(no_nisdomain)

    ssh_trust_dns = knob(
        None,
        description="configure OpenSSH client to trust DNS SSHFP records",
    )
    ssh_trust_dns = enroll_only(ssh_trust_dns)

    no_ssh = knob(
        None,
        description="do not configure OpenSSH client",
    )
    no_ssh = enroll_only(no_ssh)

    no_sshd = knob(
        None,
        description="do not configure OpenSSH server",
    )
    no_sshd = enroll_only(no_sshd)

    no_sudo = knob(
        None,
        description="do not configure SSSD as data source for sudo",
    )
    no_sudo = enroll_only(no_sudo)

    subid = knob(
        None,
        description="configure SSSD as data source for subid",
    )
    subid = enroll_only(subid)

    no_dns_sshfp = knob(
        None,
        description="do not automatically create DNS SSHFP records",
    )
    no_dns_sshfp = enroll_only(no_dns_sshfp)

    kinit_attempts = knob(
        int, 5,
        description="number of attempts to obtain host TGT (defaults to 5).",
    )
    kinit_attempts = enroll_only(kinit_attempts)

    @kinit_attempts.validator
    def kinit_attempts(self, value):
        if value < 1:
            raise ValueError("expects an integer greater than 0.")

    request_cert = knob(
        None,
        deprecated=True,
        description="request certificate for the machine",
    )
    request_cert = prepare_only(request_cert)

    def __init__(self, **kwargs):
        super(ClientInstallInterface, self).__init__(**kwargs)

        if self.servers and not self.domain_name:
            raise RuntimeError(
                "--server cannot be used without providing --domain")

        if self.force_ntpd:
            logger.warning(
                "Option --force-ntpd has been deprecated and will be "
                "removed in a future release."
            )

        if self.ntp_servers and self.no_ntp:
            raise RuntimeError(
                "--ntp-server cannot be used together with --no-ntp")

        if self.ntp_pool and self.no_ntp:
            raise RuntimeError(
                "--ntp-pool cannot be used together with --no-ntp")

        if self.request_cert:
            logger.warning(
                "Option --request-cert has been deprecated and will be "
                "removed in a future release."
            )

        if self.no_nisdomain and self.nisdomain:
            raise RuntimeError(
                "--no-nisdomain cannot be used together with --nisdomain")

        if self.ip_addresses:
            if self.enable_dns_updates:
                raise RuntimeError(
                    "--ip-address cannot be used together with"
                    " --enable-dns-updates")

            if self.all_ip_addresses:
                raise RuntimeError(
                    "--ip-address cannot be used together with"
                    "--all-ip-addresses")


@group
class PKINITInstallInterface(service.ServiceInstallInterface):
    description = "PKINIT"

    pkinit_identity = knob(
        type=str,
        default=None,
        description=(
            "PKINIT identity information (for example "
            "FILE:/path/to/cert.pem,/path/to/key.pem)"
        ),
        cli_metavar="IDENTITY",
    )

    @pkinit_identity.validator
    def pkinit_identity(self, value):
        # see pkinit_crypto_openssl.c:crypto_load_certs()
        # ignore "ENV:" prefix
        if not value.startswith(
            ("FILE:", "PKCS11:", "PKCS12:", "DIR:", "ENV:")
        ):
            raise ValueError(
                "identity must start with FILE:, PKCS11:, PKCS12:, DIR:, "
                "or ENV:"
            )

    pkinit_anchors = knob(
        type=typing.List[str],
        default=None,
        description=(
            "PKINIT trust anchors, prefixed with FILE: for CA PEM bundle "
            "file or DIR: for an OpenSSL hash dir. The option can be used "
            "used multiple times."
        ),
        cli_names="--pkinit-anchor",
        cli_metavar="FILEDIR",
    )

    @pkinit_anchors.validator
    def pkinit_anchors(self, value):
        # see pkinit_crypto_openssl.c:crypto_load_cas_and_crls()
        for part in value:
            prefix, sep, path = part.partition(":")
            if not sep or prefix not in {"FILE", "DIR", "ENV:"}:
                raise ValueError(
                    "Invalid pkinit_anchor '{part}' is not prefixed with "
                    "FILE: or DIR:."
                )
            if prefix == "FILE" and not os.path.isfile(path):
                raise ValueError(
                    f"pkinit anchor path '{path}' does not exist or is not "
                    "a file."
                )
            if prefix == "DIR" and not os.path.isdir(path):
                raise ValueError(
                    f"pkinit anchor path '{path}' does not exist or is not "
                    "a file."
                )

class ClientInstall(ClientInstallInterface,
                    PKINITInstallInterface,
                    automount.AutomountInstallInterface):
    """
    Client installer
    """

    dm_password = None

    ca_cert_files = extend_knob(
        ClientInstallInterface.ca_cert_files,
    )

    @ca_cert_files.validator
    def ca_cert_files(self, value):
        if not isinstance(value, list):
            raise ValueError("Expected list, got {!r}".format(value))
        # this is what init() does
        value = value[-1]
        if not os.path.exists(value):
            raise ValueError("'%s' does not exist" % value)
        if not os.path.isfile(value):
            raise ValueError("'%s' is not a file" % value)
        if not os.path.isabs(value):
            raise ValueError("'%s' is not an absolute file path" % value)

        try:
            x509.load_certificate_from_file(value)
        except Exception:
            raise ValueError("'%s' is not a valid certificate file" % value)

    @property
    def prompt_password(self):
        return self.interactive

    no_ac = False

    force = knob(
        None,
        description="force setting of LDAP/Kerberos conf",
        cli_names=[None, '-f'],
    )

    on_master = False

    configure_firefox = knob(
        None,
        description="configure Firefox to use IPA domain credentials",
    )

    firefox_dir = knob(
        str, None,
        description="specify directory where Firefox is installed (for "
                    "example: '/usr/lib/firefox')",
    )

    def __init__(self, **kwargs):
        super(ClientInstall, self).__init__(**kwargs)

        if self.firefox_dir and not self.configure_firefox:
            raise RuntimeError(
                "--firefox-dir cannot be used without --configure-firefox "
                "option")

    @step()
    def main(self):
        init(self)
        install_check(self)
        yield
        install(self)

    @main.uninstaller
    def main(self):
        init(self)
        uninstall_check(self)
        yield
        uninstall(self)
