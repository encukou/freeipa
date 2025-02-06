#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function, absolute_import

import errno
import itertools
import logging
import re
import os
import glob
import shutil
import fileinput
import stat
import sys
import tempfile
from contextlib import contextmanager
from augeas import Augeas
from pkg_resources import parse_version

from ipalib import api, x509
from ipalib.constants import RENEWAL_CA_NAME, RA_AGENT_PROFILE, IPA_CA_RECORD
from ipalib.install import certmonger
from ipalib import sysrestore
from ipalib.facts import is_ipa_configured
import SSSDConfig
import ipalib.util
import ipalib.errors
from ipaclient.install import timeconf
from ipaclient.install.client import sssd_enable_ifp
from ipalib.install.dnsforwarders import detect_resolve1_resolv_conf
from ipaplatform import services
from ipaplatform.tasks import tasks
from ipapython import ipautil, version
from ipapython import ipaldap
from ipapython import directivesetter
from ipapython.dn import DN
from ipapython.version import KRB5_BUILD_VERSION
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipaserver import servroles
from ipaserver.install import installutils
from ipaserver.install import dsinstance
from ipaserver.install import httpinstance
from ipaserver.install import bindinstance
from ipaserver.install import service
from ipaserver.install import cainstance
from ipaserver.install import krainstance
from ipaserver.install import certs
from ipaserver.install import otpdinstance
from ipaserver.install import schemaupdate
from ipaserver.install import custodiainstance
from ipaserver.install import sysupgrade
from ipaserver.install import dnskeysyncinstance
from ipaserver.install import dogtaginstance
from ipaserver.install import krbinstance
from ipaserver.install import adtrustinstance
from ipaserver.install import replication
from ipaserver.install.upgradeinstance import IPAUpgrade
from ipaserver.install.ldapupdate import BadSyntax

import six
# pylint: disable=import-error
if six.PY3:
    # The SafeConfigParser class has been renamed to ConfigParser in Py3
    from configparser import ConfigParser as SafeConfigParser
else:
    from ConfigParser import SafeConfigParser
# pylint: enable=import-error

if six.PY3:
    unicode = str


logger = logging.getLogger(__name__)


class KpasswdInstance(service.SimpleServiceInstance):
    def __init__(self):
        service.SimpleServiceInstance.__init__(self, "ipa_kpasswd")

def uninstall_ipa_kpasswd():
    """
    We can't use the full service uninstaller because that will attempt
    to stop and disable the service which by now doesn't exist. We just
    want to clean up sysrestore.state to remove all references to
    ipa_kpasswd.
    """
    ipa_kpasswd = KpasswdInstance()

    enabled = not ipa_kpasswd.restore_state("enabled")

    if enabled is not None and not enabled:
        ipa_kpasswd.remove()


def uninstall_ipa_memcached():
    """
    We can't use the full service uninstaller because that will attempt
    to stop and disable the service which by now doesn't exist. We just
    want to clean up sysrestore.state to remove all references to
    ipa_memcached.
    """
    ipa_memcached = service.SimpleServiceInstance('ipa_memcached')

    if ipa_memcached.is_configured():
        ipa_memcached.uninstall()


def backup_file(filename, ext):
    """Make a backup of filename using ext as the extension. Do not overwrite
       previous backups."""
    if not os.path.isabs(filename):
        raise ValueError("Absolute path required")

    backupfile = filename + ".bak"

    while os.path.exists(backupfile):
        backupfile = backupfile + "." + str(ext)

    try:
        shutil.copy2(filename, backupfile)
    except IOError as e:
        if e.errno == 2: # No such file or directory
            pass
        else:
            raise e

def update_conf(sub_dict, filename, template_filename):
    template = ipautil.template_file(template_filename, sub_dict)
    fd = open(filename, "w")
    fd.write(template)
    fd.close()

def find_autoredirect(fqdn):
    """
    When upgrading ipa-rewrite.conf we need to see if the automatic redirect
    was disabled during install time (or afterward). So sift through the
    configuration file and see if we can determine the status.

    Returns True if autoredirect is enabled, False otherwise
    """
    filename = paths.HTTPD_IPA_REWRITE_CONF
    if os.path.exists(filename):
        pattern = r"^RewriteRule \^/\$ https://%s/ipa/ui \[L,NC,R=301\]" % fqdn
        p = re.compile(pattern)
        for line in fileinput.input(filename):
            if p.search(line):
                fileinput.close()
                return True
        fileinput.close()
        return False
    return True

def find_version(filename):
    """Find the version of a configuration file

    If no VERSION entry exists in the file, returns 0.
    If the file does not exist, returns -1.
    """
    if os.path.exists(filename):
        pattern = r"^[\s#]*VERSION\s+([0-9]+)\s+.*"
        p = re.compile(pattern)
        for line in fileinput.input(filename):
            if p.search(line):
                fileinput.close()
                return p.search(line).group(1)
        fileinput.close()

        # no VERSION found
        return 0
    else:
        return -1


def upgrade_file(sub_dict, filename, template, add=False, force=False):
    """
    Get the version from the current and template files and update the
    installed configuration file if there is a new template.

    If add is True then create a new configuration file.

    If force is True then the version comparison is skipped. This should
    be used judiciously. It does not override add nor will it affect
    files that don't exist (version == -1).
    """
    old = int(find_version(filename))
    new = int(find_version(template))

    if old < 0 and not add:
        logger.error("%s not found.", filename)
        raise RuntimeError("%s not found." % filename)

    if new < 0:
        logger.error("%s not found.", template)

    if new == 0:
        logger.error("Template %s is not versioned.", template)

    if old == 0:
        # The original file does not have a VERSION entry. This means it's now
        # managed by IPA, but previously was not.
        logger.warning("%s is now managed by IPA. It will be "
                       "overwritten. A backup of the original will be made.",
                       filename)

    if force:
        logger.error("Forcing update of template %s", template)

    if ((old < new) or (add and old == 0)) or force:
        backup_file(filename, new)
        update_conf(sub_dict, filename, template)
        logger.info("Upgraded %s to version %d", filename, new)

def check_certs():
    """Check ca.crt is in the right place, and try to fix if not"""
    logger.info('[Verifying that root certificate is published]')
    if not os.path.exists(paths.CA_CRT):
        ca_file = paths.IPA_CA_CRT
        if os.path.exists(ca_file):
            old_umask = os.umask(0o22)   # make sure its readable by httpd
            try:
                shutil.copyfile(ca_file, paths.CA_CRT)
            finally:
                os.umask(old_umask)
        else:
            logger.error("Missing Certification Authority file.")
            logger.error("You should place a copy of the CA certificate in "
                         "/usr/share/ipa/html/ca.crt")
    else:
        logger.debug('Certificate file exists')

def update_dbmodules(realm, filename=paths.KRB5_CONF):
    newfile = []
    found_dbrealm = False
    found_realm = False
    prefix = ''

    logger.info('[Verifying that KDC configuration is using ipa-kdb backend]')
    fd = open(filename)

    lines = fd.readlines()
    fd.close()

    if '    db_library = ipadb.so\n' in lines:
        logger.debug('dbmodules already updated in %s', filename)
        return

    for line in lines:
        if line.startswith('[dbmodules]'):
            found_dbrealm = True
        if found_dbrealm and line.find(realm) > -1:
            found_realm = True
            prefix = '#'
        if found_dbrealm and line.find('}') > -1 and found_realm:
            found_realm = False
            newfile.append('#%s' % line)
            prefix = ''
            continue

        newfile.append('%s%s' % (prefix, line))

    # Append updated dbmodules information
    newfile.append('  %s = {\n' % realm)
    newfile.append('    db_library = ipadb.so\n')
    newfile.append('  }\n')

    # Write out new file
    fd = open(filename, 'w')
    fd.write("".join(newfile))
    fd.close()
    logger.debug('%s updated', filename)

def cleanup_kdc(fstore):
    """
    Clean up old KDC files if they exist. We need to remove the actual
    file and any references in the uninstall configuration.
    """
    logger.info('[Checking for deprecated KDC configuration files]')
    for file in ['kpasswd.keytab', 'ldappwd']:
        filename = os.path.join(paths.VAR_KERBEROS_KRB5KDC_DIR, file)
        ipautil.remove_file(filename)
        if fstore.has_file(filename):
            fstore.untrack_file(filename)
            logger.debug('Uninstalling %s', filename)

def cleanup_adtrust(fstore):
    """
    Clean up any old Samba backup files that were deprecated.
    """

    logger.info('[Checking for deprecated backups of Samba '
                'configuration files]')

    for backed_up_file in [paths.SMB_CONF]:
        if fstore.has_file(backed_up_file):
            fstore.untrack_file(backed_up_file)
            logger.debug('Removing %s from backup', backed_up_file)


def cleanup_dogtag():
    """
    pkispawn leaves some mess we were not cleaning up until recently. Try
    to clean up what we can.
    """
    subsystems = []
    if api.Command.ca_is_enabled()['result']:
        subsystems.append('CA')
        if api.Command.kra_is_enabled()['result']:
            subsystems.append('KRA')

    for system in subsystems:
        logger.debug(
            "Cleaning up after pkispawn for the %s subsystem",
            system)
        instance = dogtaginstance.DogtagInstance(
            api.env.realm, system, service_desc=None,
        )
        instance.clean_pkispawn_files()


def cleanup_kdcinfo():
    """ Remove stale kdcinfo.*|kpasswdinfo.* files generated by SSSD """

    for pattern in ('kdcinfo.*', 'kpasswdinfo.*'):
        for fname in glob.glob(os.path.join(paths.SSSD_PUBCONF_DIR, pattern)):
            logger.debug('Removing stale info file %s', fname)
            os.unlink(fname)


def upgrade_adtrust_config():
    """
    Upgrade 'dedicated keytab file' in smb.conf to omit FILE: prefix
    """

    if not adtrustinstance.ipa_smb_conf_exists():
        return

    logger.info("[Remove FILE: prefix from 'dedicated keytab file' "
                "in Samba configuration]")

    args = [paths.NET, "conf", "setparm", "global",
            "dedicated keytab file", paths.SAMBA_KEYTAB]

    try:
        ipautil.run(args)
    except ipautil.CalledProcessError as e:
        logger.warning("Error updating Samba registry: %s", e)

    logger.info("[Update 'max smbd processes' in Samba configuration "
                "to prevent unlimited SMBLoris attack amplification]")

    args = [paths.NET, "conf", "getparm", "global", "max smbd processes"]

    try:
        ipautil.run(args)
    except ipautil.CalledProcessError as e:
        if e.returncode == 255:
            # 'max smbd processes' does not exist
            args = [paths.NET, "conf", "setparm", "global",
                    "max smbd processes", "1000"]
            try:
                ipautil.run(args)
            except ipautil.CalledProcessError as e2:
                logger.warning("Error updating Samba registry: %s", e2)
        else:
            logger.warning("Error updating Samba registry: %s", e)

    logger.info("[Change 'server role' from "
                "'CLASSIC PRIMARY DOMAIN CONTROLLER' "
                "to 'IPA PRIMARY DOMAIN CONTROLLER' in Samba configuration]")

    args = [paths.NET, "conf", "setparm", "global",
            "server role", "IPA PRIMARY DOMAIN CONTROLLER"]

    try:
        ipautil.run(args)
    except ipautil.CalledProcessError as e:
        # Only report an error if return code is not 255
        # which indicates that the new server role is not supported
        # and we don't need to do anything
        if e.returncode != 255:
            logger.warning("Error updating Samba registry: %s", e)

def ca_configure_profiles_acl(ca):
    logger.info('[Authorizing RA Agent to modify profiles]')

    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    return cainstance.configure_profiles_acl()


def ca_configure_lightweight_ca_acls(ca):
    logger.info('[Authorizing RA Agent to manage lightweight CAs]')

    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    return cainstance.configure_lightweight_ca_acls()


def ca_enable_ldap_profile_subsystem(ca):
    logger.info('[Ensuring CA is using LDAPProfileSubsystem]')
    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    needs_update = False
    directive = None
    try:
        i = 0
        while True:
            # find profile subsystem
            directive = "subsystem.{}.id".format(i)
            value = directivesetter.get_directive(
                paths.CA_CS_CFG_PATH,
                directive,
                separator='=')
            if not value:
                logger.error('Unable to find profile subsystem in %s',
                             paths.CA_CS_CFG_PATH)
                return False
            if value != 'profile':
                i = i + 1
                continue

            # check profile subsystem class name
            directive = "subsystem.{}.class".format(i)
            value = directivesetter.get_directive(
                paths.CA_CS_CFG_PATH,
                directive,
                separator='=')
            if value != 'com.netscape.cmscore.profile.LDAPProfileSubsystem':
                needs_update = True

            # break after finding profile subsystem
            break

    except OSError as e:
        logger.error('Cannot read CA configuration file "%s": %s',
                     paths.CA_CS_CFG_PATH, e)
        return False

    if needs_update:
        directivesetter.set_directive(
            paths.CA_CS_CFG_PATH,
            directive,
            'com.netscape.cmscore.profile.LDAPProfileSubsystem',
            quotes=False,
            separator='=')

        ca.restart('pki-tomcat')

    logger.info('[Migrating certificate profiles to LDAP]')
    cainstance.migrate_profiles_to_ldap()

    return needs_update


def ca_import_included_profiles(ca):
    logger.info('[Ensuring presence of included profiles]')

    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    return cainstance.import_included_profiles()


def ca_ensure_lightweight_cas_container(ca):
    logger.info('[Ensuring Lightweight CAs container exists in Dogtag '
                'database]')

    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    return cainstance.ensure_lightweight_cas_container()


def ca_enable_lightweight_ca_monitor(ca):
    logger.info('[Enabling LWCA monitor]')

    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    return cainstance.enable_lightweight_ca_monitor()


def ca_add_default_ocsp_uri(ca):
    logger.info('[Adding default OCSP URI configuration]')
    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    value = directivesetter.get_directive(
        paths.CA_CS_CFG_PATH,
        'ca.defaultOcspUri',
        separator='=')
    if value:
        return False  # already set; restart not needed

    directivesetter.set_directive(
        paths.CA_CS_CFG_PATH,
        'ca.defaultOcspUri',
        'http://ipa-ca.%s/ca/ocsp' % ipautil.format_netloc(api.env.domain),
        quotes=False,
        separator='=')
    return True  # restart needed


def ca_disable_publish_cert(ca):
    logger.info('[Disabling cert publishing]')
    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    value = directivesetter.get_directive(
        paths.CA_CS_CFG_PATH,
        'ca.publish.cert.enable',
        separator='=')
    if value:
        return False  # already set; restart not needed

    directivesetter.set_directive(
        paths.CA_CS_CFG_PATH,
        'ca.publish.cert.enable',
        'false',
        quotes=False,
        separator='=')
    return True  # restart needed


def ca_initialize_hsm_state(ca):
    """Initializse HSM state as False / internal token
    """
    if not ca.sstore.has_state(ca.hsm_sstore):
        section_name = ca.subsystem.upper()
        config = SafeConfigParser()
        config.add_section(section_name)
        config.set(section_name, 'pki_hsm_enable', 'False')
        ca.set_hsm_state(config)


def dnssec_set_openssl_engine(dnskeysyncd):
    """
    Setup OpenSSL engine or provider for BIND
    """
    if all([constants.NAMED_OPENSSL_ENGINE is None,
            constants.NAMED_OPENSSL_PROVIDER is None]):
        return False

    # Nothing to do if we are using OpenSSL engine already and not on the OS
    # that requires OpenSSL provider instead.
    if all([sysupgrade.get_upgrade_state('dns', 'openssl_engine'),
            constants.NAMED_OPENSSL_PROVIDER is None]):
        return False

    logger.info('[Set OpenSSL engine or provider for BIND]')
    dnskeysyncd.setup_named_openssl_conf()
    dnskeysyncd.setup_named_sysconfig()
    dnskeysyncd.setup_ipa_dnskeysyncd_sysconfig()
    sysupgrade.set_upgrade_state('dns', 'openssl_engine', True)

    return True


def certificate_renewal_update(ca, kra, ds, http):
    """
    Update certmonger certificate renewal configuration.
    """

    # First ensure the renewal helpers are defined.
    ca.configure_certmonger_renewal_helpers()

    template = paths.CERTMONGER_COMMAND_TEMPLATE
    serverid = ipaldap.realm_to_serverid(api.env.realm)

    requests = []

    dogtag_reqs = ca.tracking_reqs.items()
    if kra.is_installed():
        dogtag_reqs = itertools.chain(dogtag_reqs, kra.tracking_reqs.items())

    for nick, profile in dogtag_reqs:
        req = {
            'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
            'cert-nickname': nick,
            'ca-name': RENEWAL_CA_NAME,
            'cert-presave-command': template % 'stop_pkicad',
            'cert-postsave-command':
                (template % 'renew_ca_cert "{}"'.format(nick)),
            'template-profile': profile,
        }
        requests.append(req)

    requests.append(
        {
            'cert-file': paths.RA_AGENT_PEM,
            'key-file': paths.RA_AGENT_KEY,
            'ca-name': RENEWAL_CA_NAME,
            'template-profile': RA_AGENT_PROFILE,
            'cert-presave-command': template % 'renew_ra_cert_pre',
            'cert-postsave-command': template % 'renew_ra_cert',
        },
    )

    logger.info("[Update certmonger certificate renewal configuration]")
    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    # Check the http server cert if issued by IPA
    cert = x509.load_certificate_from_file(paths.HTTPD_CERT_FILE)
    if certs.is_ipa_issued_cert(api, cert):
        requests.append(
            {
                'cert-file': paths.HTTPD_CERT_FILE,
                'key-file': paths.HTTPD_KEY_FILE,
                'ca-name': 'IPA',
                'cert-postsave-command': template % 'restart_httpd',
                'template-hostname': [
                    http.fqdn,
                    f'{IPA_CA_RECORD}.{ipautil.format_netloc(api.env.domain)}',
                ],
            }
        )

    # Check the ldap server cert if issued by IPA
    ds_nickname = ds.get_server_cert_nickname(serverid)
    ds_db_dirname = dsinstance.config_dirname(serverid)
    ds_db = certs.CertDB(api.env.realm, nssdir=ds_db_dirname)
    if ds_db.is_ipa_issued_cert(api, ds_nickname):
        requests.append(
            {
                'cert-database': ds_db_dirname[:-1],
                'cert-nickname': ds_nickname,
                'ca-name': 'IPA',
                'cert-postsave-command':
                    '%s %s' % (template % 'restart_dirsrv', serverid),
            }
        )

    db = certs.CertDB(api.env.realm, paths.PKI_TOMCAT_ALIAS_DIR)
    for nickname, _trust_flags in db.list_certs():
        if nickname.startswith('caSigningCert cert-pki-ca '):
            requests.append(
                {
                    'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                    'cert-nickname': nickname,
                    'ca-name': RENEWAL_CA_NAME,
                    'cert-presave-command': template % 'stop_pkicad',
                    'cert-postsave-command':
                        (template % ('renew_ca_cert "%s"' % nickname)),
                    'template-profile': 'caCACert',
                }
            )

    # State not set, lets see if we are already configured
    missing_or_misconfigured_requests = []
    for request in requests:
        request_id = certmonger.get_request_id(request)
        if request_id is None:
            missing_or_misconfigured_requests.append(request)

    if len(missing_or_misconfigured_requests) == 0:
        logger.info("Certmonger certificate renewal configuration already "
                    "up-to-date")
        return False

    # Print info about missing requests
    logger.info("Missing or incorrect tracking request for certificates:")
    for request in missing_or_misconfigured_requests:
        cert = None
        if 'cert-file' in request:
            cert = request['cert-file']
        elif 'cert-database' in request and 'cert-nickname' in request:
            cert = '{cert-database}:{cert-nickname}'.format(**request)
        if cert is not None:
            logger.info("  %s", cert)

    # Ok, now we need to stop tracking, then we can start tracking them
    # again with new configuration:
    ca.stop_tracking_certificates()
    if kra.is_installed():
        kra.stop_tracking_certificates()
    ds.stop_tracking_certificates(serverid)
    http.stop_tracking_certificates()

    filename = paths.CERTMONGER_CAS_CA_RENEWAL
    if os.path.exists(filename):
        with installutils.stopped_service('certmonger'):
            logger.info("Removing %s", filename)
            ipautil.remove_file(filename)

    ca.configure_renewal()
    ca.configure_agent_renewal()
    ca.add_lightweight_ca_tracking_requests()
    if kra.is_installed():
        kra.configure_renewal()
    ds.start_tracking_certificates(serverid)
    http.start_tracking_certificates()

    logger.info("Certmonger certificate renewal configuration updated")
    return True


def http_certificate_ensure_ipa_ca_dnsname(http):
    """
    Ensure the HTTP service certificate has the ipa-ca.$DOMAIN SAN dNSName.

    This subroutine should be executed *after* ``certificate_renewal_update``,
    which adds the name to the tracking request.  It assumes that the tracking
    request already has the ipa-ca.$DOMAIN DNS name set, and all that is needed
    is to resubmit the request.

    If HTTP certificate is issued by a third party, print manual remediation
    steps.

    """
    logger.info('[Adding ipa-ca alias to HTTP certificate]')

    expect = f'{IPA_CA_RECORD}.{ipautil.format_netloc(api.env.domain)}'
    cert = x509.load_certificate_from_file(paths.HTTPD_CERT_FILE)

    try:
        cert.match_hostname(expect)
    except x509.ssl_match_hostname.CertificateError:
        if certs.is_ipa_issued_cert(api, cert):
            request_id = certmonger.get_request_id(
                {'cert-file': paths.HTTPD_CERT_FILE})
            if request_id is None:
                # shouldn't happen
                logger.error('Could not find HTTP cert tracking request.')
            else:
                logger.info('Resubmitting HTTP cert tracking request')
                certmonger.resubmit_request(request_id)
                # NOTE: due to https://pagure.io/certmonger/issue/143, the
                # resubmitted request, if it does not immediately succeed
                # (fairly likely during ipa-server-upgrade) and if the notAfter
                # date of the current cert is still far off (also likely), then
                # Certmonger will wait 7 days before trying again (unless
                # restarted).  There is not much we can do about that here, in
                # the middle of ipa-server-upgrade.
        else:
            logger.error('HTTP certificate is issued by third party.')
            logger.error(
                'Obtain a new certificate with the following DNS names, \n'
                'and install via ipa-server-certinstall(1):\n'
                ' - %s\n'
                ' - %s',
                http.fqdn,
                expect,
            )
    else:
        logger.info('Certificate is OK; nothing to do')


def copy_crl_file(old_path, new_path=None):
    """
    Copy CRL to new location, update permissions and SELinux context
    """
    if new_path is None:
        filename = os.path.basename(old_path)
        new_path = os.path.join(paths.PKI_CA_PUBLISH_DIR, filename)
    logger.debug('copy_crl_file: %s -> %s', old_path, new_path)

    if os.path.islink(old_path):
        # update symlink to the most most recent CRL file
        filename = os.path.basename(os.readlink(old_path))
        realpath = os.path.join(paths.PKI_CA_PUBLISH_DIR, filename)
        logger.debug('copy_crl_file: Create symlink %s -> %s',
                     new_path, realpath)
        os.symlink(realpath, new_path)
    else:
        shutil.copy2(old_path, new_path)
        constants.PKI_USER.chown(new_path)

    tasks.restore_context(new_path)

def migrate_crl_publish_dir(ca):
    """
    Move CRL publish dir from /var/lib/pki-ca/publish to IPA controlled tree:
    /var/lib/ipa/pki-ca/publish
    """
    logger.info('[Migrate CRL publish directory]')
    if sysupgrade.get_upgrade_state('dogtag', 'moved_crl_publish_dir'):
        logger.info('CRL tree already moved')
        return False

    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    try:
        old_publish_dir = directivesetter.get_directive(
            paths.CA_CS_CFG_PATH,
            'ca.publish.publisher.instance.FileBaseCRLPublisher.directory',
            separator='=')
    except OSError as e:
        logger.error('Cannot read CA configuration file "%s": %s',
                     paths.CA_CS_CFG_PATH, e)
        return False

    # Prepare target publish dir (creation, permissions, SELinux context)
    # Run this every update to ensure proper values
    publishdir = ca.prepare_crl_publish_dir()

    if old_publish_dir == paths.PKI_CA_PUBLISH_DIR:
        # publish dir is already updated
        logger.info('Publish directory already set to new location')
        sysupgrade.set_upgrade_state('dogtag', 'moved_crl_publish_dir', True)
        return False

    # Copy all CRLs to new directory
    logger.info('Copy all CRLs to new publish directory')
    try:
        crl_files_unsorted = cainstance.get_crl_files(old_publish_dir)
    except OSError as e:
        logger.error('Cannot move CRL files to new directory: %s', e)
    else:
        # Move CRL files at the end of the list to make sure that the actual
        # CRL files are copied first
        crl_files = sorted(crl_files_unsorted,
                           key=lambda f: os.path.islink(f))
        for f in crl_files:
            try:
                copy_crl_file(f)
            except Exception as e:
                logger.error('Cannot move CRL file to new directory: %s', e)

    try:
        directivesetter.set_directive(
            paths.CA_CS_CFG_PATH,
            'ca.publish.publisher.instance.FileBaseCRLPublisher.directory',
            publishdir, quotes=False, separator='=')
    except OSError as e:
        logger.error('Cannot update CA configuration file "%s": %s',
                     paths.CA_CS_CFG_PATH, e)
        return False
    sysupgrade.set_upgrade_state('dogtag', 'moved_crl_publish_dir', True)
    logger.info('CRL publish directory has been migrated, '
                'request pki-tomcat restart')
    return True


def ca_enable_pkix(ca):
    logger.info('[Enable PKIX certificate path discovery and validation]')
    if sysupgrade.get_upgrade_state('dogtag', 'pkix_enabled'):
        logger.info('PKIX already enabled')
        return False

    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    ca.enable_pkix()
    sysupgrade.set_upgrade_state('dogtag', 'pkix_enabled', True)

    return True


def add_ca_dns_records(bind):
    logger.info('[Add missing CA DNS records]')

    if sysupgrade.get_upgrade_state('dns', 'ipa_ca_records'):
        logger.info('IPA CA DNS records already processed')
        return False

    ret = api.Command['dns_is_enabled']()
    if not ret['result']:
        logger.info('DNS is not configured')
        sysupgrade.set_upgrade_state('dns', 'ipa_ca_records', True)
        return False

    bind.remove_ipa_ca_cnames(api.env.domain)
    bind.update_system_records()

    sysupgrade.set_upgrade_state('dns', 'ipa_ca_records', True)
    return True


def find_subject_base():
    """
    Try to find the current value of certificate subject base.
    See the docstring in dsinstance.DsInstance for details.
    """
    subject_base =  dsinstance.DsInstance().find_subject_base()

    if subject_base:
        sysupgrade.set_upgrade_state(
            'certmap.conf',
            'subject_base',
            subject_base
        )
        return subject_base

    logger.error('Unable to determine certificate subject base. '
                 'certmap.conf will not be updated.')
    return None


def uninstall_selfsign(ds, http):
    logger.info('[Removing self-signed CA]')
    """Replace self-signed CA by a CA-less install"""
    if api.env.ra_plugin != 'selfsign':
        logger.debug('Self-signed CA is not installed')
        return

    logger.warning(
        'Removing self-signed CA. Certificates will need to managed manually.')
    p = SafeConfigParser()
    p.read(paths.IPA_DEFAULT_CONF)
    p.set('global', 'enable_ra', 'False')
    p.set('global', 'ra_plugin', 'none')
    with open(paths.IPA_DEFAULT_CONF, 'w') as f:
        p.write(f)

    ds.stop_tracking_certificates()
    http.stop_tracking_certificates()


def uninstall_dogtag_9(ds, http):
    logger.info('[Removing Dogtag 9 CA]')

    if api.env.ra_plugin != 'dogtag':
        logger.debug('Dogtag CA is not installed')
        return
    if api.env.dogtag_version >= 10:
        logger.debug('Dogtag is version 10 or above')
        return

    dn = DN(('cn', 'CA'), ('cn', api.env.host), api.env.container_masters,
            api.env.basedn)
    try:
        api.Backend.ldap2.delete_entry(dn)
    except ipalib.errors.PublicError as e:
        logger.error("Cannot delete %s: %s", dn, e)

    p = SafeConfigParser()
    p.read(paths.IPA_DEFAULT_CONF)
    p.set('global', 'dogtag_version', '10')
    with open(paths.IPA_DEFAULT_CONF, 'w') as f:
        p.write(f)

    sstore = sysrestore.StateFile(paths.SYSRESTORE)
    sstore.restore_state('pkids', 'enabled')
    sstore.restore_state('pkids', 'running')
    sstore.restore_state('pkids', 'user_exists')
    serverid = sstore.restore_state('pkids', 'serverid')
    sstore.save()

    ca = dogtaginstance.DogtagInstance(
        api.env.realm, "CA", "certificate server",
        nss_db=paths.VAR_LIB_PKI_CA_ALIAS_DIR)
    ca.stop_tracking_certificates()

    if serverid is not None:
        # drop the trailing / off the config_dirname so the directory
        # will match what is in certmonger
        dirname = dsinstance.config_dirname(serverid)[:-1]
        dsdb = certs.CertDB(api.env.realm, nssdir=dirname)
        dsdb.untrack_server_cert("Server-Cert")

    try:
        services.service('pki-cad', api).disable('pki-ca')
    except Exception as e:
        logger.warning("Failed to disable pki-cad: %s", e)
    try:
        services.service('pki-cad', api).stop('pki-ca')
    except Exception as e:
        logger.warning("Failed to stop pki-cad: %s", e)

    if serverid is not None:
        try:
            services.service('dirsrv', api).disable(serverid)
        except Exception as e:
            logger.warning("Failed to disable dirsrv: %s", e)
        try:
            services.service('dirsrv', api).stop(serverid)
        except Exception as e:
            logger.warning("Failed to stop dirsrv: %s", e)

    http.restart()


def fix_schema_file_syntax():
    """Fix syntax errors in schema files

    https://fedorahosted.org/freeipa/ticket/3578
    """
    logger.info('[Fix DS schema file syntax]')

    # This is not handled by normal schema updates, because pre-1.3.2 DS will
    # ignore (auto-fix) these syntax errors, and 1.3.2 and above will choke on
    # them before checking dynamic schema updates.

    if sysupgrade.get_upgrade_state('ds', 'fix_schema_syntax'):
        logger.info('Syntax already fixed')
        return

    serverid = ipaldap.realm_to_serverid(api.env.realm)
    ds_dir = dsinstance.config_dirname(serverid)

    # 1. 60ipadns.ldif: Add parenthesis to idnsRecord

    filename = os.path.join(ds_dir, 'schema', '60ipadns.ldif')
    result_lines = []
    with open(filename) as file:
        for line in file:
            line = line.strip('\n')
            if (line.startswith('objectClasses:') and
                    "NAME 'idnsRecord'" in line and
                    line.count('(') == 2 and
                    line.count(')') == 1):
                logger.debug('Add closing parenthesis in idnsRecord')
                line += ' )'
            result_lines.append(line)

    with open(filename, 'w') as file:
        file.write('\n'.join(result_lines))

    # 2. 65ipasudo.ldif: Remove extra dollar from ipaSudoRule

    filename = os.path.join(ds_dir, 'schema', '65ipasudo.ldif')
    result_lines = []
    with open(filename) as file:
        for line in file:
            line = line.strip('\n')
            if (line.startswith('objectClasses:') and
                    "NAME 'ipaSudoRule'" in line):
                logger.debug('Remove extra dollar sign in ipaSudoRule')
                line = line.replace('$$', '$')
            result_lines.append(line)

    with open(filename, 'w') as file:
        file.write('\n'.join(result_lines))

    # Done

    sysupgrade.set_upgrade_state('ds', 'fix_schema_syntax', True)


def sssd_update():
    sssdconfig = SSSDConfig.SSSDConfig()
    sssdconfig.import_config()
    # upgrade domain
    domain = sssdconfig.get_domain(str(api.env.domain))
    domain.set_option('ipa_server_mode', 'True')
    domain.set_option('ipa_server', api.env.host)
    sssdconfig.save_domain(domain)
    # check if service has ok_to_auth_as_delegate
    service = 'HTTP/{}'.format(api.env.host)
    result = api.Command.service_show(service, all=True)
    flag = result['result'].get('ipakrboktoauthasdelegate', False)
    if flag:
        logger.debug(
            "%s has ok_to_auth_as_delegate, allow Apache to access IFP",
            services
        )
    # enable and configure IFP plugin
    sssd_enable_ifp(sssdconfig, allow_httpd=flag)
    # clean stale files generated by sssd
    cleanup_kdcinfo()
    # write config and restart service
    sssdconfig.write(paths.SSSD_CONF)
    sssd = services.service('sssd', api)
    sssd.restart()


def remove_ds_ra_cert(subject_base):
    logger.info('[Removing RA cert from DS NSS database]')

    if sysupgrade.get_upgrade_state('ds', 'remove_ra_cert'):
        logger.info('RA cert already removed')
        return

    dbdir = dsinstance.config_dirname(
        ipaldap.realm_to_serverid(api.env.realm))
    dsdb = certs.CertDB(api.env.realm, nssdir=dbdir, subject_base=subject_base)

    nickname = 'CN=IPA RA,%s' % subject_base
    cert = dsdb.get_cert_from_db(nickname)
    if cert:
        dsdb.delete_cert(nickname)

    sysupgrade.set_upgrade_state('ds', 'remove_ra_cert', True)


def migrate_to_mod_ssl(http):
    logger.info('[Migrating from mod_nss to mod_ssl]')

    if sysupgrade.get_upgrade_state('ssl.conf', 'migrated_to_mod_ssl'):
        logger.info("Already migrated to mod_ssl")
        return

    http.migrate_to_mod_ssl()

    sysupgrade.set_upgrade_state('ssl.conf', 'migrated_to_mod_ssl', True)



def update_ipa_httpd_service_conf(http):
    logger.info('[Updating HTTPD service IPA configuration]')
    http.update_httpd_service_ipa_conf()


def update_ipa_http_wsgi_conf(http):
    logger.info('[Updating HTTPD service IPA WSGI configuration]')
    http.update_httpd_wsgi_conf()


def update_http_keytab(http):
    logger.info('[Moving HTTPD service keytab to gssproxy]')
    if os.path.exists(paths.OLD_IPA_KEYTAB):
        # ensure proper SELinux context by using copy operation
        shutil.copy(paths.OLD_IPA_KEYTAB, http.keytab)
        try:
            os.remove(paths.OLD_IPA_KEYTAB)
        except OSError as e:
            logger.error(
                'Cannot remove file %s (%s). Please remove the file manually.',
                paths.OLD_IPA_KEYTAB, e
            )
    http.keytab_user.chown(http.keytab)
    tasks.restore_context(http.keytab)


def ds_enable_sidgen_extdom_plugins(ds):
    """For AD trust agents, make sure we enable sidgen and extdom plugins
    """
    logger.info('[Enable sidgen and extdom plugins by default]')

    if sysupgrade.get_upgrade_state('ds', 'enable_ds_sidgen_extdom_plugins'):
        logger.debug('sidgen and extdom plugins are enabled already')
        return False

    ds.add_sidgen_plugin(api.env.basedn)
    ds.add_extdom_plugin(api.env.basedn)
    sysupgrade.set_upgrade_state('ds', 'enable_ds_sidgen_extdom_plugins', True)
    return True


def ds_enable_graceperiod_plugin(ds):
    """Graceperiod is a newer DS plugin so needs to be enabled on upgrade"""
    if sysupgrade.get_upgrade_state('ds', 'enable_ds_graceperiod_plugin'):
        logger.debug('graceperiod is enabled already')
        return False

    ds.config_graceperiod_module()
    sysupgrade.set_upgrade_state('ds', 'enable_ds_graceperiod_plugin', True)
    return True


def ca_upgrade_schema(ca):
    logger.info('[Upgrading CA schema]')
    if not ca.is_configured():
        logger.info('CA is not configured')
        return False

    # ACME schema file moved in pki-server-10.9.0-0.3
    # ACME database connections were abstrated in pki-acme-10.10.0
    for path in [
        '/usr/share/pki/acme/conf/database/ds/schema.ldif',
        '/usr/share/pki/acme/conf/database/ldap/schema.ldif',
        '/usr/share/pki/acme/database/ldap/schema.ldif',
    ]:
        if os.path.exists(path):
            acme_schema_ldif = path
            break
    else:
        logger.info('ACME schema is not available')
        return False

    schema_files=[
        '/usr/share/pki/server/conf/schema-certProfile.ldif',
        '/usr/share/pki/server/conf/schema-authority.ldif',
        acme_schema_ldif,
    ]
    try:
        modified = schemaupdate.update_schema(schema_files, ldapi=True)
    except Exception as e:
        logger.error("%s", e)
        raise RuntimeError('CA schema upgrade failed.', 1)
    else:
        if modified:
            logger.info('CA schema update complete')
            return True
        else:
            logger.info('CA schema update complete (no changes)')
            return False


def add_default_caacl(ca):
    logger.info('[Add default CA ACL]')

    if sysupgrade.get_upgrade_state('caacl', 'add_default_caacl'):
        logger.info('Default CA ACL already added')
        return

    if ca.is_configured():
        cainstance.ensure_default_caacl()

    sysupgrade.set_upgrade_state('caacl', 'add_default_caacl', True)


def add_agent_to_security_domain_admins():
    user_dn = DN(('uid', "ipara"), ('ou', 'People'), ('o', 'ipaca'))
    group_dn = DN(('cn', 'Security Domain Administrators'), ('ou', 'groups'),
                  ('o', 'ipaca'))
    try:
        api.Backend.ldap2.add_entry_to_group(user_dn, group_dn, 'uniqueMember')
    except ipalib.errors.AlreadyGroupMember:
        pass


def setup_pkinit(krb):
    logger.info("[Setup PKINIT]")

    if not krbinstance.is_pkinit_enabled():
        krb.issue_selfsigned_pkinit_certs()

    aug = Augeas(flags=Augeas.NO_LOAD | Augeas.NO_MODL_AUTOLOAD,
                 loadpath=paths.USR_SHARE_IPA_DIR)
    try:
        aug.transform('IPAKrb5', paths.KRB5KDC_KDC_CONF)
        aug.load()

        path = '/files{}/realms/{}'.format(paths.KRB5KDC_KDC_CONF, krb.realm)
        modified = False

        value = 'FILE:{},{}'.format(paths.KDC_CERT, paths.KDC_KEY)
        expr = '{}[count(pkinit_identity)=1][pkinit_identity="{}"]'.format(
            path, value)
        if not aug.match(expr):
            aug.remove('{}/pkinit_identity'.format(path))
            aug.set('{}/pkinit_identity'.format(path), value)
            modified = True

        for value in  ['FILE:{}'.format(paths.KDC_CERT),
                       'FILE:{}'.format(paths.CACERT_PEM)]:
            expr = '{}/pkinit_anchors[.="{}"]'.format(path, value)
            if not aug.match(expr):
                aug.set('{}/pkinit_anchors[last()+1]'.format(path), value)
                modified = True

        value = 'FILE:{}'.format(paths.CA_BUNDLE_PEM)
        expr = '{}/pkinit_pool[.="{}"]'.format(path, value)
        if not aug.match(expr):
            aug.set('{}/pkinit_pool[last()+1]'.format(path), value)
            modified = True

        if modified:
            try:
                aug.save()
            except IOError:
                for error_path in aug.match('/augeas//error'):
                    logger.error('augeas: %s', aug.get(error_path))
                raise

            if krb.is_running():
                krb.stop()
            krb.start()
    finally:
        aug.close()


def setup_spake(krb):
    logger.info("[Setup SPAKE]")

    aug = Augeas(flags=Augeas.NO_LOAD | Augeas.NO_MODL_AUTOLOAD,
                 loadpath=paths.USR_SHARE_IPA_DIR)
    try:
        aug.transform("IPAKrb5", paths.KRB5KDC_KDC_CONF)
        aug.load()

        path = "/files{}/libdefaults/spake_preauth_kdc_challenge"
        path = path.format(paths.KRB5KDC_KDC_CONF)
        value = "edwards25519"
        if aug.match(path):
            return

        aug.remove(path)
        aug.set(path, value)
        try:
            aug.save()
        except IOError:
            for error_path in aug.match('/augeas//error'):
                logger.error('augeas: %s', aug.get(error_path))
                raise

        if krb.is_running():
            krb.stop()
            krb.start()
    finally:
        aug.close()


# Currently, this doesn't support templating.
def enable_server_snippet():
    logger.info("[Enable server krb5.conf snippet]")
    template = os.path.join(
        paths.USR_SHARE_IPA_DIR,
        os.path.basename(paths.KRB5_FREEIPA_SERVER) + ".template"
    )
    shutil.copy(template, paths.KRB5_FREEIPA_SERVER)
    os.chmod(paths.KRB5_FREEIPA_SERVER, 0o644)

    tasks.restore_context(paths.KRB5_FREEIPA_SERVER)


def setup_kpasswd_server(krb):
    logger.info("[Setup kpasswd_server]")
    aug = Augeas(
        flags=Augeas.NO_LOAD | Augeas.NO_MODL_AUTOLOAD,
        loadpath=paths.USR_SHARE_IPA_DIR,
    )
    try:
        aug.transform("IPAKrb5", paths.KRB5_CONF)
        aug.load()

        kpass_srv_path = "/files{}/realms/{}/kpasswd_server"
        kpass_srv_path = kpass_srv_path.format(paths.KRB5_CONF, krb.realm)

        if aug.match(kpass_srv_path):
            return

        aug.set(kpass_srv_path, f"{krb.fqdn}:464")
        aug.save()

    finally:
        aug.close()


def ntpd_cleanup(fqdn, fstore):
    sstore = sysrestore.StateFile(paths.SYSRESTORE)
    timeconf.restore_forced_timeservices(sstore, 'ntpd')
    if sstore.has_state('ntp'):
        instance = services.service('ntpd', api)
        sstore.restore_state(instance.service_name, 'enabled')
        sstore.restore_state(instance.service_name, 'running')
        sstore.restore_state(instance.service_name, 'step-tickers')
        try:
            instance.disable()
            instance.stop()
        except Exception:
            logger.debug("Service ntpd was not disabled or stopped")

    for ntpd_file in [paths.NTP_CONF, paths.NTP_STEP_TICKERS,
                      paths.SYSCONFIG_NTPD]:
        try:
            fstore.restore_file(ntpd_file)
        except ValueError as e:
            logger.debug(e)

    try:
        api.Backend.ldap2.delete_entry(DN(('cn', 'NTP'), ('cn', fqdn),
                                       api.env.container_masters))
    except ipalib.errors.NotFound:
        logger.debug("NTP service entry was not found in LDAP.")

    ntp_role_instance = servroles.ServiceBasedRole(
         u"ntp_server_server",
         u"NTP server",
         component_services=['NTP']
    )

    updated_role_instances = tuple()
    for role_instance in servroles.role_instances:
        if role_instance is not ntp_role_instance:
            updated_role_instances += tuple([role_instance])

    servroles.role_instances = updated_role_instances
    sysupgrade.set_upgrade_state('ntpd', 'ntpd_cleaned', True)


def update_replica_config(db_suffix):
    dn = DN(
        ('cn', 'replica'), ('cn', db_suffix), ('cn', 'mapping tree'),
        ('cn', 'config')
    )
    try:
        entry = api.Backend.ldap2.get_entry(dn)
    except ipalib.errors.NotFound:
        return  # entry does not exist until a replica is installed

    for key, value in replication.REPLICA_FINAL_SETTINGS.items():
        entry[key] = value
    try:
        api.Backend.ldap2.update_entry(entry)
    except ipalib.errors.EmptyModlist:
        pass
    else:
        logger.info("Updated entry %s", dn)


def migrate_to_authselect():
    logger.info('[Migrating to authselect profile]')
    if sysupgrade.get_upgrade_state('authcfg', 'migrated_to_authselect'):
        logger.info("Already migrated to authselect profile")
        return

    statestore = sysrestore.StateFile(paths.IPA_CLIENT_SYSRESTORE)
    try:
        tasks.migrate_auth_configuration(statestore)
    except ipautil.CalledProcessError as e:
        raise RuntimeError(
            "Failed to migrate to authselect profile: %s" % e, 1)
    sysupgrade.set_upgrade_state('authcfg', 'migrated_to_authselect', True)


def add_systemd_user_hbac():
    logger.info('[Create systemd-user hbac service and rule]')
    rule = u'allow_systemd-user'
    service = u'systemd-user'
    try:
        api.Command.hbacsvc_add(
            service,
            description=u'pam_systemd and systemd user@.service'
        )
    except ipalib.errors.DuplicateEntry:
        logger.info('hbac service %s already exists', service)
        # Don't create hbac rule when hbacsvc already exists, so the rule
        # does not get re-created after it has been deleted by an admin.
        return
    else:
        logger.info('Created hbacsvc %s', service)

    try:
        api.Command.hbacrule_add(
            rule,
            description=(u'Allow pam_systemd to run user@.service to create '
                         'a system user session'),
            usercategory=u'all',
            hostcategory=u'all',
        )
    except ipalib.errors.DuplicateEntry:
        logger.info('hbac rule %s already exists', rule)
    else:
        api.Command.hbacrule_add_service(
            rule,
            hbacsvc=(service,)
        )
        logger.info('Created hbac rule %s with hbacsvc=%s', rule, service)


def add_admin_root_alias():
    """Make root principal an alias of admin

    Fix for CVE-2020-10747
    """
    rootprinc = "root@{}".format(api.env.realm)
    logger.info("[Add %s alias to admin account]", rootprinc)
    try:
        api.Command.user_add_principal("admin", rootprinc)
    except ipalib.errors.DuplicateEntry:
        results = api.Command.user_find(krbprincipalname=rootprinc)
        uid = results["result"][0]["uid"][0]
        logger.warning(
            "WARN: '%s' alias is assigned to user '%s'!", rootprinc, uid
        )
    except ipalib.errors.AlreadyContainsValueError:
        logger.info("Alias already exists")
    else:
        logger.info("Added '%s' alias to admin account", rootprinc)


def fix_permissions():
    """Fix permission of public accessible files and directories

    In case IPA was installed with restricted umask, some public files and
    directories may not be readable and accessible.

    See https://pagure.io/freeipa/issue/7594
    """
    candidates = [
        os.path.dirname(paths.GSSAPI_SESSION_KEY),
        paths.CA_BUNDLE_PEM,
        paths.KDC_CA_BUNDLE_PEM,
        paths.IPA_CA_CRT,
        paths.IPA_P11_KIT,
    ]
    for filename in candidates:
        try:
            s = os.stat(filename)
        except OSError as e:
            if e.errno != errno.ENOENT:
                raise
            continue
        mode = 0o755 if stat.S_ISDIR(s.st_mode) else 0o644
        if mode != stat.S_IMODE(s.st_mode):
            logger.debug("Fix permission of %s to %o", filename, mode)
            os.chmod(filename, mode)


def upgrade_bind(fstore):
    """Update BIND named DNS server instance
    """
    bind = bindinstance.BindInstance(fstore, api=api)
    bind.setup_templating(
        fqdn=api.env.host,
        realm_name=api.env.realm,
        domain_name=api.env.domain
    )

    # always executed
    add_ca_dns_records(bind)

    if not bindinstance.named_conf_exists():
        logger.info("DNS service is not configured")
        return False

    bind_switch_service(bind)

    # get rid of old states
    bind_old_states(bind)
    bind_old_upgrade_states()

    # only upgrade with drop-in is missing and /etc/resolv.conf is a link to
    # resolve1's stub resolver config file.
    has_resolved_ipa_conf = os.path.isfile(paths.SYSTEMD_RESOLVED_IPA_CONF)
    if not has_resolved_ipa_conf and detect_resolve1_resolv_conf():
        ip_addresses = installutils.resolve_ip_addresses_nss(
            api.env.host
        )
        bind.ip_addresses = ip_addresses
        bind.setup_resolv_conf()
        logger.info("Updated systemd-resolved configuration")

    if bind.is_configured() and not bind.is_running():
        # some upgrade steps may require bind running
        bind_started = True
        bind.start()
    else:
        bind_started = False

    # create or update autobind entry
    bind.setup_autobind()

    try:
        changed = bind.setup_named_conf(backup=True)
        if changed:
            logger.info("named.conf has been modified, restarting named")
        try:
            if bind.is_running():
                bind.restart()
        except ipautil.CalledProcessError as e:
            logger.error("Failed to restart %s: %s", bind.service_name, e)
    finally:
        if bind_started:
            bind.stop()

    return changed


def bind_switch_service(bind):
    """
    Mask either named or named-pkcs11, we need to run only one,
    running both can cause unexpected errors.
    """
    named_conflict_name = bind.named_conflict.systemd_name
    named_conflict_old = sysupgrade.get_upgrade_state('dns', 'conflict_named')

    # nothing changed
    if named_conflict_old and named_conflict_old == named_conflict_name:
        return False

    bind.switch_service()

    sysupgrade.set_upgrade_state('dns', 'conflict_named', named_conflict_name)
    return True


def bind_old_states(bind):
    """Remove old states
    """
    # no longer used states
    old_states = [
        "enabled",
        "running",
        "named-regular-enabled",
        "named-regular-running",
    ]
    for state in old_states:
        bind.delete_state(state)


def bind_old_upgrade_states():
    """Remove old upgrade states
    """
    named_conf_states = (
        # old states before 4.8.7
        "gssapi_updated",
        "pid-file_updated",
        "dnssec-enabled_remove",
        "bindkey-file_removed",
        "managed-keys-directory_updated",
        "root_key_updated",
        "forward_policy_conflict_with_empty_zones_handled",
        "add_server_id",
        "add_crypto_policy",
    )
    dns_states = (
        "regular_named_masked",
        "dyndb_ipa_workdir_perm"
    )
    for state in named_conf_states:
        sysupgrade.remove_upgrade_state("named.conf", state)
    for state in dns_states:
        sysupgrade.remove_upgrade_state("dns", state)


def ca_update_acme_configuration(ca, fqdn):
    """
    Re-apply the templates in case anyting has been updated.
    """
    logger.info('[Updating ACME configuration]')
    if not os.path.isdir(os.path.join(paths.PKI_TOMCAT, 'acme')):
        logger.info('ACME is not deployed, skipping')
        return

    if not os.path.exists(paths.PKI_ACME_ISSUER_CONF):
        logger.info('ACME configuration file %s is missing',
                    paths.PKI_ACME_ISSUER_CONF)
        return

    password = directivesetter.get_directive(
        paths.PKI_ACME_ISSUER_CONF,
        'password',
        separator='=')
    acme_user = ca.acme_uid(fqdn)
    sub_dict = dict(
        FQDN=fqdn,
        USER=acme_user,
        PASSWORD=password,
    )
    for template_name, target in cainstance.ACME_CONFIG_FILES:
        upgrade_file(sub_dict, target,
                     os.path.join(paths.USR_SHARE_IPA_DIR,
                                  template_name))


def set_default_grace_time():
    dn = DN(
        ('cn', 'global_policy'), ('cn', api.env.realm),
        ('cn', 'kerberos'), api.env.basedn
    )
    entry = api.Backend.ldap2.get_entry(dn)
    for (a,_v) in entry.items():
        if a.lower() == 'passwordgracelimit':
            return

    entry['objectclass'].append('ipapwdpolicy')
    entry['passwordgracelimit'] = -1
    api.Backend.ldap2.update_entry(entry)


def upgrade_configuration():
    """
    Execute configuration upgrade of the IPA services
    """

    logger.debug('IPA version %s', version.VENDOR_VERSION)

    fstore = sysrestore.FileStore(paths.SYSRESTORE)
    sstore = sysrestore.StateFile(paths.SYSRESTORE)

    if not sstore.has_state('installation'):
        if is_ipa_configured():
            sstore.backup_state('installation', 'complete', True)
        else:
            sstore.backup_state('installation', 'complete', False)

    fqdn = api.env.host

    # Ok, we are an IPA server, do the additional tests
    ds = dsinstance.DsInstance(realm_name=api.env.realm)

    # start DS, CA will not start without running DS, and cause error
    ds_running = ds.is_running()
    if not ds_running:
        ds.start(ds.serverid)

    if not sysupgrade.get_upgrade_state('ntpd', 'ntpd_cleaned'):
        ntpd_cleanup(fqdn, fstore)

    if tasks.configure_pkcs11_modules(fstore):
        print("Disabled p11-kit-proxy")

    check_certs()
    fix_permissions()

    auto_redirect = find_autoredirect(fqdn)
    sub_dict = dict(
        REALM=api.env.realm,
        FQDN=fqdn,
        AUTOREDIR='' if auto_redirect else '#',
        CRL_PUBLISH_PATH=paths.PKI_CA_PUBLISH_DIR,
        DOGTAG_PORT=8009,
        CLONE='#',
        WSGI_PREFIX_DIR=paths.WSGI_PREFIX_DIR,
        WSGI_PROCESSES=constants.WSGI_PROCESSES,
        GSSAPI_SESSION_KEY=paths.GSSAPI_SESSION_KEY,
        FONTS_DIR=paths.FONTS_DIR,
        FONTS_OPENSANS_DIR=paths.FONTS_OPENSANS_DIR,
        FONTS_FONTAWESOME_DIR=paths.FONTS_FONTAWESOME_DIR,
        IPA_CCACHES=paths.IPA_CCACHES,
        IPA_CUSTODIA_SOCKET=paths.IPA_CUSTODIA_SOCKET,
        KDCPROXY_CONFIG=paths.KDCPROXY_CONFIG,
        DOMAIN=api.env.domain,
    )

    subject_base = find_subject_base()
    if subject_base:
        sub_dict['ISSUER_DN'] = 'CN=Certificate Authority,' + subject_base

    ca = cainstance.CAInstance(
            api.env.realm, host_name=api.env.host)
    ca_running = ca.is_running()

    kra = krainstance.KRAInstance(api.env.realm)

    # create passswd.txt file in PKI_TOMCAT_ALIAS_DIR if it does not exist
    # this file will be required on most actions over this NSS DB in FIPS
    if ca.is_configured() and not os.path.exists(os.path.join(
            paths.PKI_TOMCAT_ALIAS_DIR, 'pwdfile.txt')):
        ca.create_certstore_passwdfile()

    with installutils.stopped_service('pki-tomcatd', 'pki-tomcat'):
        # Dogtag must be stopped to be able to backup CS.cfg config
        if ca.is_configured():
            ca.backup_config()

        # migrate CRL publish dir before the location in ipa.conf is updated
        ca_restart = migrate_crl_publish_dir(ca)

        if ca.is_configured():
            crl = directivesetter.get_directive(
                paths.CA_CS_CFG_PATH, 'ca.crl.MasterCRL.enableCRLUpdates', '=')
            sub_dict['CLONE']='#' if crl.lower() == 'true' else ''

        ds_dirname = dsinstance.config_dirname(ds.serverid)

        upgrade_file(sub_dict, paths.HTTPD_IPA_CONF,
                     os.path.join(paths.USR_SHARE_IPA_DIR,
                                  "ipa.conf.template"))
        upgrade_file(sub_dict, paths.HTTPD_IPA_REWRITE_CONF,
                     os.path.join(paths.USR_SHARE_IPA_DIR,
                                  "ipa-rewrite.conf.template"))
        upgrade_file(sub_dict, paths.HTTPD_IPA_KDCPROXY_CONF,
                     os.path.join(paths.USR_SHARE_IPA_DIR,
                                  "ipa-kdc-proxy.conf.template"))
        if ca.is_configured():
            # Ensure that the drop-in file is present
            if not os.path.isfile(paths.SYSTEMD_PKI_TOMCAT_IPA_CONF):
                ca.add_ipa_wait()

            # Handle upgrade of AJP connector configuration
            rewrite = ca.secure_ajp_connector()
            if ca.ajp_secret:
                sub_dict['DOGTAG_AJP_SECRET'] = "secret={}".format(
                    ca.ajp_secret)
            else:
                sub_dict['DOGTAG_AJP_SECRET'] = ''

            # force=True will ensure the secret is updated if it changes
            if rewrite:
                upgrade_file(
                    sub_dict,
                    paths.HTTPD_IPA_PKI_PROXY_CONF,
                    os.path.join(paths.USR_SHARE_IPA_DIR,
                                 "ipa-pki-proxy.conf.template"),
                    add=True, force=True)
        else:
            if os.path.isfile(paths.HTTPD_IPA_PKI_PROXY_CONF):
                os.remove(paths.HTTPD_IPA_PKI_PROXY_CONF)
        if subject_base:
            upgrade_file(
                sub_dict,
                os.path.join(ds_dirname, "certmap.conf"),
                os.path.join(paths.USR_SHARE_IPA_DIR, "certmap.conf.template")
            )

        if kra.is_installed():
            logger.info('[Ensuring ephemeralRequest is enabled in KRA]')
            kra.backup_config()
            value = directivesetter.get_directive(
                paths.KRA_CS_CFG_PATH,
                'kra.ephemeralRequests',
                separator='=')
            if value is None or value.lower() != 'true':
                logger.info('Enabling ephemeralRequest')
                kra.enable_ephemeral()
            else:
                logger.info('ephemeralRequest is already enabled')

            if tasks.is_fips_enabled():
                logger.info('[Ensuring KRA OAEP wrap algo is enabled in FIPS]')
                value = directivesetter.get_directive(
                    paths.KRA_CS_CFG_PATH,
                    'keyWrap.useOAEP',
                    separator='=')
                if value is None or value.lower() != 'true':
                    logger.info('Use the OAEP key wrap algo')
                    kra.enable_oaep_wrap_algo()
                else:
                    logger.info('OAEP key wrap algo is already enabled')

    # several upgrade steps require running CA.  If CA is configured,
    # always run ca.start() because we need to wait until CA is really ready
    # by checking status using http
    if ca.is_configured():
        ca.start('pki-tomcat')
    if kra.is_installed() and not kra.is_running():
        # This is for future-proofing in case the KRA is ever standalone.
        kra.start('pki-tomcat')

    certmonger_service = services.knownservices.certmonger
    if ca.is_configured() and not certmonger_service.is_running():
        certmonger_service.start()

    ca.unconfigure_certmonger_renewal_guard()

    update_dbmodules(api.env.realm)
    uninstall_ipa_kpasswd()
    uninstall_ipa_memcached()

    removed_sysconfig_file = paths.SYSCONFIG_HTTPD
    if fstore.has_file(removed_sysconfig_file):
        logger.info('Restoring %s as it is no longer required',
                    removed_sysconfig_file)
        fstore.restore_file(removed_sysconfig_file)

    http = httpinstance.HTTPInstance(fstore)
    http.fqdn = fqdn
    http.realm = api.env.realm
    http.suffix = ipautil.realm_to_suffix(api.env.realm)
    http.configure_selinux_for_httpd()
    http.set_mod_ssl_protocol()

    http.configure_certmonger_renewal_guard()

    http.enable_and_start_oddjobd()

    ds.configure_systemd_ipa_env()

    update_replica_config(ipautil.realm_to_suffix(api.env.realm))
    if ca.is_configured():
        update_replica_config(DN(('o', 'ipaca')))

    ds.stop(ds.serverid)
    fix_schema_file_syntax()
    remove_ds_ra_cert(subject_base)
    ds.start(ds.serverid)

    ds.fqdn = fqdn
    ds.realm = api.env.realm
    ds.suffix = ipautil.realm_to_suffix(api.env.realm)

    if any([
        ds_enable_sidgen_extdom_plugins(ds),
        ds_enable_graceperiod_plugin(ds)
    ]):
        ds.restart(ds.serverid)

    set_default_grace_time()

    if not http.is_kdcproxy_configured():
        logger.info('[Enabling KDC Proxy]')
        http.create_kdcproxy_conf()
        http.enable_kdcproxy()

    http.stop()
    update_ipa_httpd_service_conf(http)
    update_ipa_http_wsgi_conf(http)
    migrate_to_mod_ssl(http)
    update_http_keytab(http)
    http.configure_gssproxy()
    http.start()

    uninstall_selfsign(ds, http)
    uninstall_dogtag_9(ds, http)

    simple_service_list = (
        (otpdinstance.OtpdInstance(), 'OTPD'),
    )

    for svc, ldap_name in simple_service_list:
        try:
            if not svc.is_configured():
                svc.create_instance(ldap_name, fqdn,
                                    ipautil.realm_to_suffix(api.env.realm),
                                    realm=api.env.realm)
        except ipalib.errors.DuplicateEntry:
            pass

    # install DNSKeySync service only if DNS is configured on server
    if bindinstance.named_conf_exists():
            dnskeysyncd = dnskeysyncinstance.DNSKeySyncInstance(fstore)
            if not dnskeysyncd.is_configured():
                dnskeysyncd.create_instance(fqdn, api.env.realm)
                dnskeysyncd.start_dnskeysyncd()
            else:
                if dnssec_set_openssl_engine(dnskeysyncd):
                    dnskeysyncd.start_dnskeysyncd()
            dnskeysyncd.set_dyndb_ldap_workdir_permissions()

    cleanup_kdc(fstore)
    cleanup_adtrust(fstore)
    cleanup_dogtag()
    upgrade_adtrust_config()

    upgrade_bind(fstore)

    custodia = custodiainstance.CustodiaInstance(api.env.host, api.env.realm)
    custodia.upgrade_instance()

    # Don't include schema upgrades in restart consideration, see
    # https://pagure.io/freeipa/issue/9204
    ca_upgrade_schema(ca)

    ca_restart = any([
        ca_restart,
        certificate_renewal_update(ca, kra, ds, http),
        ca_enable_pkix(ca),
        ca_configure_profiles_acl(ca),
        ca_configure_lightweight_ca_acls(ca),
        ca_ensure_lightweight_cas_container(ca),
        ca_enable_lightweight_ca_monitor(ca),
        ca_add_default_ocsp_uri(ca),
        ca_disable_publish_cert(ca),
    ])

    if ca_restart:
        logger.info(
            'pki-tomcat configuration changed, restart pki-tomcat')
        try:
            ca.restart('pki-tomcat')
        except ipautil.CalledProcessError as e:
            logger.error("Failed to restart %s: %s", ca.service_name, e)

    ca_enable_ldap_profile_subsystem(ca)

    # This step MUST be done after ca_enable_ldap_profile_subsystem and
    # ca_configure_profiles_acl, and the consequent restart, but does not
    # itself require a restart.
    #
    ca_import_included_profiles(ca)
    add_default_caacl(ca)

    if ca.is_configured():
        ca.reindex_task()
        cainstance.repair_profile_caIPAserviceCert()
        ca.setup_lightweight_ca_key_retrieval()
        cainstance.ensure_ipa_authority_entry()
        ca.setup_acme()
        ca_update_acme_configuration(ca, fqdn)
        ca_initialize_hsm_state(ca)
        add_agent_to_security_domain_admins()

    migrate_to_authselect()
    add_systemd_user_hbac()
    add_admin_root_alias()

    sssd_update()

    krb = krbinstance.KrbInstance(fstore)
    krb.fqdn = fqdn
    krb.realm = api.env.realm
    krb.suffix = ipautil.realm_to_suffix(krb.realm)
    krb.subject_base = subject_base
    krb.sub_dict = dict(FQDN=krb.fqdn,
                        SUFFIX=krb.suffix,
                        DOMAIN=api.env.domain,
                        HOST=api.env.host,
                        SERVER_ID=ipaldap.realm_to_serverid(krb.realm),
                        REALM=krb.realm,
                        KRB5KDC_KADM5_ACL=paths.KRB5KDC_KADM5_ACL,
                        DICT_WORDS=paths.DICT_WORDS,
                        KRB5KDC_KADM5_KEYTAB=paths.KRB5KDC_KADM5_KEYTAB,
                        KDC_CERT=paths.KDC_CERT,
                        KDC_KEY=paths.KDC_KEY,
                        CACERT_PEM=paths.CACERT_PEM,
                        KDC_CA_BUNDLE_PEM=paths.KDC_CA_BUNDLE_PEM,
                        CA_BUNDLE_PEM=paths.CA_BUNDLE_PEM)
    krb.add_anonymous_principal()
    setup_spake(krb)
    setup_pkinit(krb)
    enable_server_snippet()
    setup_kpasswd_server(krb)

    if KRB5_BUILD_VERSION >= parse_version('1.20'):
        krb.pac_tkt_sign_support_enable()

    # Must be executed after certificate_renewal_update
    # (see function docstring for details)
    http_certificate_ensure_ipa_ca_dnsname(http)

    # Convert configuredService to either enabledService or hiddenService
    # depending on the state of the server role.  This is to fix situations
    # when deployment has happened before introduction of hidden replicas
    # as those services will stay as configuredService and will not get
    # started after upgrade, rendering the system non-functioning
    service.sync_services_state(fqdn)

    if not ds_running:
        ds.stop(ds.serverid)

    if ca.is_configured():
        if ca_running and not ca.is_running():
            ca.start('pki-tomcat')
        elif not ca_running and ca.is_running():
            ca.stop('pki-tomcat')


def upgrade_check(options):
    try:
        installutils.check_server_configuration()
        tasks.check_ipv6_stack_enabled()
    except RuntimeError as e:
        logger.error("%s", e)
        sys.exit(1)

    if not options.skip_version_check:
        # check IPA version and data version
        try:
            installutils.check_version()
        except (installutils.UpgradePlatformError,
                installutils.UpgradeDataNewerVersionError) as e:
            raise RuntimeError(
                'Unable to execute IPA upgrade: %s' % e, 1)
        except installutils.UpgradeMissingVersionError as e:
            logger.info("Missing version: %s", e)
        except installutils.UpgradeVersionError:
            # Ignore other errors
            pass
    else:
        logger.info("Skipping version check")
        logger.warning("Upgrade without version check may break your system")


@contextmanager
def empty_ccache():
    # Create temporary directory and use it as a DIR: ccache collection
    # instead of whatever is a default in /etc/krb5.conf
    #
    # In Fedora 28 KCM: became a default credentials cache collection
    # but if KCM daemon (part of SSSD) is not running, libkrb5 will fail
    # to initialize. This causes kadmin.local to fail.
    # Since we are in upgrade, we cannot kinit anyway (KDC is offline).
    # Bug https://bugzilla.redhat.com/show_bug.cgi?id=1558818
    kpath_dir = tempfile.mkdtemp(prefix="upgrade_ccaches",
                                 dir=paths.IPA_CCACHES)
    kpath = "DIR:{}".format(kpath_dir)
    old_path = os.environ.get('KRB5CCNAME')
    try:
        os.environ['KRB5CCNAME'] = kpath
        yield
    finally:
        if old_path:
            os.environ['KRB5CCNAME'] = old_path
        else:
            os.environ.pop('KRB5CCNAME', None)
        shutil.rmtree(kpath_dir)


def upgrade():
    realm = api.env.realm
    schema_files = [os.path.join(paths.USR_SHARE_IPA_DIR, f) for f
                    in dsinstance.ALL_SCHEMA_FILES]

    schema_files.extend(dsinstance.get_all_external_schema_files(
                        paths.EXTERNAL_SCHEMA_DIR))
    data_upgrade = IPAUpgrade(realm, schema_files=schema_files)

    try:
        data_upgrade.create_instance()
    except BadSyntax:
        raise RuntimeError(
            'Bad syntax detected in upgrade file(s).', 1)
    except RuntimeError:
        raise RuntimeError('IPA upgrade failed.', 1)
    else:
        if data_upgrade.modified:
            logger.info('Update complete')
        else:
            logger.info('Update complete, no data were modified')

    print('Upgrading IPA services')
    logger.info('Upgrading the configuration of the IPA services')
    with empty_ccache():
        upgrade_configuration()
    logger.info('The IPA services were upgraded')

    # store new data version after upgrade
    installutils.store_version()
