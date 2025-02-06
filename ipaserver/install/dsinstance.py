# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#          Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007  Red Hat
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

import logging
import shutil
import os
import tempfile
import fnmatch

from lib389 import DirSrv
from lib389.idm.ipadomain import IpaDomain
from lib389.instance.options import General2Base, Slapd2Base
from lib389.instance.remove import remove_ds_instance as lib389_remove_ds
from lib389.instance.setup import SetupDs
from lib389.utils import get_default_db_lib

from ipalib import x509
from ipalib.install import certmonger, certstore
from ipapython.certdb import (IPA_CA_TRUST_FLAGS,
                              EXTERNAL_CA_TRUST_FLAGS,
                              TrustFlags)
from ipapython import ipautil, ipaldap
from ipapython import dogtag
from ipaserver.install import service
from ipaserver.install import installutils
from ipaserver.install import certs
from ipaserver.install import replication
from ipaserver.install import sysupgrade
from ipaserver.install import upgradeinstance
from ipaserver.install import ldapupdate
from ipalib import api
from ipalib import errors
from ipalib import constants
from ipaplatform.constants import constants as platformconstants
from ipaplatform.tasks import tasks
from ipapython.dn import DN
from ipapython.admintool import ScriptError
from ipaplatform import services
from ipaplatform.paths import paths

logger = logging.getLogger(__name__)

DS_USER = platformconstants.DS_USER
DS_GROUP = platformconstants.DS_GROUP

IPA_SCHEMA_FILES = ("60kerberos.ldif",
                    "60samba.ldif",
                    "60ipaconfig.ldif",
                    "60basev2.ldif",
                    "60basev3.ldif",
                    "60basev4.ldif",
                    "60ipapk11.ldif",
                    "60ipadns.ldif",
                    "60certificate-profiles.ldif",
                    "61kerberos-ipav3.ldif",
                    "65ipacertstore.ldif",
                    "65ipasudo.ldif",
                    "70ipaotp.ldif",
                    "70topology.ldif",
                    "71idviews.ldif",
                    "72domainlevels.ldif",
                    "73certmap.ldif",
                    "75pgp.ldif",
                    "15rfc2307bis.ldif",
                    "15rfc4876.ldif")

ALL_SCHEMA_FILES = IPA_SCHEMA_FILES + ("05rfc2247.ldif", )
DS_INSTANCE_PREFIX = 'slapd-'


def find_server_root():
    if os.path.isdir(paths.USR_LIB_DIRSRV_64):
        return paths.USR_LIB_DIRSRV_64
    else:
        return paths.USR_LIB_DIRSRV

def config_dirname(serverid):
    return (paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % serverid) + "/"

def schema_dirname(serverid):
    return config_dirname(serverid) + "/schema/"


def remove_ds_instance(serverid):
    """Call the lib389 api to remove the instance. Because of the
    design of the api, there is no "force" command. Provided a marker
    file exists, it will attempt the removal, and the marker is the *last*
    file to be removed. IE just run this multiple times til it works (if
    you even need multiple times ....)
    """

    logger.debug("Attempting to remove instance %s", serverid)
    # Alloc the local instance by name (no creds needed!)
    ds = DirSrv(verbose=True, external_log=logger)
    ds.local_simple_allocate(serverid)

    # Remove it
    lib389_remove_ds(ds)
    logger.debug("Instance removed correctly.")


def get_ds_instances():
    '''
    Return a sorted list of all 389ds instances.

    If the instance name ends with '.removed' it is ignored. This
    matches 389ds behavior.
    '''

    dirsrv_instance_dir = paths.ETC_DIRSRV

    instances = []

    for basename in os.listdir(dirsrv_instance_dir):
        pathname = os.path.join(dirsrv_instance_dir, basename)
        # Must be a directory
        if os.path.isdir(pathname):
            # Must start with prefix and not end with .removed
            if (basename.startswith(DS_INSTANCE_PREFIX) and
                    not basename.endswith('.removed')):
                # Strip off prefix
                instance = basename[len(DS_INSTANCE_PREFIX):]
                # Must be non-empty
                if instance:
                    instances.append(instance)

    instances.sort()
    return instances

def check_ports():
    """
    Check of Directory server ports are open.

    Returns a tuple with two booleans, one for unsecure port 389 and one for
    secure port 636. True means that the port is free, False means that the
    port is taken.
    """
    ds_unsecure = not ipautil.host_port_open(None, 389)
    ds_secure = not ipautil.host_port_open(None, 636)
    return (ds_unsecure, ds_secure)

def is_ds_running(server_id=''):
    return services.knownservices.dirsrv.is_running(instance_name=server_id)


def get_domain_level(api=api):
    dn = DN(('cn', 'Domain Level'),
            ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)

    with ipaldap.LDAPClient.from_realm(api.env.realm) as conn:
        conn.external_bind()
        try:
            entry = conn.get_entry(dn, ['ipaDomainLevel'])
        except errors.NotFound:
            return constants.DOMAIN_LEVEL_0
        else:
            return int(entry.single_value['ipaDomainLevel'])


def get_all_external_schema_files(root):
    """Get all schema files"""
    f = []
    for path, _subdirs, files in os.walk(root):
        for name in files:
            if fnmatch.fnmatch(name, "*.ldif"):
                f.append(os.path.join(path, name))
    return sorted(f)


class DsInstance(service.Service):
    def __init__(self, realm_name=None, domain_name=None, fstore=None,
                 domainlevel=None, config_ldif=None):
        super(DsInstance, self).__init__(
            "dirsrv",
            service_desc="directory server",
            fstore=fstore,
            service_prefix=u'ldap',
            keytab=paths.DS_KEYTAB,
            service_user=DS_USER,
            realm_name=realm_name
        )
        self.nickname = 'Server-Cert'
        self.sub_dict = None
        self.domain = domain_name
        self.master_fqdn = None
        self.pkcs12_info = None
        self.cacert_name = None
        self.ca_is_configured = True
        self.cert = None
        self.idstart = None
        self.idmax = None
        self.ca_subject = None
        self.subject_base = None
        self.open_ports = []
        self.run_init_memberof = True
        self.config_ldif = config_ldif  # updates for dse.ldif
        self.domainlevel = domainlevel
        if realm_name:
            self.suffix = ipautil.realm_to_suffix(self.realm)
            self.serverid = ipaldap.realm_to_serverid(self.realm)
            if self.domain is None:
                self.domain = self.realm.lower()
            self.__setup_sub_dict()
        else:
            self.suffix = DN()
            self.serverid = None

    subject_base = ipautil.dn_attribute_property('_subject_base')

    def __common_setup(self):

        self.step("creating directory server instance", self.__create_instance)
        if get_default_db_lib() == 'bdb':
            self.step("tune ldbm plugin", self.__tune_ldbm)
        if self.config_ldif is not None:
            self.step("stopping directory server", self.__stop_instance)
            self.step(
                "updating configuration in dse.ldif", self.__update_dse_ldif
            )
            self.step("starting directory server", self.__start_instance)
        self.step("adding default schema", self.__add_default_schemas)
        self.step("enabling memberof plugin", self.__add_memberof_module)
        self.step("enabling winsync plugin", self.__add_winsync_module)
        self.step("configure password logging", self.__password_logging)
        self.step("configuring replication version plugin", self.__config_version_module)
        self.step("enabling IPA enrollment plugin", self.__add_enrollment_module)
        self.step("configuring uniqueness plugin", self.__set_unique_attrs)
        self.step("configuring uuid plugin", self.__config_uuid_module)
        self.step("configuring modrdn plugin", self.__config_modrdn_module)
        self.step("configuring DNS plugin", self.__config_dns_module)
        self.step("enabling entryUSN plugin", self.__enable_entryusn)
        self.step("configuring lockout plugin", self.__config_lockout_module)
        self.step("configuring graceperiod plugin",
                  self.config_graceperiod_module)
        self.step("configuring topology plugin", self.__config_topology_module)
        self.step("creating indices", self.__create_indices)
        self.step("enabling referential integrity plugin", self.__add_referint_module)
        self.step("configuring certmap.conf", self.__certmap_conf)
        self.step("configure new location for managed entries", self.__repoint_managed_entries)
        self.step("configure dirsrv ccache and keytab",
                  self.configure_systemd_ipa_env)
        self.step("enabling SASL mapping fallback",
                  self.__enable_sasl_mapping_fallback)

    def __common_post_setup(self):
        self.step("initializing group membership", self.init_memberof)
        self.step("adding master entry", self.__add_master_entry)
        self.step("initializing domain level", self.__set_domain_level)
        self.step("configuring Posix uid/gid generation",
                  self.__config_uidgid_gen)
        self.step("adding replication acis", self.__add_replication_acis)
        self.step("activating sidgen plugin", self._add_sidgen_plugin)
        self.step("activating extdom plugin", self._add_extdom_plugin)

        self.step("configuring directory to start on boot", self.__enable)
        # restart to enable plugins
        # speeds up creation of DNA plugin entries in cn=dna,cn=ipa,cn=etc
        self.step("restarting directory server", self.__restart_instance)

    def init_info(self, realm_name, fqdn, domain_name, dm_password,
                  subject_base, ca_subject,
                  idstart, idmax, pkcs12_info, ca_file=None,
                  setup_pkinit=False):
        self.realm = realm_name.upper()
        self.serverid = ipaldap.realm_to_serverid(self.realm)
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.fqdn = fqdn
        self.dm_password = dm_password
        self.domain = domain_name
        self.subject_base = subject_base
        self.ca_subject = ca_subject
        self.idstart = idstart
        self.idmax = idmax
        self.pkcs12_info = pkcs12_info
        if pkcs12_info:
            self.ca_is_configured = False
        self.setup_pkinit = setup_pkinit
        self.ca_file = ca_file

        self.__setup_sub_dict()

    def create_instance(self, realm_name, fqdn, domain_name,
                        dm_password, pkcs12_info=None,
                        idstart=1100, idmax=999999,
                        subject_base=None, ca_subject=None,
                        hbac_allow=True, ca_file=None, setup_pkinit=False):
        self.init_info(
            realm_name, fqdn, domain_name, dm_password,
            subject_base, ca_subject,
            idstart, idmax, pkcs12_info, ca_file=ca_file,
            setup_pkinit=setup_pkinit)

        self.__common_setup()
        self.step("restarting directory server", self.__restart_instance)

        self.step("adding sasl mappings to the directory", self.__configure_sasl_mappings)
        self.step("adding default layout", self.__add_default_layout)
        self.step("adding delegation layout", self.__add_delegation_layout)
        self.step("creating container for managed entries", self.__managed_entries)
        self.step("configuring user private groups", self.__user_private_groups)
        self.step("configuring netgroups from hostgroups", self.__host_nis_groups)
        self.step("creating default Sudo bind user", self.__add_sudo_binduser)
        self.step("creating default Auto Member layout", self.__add_automember_config)
        self.step("adding range check plugin", self.__add_range_check_plugin)
        if hbac_allow:
            self.step("creating default HBAC rule allow_all", self.add_hbac)
        self.step("adding entries for topology management", self.__add_topology_entries)

        self.__common_post_setup()

        self.start_creation(runtime=30)

    def enable_ssl(self):
        self.steps = []

        self.step("configuring TLS for DS instance", self.__enable_ssl)
        if self.master_fqdn is None:
            self.step("adding CA certificate entry", self.__upload_ca_cert)
        else:
            self.step("importing CA certificates from LDAP",
                      self.__import_ca_certs)
        self.step("restarting directory server", self.__restart_instance)

        self.start_creation()

    def create_replica(self, realm_name, master_fqdn, fqdn,
                       domain_name, dm_password,
                       subject_base, ca_subject,
                       api, pkcs12_info=None, ca_file=None,
                       ca_is_configured=None,
                       setup_pkinit=False):
        # idstart and idmax are configured so that the range is seen as
        # depleted by the DNA plugin and the replica will go and get a
        # new range from the master.
        # This way all servers use the initially defined range by default.
        idstart = 1101
        idmax = 1100

        self.init_info(
            realm_name=realm_name,
            fqdn=fqdn,
            domain_name=domain_name,
            dm_password=dm_password,
            subject_base=subject_base,
            ca_subject=ca_subject,
            idstart=idstart,
            idmax=idmax,
            pkcs12_info=pkcs12_info,
            ca_file=ca_file,
            setup_pkinit=setup_pkinit,
        )
        self.master_fqdn = master_fqdn
        if ca_is_configured is not None:
            self.ca_is_configured = ca_is_configured
        self.promote = True
        self.api = api

        self.__common_setup()
        self.step("restarting directory server", self.__restart_instance)

        self.step("creating DS keytab", self.request_service_keytab)

        # 389-ds allows to ignore time skew during replication. It is disabled
        # by default to avoid issues with non-contiguous CSN values which
        # derived from a time stamp when the change occurs. However, there are
        # cases when we are interested only in the changes coming from the
        # other side and should therefore allow ignoring the time skew.
        #
        # This helps with initial replication or force-sync because
        # the receiving side has no valuable changes itself yet.
        self.step("ignore time skew for initial replication",
                  self.replica_ignore_initial_time_skew)

        self.step("setting up initial replication", self.__setup_replica)
        self.step("prevent time skew after initial replication",
                  self.replica_revert_time_skew)
        self.step("adding sasl mappings to the directory", self.__configure_sasl_mappings)
        self.step("updating schema", self.__update_schema)
        # See LDIFs for automember configuration during replica install
        self.step("setting Auto Member configuration", self.__add_replica_automember_config)
        self.step("enabling S4U2Proxy delegation", self.__setup_s4u2proxy)

        self.__common_post_setup()

        self.start_creation(runtime=30)

    def _get_replication_manager(self):
        # Always connect to self over ldapi
        conn = ipaldap.LDAPClient.from_realm(self.realm)
        conn.external_bind()
        repl = replication.ReplicationManager(
            self.realm, self.fqdn, self.dm_password, conn=conn
        )
        if self.dm_password is not None and not self.promote:
            bind_dn = DN(('cn', 'Directory Manager'))
            bind_pw = self.dm_password
        else:
            bind_dn = bind_pw = None
        return repl, bind_dn, bind_pw

    def __setup_replica(self):
        """
        Setup initial replication between replica and remote master.
        GSSAPI is always used as a replication bind method. Note, however,
        that the bind method for the replication differs between domain levels:
            * in domain level 0, Directory Manager credentials are used to bind
              to remote master
            * in domain level 1, GSSAPI using admin/privileged host credentials
              is used (we do not have access to masters' DM password in this
              stage)
        """
        replication.enable_replication_version_checking(
            self.realm,
            self.dm_password)

        repl, bind_dn, bind_pw = self._get_replication_manager()
        repl.setup_promote_replication(
            self.master_fqdn,
            r_binddn=bind_dn,
            r_bindpw=bind_pw,
            cacert=self.ca_file
        )
        self.run_init_memberof = repl.needs_memberof_fixup()

    def finalize_replica_config(self):
        repl, bind_dn, bind_pw = self._get_replication_manager()
        repl.finalize_replica_config(
            self.master_fqdn,
            r_binddn=bind_dn,
            r_bindpw=bind_pw,
            cacert=self.ca_file
        )

    def __configure_sasl_mappings(self):
        # we need to remove any existing SASL mappings in the directory as otherwise they
        # they may conflict.

        try:
            res = api.Backend.ldap2.get_entries(
                DN(('cn', 'mapping'), ('cn', 'sasl'), ('cn', 'config')),
                api.Backend.ldap2.SCOPE_ONELEVEL,
                "(objectclass=nsSaslMapping)")
            for r in res:
                try:
                    api.Backend.ldap2.delete_entry(r)
                except Exception as e:
                    logger.critical(
                        "Error during SASL mapping removal: %s", e)
                    raise
        except Exception as e:
            logger.critical("Error while enumerating SASL mappings %s", e)
            raise

        entry = api.Backend.ldap2.make_entry(
            DN(
                ('cn', 'Full Principal'), ('cn', 'mapping'), ('cn', 'sasl'),
                ('cn', 'config')),
            objectclass=["top", "nsSaslMapping"],
            cn=["Full Principal"],
            nsSaslMapRegexString=[r'\(.*\)@\(.*\)'],
            nsSaslMapBaseDNTemplate=[self.suffix],
            nsSaslMapFilterTemplate=['(krbPrincipalName=\\1@\\2)'],
            nsSaslMapPriority=['10'],
        )
        api.Backend.ldap2.add_entry(entry)

        entry = api.Backend.ldap2.make_entry(
            DN(
                ('cn', 'Name Only'), ('cn', 'mapping'), ('cn', 'sasl'),
                ('cn', 'config')),
            objectclass=["top", "nsSaslMapping"],
            cn=["Name Only"],
            nsSaslMapRegexString=['^[^:@]+$'],
            nsSaslMapBaseDNTemplate=[self.suffix],
            nsSaslMapFilterTemplate=['(krbPrincipalName=&@%s)' % self.realm],
            nsSaslMapPriority=['10'],
        )
        api.Backend.ldap2.add_entry(entry)

    def __update_schema(self):
        # FIXME: https://fedorahosted.org/389/ticket/47490
        self._ldap_mod("schema-update.ldif")

    def __enable(self):
        self.backup_state("enabled", self.is_enabled())
        # At the end of the installation ipa-server-install will enable the
        # 'ipa' service wich takes care of starting/stopping dirsrv
        self.disable()

    def __setup_sub_dict(self):
        server_root = find_server_root()
        self.sub_dict = ldapupdate.get_sub_dict(
            realm=self.realm,
            domain=self.domain,
            suffix=self.suffix,
            fqdn=self.fqdn,
            idstart=self.idstart,
            idmax=self.idmax,
        )
        self.sub_dict.update(
            DOMAIN_LEVEL=self.domainlevel,
            SERVERID=self.serverid,
            PASSWORD=self.dm_password,
            RANDOM_PASSWORD=ipautil.ipa_generate_password(),
            USER=DS_USER,
            GROUP=DS_GROUP,
            SERVER_ROOT=server_root,
        )

    def __create_instance(self):
        self.backup_state("serverid", self.serverid)

        # The new installer is api driven. We can pass it a log function
        # and it will use it. Because of this, we can pass verbose true,
        # and allow our logger to control the display based on level.
        sds = SetupDs(verbose=True, dryrun=False, log=logger)

        # General environmental options.
        general_options = General2Base(logger)
        general_options.set('strict_host_checking', False)
        # Check that our requested configuration is actually valid ...
        general_options.verify()
        general = general_options.collect()

        # Slapd options, ie instance name.
        slapd_options = Slapd2Base(logger)
        slapd_options.set('instance_name', self.serverid)
        slapd_options.set('root_password', self.dm_password)
        slapd_options.set('self_sign_cert', False)
        slapd_options.verify()
        slapd = slapd_options.collect()

        # Create userroot. Note that the new install does NOT
        # create sample entries, so this is *empty*.
        userroot = {
            'cn': 'userRoot',
            'nsslapd-suffix': self.suffix.ldap_text()
        }

        backends = [userroot]

        sds.create_from_args(general, slapd, backends, None)

        # Now create the new domain root object in the format that IPA expects.
        # Get the instance and setup LDAPI with root autobind.
        inst = DirSrv(verbose=True, external_log=logger)
        inst.local_simple_allocate(
            serverid=self.serverid,
            ldapuri=ipaldap.get_ldap_uri(realm=self.realm, protocol='ldapi'),
        )
        inst.setup_ldapi()
        inst.open()

        def get_entry(dn, attrs):
            return inst.getEntry(str(dn), attrlist=attrs)

        self.sub_dict['REPLICATION_PLUGIN'] = (
            installutils.get_replication_plugin_name(get_entry)
        )

        try:
            ipadomain = IpaDomain(inst, dn=self.suffix.ldap_text())
            ipadomain.create(properties={
                'dc': self.realm.split('.')[0].lower(),
                'info': 'IPA V2.0',
            })
        finally:
            inst.close()

        # Done!
        logger.debug("completed creating DS instance")

    def __tune_ldbm(self):
        self._ldap_mod("ldbm-tuning.ldif")

    def __update_dse_ldif(self):
        """
        This method updates dse.ldif right after instance creation. This is
        supposed to allow admin modify configuration of the DS which has to be
        done before IPA is fully installed (for example: settings for
        replication on replicas)
        DS must be turned off.
        """
        dse_filename = os.path.join(
            paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % self.serverid,
            'dse.ldif'
        )

        with tempfile.NamedTemporaryFile(
                mode='w', delete=False) as new_dse_ldif:
            temp_filename = new_dse_ldif.name
            with open(dse_filename, "r") as input_file:
                parser = installutils.ModifyLDIF(input_file, new_dse_ldif)
                if self.config_ldif:
                    # parse modifications from ldif file supplied by the admin
                    with open(self.config_ldif, "r") as config_ldif:
                        parser.modifications_from_ldif(config_ldif)
                parser.parse()
            new_dse_ldif.flush()
        shutil.copy2(temp_filename, dse_filename)
        tasks.restore_context(dse_filename)
        try:
            os.remove(temp_filename)
        except OSError as e:
            logger.debug("Failed to clean temporary file: %s", e)

    def __add_default_schemas(self):
        for schema_fname in IPA_SCHEMA_FILES:
            target_fname = schema_dirname(self.serverid) + schema_fname
            shutil.copyfile(
                os.path.join(paths.USR_SHARE_IPA_DIR, schema_fname),
                target_fname)
            os.chmod(target_fname, 0o440)    # read access for dirsrv user/group
            DS_USER.chown(target_fname)

        try:
            shutil.move(schema_dirname(self.serverid) + "05rfc2247.ldif",
                            schema_dirname(self.serverid) + "05rfc2247.ldif.old")

            target_fname = schema_dirname(self.serverid) + "05rfc2247.ldif"
            shutil.copyfile(
                os.path.join(paths.USR_SHARE_IPA_DIR, "05rfc2247.ldif"),
                target_fname)
            os.chmod(target_fname, 0o440)
            DS_USER.chown(target_fname)
        except IOError:
            # Does not apply with newer DS releases
            pass

    def start(self, instance_name="", capture_output=True, wait=True):
        super(DsInstance, self).start(
            instance_name, capture_output=capture_output, wait=wait
        )
        api.Backend.ldap2.connect()

    def stop(self, instance_name="", capture_output=True):
        if api.Backend.ldap2.isconnected():
            api.Backend.ldap2.disconnect()

        super(DsInstance, self).stop(
            instance_name, capture_output=capture_output
        )

    def restart(self, instance_name="", capture_output=True, wait=True):
        if api.Backend.ldap2.isconnected():
            api.Backend.ldap2.disconnect()
        try:
            super(DsInstance, self).restart(
                instance_name, capture_output=capture_output, wait=wait
            )
            if not is_ds_running(instance_name):
                logger.critical("Failed to restart the directory server. "
                                "See the installation log for details.")
                raise ScriptError()
        except SystemExit as e:
            raise e
        except Exception as e:
            # TODO: roll back here?
            logger.critical("Failed to restart the directory server (%s). "
                            "See the installation log for details.", e)
        api.Backend.ldap2.connect()

    def __start_instance(self):
        self.start(self.serverid)

    def __stop_instance(self):
        self.stop(self.serverid)

    def __restart_instance(self):
        self.restart(self.serverid)

    def __enable_entryusn(self):
        self._ldap_mod("entryusn.ldif")

    def __add_memberof_module(self):
        self._ldap_mod("memberof-conf.ldif")

    def init_memberof(self):
        if not self.run_init_memberof:
            return

        self._ldap_mod("memberof-task.ldif", self.sub_dict)
        # Note, keep dn in sync with dn in install/share/memberof-task.ldif
        dn = DN(('cn', 'IPA install %s' % self.sub_dict["TIME"]), ('cn', 'memberof task'),
                ('cn', 'tasks'), ('cn', 'config'))
        logger.debug("Waiting for memberof task to complete.")
        with ipaldap.LDAPClient.from_realm(self.realm) as conn:
            conn.external_bind()
            replication.wait_for_task(conn, dn)

    def apply_updates(self):
        schema_files = get_all_external_schema_files(paths.EXTERNAL_SCHEMA_DIR)
        data_upgrade = upgradeinstance.IPAUpgrade(self.realm,
                                                  schema_files=schema_files)
        try:
            data_upgrade.create_instance()
        except Exception as e:
            # very fatal errors only will raise exception
            raise RuntimeError("Update failed: %s" % e)
        installutils.store_version()


    def __add_referint_module(self):
        self._ldap_mod("referint-conf.ldif")

    def __set_unique_attrs(self):
        self._ldap_mod("unique-attributes.ldif", self.sub_dict)

    def __config_uidgid_gen(self):
        self._ldap_mod("dna.ldif", self.sub_dict)

    def __add_master_entry(self):
        self._ldap_mod("master-entry.ldif", self.sub_dict)

    def __add_topology_entries(self):
        self._ldap_mod("topology-entries.ldif", self.sub_dict)

    def __add_winsync_module(self):
        self._ldap_mod("ipa-winsync-conf.ldif")

    def __password_logging(self):
        self._ldap_mod("pw-logging-conf.ldif")

    def __config_version_module(self):
        self._ldap_mod("version-conf.ldif", self.sub_dict)

    def __config_uuid_module(self):
        self._ldap_mod("uuid-conf.ldif")
        self._ldap_mod("uuid.ldif", self.sub_dict)

    def __config_modrdn_module(self):
        self._ldap_mod("modrdn-conf.ldif")
        self._ldap_mod("modrdn-krbprinc.ldif", self.sub_dict)

    def __config_dns_module(self):
        # Configure DNS plugin unconditionally as we would otherwise have
        # troubles if other replica just configured DNS with ipa-dns-install
        self._ldap_mod("ipa-dns-conf.ldif")

    def __config_lockout_module(self):
        self._ldap_mod("lockout-conf.ldif")

    def config_graceperiod_module(self):
        if not api.Backend.ldap2.isconnected():
            api.Backend.ldap2.connect()
        dn = DN('cn=IPA Graceperiod,cn=plugins,cn=config')
        try:
            api.Backend.ldap2.get_entry(dn)
        except errors.NotFound:
            self._ldap_mod("graceperiod-conf.ldif")

    def __config_topology_module(self):
        self._ldap_mod("ipa-topology-conf.ldif", self.sub_dict)

    def __repoint_managed_entries(self):
        self._ldap_mod("repoint-managed-entries.ldif", self.sub_dict)

    def configure_systemd_ipa_env(self):
        template = os.path.join(
            paths.USR_SHARE_IPA_DIR, "ds-ipa-env.conf.template"
        )
        sub_dict = dict(
            KRB5_KTNAME=paths.DS_KEYTAB,
            KRB5CCNAME=paths.TMP_KRB5CC % platformconstants.DS_USER.uid
        )
        conf = ipautil.template_file(template, sub_dict)

        destfile = paths.SLAPD_INSTANCE_SYSTEMD_IPA_ENV_TEMPLATE % (
            self.serverid
        )
        destdir = os.path.dirname(destfile)

        if not os.path.isdir(destdir):
            # create dirsrv-$SERVERID.service.d
            os.mkdir(destdir, 0o755)
        with open(destfile, 'w') as f:
            os.fchmod(f.fileno(), 0o644)
            f.write(conf)
        tasks.restore_context(destfile)

        # remove variables from old /etc/sysconfig/dirsrv file
        if os.path.isfile(paths.SYSCONFIG_DIRSRV):
            self.fstore.backup_file(paths.SYSCONFIG_DIRSRV)
            ipautil.config_replace_variables(
                paths.SYSCONFIG_DIRSRV,
                removevars={'KRB5_KTNAME', 'KRB5CCNAME'}
            )
        # reload systemd to materialize new config file
        tasks.systemd_daemon_reload()

    def __managed_entries(self):
        self._ldap_mod("managed-entries.ldif", self.sub_dict)

    def __user_private_groups(self):
        self._ldap_mod("user_private_groups.ldif", self.sub_dict)

    def __host_nis_groups(self):
        self._ldap_mod("host_nis_groups.ldif", self.sub_dict)

    def __add_enrollment_module(self):
        self._ldap_mod("enrollment-conf.ldif", self.sub_dict)

    def __enable_ssl(self):
        dirname = config_dirname(self.serverid)
        dsdb = certs.CertDB(
            self.realm,
            nssdir=dirname,
            subject_base=self.subject_base,
            ca_subject=self.ca_subject,
        )
        if self.pkcs12_info:
            if self.ca_is_configured:
                trust_flags = IPA_CA_TRUST_FLAGS
            else:
                trust_flags = EXTERNAL_CA_TRUST_FLAGS
            dsdb.create_from_pkcs12(self.pkcs12_info[0], self.pkcs12_info[1],
                                    ca_file=self.ca_file,
                                    trust_flags=trust_flags)
            # rewrite the pin file with current password
            dsdb.create_pin_file()
            server_certs = dsdb.find_server_certs()
            if len(server_certs) == 0:
                raise RuntimeError("Could not find a suitable server cert in import in %s" % self.pkcs12_info[0])

            # We only handle one server cert
            self.nickname = server_certs[0][0]
            self.cert = dsdb.get_cert_from_db(self.nickname)

            if self.ca_is_configured:
                dsdb.track_server_cert(
                    self.nickname, self.principal, dsdb.passwd_fname,
                    'restart_dirsrv %s' % self.serverid)

            self.add_cert_to_service()
        else:
            dsdb.create_from_cacert()
            # rewrite the pin file with current password
            dsdb.create_pin_file()
            if self.master_fqdn is None:
                ca_args = [
                    paths.CERTMONGER_DOGTAG_SUBMIT,
                    '--ee-url', 'https://%s:8443/ca/ee/ca' % self.fqdn,
                    '--certfile', paths.RA_AGENT_PEM,
                    '--keyfile', paths.RA_AGENT_KEY,
                    '--cafile', paths.IPA_CA_CRT,
                    '--agent-submit'
                ]
                helper = " ".join(ca_args)
                prev_helper = certmonger.modify_ca_helper('IPA', helper)
            else:
                prev_helper = None
            try:
                cmd = 'restart_dirsrv %s' % self.serverid
                certmonger.request_and_wait_for_cert(
                    certpath=dirname,
                    storage='NSSDB',
                    nickname=self.nickname,
                    principal=self.principal,
                    passwd_fname=dsdb.passwd_fname,
                    subject=str(DN(('CN', self.fqdn), self.subject_base)),
                    ca='IPA',
                    profile=dogtag.DEFAULT_PROFILE,
                    dns=[self.fqdn],
                    post_command=cmd,
                    resubmit_timeout=api.env.certmonger_wait_timeout
                )
            finally:
                if prev_helper is not None:
                    certmonger.modify_ca_helper('IPA', prev_helper)

            # restart_dirsrv in the request above restarts DS, reconnect ldap2
            api.Backend.ldap2.disconnect()
            api.Backend.ldap2.connect()

            self.cert = dsdb.get_cert_from_db(self.nickname)

            if prev_helper is not None:
                self.add_cert_to_service()

        self.cacert_name = dsdb.cacert_name

        # use LDAPI?
        conn = ipaldap.LDAPClient.from_realm(self.realm)
        conn.external_bind()

        encrypt_entry = conn.make_entry(
            DN(('cn', 'encryption'), ('cn', 'config')),
            nsSSLClientAuth=b'allowed',
            nsSSL3Ciphers=b'default',
            allowWeakCipher=b'off'
        )
        try:
            conn.update_entry(encrypt_entry)
        except errors.EmptyModlist:
            logger.debug(
                "cn=encryption,cn=config is already properly configured")

        conf_entry = conn.make_entry(
            DN(('cn', 'config')),
            # one does not simply uses '-' in variable name
            **{'nsslapd-security': b'on'}
        )
        try:
            conn.update_entry(conf_entry)
        except errors.EmptyModlist:
            logger.debug("nsslapd-security is already on")

        entry = conn.make_entry(
            DN(('cn', 'RSA'), ('cn', 'encryption'), ('cn', 'config')),
            objectclass=["top", "nsEncryptionModule"],
            cn=["RSA"],
            nsSSLPersonalitySSL=[self.nickname],
            nsSSLToken=["internal (software)"],
            nsSSLActivation=["on"],
        )
        try:
            conn.add_entry(entry)
        except errors.DuplicateEntry:
            # 389-DS >= 1.4.0 has a default entry, update it.
            conn.update_entry(entry)

        conn.unbind()

        # check for open secure port 636 from now on
        self.open_ports.append(636)

    def __upload_ca_cert(self):
        """
        Upload the CA certificate from the NSS database to the LDAP directory.
        """

        dirname = config_dirname(self.serverid)
        dsdb = certs.CertDB(self.realm, nssdir=dirname,
                            subject_base=self.subject_base)
        trust_flags = dict(reversed(dsdb.list_certs()))

        conn = ipaldap.LDAPClient.from_realm(self.realm)
        conn.external_bind()

        nicknames = dsdb.find_root_cert(self.cacert_name)[:-1]
        for nickname in nicknames:
            cert = dsdb.get_cert_from_db(nickname)
            certstore.put_ca_cert_nss(conn, self.suffix, cert, nickname,
                                      trust_flags[nickname])

        nickname = self.cacert_name
        cert = dsdb.get_cert_from_db(nickname)
        cacert_flags = trust_flags[nickname]
        if self.setup_pkinit:
            cacert_flags = TrustFlags(
                cacert_flags.has_key,
                cacert_flags.trusted,
                cacert_flags.ca,
                (cacert_flags.usages |
                    {x509.EKU_PKINIT_CLIENT_AUTH, x509.EKU_PKINIT_KDC}),
            )
        certstore.put_ca_cert_nss(conn, self.suffix, cert, nickname,
                                  cacert_flags,
                                  config_ipa=self.ca_is_configured,
                                  config_compat=self.master_fqdn is None)

        conn.unbind()

    def __import_ca_certs(self):
        dirname = config_dirname(self.serverid)
        dsdb = certs.CertDB(self.realm, nssdir=dirname,
                            subject_base=self.subject_base)

        with ipaldap.LDAPClient.from_realm(self.realm) as conn:
            conn.external_bind()
            self.export_ca_certs_nssdb(dsdb, self.ca_is_configured, conn)

    def __add_default_layout(self):
        self._ldap_mod("bootstrap-template.ldif", self.sub_dict)

    def __add_delegation_layout(self):
        self._ldap_mod("delegation.ldif", self.sub_dict)

    def __add_replication_acis(self):
        self._ldap_mod("replica-acis.ldif", self.sub_dict)

    def __setup_s4u2proxy(self):

        def __add_principal(last_cn, principal, self):
            dn = DN(('cn', last_cn), ('cn', 's4u2proxy'),
                    ('cn', 'etc'), self.suffix)

            value = '{principal}/{fqdn}@{realm}'.format(fqdn=self.fqdn,
                                                        realm=self.realm,
                                                        principal=principal)

            entry = api.Backend.ldap2.get_entry(dn, ['memberPrincipal'])
            try:
                entry['memberPrincipal'].append(value)
                api.Backend.ldap2.update_entry(entry)
            except errors.EmptyModlist:
                pass

        __add_principal('ipa-http-delegation', 'HTTP', self)
        __add_principal('ipa-ldap-delegation-targets', 'ldap', self)

    def __create_indices(self):
        self._ldap_update(["20-indices.update"])

    def __certmap_conf(self):
        write_certmap_conf(self.realm, self.ca_subject)
        sysupgrade.set_upgrade_state(
            'certmap.conf',
            'subject_base',
            str(self.subject_base)
        )

    def __enable_sasl_mapping_fallback(self):
        self._ldap_mod("sasl-mapping-fallback.ldif", self.sub_dict)

    def add_hbac(self):
        self._ldap_mod("default-hbac.ldif", self.sub_dict)

    def change_admin_password(self, password):
        logger.debug("Changing admin password")

        dir_ipa = paths.VAR_LIB_IPA
        with tempfile.NamedTemporaryFile("w", dir=dir_ipa) as dmpwdfile, \
                tempfile.NamedTemporaryFile("w", dir=dir_ipa) as admpwdfile:
            dmpwdfile.write(self.dm_password)
            dmpwdfile.flush()

            admpwdfile.write(password)
            admpwdfile.flush()

            args = [paths.LDAPPASSWD, "-H", "ldap://{}".format(self.fqdn),
                    "-ZZ", "-x", "-D", str(DN(('cn', 'Directory Manager'))),
                    "-y", dmpwdfile.name, "-T", admpwdfile.name,
                    str(DN(('uid', 'admin'), ('cn', 'users'), ('cn', 'accounts'), self.suffix))]
            try:
                env = {'LDAPTLS_CACERTDIR': os.path.dirname(paths.IPA_CA_CRT),
                       'LDAPTLS_CACERT': paths.IPA_CA_CRT}
                ipautil.run(args, env=env)
                logger.debug("ldappasswd done")
            except ipautil.CalledProcessError as e:
                print("Unable to set admin password", e)
                logger.debug("Unable to set admin password %s", e)

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring directory server")

        enabled = self.restore_state("enabled")

        # Just eat this state if it exists
        self.restore_state("running")

        try:
            self.fstore.restore_file(paths.LIMITS_CONF)
        except ValueError as error:
            logger.debug("%s: %s", paths.LIMITS_CONF, error)

        try:
            self.fstore.restore_file(paths.SYSCONFIG_DIRSRV)
        except ValueError as error:
            logger.debug("%s: %s", paths.SYSCONFIG_DIRSRV, error)

        # disabled during IPA installation
        if enabled:
            logger.debug("Re-enabling instance of Directory Server")
            self.enable()

        serverid = self.restore_state("serverid")
        if serverid is not None:
            # What if this fails? Then what?
            self.stop_tracking_certificates(serverid)
            logger.debug("Removing DS instance %s", serverid)
            try:
                remove_ds_instance(serverid)
            except ipautil.CalledProcessError:
                logger.error("Failed to remove DS instance. You may "
                             "need to remove instance data manually")
            destfile = paths.SLAPD_INSTANCE_SYSTEMD_IPA_ENV_TEMPLATE % (
                serverid
            )
            ipautil.remove_file(destfile)
            ipautil.remove_directory(os.path.dirname(destfile))

        else:
            logger.error("Failed to remove DS instance. No serverid present "
                         "in sysrestore file.")

        ipautil.remove_keytab(paths.DS_KEYTAB)
        ipautil.remove_ccache(run_as=DS_USER)

        if serverid is None:
            # Remove scripts dir
            scripts = paths.VAR_LIB_DIRSRV_INSTANCE_SCRIPTS_TEMPLATE % (
                serverid)
            ipautil.rmtree(scripts)

            # remove systemd unit file
            unitfile = paths.SLAPD_INSTANCE_SYSTEMD_IPA_ENV_TEMPLATE % (
                serverid
            )
            ipautil.remove_file(unitfile)
            try:
                os.rmdir(os.path.dirname(unitfile))
            except OSError:
                # not empty
                pass

        # Just eat this state
        self.restore_state("user_exists")

        # Make sure some upgrade-related state is removed. This could cause
        # re-installation problems.
        self.restore_state('nsslapd-port')
        self.restore_state('nsslapd-security')
        self.restore_state('nsslapd-ldapiautobind')

        # If any dirsrv instances remain after we've removed ours then
        # (re)start them.
        for ds_instance in get_ds_instances():
            try:
                services.knownservices.dirsrv.restart(ds_instance, wait=False)
            except Exception as e:
                logger.error(
                    'Unable to restart DS instance %s: %s', ds_instance, e)

    def get_server_cert_nickname(self, serverid=None):
        """
        Retrieve the nickname of the server cert used by dirsrv.

        The method directly reads the dse.ldif to find the attribute
        nsSSLPersonalitySSL of cn=RSA,cn=encryption,cn=config because
        LDAP is not always accessible when we need to get the nickname
        (for instance during uninstall).
        """
        if serverid is None:
            serverid = self.get_state("serverid")
        if serverid is not None:
            dirname = config_dirname(serverid)
            config_file = os.path.join(dirname, "dse.ldif")
            rsa_dn = "cn=RSA,cn=encryption,cn=config"
            with open(config_file, "r") as in_file:
                parser = upgradeinstance.GetEntryFromLDIF(
                    in_file,
                    entries_dn=[rsa_dn])
                parser.parse()
                try:
                    config_entry = parser.get_results()[rsa_dn]
                    nickname = config_entry["nsSSLPersonalitySSL"][0]
                    return nickname.decode('utf-8')
                except (KeyError, IndexError):
                    logger.error("Unable to find server cert nickname in %s",
                                 config_file)

        logger.debug("Falling back to nickname Server-Cert")
        return 'Server-Cert'

    def stop_tracking_certificates(self, serverid=None):
        if serverid is None:
            serverid = self.get_state("serverid")
        if serverid is not None:
            nickname = self.get_server_cert_nickname(serverid)
            # drop the trailing / off the config_dirname so the directory
            # will match what is in certmonger
            dirname = config_dirname(serverid)[:-1]
            dsdb = certs.CertDB(self.realm, nssdir=dirname)
            dsdb.untrack_server_cert(nickname)

    def start_tracking_certificates(self, serverid):
        nickname = self.get_server_cert_nickname(serverid)
        dirname = config_dirname(serverid)[:-1]
        dsdb = certs.CertDB(self.realm, nssdir=dirname)
        if dsdb.is_ipa_issued_cert(api, nickname):
            dsdb.track_server_cert(
                nickname,
                self.principal,
                password_file=dsdb.passwd_fname,
                command='restart_dirsrv %s' % serverid,
                profile=dogtag.DEFAULT_PROFILE)
        else:
            logger.debug("Will not track DS server certificate %s as it is "
                         "not issued by IPA", nickname)

    # we could probably move this function into the service.Service
    # class - it's very generic - all we need is a way to get an
    # instance of a particular Service
    def add_ca_cert(self, cacert_fname, cacert_name=''):
        """Add a CA certificate to the directory server cert db.  We
        first have to shut down the directory server in case it has
        opened the cert db read-only.  Then we use the CertDB class
        to add the CA cert.  We have to provide a nickname, and we
        do not use 'IPA CA' since that's the default, so
        we use 'Imported CA' if none specified.  Then we restart
        the server."""
        # first make sure we have a valid cacert_fname
        try:
            if not os.access(cacert_fname, os.R_OK):
                logger.critical("The given CA cert file named [%s] could not "
                                "be read", cacert_fname)
                return False
        except OSError as e:
            logger.critical("The given CA cert file named [%s] could not "
                            "be read: %s", cacert_fname, str(e))
            return False
        # ok - ca cert file can be read
        # shutdown the server
        self.stop()

        dirname = config_dirname(
            ipaldap.realm_to_serverid(self.realm))
        certdb = certs.CertDB(
            self.realm,
            nssdir=dirname,
            subject_base=self.subject_base,
            ca_subject=self.ca_subject,
        )
        if not cacert_name or len(cacert_name) == 0:
            cacert_name = "Imported CA"
        # we can't pass in the nickname, so we set the instance variable
        certdb.cacert_name = cacert_name
        status = True
        try:
            certdb.load_cacert(cacert_fname, EXTERNAL_CA_TRUST_FLAGS)
        except ipautil.CalledProcessError as e:
            logger.critical("Error importing CA cert file named [%s]: %s",
                            cacert_fname, str(e))
            status = False
        # restart the directory server
        self.start()

        return status

    def __add_sudo_binduser(self):
        self._ldap_mod("sudobind.ldif", self.sub_dict)

    def __add_automember_config(self):
        self._ldap_mod("automember.ldif", self.sub_dict)

    def __add_replica_automember_config(self):
        self._ldap_mod("replica-automember.ldif", self.sub_dict)

    def __add_range_check_plugin(self):
        self._ldap_mod("range-check-conf.ldif", self.sub_dict)

    def _add_sidgen_plugin(self):
        """
        Add sidgen directory server plugin configuration if it does not already exist.
        """
        self.add_sidgen_plugin(self.sub_dict['SUFFIX'])

    def add_sidgen_plugin(self, suffix):
        """
        Add sidgen plugin configuration only if it does not already exist.
        """
        dn = DN('cn=IPA SIDGEN,cn=plugins,cn=config')
        try:
            api.Backend.ldap2.get_entry(dn)
        except errors.NotFound:
            self._ldap_mod('ipa-sidgen-conf.ldif', dict(SUFFIX=suffix))
        else:
            logger.debug("sidgen plugin is already configured")

    def _add_extdom_plugin(self):
        """
        Add directory server configuration for the extdom extended operation.
        """
        self.add_extdom_plugin(self.sub_dict['SUFFIX'])

    def add_extdom_plugin(self, suffix):
        """
        Add extdom configuration if it does not already exist.
        """
        dn = DN('cn=ipa_extdom_extop,cn=plugins,cn=config')
        try:
            api.Backend.ldap2.get_entry(dn)
        except errors.NotFound:
            self._ldap_mod('ipa-extdom-extop-conf.ldif', dict(SUFFIX=suffix))
        else:
            logger.debug("extdom plugin is already configured")

    def find_subject_base(self):
        """
        Try to find the current value of certificate subject base.
        1) Look in sysupgrade first
        2) If no value is found there, look in DS (start DS if necessary)
        3) If all fails, log loudly and return None

        Note that this method can only be executed AFTER the ipa server
        is configured, the api is initialized elsewhere and
        that a ticket already have been acquired.
        """
        logger.debug(
            'Trying to find certificate subject base in sysupgrade')
        subject_base = sysupgrade.get_upgrade_state(
            'certmap.conf', 'subject_base')

        if subject_base:
            logger.debug(
                'Found certificate subject base in sysupgrade: %s',
                subject_base)
            return subject_base

        logger.debug(
            'Unable to find certificate subject base in sysupgrade')
        logger.debug(
            'Trying to find certificate subject base in DS')

        ds_is_running = is_ds_running()
        if not ds_is_running:
            try:
                self.start()
                ds_is_running = True
            except ipautil.CalledProcessError as e:
                logger.error('Cannot start DS to find certificate '
                             'subject base: %s', e)

        if ds_is_running:
            try:
                ret = api.Command['config_show']()
                subject_base = str(
                    ret['result']['ipacertificatesubjectbase'][0])
                logger.debug(
                    'Found certificate subject base in DS: %s', subject_base)
            except errors.PublicError as e:
                logger.error('Cannot connect to DS to find certificate '
                             'subject base: %s', e)

        if subject_base:
            return subject_base

        logger.debug('Unable to find certificate subject base in certmap.conf')
        return None

    def __set_domain_level(self):
        # Create global domain level entry and set the domain level
        if self.domainlevel is not None:
            self._ldap_mod("domainlevel.ldif", self.sub_dict)


def write_certmap_conf(realm, ca_subject):
    """(Re)write certmap.conf with given CA subject DN."""
    serverid = ipaldap.realm_to_serverid(realm)
    ds_dirname = config_dirname(serverid)
    certmap_filename = os.path.join(ds_dirname, "certmap.conf")
    shutil.copyfile(
        os.path.join(paths.USR_SHARE_IPA_DIR, "certmap.conf.template"),
        certmap_filename)
    installutils.update_file(
        certmap_filename,
        '$ISSUER_DN',  # lgtm [py/regex/unmatchable-dollar]
        str(ca_subject)
    )
