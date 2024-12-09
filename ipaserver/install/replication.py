# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
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
import itertools

import re
import six
import time
import datetime
import sys
import os
import json
from random import randint

import ldap

from ipalib import api, errors
from ipalib.cli import textui
from ipalib.text import _
from ipapython import ipautil, ipaldap
from ipapython.admintool import ScriptError
from ipapython.dn import DN
from ipapython.ipaldap import ldap_initialize
from ipaplatform.paths import paths
from ipaserver.install import installutils

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

# the default container used by AD for user entries
WIN_USER_CONTAINER = DN(('cn', 'Users'))
# the default container used by IPA for user entries
IPA_USER_CONTAINER = DN(('cn', 'users'), ('cn', 'accounts'))
PORT = 636
DEFAULT_PORT = 389
TIMEOUT = 120
REPL_MAN_DN = DN(('cn', 'replication manager'), ('cn', 'config'))
DNA_DN = DN(('cn', 'Posix IDs'), ('cn', 'Distributed Numeric Assignment Plugin'), ('cn', 'plugins'), ('cn', 'config'))
REPL_MANAGERS_CN = DN(('cn', 'replication managers'))

IPA_REPLICA = 1
WINSYNC = 2

# List of attributes that need to be excluded from replication initialization.
TOTAL_EXCLUDES = ('entryusn',
                  'krblastsuccessfulauth',
                  'krblastfailedauth',
                  'krbloginfailedcount',
                  'passwordgraceusertime',)

# List of attributes that need to be excluded from normal replication.
EXCLUDES = ('memberof', 'idnssoaserial') + TOTAL_EXCLUDES

# List of attributes that are not updated on empty replication
STRIP_ATTRS = ('modifiersName',
               'modifyTimestamp',
               'internalModifiersName',
               'internalModifyTimestamp')

# settings for cn=replica,cn=$DB,cn=mapping tree,cn=config
# during replica installation
REPLICA_CREATION_SETTINGS = {
    "nsds5ReplicaReleaseTimeout": ["20"],
    "nsds5ReplicaBackoffMax": ["3"],
    "nsDS5ReplicaBindDnGroupCheckInterval": ["2"]
}
# after replica installation
REPLICA_FINAL_SETTINGS = {
    "nsds5ReplicaReleaseTimeout": ["60"],
    "nsds5ReplicaBackoffMax": ["300"],  # default
    "nsDS5ReplicaBindDnGroupCheckInterval": ["60"]
}


def replica_conn_check(master_host, host_name, realm, check_ca,
                       dogtag_master_ds_port, admin_password=None,
                       principal="admin", ca_cert_file=None):
    """
    Check the ports used by the replica both locally and remotely to be sure
    that replication will work.

    Does not return a value, will raise ScriptError on failure.
    """
    print("Run connection check to master")
    args = [paths.IPA_REPLICA_CONNCHECK, "--master", master_host,
            "--auto-master-check", "--realm", realm,
            "--hostname", host_name]
    nolog=tuple()

    if principal is not None:
        args.extend(["--principal", principal])

    if admin_password:
        args.extend(["--password", admin_password])
        nolog=(admin_password,)

    if check_ca and dogtag_master_ds_port == 7389:
        args.append('--check-ca')

    if ca_cert_file:
        args.extend(["--ca-cert-file", ca_cert_file])

    result = ipautil.run(
        args, raiseonerr=False, capture_output=False, nolog=nolog)

    if result.returncode != 0:
        raise ScriptError(
            "Connection check failed!"
            "\nSee /var/log/ipareplica-conncheck.log for more information."
            "\nIf the check results are not valid it can be skipped with --skip-conncheck parameter.")
    else:
        print("Connection check OK")


def enable_replication_version_checking(realm, dirman_passwd):
    """
    Check the replication version checking plugin. If it is not
    enabled then enable it and restart 389-ds. If it is enabled
    the do nothing.
    """
    conn = ipaldap.LDAPClient.from_realm(realm)
    if dirman_passwd:
        conn.simple_bind(bind_dn=ipaldap.DIRMAN_DN,
                         bind_password=dirman_passwd)
    else:
        conn.gssapi_bind()
    entry = conn.get_entry(DN(('cn', 'IPA Version Replication'),
                              ('cn', 'plugins'),
                              ('cn', 'config')))
    if entry.single_value.get('nsslapd-pluginenabled') == 'off':
        conn.modify_s(entry.dn, [(ldap.MOD_REPLACE, 'nsslapd-pluginenabled', 'on')])
        conn.unbind()
        serverid = "-".join(realm.split("."))
        installutils.restart_dirsrv(serverid)
    else:
        conn.unbind()


def wait_for_task(conn, dn):
    """Check task status

    Task is complete when the nsTaskExitCode attr is set.

    :return: the task's return code
    """
    assert isinstance(dn, DN)
    attrlist = [
        'nsTaskLog', 'nsTaskStatus', 'nsTaskExitCode', 'nsTaskCurrentItem',
        'nsTaskTotalItems']
    while True:
        entry = conn.get_entry(dn, attrlist)
        if entry.single_value.get('nsTaskExitCode'):
            exit_code = int(entry.single_value['nsTaskExitCode'])
            break
        time.sleep(1)
    return exit_code


def wait_for_entry(connection, dn, timeout, attr=None, attrvalue='*',
                   quiet=True):
    """Wait for entry and/or attr to show up
    """
    log = logger.debug if quiet else logger.info
    attrlist = []
    if attr is not None:
        filterstr = ipaldap.LDAPClient.make_filter_from_attr(attr, attrvalue)
        attrlist.append(attr)
    else:
        filterstr = "(objectclass=*)"
    log("Waiting up to %s seconds for replication (%s) %s %s",
        timeout, connection, dn, filterstr)
    entry = []
    deadline = time.time() + timeout
    for i in itertools.count(start=1):
        try:
            entry = connection.get_entries(
                dn, ldap.SCOPE_BASE, filterstr, attrlist)
        except errors.NotFound:
            pass  # no entry yet
        except Exception as e:  # badness
            logger.error("Error reading entry %s: %s", dn, e)
            raise

        if entry:
            log("Entry found %r", entry)
            return
        elif time.time() > deadline:
            raise errors.NotFound(
                reason="wait_for_entry timeout on {} for {}".format(
                    connection, dn
                )
            )
        else:
            if i % 10 == 0:
                logger.debug("Still waiting for replication of %s", dn)
            time.sleep(1)


def get_ds_version(conn):
    """Returns the DS version

    Retrieves the DS version from the vendorVersion attribute stored in LDAP.
    :param conn: LDAP connection established and authenticated to the server
                 for which we need the version
    :return: a tuple containing the DS version
    """
    # Find which 389-ds is installed
    rootdse = conn.get_entry(DN(''), ['vendorVersion'])
    version = rootdse.single_value.get('vendorVersion')
    mo = re.search(r'(\d+)\.(\d+)\.(\d+)[\.\d]*', version)
    vendor_version = tuple(int(v) for v in mo.groups())
    return vendor_version


class ReplicationManager:
    """Manage replication agreements

    between DS servers, and sync  agreements with Windows servers
    """

    def __init__(self, realm, hostname, dirman_passwd=None, port=PORT,
                 starttls=False, conn=None):
        self.hostname = hostname
        self.port = port
        self.dirman_passwd = dirman_passwd
        self.realm = realm
        self.starttls = starttls
        self.suffix = ipautil.realm_to_suffix(realm)
        self.need_memberof_fixup = False
        self.db_suffix = self.suffix
        self.agreement_name_format = "meTo%s"

        # The caller is allowed to pass in an existing LDAPClient connection.
        # Open a new one if not provided
        if conn is None:
            # If we are passed a password we'll use it as the DM password
            # otherwise we'll do a GSSAPI bind.
            protocol = 'ldap' if starttls else None
            ldap_uri = ipaldap.get_ldap_uri(
                hostname, port, protocol=protocol, cacert=paths.IPA_CA_CRT)
            self.conn = ipaldap.LDAPClient(ldap_uri, cacert=paths.IPA_CA_CRT,
                                           start_tls=starttls)
            if dirman_passwd:
                self.conn.simple_bind(bind_dn=ipaldap.DIRMAN_DN,
                                      bind_password=dirman_passwd)
            else:
                self.conn.gssapi_bind()
        else:
            self.conn = conn

        self.repl_man_passwd = dirman_passwd

        # these are likely constant, but you could change them
        # at runtime if you really want
        self.repl_man_dn = REPL_MAN_DN
        self.repl_man_cn = "replication manager"
        self.repl_man_group_dn = DN(
            REPL_MANAGERS_CN, api.env.container_sysaccounts, api.env.basedn)

    def _get_replica_id(self, conn, master_conn):
        """
        Returns the replica ID which is unique for each backend.

        conn is the connection we are trying to get the replica ID for.
        master_conn is the master we are going to replicate with.
        """
        # First see if there is already one set
        dn = self.replica_dn()
        assert isinstance(dn, DN)
        try:
            replica = conn.get_entry(dn)
        except errors.NotFound:
            pass
        else:
            if replica.single_value.get('nsDS5ReplicaId'):
                return int(replica.single_value['nsDS5ReplicaId'])

        # Ok, either the entry doesn't exist or the attribute isn't set
        # so get it from the other master
        return self._get_and_update_id_from_master(master_conn)

    def _get_and_update_id_from_master(self, master_conn, attempts=5):
        """
        Fetch replica ID from remote master and update nsDS5ReplicaId attribute
        on 'cn=replication,cn=etc,$SUFFIX' entry. Do it as MOD_DELETE+MOD_ADD
        operations and retry when conflict occurs, e.g. due to simultaneous
        update from another replica.
        :param master_conn: LDAP connection to master
        :param attempts: number of attempts to update nsDS5ReplicaId
        :return: value of nsDS5ReplicaId before incrementation
        """
        dn = DN(('cn','replication'),('cn','etc'), self.suffix)

        for a in range(1, attempts + 1):
            try:
                logger.debug('Fetching nsDS5ReplicaId from master '
                             '[attempt %d/%d]', a, attempts)
                replica = master_conn.get_entry(dn)
                id_values = replica.get('nsDS5ReplicaId')
                if not id_values:
                    logger.debug("Unable to retrieve nsDS5ReplicaId from "
                                 "remote server")
                    raise RuntimeError("Unable to retrieve nsDS5ReplicaId from remote server")
                # nsDS5ReplicaId is single-valued now, but historically it could
                # contain multiple values, of which we need the highest.
                # see bug: https://fedorahosted.org/freeipa/ticket/3394
                retval = max(int(v) for v in id_values)

                # Now update the value on the master
                mod_list = [(ldap.MOD_DELETE, 'nsDS5ReplicaId', str(retval)),
                            (ldap.MOD_ADD, 'nsDS5ReplicaId', str(retval + 1))]

                master_conn.modify_s(dn, mod_list)
                logger.debug('Successfully updated nsDS5ReplicaId.')
                return retval

            except errors.NotFound:
                logger.debug("Unable to retrieve nsDS5ReplicaId from remote "
                             "server")
                raise
            # these errors signal a conflict in updating replica ID.
            # We then wait for a random time interval and try again
            except (ldap.NO_SUCH_ATTRIBUTE, ldap.OBJECT_CLASS_VIOLATION) as e:
                sleep_interval = randint(1, 5)
                logger.debug("Update failed (%s). Conflicting operation?", e)
                time.sleep(sleep_interval)
            # in case of other error we bail out
            except ldap.LDAPError as e:
                logger.debug("Problem updating nsDS5ReplicaID %s", e)
                raise

        raise RuntimeError("Failed to update nsDS5ReplicaId in %d attempts"
                           % attempts)

    def get_agreement_filter(self, agreement_types=None, host=None):
        """
        Get an LDAP replication agreement filter with a possibility to filter
        the agreements by their type and a host
        """
        if agreement_types is None:
            agreement_types = (IPA_REPLICA, WINSYNC)
        elif not isinstance(agreement_types, (list, tuple)):
            agreement_types = (agreement_types,)

        agreement_types_filters = []
        if IPA_REPLICA in agreement_types:
            agreement_types_filters.append('(&(objectclass=nsds5ReplicationAgreement)(nsDS5ReplicaRoot=%s))'
                                           % self.db_suffix)
        if WINSYNC in agreement_types:
            agreement_types_filters.append('(objectclass=nsDSWindowsReplicationAgreement)')
        if len(agreement_types_filters) > 1:
            agreement_filter = '(|%s)' % ''.join(agreement_types_filters)
        else:
            agreement_filter = ''.join(agreement_types_filters)

        if host is not None:
            agreement_filter = '(&%s(nsDS5ReplicaHost=%s))' % (agreement_filter, host)

        return agreement_filter

    def find_replication_agreements(self):
        """
        The replication agreements are stored in
        cn="$SUFFIX",cn=mapping tree,cn=config

        FIXME: Rather than failing with a read error if a user tries
        to read this it simply returns zero entries. We need to use
        GER to determine if we are allowed to read this to return a proper
        response. For now just return "No entries" even if the user may
        not be allowed to see them.
        """
        filt = self.get_agreement_filter()
        try:
            ents = self.conn.get_entries(
                DN(('cn', 'mapping tree'), ('cn', 'config')),
                ldap.SCOPE_SUBTREE, filt)
        except errors.NotFound:
            ents = []
        return ents

    def find_ipa_replication_agreements(self):
        """
        The replication agreements are stored in
        cn="$SUFFIX",cn=mapping tree,cn=config

        Return the list of hosts we have replication agreements.
        """

        filt = self.get_agreement_filter(IPA_REPLICA)
        try:
            ents = self.conn.get_entries(
                DN(('cn', 'mapping tree'), ('cn', 'config')),
                ldap.SCOPE_SUBTREE, filt)
        except errors.NotFound:
            ents = []

        return ents

    def get_replication_agreement(self, hostname):
        """
        The replication agreements are stored in
        cn="$SUFFIX",cn=mapping tree,cn=config

        Get the replication agreement for a specific host.

        Returns None if not found.
        """

        filt = self.get_agreement_filter(host=hostname)
        try:
            entries = self.conn.get_entries(
                DN(('cn', 'mapping tree'), ('cn', 'config')),
                ldap.SCOPE_SUBTREE, filt)
        except errors.NotFound:
            return None

        if len(entries) == 0:
            return None
        else:
            return entries[0] # There can be only one

    def add_replication_manager(self, conn, dn, pw):
        """
        Create a pseudo user to use for replication.
        """
        assert isinstance(dn, DN)
        rdn_attr = dn[0].attr
        rdn_val = dn[0].value

        ent = conn.make_entry(
            dn,
            {
                'objectclass': ["top", "person"],
                rdn_attr: [rdn_val],
                'userpassword': [pw],
                'sn': ["replication manager pseudo user"],
            }
        )

        try:
            conn.add_entry(ent)
        except errors.DuplicateEntry:
            conn.modify_s(dn, [(ldap.MOD_REPLACE, "userpassword", pw)])

    def delete_replication_manager(self, conn, dn=REPL_MAN_DN):
        assert isinstance(dn, DN)
        try:
            conn.delete_entry(dn)
        except errors.NotFound:
            pass

    def get_replica_type(self, master=True):
        if master:
            return "3"
        else:
            return "2"

    def replica_dn(self):
        return DN(('cn', 'replica'), ('cn', self.db_suffix),
                  ('cn', 'mapping tree'), ('cn', 'config'))

    def get_be_name(self, conn):
        # Get the backend name for this suffix
        suffix_entry = conn.get_entry(
            DN(('cn', self.db_suffix),
               ('cn', 'mapping tree'),
               ('cn', 'config')),
            ['nsslapd-backend'])
        return suffix_entry.single_value.get('nsslapd-backend')

    def _set_replica_binddngroup(self, r_conn, entry):
        """
        Set nsds5replicabinddngroup attribute on remote master's replica entry.
        Older masters (ipa < 3.3) may not support setting this attribute. In
        this case log the error and fall back to setting replica's binddn
        directly.
        """
        binddn_groups = {
            DN(p) for p in entry.get('nsds5replicabinddngroup', [])}

        mod = []
        if self.repl_man_group_dn not in binddn_groups:
            mod.append((ldap.MOD_ADD, 'nsds5replicabinddngroup',
                        self.repl_man_group_dn))

        if mod:
            try:
                r_conn.modify_s(entry.dn, mod)
            except ldap.UNWILLING_TO_PERFORM:
                logger.debug(
                    "nsds5replicabinddngroup attribute not supported on "
                    "remote master.")
            except (ldap.ALREADY_EXISTS, ldap.CONSTRAINT_VIOLATION):
                logger.debug("No update to %s necessary", entry.dn)

    def replica_config(self, conn, replica_id, replica_binddn):
        assert isinstance(replica_binddn, DN)
        dn = self.replica_dn()
        assert isinstance(dn, DN)

        logger.debug("Add or update replica config %s", dn)
        try:
            entry = conn.get_entry(dn)
        except errors.NotFound:
            # no entry, create new one
            entry = conn.make_entry(
                dn,
                objectclass=["top", "nsds5replica", "extensibleobject"],
                cn=["replica"],
                nsds5replicaroot=[str(self.db_suffix)],
                nsds5replicaid=[str(replica_id)],
                nsds5replicatype=[self.get_replica_type()],
                nsds5flags=["1"],
                nsds5replicabinddn=[replica_binddn],
                nsds5replicabinddngroup=[self.repl_man_group_dn],
                nsds5replicalegacyconsumer=["off"],
                **REPLICA_CREATION_SETTINGS
            )
            try:
                conn.add_entry(entry)
            except errors.DuplicateEntry:
                logger.debug("Lost race against another replica, updating")
                # fetch entry that have been added by another replica
                entry = conn.get_entry(dn)
            else:
                logger.debug("Added replica config %s", dn)
                # added entry successfully
                return entry

        # either existing entry or lost race
        binddns = entry.setdefault('nsDS5ReplicaBindDN', [])
        if replica_binddn not in {DN(m) for m in binddns}:
            # Add the new replication manager
            binddns.append(replica_binddn)

        # If the remote server has 389-ds < 1.3, it does not
        # support the attributes we are trying to set.
        # Find which 389-ds is installed
        vendor_version = get_ds_version(conn)
        if vendor_version >= (1, 3, 0):
            for key, value in REPLICA_CREATION_SETTINGS.items():
                entry[key] = value
        else:
            logger.debug("replication attributes not supported "
                         "on remote master, skipping update.")

        try:
            conn.update_entry(entry)
        except errors.EmptyModlist:
            logger.debug("No update to %s necessary", entry.dn)
        else:
            logger.debug("Update replica config %s", entry.dn)

        self._set_replica_binddngroup(conn, entry)

        return entry

    def setup_changelog(self, conn):
        try:
            """Check if we have the new per backend changelog, and set
            the trimming max-age setting.  If the new changelog entry
            is not found then we are still using the old global changelog.
            """
            cl_dn = DN(
                ('cn', 'changelog'),
                ('cn', self.get_be_name(conn)),
                ('cn', 'ldbm database'),
                ('cn', 'plugins'),
                ('cn', 'config'))
            cl_entry = conn.get_entry(cl_dn)
        except errors.NotFound:
            """Did not find a per-backend changelog, so add the global
            changelog entry.  First get the database directory to build
            the changelog directory location from.
            """
            ent = conn.get_entry(
                DN(
                    ('cn', 'config'),
                    ('cn', 'ldbm database'),
                    ('cn', 'plugins'),
                    ('cn', 'config')),
                ['nsslapd-directory'])
            dbdir = os.path.dirname(ent.single_value.get('nsslapd-directory'))

            entry = conn.make_entry(
                DN(
                    ('cn', 'changelog5'),
                    ('cn', 'config')),
                {
                    'objectclass': ["top", "extensibleobject"],
                    'cn': ["changelog5"],
                    'nsslapd-changelogdir': [os.path.join(dbdir, "cldb")],
                    'nsslapd-changelogmaxage': ['30d'],
                }
            )
            try:
                conn.add_entry(entry)
            except errors.DuplicateEntry:
                return
        else:
            # Set the changelog trimming
            cl_entry['nsslapd-changelogmaxage'] = '30d'
            try:
                conn.update_entry(cl_entry)
            except errors.EmptyModlist:
                # not a problem since the trimming is already set
                pass

    def _finalize_replica_settings(self, conn):
        """Change replica settings to final values

        During replica installation, some settings are configured for faster
        replication.
        """
        dn = self.replica_dn()
        entry = conn.get_entry(dn)
        for key, value in REPLICA_FINAL_SETTINGS.items():
            entry[key] = value
        try:
            conn.update_entry(entry)
        except errors.EmptyModlist:
            pass

    def finalize_replica_config(self, r_hostname, r_binddn=None,
                                r_bindpw=None, cacert=paths.IPA_CA_CRT):
        """Apply final cn=replica settings

        replica_config() sets several attribute to fast cache invalidation
        and fast reconnects to optimize replicat installation. For
        production, longer timeouts and less aggressive cache invalidation
        is sufficient. finalize_replica_config() sets the values on new
        replica and the master.

        When installing multiple replicas in parallel, one replica may
        finalize the values while another is still installing.

        See https://pagure.io/freeipa/issue/7617
        """
        self._finalize_replica_settings(self.conn)

        r_conn = ipaldap.LDAPClient.from_hostname_secure(
            r_hostname, cacert=cacert
        )
        if r_bindpw:
            r_conn.simple_bind(r_binddn, r_bindpw)
        else:
            r_conn.gssapi_bind()
        # If the remote server has 389-ds < 1.3, it does not
        # support the attributes we are trying to set.
        # Find which 389-ds is installed
        vendor_version = get_ds_version(r_conn)
        if vendor_version >= (1, 3, 0):
            # 389-ds understands the replication attributes,
            # we can safely modify them
            self._finalize_replica_settings(r_conn)
        else:
            logger.debug("replication attributes not supported "
                         "on remote master, skipping update.")
        r_conn.close()

    def setup_chaining_backend(self, conn):
        chaindn = DN(('cn', 'chaining database'), ('cn', 'plugins'), ('cn', 'config'))
        benamebase = "chaindb"
        urls = [conn.ldap_uri]
        cn = ""
        benum = 1
        done = False
        while not done:
            try:
                cn = benamebase + str(benum) # e.g. localdb1
                dn = DN(('cn', cn), chaindn)
                entry = conn.make_entry(
                    dn,
                    {
                        'objectclass': [
                            'top', 'extensibleObject', 'nsBackendInstance'],
                        'cn': [cn],
                        'nsslapd-suffix': [str(self.db_suffix)],
                        'nsfarmserverurl': urls,
                        'nsmultiplexorbinddn': [self.repl_man_dn],
                        'nsmultiplexorcredentials': [self.repl_man_passwd],
                    }
                )
                self.conn.add_entry(entry)
                done = True
            except errors.DuplicateEntry:
                benum += 1
            except errors.ExecutionError as e:
                print("Could not add backend entry " + dn, e)
                raise

        return cn

    def setup_chaining_farm(self, conn):
        try:
            conn.modify_s(self.db_suffix, [(ldap.MOD_ADD, 'aci',
                                    [ "(targetattr = \"*\")(version 3.0; acl \"Proxied authorization for database links\"; allow (proxy) userdn = \"ldap:///%s\";)" % self.repl_man_dn ])])
        except ldap.TYPE_OR_VALUE_EXISTS:
            logger.debug("proxy aci already exists in suffix %s on %s",
                         self.db_suffix, conn.ldap_uri)

    def get_mapping_tree_entry(self):
        try:
            entries = self.conn.get_entries(
                DN(('cn', 'mapping tree'), ('cn', 'config')),
                ldap.SCOPE_ONELEVEL,
                "(cn=\"%s\")" % (self.db_suffix))
            # TODO: Check we got only one entry
            return entries[0]
        except errors.NotFound:
            logger.debug(
                "failed to find mapping tree entry for %s", self.db_suffix)
            raise


    def enable_chain_on_update(self, bename):
        mtent = self.get_mapping_tree_entry()
        dn = mtent.dn

        def get_entry(dn, attrs):
            return self.conn.get_entry(DN(dn), attrs)

        replication_plugin_name = (
            installutils.get_replication_plugin_name(get_entry)
        )

        plgent = self.conn.get_entry(
            DN(('cn', replication_plugin_name), ('cn', 'plugins'),
               ('cn', 'config')),
            ['nsslapd-pluginPath'])
        path = plgent.single_value.get('nsslapd-pluginPath')

        mod = [(ldap.MOD_REPLACE, 'nsslapd-state', 'backend'),
               (ldap.MOD_ADD, 'nsslapd-backend', bename),
               (ldap.MOD_ADD, 'nsslapd-distribution-plugin', path),
               (ldap.MOD_ADD, 'nsslapd-distribution-funct', 'repl_chain_on_update')]

        try:
            self.conn.modify_s(dn, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            logger.debug("chainOnUpdate already enabled for %s",
                         self.db_suffix)

    def setup_chain_on_update(self, other_conn):
        chainbe = self.setup_chaining_backend(other_conn)
        self.enable_chain_on_update(chainbe)

    def add_passsync_user(self, conn, password):
        pass_dn = DN(('uid', 'passsync'), api.env.container_sysaccounts,
                     self.suffix)
        print("The user for the Windows PassSync service is %s" % pass_dn)
        try:
            conn.get_entry(pass_dn)
            print("Windows PassSync system account exists, not resetting password")
        except errors.NotFound:
            # The user doesn't exist, add it
            print("Adding Windows PassSync system account")
            entry = conn.make_entry(
                pass_dn,
                objectclass=["account", "simplesecurityobject", "inetUser"],
                uid=["passsync"],
                userPassword=[password],
            )
            try:
                conn.add_entry(entry)
            except errors.DuplicateEntry:
                pass

        # Add the user to the list of users allowed to bypass password policy
        extop_dn = DN(('cn', 'ipa_pwd_extop'), ('cn', 'plugins'), ('cn', 'config'))
        entry = conn.get_entry(extop_dn)
        pass_mgrs = entry.get('passSyncManagersDNs', [])
        pass_mgrs.append(pass_dn)
        mod = [(ldap.MOD_REPLACE, 'passSyncManagersDNs', pass_mgrs)]
        try:
            conn.modify_s(extop_dn, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            logger.debug("Plugin '%s' already '%s' in passSyncManagersDNs",
                         extop_dn, pass_dn)

        # And finally add it is a member of PassSync privilege to allow
        # displaying user NT attributes and reset passwords
        passsync_privilege_dn = DN(('cn','PassSync Service'),
                api.env.container_privilege,
                api.env.basedn)
        members = entry.get('member', [])
        members.append(pass_dn)
        mod = [(ldap.MOD_REPLACE, 'member', members)]
        try:
            conn.modify_s(passsync_privilege_dn, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            logger.debug("PassSync service '%s' already have '%s' as member",
                         passsync_privilege_dn, pass_dn)

    def setup_winsync_agmt(self, entry, win_subtree=None):
        if win_subtree is None:
            win_subtree = DN(WIN_USER_CONTAINER, self.ad_suffix)
        ds_subtree = DN(IPA_USER_CONTAINER, self.suffix)
        windomain = ipautil.suffix_to_realm(self.suffix)

        entry["objectclass"] = ["nsDSWindowsReplicationAgreement"]
        entry["nsds7WindowsReplicaSubtree"] = [win_subtree]
        entry["nsds7DirectoryReplicaSubtree"] = [ds_subtree]
        # for now, just sync users and ignore groups
        entry["nsds7NewWinUserSyncEnabled"] = ['true']
        entry["nsds7NewWinGroupSyncEnabled"] = ['false']
        entry["nsds7WindowsDomain"] = [windomain]

    def agreement_dn(self, hostname, master=None):
        """
        IPA agreement use the same dn on both sides, dogtag does not.
        master is not used for IPA agreements but for dogtag it will
        tell which side we want.
        """
        cn = self.agreement_name_format % (hostname)
        dn = DN(('cn', cn), self.replica_dn())

        return (cn, dn)

    def setup_agreement(self, a_conn, b_hostname, port=389,
                        repl_man_dn=None, repl_man_passwd=None,
                        iswinsync=False, win_subtree=None, isgssapi=False,
                        master=None):
        """
        master is used to determine which side of the agreement we are
        creating. This is only needed for dogtag replication agreements
        which use a different name on each side. If master is None then
        isn't a dogtag replication agreement.
        """

        if repl_man_dn is not None:
            assert isinstance(repl_man_dn, DN)

        cn, dn = self.agreement_dn(b_hostname, master=master)
        try:
            a_conn.get_entry(dn)
            return
        except errors.NotFound:
            pass

        entry = a_conn.make_entry(
            dn,
            objectclass=["nsds5replicationagreement"],
            cn=[cn],
            nsds5replicahost=[b_hostname],
            nsds5replicaport=[str(port)],
            nsds5replicatimeout=[str(TIMEOUT)],
            nsds5replicaroot=[str(self.db_suffix)],
            description=["me to %s" % b_hostname],
        )
        if master is None:
            entry['nsDS5ReplicatedAttributeList'] = [
                '(objectclass=*) $ EXCLUDE %s' % " ".join(EXCLUDES)]
        if isgssapi:
            entry['nsds5replicatransportinfo'] = ['LDAP']
            entry['nsds5replicabindmethod'] = ['SASL/GSSAPI']
        else:
            entry['nsds5replicabinddn'] = [repl_man_dn]
            entry['nsds5replicacredentials'] = [repl_man_passwd]
            entry['nsds5replicatransportinfo'] = ['TLS']
            entry['nsds5replicabindmethod'] = ['simple']

        if iswinsync:
            self.setup_winsync_agmt(entry, win_subtree)
        else:
            entry['nsds5ReplicaStripAttrs'] = [" ".join(STRIP_ATTRS)]

        a_conn.add_entry(entry)

        try:
            mod = [(ldap.MOD_ADD, 'nsDS5ReplicatedAttributeListTotal',
                   '(objectclass=*) $ EXCLUDE %s' % " ".join(TOTAL_EXCLUDES))]
            a_conn.modify_s(dn, mod)
        except ldap.LDAPError:
            # Apparently there are problems set the total list
            # Probably the master is an old 389-ds server, tell the caller
            # that we will have to set the memberof fixup task
            self.need_memberof_fixup = True

        wait_for_entry(
            a_conn, entry.dn, timeout=api.env.replication_wait_timeout
        )

    def needs_memberof_fixup(self):
        return self.need_memberof_fixup

    def get_replica_principal_dns(self, a, b, retries):
        """
        Get the DNs of the ldap principals we are going to convert
        to using GSSAPI replication.

        Arguments a and b are LDAP connections. retries is the number
        of attempts that should be made to find the entries. It could
        be that replication is slow.

        If successful this returns a tuple (dn_a, dn_b).

        If either of the DNs doesn't exist after the retries are
        exhausted an exception is raised.
        """
        filter_a = '(krbprincipalname=ldap/%s@%s)' % (a.host, self.realm)
        filter_b = '(krbprincipalname=ldap/%s@%s)' % (b.host, self.realm)

        a_entry = None
        b_entry = None
        error_message = ''

        while (retries > 0 ):
            logger.info('Getting ldap service principals for conversion: '
                        '%s and %s', filter_a, filter_b)
            try:
                a_entry = b.get_entries(self.suffix, ldap.SCOPE_SUBTREE,
                                        filter=filter_a)
            except errors.NotFound:
                pass

            try:
                b_entry = a.get_entries(self.suffix, ldap.SCOPE_SUBTREE,
                                        filter=filter_b)
            except errors.NotFound:
                pass

            if a_entry and b_entry:
                logger.debug('Found both principals.')
                break

            # One or both is missing, force sync again
            if not a_entry:
                logger.debug('Unable to find entry for %s on %s',
                             filter_a, str(b))
                self.force_sync(a, b.host)
                _cn, dn = self.agreement_dn(b.host)
                _haserror, error_message = self.wait_for_repl_update(a, dn, 60)

            if not b_entry:
                logger.debug('Unable to find entry for %s on %s',
                             filter_b, str(a))
                self.force_sync(b, a.host)
                _cn, dn = self.agreement_dn(a.host)
                _haserror, error_message = self.wait_for_repl_update(b, dn, 60)

            retries -= 1

        if not a_entry or not b_entry:
            error = 'One of the ldap service principals is missing. ' \
                    'Replication agreement cannot be converted.'
            if error_message:
                error += '\nReplication error message: %s' % error_message
            raise RuntimeError(error)

        return (a_entry[0].dn, b_entry[0].dn)

    def _add_replica_bind_dn(self, conn, bind_dn):
        rep_dn = self.replica_dn()
        assert isinstance(rep_dn, DN)
        try:
            mod = [(ldap.MOD_ADD, "nsds5replicabinddn", bind_dn)]
            conn.modify_s(rep_dn, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass

    def _add_dn_to_replication_managers(self, conn, bind_dn):
        try:
            mod = [(ldap.MOD_ADD, "member", bind_dn)]
            conn.modify_s(self.repl_man_group_dn, mod)
        except (ldap.TYPE_OR_VALUE_EXISTS, ldap.NO_SUCH_OBJECT):
            pass

    def setup_krb_princs_as_replica_binddns(self, a, b):
        """
        Search the appropriate principal names so we can get
        the correct DNs to store in the replication agreements.
        Then modify the replica object to allow these DNs to act
        as replication agents.
        """

        (a_dn, b_dn) = self.get_replica_principal_dns(a, b, retries=100)
        assert isinstance(a_dn, DN)
        assert isinstance(b_dn, DN)

        for conn, bind_dn in ((a, b_dn), (b, a_dn)):
            # Add kerberos principal DNs as valid bindDNs for replication
            self._add_replica_bind_dn(conn, bind_dn)

            # Add kerberos principal DNs as valid bindDNs to bindDN group
            self._add_dn_to_replication_managers(conn, bind_dn)

    def gssapi_update_agreements(self, a, b):

        self.setup_krb_princs_as_replica_binddns(a, b)

        #change replication agreements to connect to other host using GSSAPI
        mod = [(ldap.MOD_REPLACE, "nsds5replicatransportinfo", "LDAP"),
               (ldap.MOD_REPLACE, "nsds5replicabindmethod", "SASL/GSSAPI"),
               (ldap.MOD_DELETE, "nsds5replicabinddn", None),
               (ldap.MOD_DELETE, "nsds5replicacredentials", None)]

        _cn, a_ag_dn = self.agreement_dn(b.host)
        a.modify_s(a_ag_dn, mod)

        _cn, b_ag_dn = self.agreement_dn(a.host)
        b.modify_s(b_ag_dn, mod)

        # Finally remove the temporary replication manager user
        try:
            a.delete_entry(self.repl_man_dn)
        except errors.NotFound:
            pass
        try:
            b.delete_entry(self.repl_man_dn)
        except errors.NotFound:
            pass

    def delete_agreement(self, hostname, dn=None):
        """
        Delete a replication agreement.

        @hostname: the hostname of the agreement to remove
        @dn: optional dn of the agreement to remove

        For IPA agreements we can easily calculate the DN of the agreement
        to remove. Dogtag agreements are another matter, its agreement
        names depend entirely on where it is created. In this case it is
        better to pass the DN in directly.
        """
        if dn is None:
            _cn, dn = self.agreement_dn(hostname)
        return self.conn.delete_entry(dn)

    def delete_referral(self, hostname):
        dn = DN(('cn', self.db_suffix),
                ('cn', 'mapping tree'), ('cn', 'config'))
        # TODO: should we detect proto/port somehow ?
        mod = [(ldap.MOD_DELETE, 'nsslapd-referral',
                'ldap://%s/%s' % (ipautil.format_netloc(hostname, 389),
                                  self.db_suffix))]

        try:
            self.conn.modify_s(dn, mod)
        except Exception as e:
            logger.debug("Failed to remove referral value: %s", str(e))

    def check_repl_init(self, conn, agmtdn, start):
        done = False
        hasError = 0
        attrlist = ['cn', 'nsds5BeginReplicaRefresh',
                    'nsds5replicaUpdateInProgress',
                    'nsds5ReplicaLastInitStatus',
                    'nsds5ReplicaLastInitStatusJSON',
                    'nsds5ReplicaLastInitStart',
                    'nsds5ReplicaLastInitEnd']
        entry = conn.get_entry(agmtdn, attrlist)
        if not entry:
            print("Error reading status from agreement", agmtdn)
            hasError = 1
        else:
            refresh = entry.single_value.get('nsds5BeginReplicaRefresh')
            inprogress = entry.single_value.get('nsds5replicaUpdateInProgress')
            status = entry.single_value.get('nsds5ReplicaLastInitStatus')
            json_status = \
                entry.single_value.get('nsds5ReplicaLastInitStatusJSON')
            if not refresh:  # done - check status
                if json_status:
                    # Just reset status with the JSON 'message'
                    status_obj = json.loads(json_status)
                    status = status_obj['message']

                if not status:
                    print("No status yet")
                elif status.find("replica busy") > -1:
                    print("[%s] reports: Replica Busy! Status: [%s]"
                          % (conn.ldap_uri, status))
                    done = True
                    hasError = 2
                elif status.find("Total update succeeded") > -1:
                    print("\nUpdate succeeded")
                    done = True
                elif inprogress:
                    print("\nUpdate in progress yet not in progress")
                else:
                    print("\n[%s] reports: Update failed! Status: [%s]"
                          % (conn.ldap_uri, status))
                    hasError = 1
                    done = True
            else:
                now = datetime.datetime.now()
                d = now - start
                sys.stdout.write('\r')
                sys.stdout.write("Update in progress, %d seconds elapsed" % int(d.total_seconds()))
                sys.stdout.flush()

        return done, hasError

    def check_repl_update(self, conn, agmtdn):
        done = False
        hasError = 0
        error_message = ''
        attrlist = ['cn',
                    'nsds5replicaUpdateInProgress',
                    'nsds5ReplicaLastUpdateStatus',
                    'nsds5ReplicaLastUpdateStatusjson',
                    'nsds5ReplicaLastUpdateStart',
                    'nsds5ReplicaLastUpdateEnd']
        entry = conn.get_entry(agmtdn, attrlist)
        if not entry:
            print("Error reading status from agreement", agmtdn)
            hasError = 1
        else:
            inprogress = entry.single_value.get('nsds5replicaUpdateInProgress')
            status = entry.single_value.get('nsds5ReplicaLastUpdateStatus')
            json_status = \
                entry.single_value.get('nsds5ReplicaLastUpdateStatusjson')
            try:
                # nsds5ReplicaLastUpdateStart is either a GMT time
                # ending with Z or 0 (see 389-ds ticket 47836)
                # Remove the Z and convert to int
                start = entry.single_value['nsds5ReplicaLastUpdateStart']
                if start.endswith('Z'):
                    start = start[:-1]
                start = int(start)
            except (ValueError, TypeError, KeyError):
                start = 0
            try:
                # nsds5ReplicaLastUpdateEnd is either a GMT time
                # ending with Z or 0 (see 389-ds ticket 47836)
                # Remove the Z and convert to int
                end = entry.single_value['nsds5ReplicaLastUpdateEnd']
                if end.endswith('Z'):
                    end = end[:-1]
                end = int(end)
            except (ValueError, TypeError, KeyError):
                end = 0
            # incremental update is done if inprogress is false and end >= start
            done = inprogress is not None and not inprogress and start <= end
            logger.info("Replication Update in progress: %s: status: %s: "
                        "start: %d: end: %d",
                        inprogress, status, start, end)
            if json_status:
                # In 389-ds-base 1.4.1.4 we have the status message available
                # to us in a json object
                status_obj = json.loads(json_status)
                if status_obj['state'] != 'green':
                    hasError = 1
                    error_message = status_obj['message']
                    done = True
            elif status:  # always check for errors
                # status will usually be a number followed by a string
                # number != 0 means error
                # Since 389-ds-base 1.3.5 it is 'Error (%d) %s'
                # so we need to remove a prefix string and parentheses
                if status.startswith('Error '):
                    rc, msg = status[6:].split(' ', 1)
                    rc = rc.strip('()')
                else:
                    rc, msg = status.split(' ', 1)
                if rc != '0':
                    hasError = 1
                    error_message = msg
                    done = True

        return done, hasError, error_message

    def wait_for_repl_init(self, conn, agmtdn):
        done = False
        haserror = 0
        start = datetime.datetime.now()
        while not done and not haserror:
            time.sleep(1)  # give it a few seconds to get going
            done, haserror = self.check_repl_init(conn, agmtdn, start)
        print("")
        return haserror

    def wait_for_repl_update(self, conn, agmtdn, maxtries=600):
        done = False
        haserror = 0
        error_message = ''
        while not done and not haserror and maxtries > 0:
            time.sleep(1)  # give it a few seconds to get going
            done, haserror, error_message = self.check_repl_update(conn, agmtdn)
            maxtries -= 1
        if maxtries == 0: # too many tries
            print("Error: timeout: could not determine agreement status: please check your directory server logs for possible errors")
            haserror = 1
        return haserror, error_message

    def start_replication(self, conn, hostname=None, master=None):
        print("Starting replication, please wait until this has completed.")
        if hostname is None:
            hostname = self.hostname
        _cn, dn = self.agreement_dn(hostname, master)

        mod = [(ldap.MOD_ADD, 'nsds5BeginReplicaRefresh', 'start')]
        conn.modify_s(dn, mod)

        return self.wait_for_repl_init(conn, dn)

    def basic_replication_setup(self, conn, replica_id, repldn, replpw):
        assert isinstance(repldn, DN)
        if replpw is not None:
            self.add_replication_manager(conn, repldn, replpw)
        self.replica_config(conn, replica_id, repldn)
        self.setup_changelog(conn)

    def setup_replication(self, r_hostname, r_port=389, r_sslport=636,
                          r_binddn=None, r_bindpw=None,
                          is_cs_replica=False, local_port=None):
        assert isinstance(r_binddn, DN)
        if local_port is None:
            local_port = r_port
        # note - there appears to be a bug in python-ldap - it does not
        # allow connections using two different CA certs
        r_conn = ipaldap.LDAPClient.from_hostname_secure(r_hostname)

        if r_bindpw:
            r_conn.simple_bind(r_binddn, r_bindpw)
        else:
            r_conn.gssapi_bind()

        #Setup the first half
        l_id = self._get_replica_id(self.conn, r_conn)
        self.basic_replication_setup(self.conn, l_id,
                                     self.repl_man_dn, self.repl_man_passwd)

        # Now setup the other half
        r_id = self._get_replica_id(r_conn, r_conn)
        self.basic_replication_setup(r_conn, r_id,
                                     self.repl_man_dn, self.repl_man_passwd)

        if is_cs_replica:
            self.setup_agreement(r_conn, self.hostname, port=local_port,
                                 repl_man_dn=self.repl_man_dn,
                                 repl_man_passwd=self.repl_man_passwd,
                                 master=False)
            self.setup_agreement(self.conn, r_hostname, port=r_port,
                                 repl_man_dn=self.repl_man_dn,
                                 repl_man_passwd=self.repl_man_passwd,
                                 master=True)
        else:
            self.setup_agreement(r_conn, self.hostname, port=local_port,
                                 repl_man_dn=self.repl_man_dn,
                                 repl_man_passwd=self.repl_man_passwd)
            self.setup_agreement(self.conn, r_hostname, port=r_port,
                                 repl_man_dn=self.repl_man_dn,
                                 repl_man_passwd=self.repl_man_passwd)

        #Finally start replication
        ret = self.start_replication(r_conn, master=False)
        if ret != 0:
            raise RuntimeError("Failed to start replication")

    def unhashed_password_log(self, conn, value):
        if not conn:
            raise RuntimeError("unhashed_password_log no connection")

        if not value:
            return

        # Check the validity of the value
        if value.lower() not in ['off', 'on', 'nolog']:
            return

        # Change the value if needed
        entry = conn.get_entry(DN(('cn', 'config')),
                               ['nsslapd-unhashed-pw-switch'])
        toggle = entry.single_value.get("nsslapd-unhashed-pw-switch")
        if not toggle or not (toggle.lower() == value.lower()):
            entry["nsslapd-unhashed-pw-switch"] = value.lower()
            conn.update_entry(entry)

        # if unhashed password are being logged, display a warning
        if value.lower() == 'on':
            try:
                entry = conn.get_entry(
                    DN(('cn', 'changelog5'),
                       ('cn', 'config')),
                    ['nsslapd-changelogdir'])
                cldb = entry.single_value.get("nsslapd-changelogdir")
                logger.warning("This configuration (\"--winsync\") may imply "
                               "that the log file contains clear text "
                               "passwords.\n"
                               "Please ensure that these files can be accessed"
                               " only by trusted accounts.\n"
                               "Log files are under %s", cldb)
            except errors.NotFound:
                logger.warning("This configuration (\"--winsync\") may imply "
                               "that the log file contains clear text "
                               "passwords.\n"
                               "Please ensure that these files can be accessed"
                               " only by trusted accounts.")

    def setup_winsync_replication(self,
                                  ad_dc_name, ad_binddn, ad_pwd,
                                  passsync_pw, ad_subtree,
                                  cacert=paths.IPA_CA_CRT):
        self.ad_suffix = ""
        try:
            # Validate AD connection
            ad_conn = ldap_initialize(
                'ldap://%s' % ipautil.format_netloc(ad_dc_name),
                cacertfile=cacert
            )
            ad_conn.start_tls_s()
            ad_conn.simple_bind_s(str(ad_binddn), ad_pwd)
            res = ad_conn.search_s("", ldap.SCOPE_BASE, '(objectClass=*)',
                                   ['defaultNamingContext'])
            for dn,entry in res:
                if dn == "":
                    ad_suffix = entry['defaultNamingContext'][0]
                    self.ad_suffix = ad_suffix.decode('utf-8')
                    logger.info("AD Suffix is: %s", self.ad_suffix)
            if self.ad_suffix == "":
                raise RuntimeError("Failed to lookup AD's Ldap suffix")
            ad_conn.unbind_s()
            del ad_conn
        except Exception as e:
            logger.info("Failed to connect to AD server %s", ad_dc_name)
            logger.info("The error was: %s", e)
            raise RuntimeError("Failed to setup winsync replication")

        # Setup the only half.
        # there is no other side to get a replica ID from
        # So we generate one locally
        replica_id = self._get_replica_id(self.conn, self.conn)
        self.basic_replication_setup(self.conn, replica_id,
                                     self.repl_man_dn, self.repl_man_passwd)

        #now add a passync user allowed to access the AD server
        self.add_passsync_user(self.conn, passsync_pw)
        self.setup_agreement(self.conn, ad_dc_name,
                             repl_man_dn=ad_binddn, repl_man_passwd=ad_pwd,
                             iswinsync=True, win_subtree=ad_subtree)
        logger.info("Added new sync agreement, waiting for it to become "
                    "ready . . .")
        _cn, dn = self.agreement_dn(ad_dc_name)
        self.wait_for_repl_update(self.conn, dn, 300)
        logger.info("Agreement is ready, starting replication . . .")

        # Add winsync replica to the public DIT
        dn = DN(('cn',ad_dc_name),('cn','replicas'),('cn','ipa'),('cn','etc'), self.suffix)
        entry = self.conn.make_entry(
            dn,
            objectclass=["nsContainer", "ipaConfigObject"],
            cn=[ad_dc_name],
            ipaConfigString=["winsync:%s" % self.hostname],
        )

        try:
            self.conn.add_entry(entry)
        except Exception:
            logger.info("Failed to create public entry for winsync replica")

        # For winsync, unhashed passwords needs to be in replication changelog
        # Time to alarm about a security risk
        self.unhashed_password_log(self.conn, 'on')


        #Finally start replication
        ret = self.start_replication(self.conn, ad_dc_name)
        if ret != 0:
            raise RuntimeError("Failed to start replication")

    def convert_to_gssapi_replication(self, r_hostname, r_binddn, r_bindpw):
        r_conn = ipaldap.LDAPClient.from_hostname_secure(r_hostname)
        if r_bindpw:
            r_conn.simple_bind(r_binddn, r_bindpw)
        else:
            r_conn.gssapi_bind()

        # First off make sure servers are in sync so that both KDCs
        # have all principals and their passwords and can release
        # the right tickets. We do this by force pushing all our changes
        self.force_sync(self.conn, r_hostname)
        _cn, dn = self.agreement_dn(r_hostname)
        self.wait_for_repl_update(self.conn, dn, 300)

        # now in the opposite direction
        self.force_sync(r_conn, self.hostname)
        _cn, dn = self.agreement_dn(self.hostname)
        self.wait_for_repl_update(r_conn, dn, 300)

        # now that directories are in sync,
        # change the agreements to use GSSAPI
        self.gssapi_update_agreements(self.conn, r_conn)

    def setup_gssapi_replication(self, r_hostname, r_binddn=None, r_bindpw=None):
        """
        Directly sets up GSSAPI replication.
        Only usable to connect 2 existing replicas (needs existing kerberos
        principals)
        """
        r_conn = ipaldap.LDAPClient.from_hostname_secure(r_hostname)
        if r_bindpw:
            r_conn.simple_bind(r_binddn, r_bindpw)
        else:
            r_conn.gssapi_bind()

        # Allow krb principals to act as replicas
        self.setup_krb_princs_as_replica_binddns(self.conn, r_conn)

        # Create mutual replication agreementsausiung SASL/GSSAPI
        self.setup_agreement(self.conn, r_hostname, isgssapi=True)
        self.setup_agreement(r_conn, self.hostname, isgssapi=True)

    def initialize_replication(self, dn, conn):
        mod = [(ldap.MOD_ADD, 'nsds5BeginReplicaRefresh', 'start'),
               (ldap.MOD_REPLACE, 'nsds5ReplicaEnabled', 'on')]
        try:
            conn.modify_s(dn, mod)
        except ldap.ALREADY_EXISTS:
            pass

    def force_sync(self, conn, hostname):

        newschedule = '2358-2359 0'

        filter = self.get_agreement_filter(host=hostname)
        try:
            entries = conn.get_entries(
                DN(('cn', 'config')), ldap.SCOPE_SUBTREE, filter)
        except errors.NotFound:
            logger.error("Unable to find replication agreement for %s",
                         hostname)
            raise RuntimeError("Unable to proceed")
        if len(entries) > 1:
            logger.error("Found multiple agreements for %s", hostname)
            logger.error("Using the first one only (%s)", entries[0].dn)

        dn = entries[0].dn
        schedule = entries[0].single_value.get('nsds5replicaupdateschedule')

        # On the remote chance of a match. We force a synch to happen right
        # now by setting the schedule to something and quickly removing it.
        if schedule is not None:
            if newschedule == schedule:
                newschedule = '2358-2359 1'
        logger.info("Setting agreement %s schedule to %s to force synch",
                    dn, newschedule)
        mod = [(ldap.MOD_REPLACE, 'nsDS5ReplicaUpdateSchedule', [ newschedule ])]
        conn.modify_s(dn, mod)
        time.sleep(1)
        logger.info("Deleting schedule %s from agreement %s",
                    newschedule, dn)
        mod = [(ldap.MOD_DELETE, 'nsDS5ReplicaUpdateSchedule', None)]
        conn.modify_s(dn, mod)

    def get_agreement_type(self, hostname):

        entry = self.get_replication_agreement(hostname)
        if not entry:
            raise errors.NotFound(
                reason="Replication agreement for %s not found" % hostname)
        objectclass = entry.get("objectclass")

        for o in objectclass:
            if o.lower() == "nsdswindowsreplicationagreement":
                return WINSYNC

        return IPA_REPLICA

    def replica_cleanup(self, replica, realm, force=False):
        """
        This function removes information about the replica in parts
        of the shared tree that expose it, so clients stop trying to
        use this replica.
        """

        err = None

        if replica == self.hostname:
            raise RuntimeError("Can't cleanup self")

        # delete master kerberos key and all its svc principals
        try:
            entries = self.conn.get_entries(
                self.suffix, ldap.SCOPE_SUBTREE,
                filter='(krbprincipalname=*/%s@%s)' % (replica, realm))
            if entries:
                entries.sort(key=lambda x: len(x.dn), reverse=True)
                for entry in entries:
                    self.conn.delete_entry(entry)
        except errors.NotFound:
            pass
        except Exception as e:
            if not force:
                raise e
            else:
                err = e

        # remove replica memberPrincipal from s4u2proxy configuration
        dn1 = DN(('cn', 'ipa-http-delegation'), api.env.container_s4u2proxy, self.suffix)
        member_principal1 = "HTTP/%(fqdn)s@%(realm)s" % dict(fqdn=replica, realm=realm)

        dn2 = DN(('cn', 'ipa-ldap-delegation-targets'), api.env.container_s4u2proxy, self.suffix)
        member_principal2 = "ldap/%(fqdn)s@%(realm)s" % dict(fqdn=replica, realm=realm)

        dn3 = DN(('cn', 'ipa-cifs-delegation-targets'), api.env.container_s4u2proxy, self.suffix)
        member_principal3 = "cifs/%(fqdn)s@%(realm)s" % dict(fqdn=replica, realm=realm)

        for (dn, member_principal) in ((dn1, member_principal1),
                                       (dn2, member_principal2),
                                       (dn3, member_principal3)):
            try:
                mod = [(ldap.MOD_DELETE, 'memberPrincipal', member_principal)]
                self.conn.modify_s(dn, mod)
            except (ldap.NO_SUCH_OBJECT, ldap.NO_SUCH_ATTRIBUTE):
                logger.debug("Replica (%s) memberPrincipal (%s) not found in "
                             "%s",
                             replica, member_principal, dn)
            except Exception as e:
                if not force:
                    raise e
                elif not err:
                    err = e

        # delete master entry with all active services
        try:
            dn = DN(('cn', replica), api.env.container_masters, self.suffix)
            entries = self.conn.get_entries(dn, ldap.SCOPE_SUBTREE)
            if entries:
                entries.sort(key=lambda x: len(x.dn), reverse=True)
                for entry in entries:
                    self.conn.delete_entry(entry)
        except errors.NotFound:
            pass
        except Exception as e:
            if not force:
                raise e
            elif not err:
                err = e

        try:
            basedn = DN(('cn', 'etc'), self.suffix)
            filter = '(dnaHostname=%s)' % replica
            entries = self.conn.get_entries(
                basedn, ldap.SCOPE_SUBTREE, filter=filter)
            if len(entries) != 0:
                for entry in entries:
                    self.conn.delete_entry(entry)
        except errors.NotFound:
            pass
        except Exception as e:
            if not force:
                raise e
            elif not err:
                err = e

        # delete DNS server configuration, if any
        try:
            api.Command.dnsserver_del(unicode(replica))
        except errors.NotFound:
            pass
        except Exception as e:
            if not force:
                raise e
            elif not err:
                err = e

        try:
            dn = DN(('cn', 'default'), ('ou', 'profile'), self.suffix)
            ret = self.conn.get_entry(dn)
            srvlist = ret.single_value.get('defaultServerList', '')
            srvlist = srvlist.split()
            if replica in srvlist:
                srvlist.remove(replica)
                attr = ' '.join(srvlist)
                ret['defaultServerList'] = attr
                self.conn.update_entry(ret)
        except errors.NotFound:
            pass
        except errors.MidairCollision:
            pass
        except errors.EmptyModlist:
            pass
        except Exception as e:
            if force and err:
                raise err
            else:
                raise e

        if err:
            raise err

    def set_readonly(self, readonly, critical=False):
        """
        Set the database readonly status.

        @readonly: boolean for read-only status
        @critical: boolean to raise an exception on failure, default False.
        """
        dn = DN(('cn', 'userRoot'), ('cn', 'ldbm database'),
                ('cn', 'plugins'), ('cn', 'config'))

        mod = [(ldap.MOD_REPLACE, 'nsslapd-readonly', 'on' if readonly else 'off')]
        try:
            self.conn.modify_s(dn, mod)
        except ldap.INSUFFICIENT_ACCESS as e:
            # We can't modify the read-only status on the remote server.
            # This usually isn't a show-stopper.
            if critical:
                raise e
            logger.debug("No permission to modify replica read-only status, "
                         "continuing anyway")

    def cleanallruv(self, replicaId):
        """
        Create a CLEANALLRUV task and monitor it until it has
        completed.
        """
        logger.debug("Creating CLEANALLRUV task for replica id %d", replicaId)

        dn = DN(('cn', 'clean %d' % replicaId), ('cn', 'cleanallruv'),('cn', 'tasks'), ('cn', 'config'))
        e = self.conn.make_entry(
            dn,
            {
                'objectclass': ['top', 'extensibleObject'],
                'cn': ['clean %d' % replicaId],
                'replica-base-dn': [self.db_suffix],
                'replica-id': [replicaId],
                'replica-force-cleaning': ['yes'],
            }
        )
        try:
            self.conn.add_entry(e)
        except errors.DuplicateEntry:
            print("CLEANALLRUV task for replica id %d already exists." % replicaId)
        else:
            print("Background task created to clean replication data. This may take a while.")

        print("This may be safely interrupted with Ctrl+C")

        wait_for_task(self.conn, dn)

    def abortcleanallruv(self, replicaId, force=False):
        """
        Create a task to abort a CLEANALLRUV operation.
        """
        logger.debug("Creating task to abort a CLEANALLRUV operation for "
                     "replica id %d", replicaId)

        dn = DN(('cn', 'abort %d' % replicaId), ('cn', 'abort cleanallruv'),('cn', 'tasks'), ('cn', 'config'))
        e = self.conn.make_entry(
            dn,
            {
                'replica-base-dn': [api.env.basedn],
                'replica-id': [replicaId],
                'objectclass': ['top', 'extensibleObject'],
                'cn': ['abort %d' % replicaId],
                'replica-certify-all': ['no'] if force else ['yes'],
            }
        )
        try:
            self.conn.add_entry(e)
        except errors.DuplicateEntry:
            print("An abort CLEANALLRUV task for replica id %d already exists." % replicaId)
        else:
            print("Background task created. This may take a while.")

        print("This may be safely interrupted with Ctrl+C")

        wait_for_task(self.conn, dn)

    def get_DNA_range(self, hostname):
        """
        Return the DNA range on this server as a tuple, (next, max), or
        (None, None) if no range has been assigned yet.

        Raises an exception on errors reading an entry.
        """
        entry = self.conn.get_entry(DNA_DN)

        nextvalue = int(entry.single_value.get("dnaNextValue", 0))
        maxvalue = int(entry.single_value.get("dnaMaxValue", 0))

        sharedcfgdn = entry.single_value.get("dnaSharedCfgDN")
        if sharedcfgdn is not None:
            sharedcfgdn = DN(sharedcfgdn)

            shared_entry = self.conn.get_entry(sharedcfgdn)
            remaining = int(shared_entry.single_value.get("dnaRemainingValues", 0))
        else:
            remaining = 0

        if nextvalue == 0 and maxvalue == 0:
            return (None, None)

        # Check the magic values for an unconfigured DNA entry
        if maxvalue == 1100 and nextvalue == 1101 and remaining == 0:
            return (None, None)
        else:
            return (nextvalue, maxvalue)

    def get_DNA_next_range(self, hostname):
        """
        Return the DNA "on-deck" range on this server as a tuple, (next, max),
        or
        (None, None) if no range has been assigned yet.

        Raises an exception on errors reading an entry.
        """
        entry = self.conn.get_entry(DNA_DN)

        range = entry.single_value.get("dnaNextRange")

        if range is None:
            return (None, None)

        try:
            (next, max) = range.split('-')
        except ValueError:
            # Should not happen, malformed entry, return nothing.
            return (None, None)

        return (int(next), int(max))

    def save_DNA_next_range(self, next_start, next_max):
        """
        Save a DNA range into the on-deck value.

        This adds a dnaNextRange value to the DNA configuration. This
        attribute takes the form of start-next.

        Returns True on success.
        Returns False if the range is already defined.
        Raises an exception on failure.
        """
        entry = self.conn.get_entry(DNA_DN)

        range = entry.single_value.get("dnaNextRange")

        if range is not None and next_start != 0 and next_max != 0:
            return False

        if next_start == 0 and next_max == 0:
            entry["dnaNextRange"] = None
        else:
            entry["dnaNextRange"] = "%s-%s" % (next_start, next_max)

        self.conn.update_entry(entry)

        return True

    def save_DNA_range(self, next_start, next_max):
        """
        Save a DNA range.

        This is potentially very dangerous.

        Returns True on success. Raises an exception on failure.
        """
        entry = self.conn.get_entry(DNA_DN)

        entry["dnaNextValue"] = next_start
        entry["dnaMaxValue"] = next_max

        self.conn.update_entry(entry)

        return True

    def disable_agreement(self, hostname):
        """
        Disable the replication agreement to hostname.
        """
        entry = self.get_replication_agreement(hostname)
        if not entry:
            raise errors.NotFound(reason=_(
                "Replication agreement for %(hostname)s not found") % {
                    'hostname': hostname
                })
        entry['nsds5ReplicaEnabled'] = 'off'

        try:
            self.conn.update_entry(entry)
        except errors.EmptyModlist:
            pass

    def enable_agreement(self, hostname):
        """
        Enable the replication agreement to hostname.

        Note: for replication to work it needs to be enabled both ways.
        """
        entry = self.get_replication_agreement(hostname)
        if not entry:
            raise errors.NotFound(reason=_(
                "Replication agreement for %(hostname)s not found") % {
                    'hostname': hostname
                })
        entry['nsds5ReplicaEnabled'] = 'on'

        try:
            self.conn.update_entry(entry)
        except errors.EmptyModlist:
            pass

    def _add_replication_managers(self, conn):
        entry = conn.make_entry(
            self.repl_man_group_dn,
            objectclass=['top', 'groupofnames'],
            cn=['replication managers']
        )
        try:
            conn.add_entry(entry)
        except errors.DuplicateEntry:
            pass

    def ensure_replication_managers(self, conn, r_hostname):
        """
        Ensure that the 'cn=replication managers,cn=sysaccounts' group exists
        and contains the principals for master and remote replica

        On IPA 3.x masters lacking support for nsds5ReplicaBinddnGroup
        attribute, add replica bind DN directly into the replica entry.
        """
        my_dn = DN(
            ('krbprincipalname', u'ldap/%s@%s' % (self.hostname, self.realm)),
            api.env.container_service,
            api.env.basedn
        )
        remote_dn = DN(
            ('krbprincipalname', u'ldap/%s@%s' % (r_hostname, self.realm)),
            api.env.container_service,
            api.env.basedn
        )

        try:
            conn.get_entry(self.repl_man_group_dn)
        except errors.NotFound:
            self._add_replica_bind_dn(conn, my_dn)
            self._add_replication_managers(conn)

        self._add_dn_to_replication_managers(conn, my_dn)
        self._add_dn_to_replication_managers(conn, remote_dn)

    def add_temp_sasl_mapping(self, conn, r_hostname):
        """
        Create a special user to let SASL Mapping find a valid user
        on first replication.
        """
        name = 'ldap/%s@%s' % (r_hostname, self.realm)
        replica_binddn = DN(('cn', name), ('cn', 'config'))
        entry = conn.make_entry(
            replica_binddn,
            objectclass=["top", "person"],
            cn=[name],
            sn=["replication manager pseudo user"]
        )
        conn.add_entry(entry)

        entry = conn.get_entry(self.replica_dn())
        entry['nsDS5ReplicaBindDN'].append(replica_binddn)
        try:
            conn.update_entry(entry)
        except errors.EmptyModlist:
            pass

        entry = conn.make_entry(
            DN(('cn', 'Peer Master'), ('cn', 'mapping'), ('cn', 'sasl'),
                ('cn', 'config')),
            objectclass=["top", "nsSaslMapping"],
            cn=["Peer Master"],
            nsSaslMapRegexString=['^[^:@]+$'],
            nsSaslMapBaseDNTemplate=[DN(('cn', 'config'))],
            nsSaslMapFilterTemplate=['(cn=&@%s)' % self.realm],
            nsSaslMapPriority=['1'],
        )
        try:
            conn.add_entry(entry)
        except errors.DuplicateEntry:
            pass

    def remove_temp_replication_user(self, conn, r_hostname):
        """
        Remove the special SASL Mapping user created in a previous step.
        """
        name = 'ldap/%s@%s' % (r_hostname, self.realm)
        replica_binddn = DN(('cn', name), ('cn', 'config'))
        conn.delete_entry(replica_binddn)

        entry = conn.get_entry(self.replica_dn())
        while replica_binddn in entry['nsDS5ReplicaBindDN']:
            entry['nsDS5ReplicaBindDN'].remove(replica_binddn)
        conn.update_entry(entry)

    def setup_promote_replication(self, r_hostname, r_binddn=None,
                                  r_bindpw=None, cacert=paths.IPA_CA_CRT):
        r_conn = ipaldap.LDAPClient.from_hostname_secure(
            r_hostname, cacert=cacert)
        if r_bindpw:
            r_conn.simple_bind(r_binddn, r_bindpw)
        else:
            r_conn.gssapi_bind()

        # Setup the first half
        l_id = self._get_replica_id(self.conn, r_conn)
        self.basic_replication_setup(self.conn, l_id, self.repl_man_dn, None)
        self.add_temp_sasl_mapping(self.conn, r_hostname)

        # Now setup the other half
        r_id = self._get_replica_id(r_conn, r_conn)
        self.basic_replication_setup(r_conn, r_id, self.repl_man_dn, None)
        self.ensure_replication_managers(r_conn, r_hostname)

        self.setup_agreement(r_conn, self.hostname, isgssapi=True)
        self.setup_agreement(self.conn, r_hostname, isgssapi=True)

        # Finally start replication
        ret = self.start_replication(r_conn, master=False)
        if ret != 0:
            raise RuntimeError("Failed to start replication")

        self.remove_temp_replication_user(self.conn, r_hostname)


class CSReplicationManager(ReplicationManager):
    """ReplicationManager specific to CA agreements

    Note that in most cases we don't know if we're connecting to an old-style
    separate PKI DS, or to a host with a merged DB.
    Use the get_cs_replication_manager function to determine this and return
    an appropriate CSReplicationManager.
    """

    def __init__(self, realm, hostname, dirman_passwd, port):
        super(CSReplicationManager, self).__init__(
            realm, hostname, dirman_passwd, port, starttls=True)
        self.db_suffix = DN(('o', 'ipaca'))
        self.hostnames = [] # set before calling or agreement_dn() will fail

    def agreement_dn(self, hostname, master=None):
        """
        Construct a dogtag replication agreement name. This needs to be much
        more agressive than the IPA replication agreements because the name
        is different on each side.

        hostname is the local hostname, not the remote one, for both sides
        NOTE: The agreement number is hardcoded in dogtag as well

        TODO: configurable instance name
        """
        dn = None
        cn = None
        if self.conn.port == 7389:
            instance_name = 'pki-ca'
        else:
            instance_name = 'pki-tomcat'

        # if master is not None we know what dn to return:
        if master is not None:
            if master is True:
                name = "master"
            else:
                name = "clone"
            cn="%sAgreement1-%s-%s" % (name, hostname, instance_name)
            dn = DN(('cn', cn), self.replica_dn())
            return (cn, dn)

        for host in self.hostnames:
            for master in ["master", "clone"]:
                try:
                    cn="%sAgreement1-%s-%s" % (master, host, instance_name)
                    dn = DN(('cn', cn), self.replica_dn())
                    self.conn.get_entry(dn)
                    return (cn, dn)
                except errors.NotFound:
                    dn = None
                    cn = None

        raise errors.NotFound(reason='No agreement found for %s' % hostname)

    def delete_referral(self, hostname, port):
        dn = DN(('cn', self.db_suffix),
                ('cn', 'mapping tree'), ('cn', 'config'))
        entry = self.conn.get_entry(dn)
        try:
            # TODO: should we detect proto somehow ?
            entry['nsslapd-referral'].remove(
                'ldap://%s/%s' %
                (ipautil.format_netloc(hostname, port), self.db_suffix))
            self.conn.update_entry(entry)
        except Exception as e:
            logger.debug("Failed to remove referral value: %s", e)

    def has_ipaca(self):
        try:
            self.conn.get_entry(self.db_suffix)
        except errors.NotFound:
            return False
        else:
            return True


def get_cs_replication_manager(realm, host, dirman_passwd):
    """Get a CSReplicationManager for a remote host

    Detects if the host has a merged database, connects to appropriate port.
    """

    # Try merged database port first. If it has the ipaca tree, return
    # corresponding replication manager
    # If we can't connect to it at all, we're not dealing with an IPA master
    # anyway; let the exception propagate up
    # Fall back to the old PKI-only DS port. Check that it has the ipaca tree
    # (IPA with merged DB theoretically leaves port 7389 free for anyone).
    # If it doesn't, raise exception.
    ports = [389, 7389]
    for port in ports:
        logger.debug('Looking for PKI DS on %s:%s', host, port)
        replication_manager = CSReplicationManager(
            realm, host, dirman_passwd, port)
        if replication_manager.has_ipaca():
            logger.debug('PKI DS found on %s:%s', host, port)
            return replication_manager
        else:
            logger.debug('PKI tree not found on %s:%s', host, port)

    raise errors.NotFound(reason='Cannot reach PKI DS at %s on ports %s' % (host, ports))


class CAReplicationManager(ReplicationManager):
    """ReplicationManager specific to CA agreements for domain level 1 and
    above servers.
    """

    def __init__(self, realm, hostname):
        # Always connect to self over ldapi
        conn = ipaldap.LDAPClient.from_realm(realm)
        conn.external_bind()
        super(CAReplicationManager, self).__init__(
            realm, hostname, None, port=DEFAULT_PORT, conn=conn)
        self.db_suffix = DN(('o', 'ipaca'))
        self.agreement_name_format = "caTo%s"

    def setup_cs_replication(self, r_hostname):
        """
        Assumes a promote replica with working GSSAPI for replication
        and unified DS instance.
        """
        r_conn = ipaldap.LDAPClient.from_hostname_secure(r_hostname)
        r_conn.gssapi_bind()

        # Setup the first half
        l_id = self._get_replica_id(self.conn, r_conn)
        self.basic_replication_setup(self.conn, l_id, self.repl_man_dn, None)

        # Now setup the other half
        r_id = self._get_replica_id(r_conn, r_conn)
        self.basic_replication_setup(r_conn, r_id, self.repl_man_dn, None)

        self.setup_agreement(r_conn, self.hostname, isgssapi=True)
        self.setup_agreement(self.conn, r_hostname, isgssapi=True)

        # Finally start replication
        ret = self.start_replication(r_conn, master=False)
        if ret != 0:
            raise RuntimeError("Failed to start replication")


def run_server_del_as_cli(api_instance, hostname, **options):
    """
    run server_del API command and print the result to stdout/stderr using
    textui backend.

    :params api_instance: API instance
    :params hostname: server FQDN
    :params options: options for server_del command
    """
    server_del_cmd = api_instance.Command.server_del

    if 'version' not in options:
        options['version'] = api_instance.env.api_version

    result = server_del_cmd(hostname, **options)

    textui_backend = textui(api_instance)
    server_del_cmd.output_for_cli(textui_backend, result, hostname, **options)
