# ipa-migrate
#
# IPA to IPA migration tool
#
# Copyright (C) 2023  FreeIPA Contributors see COPYING for license
#
# PYTHON_ARGCOMPLETE_OK

import argcomplete
import argparse
import base64
import datetime
import getpass
import ldap
import ldif
import logging
import os
import socket
import subprocess
import sys
import time
from cryptography import x509 as crypto_x509
from ldap.controls import SimplePagedResultsControl
from ipalib import api, errors
from ipalib.facts import is_ipa_configured
from ipalib.x509 import IPACertificate
from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython.ipaldap import LDAPClient, LDAPEntry, realm_to_ldapi_uri
from ipapython.ipa_log_manager import standard_logging_setup
from ipapython.admintool import admin_cleanup_global_argv
from ipaserver.install.ipa_migrate_constants import (
    DS_CONFIG, DB_OBJECTS, DS_INDEXES, BIND_DN, LOG_FILE_NAME,
    STRIP_OP_ATTRS, STRIP_ATTRS, STRIP_OC, PROD_ATTRS,
    DNA_REGEN_VAL, DNA_REGEN_ATTRS, IGNORE_ATTRS,
    DB_EXCLUDE_TREES, POLICY_OP_ATTRS
)

"""
Migration design
==============================================================================

Design Features

- Migration consists of three areas:  schema, config, and database
- Allow online (LDAP) or offline (LDIF file) migration. Can mix and match
LDIFs with LDAP, but the LDIF needs to come from the same server where the
online data is retrieved
    - Why use LDIF files instead of over the network LDAP?
    - Large databases could take a long time to process, and connections
      could get closed.timed out, etc.
    - Also allows a "backup" to be used
      for the migration (assuming if you have LDIFs of the schema,
      config (dse.ldif) and DB (userroot))
- There are options to skip schema or config migration (not sure if this is
needed, but the functionality is present)
- Config and Database migrations uses a "map" object.  This map object also
contains the "Summary Report" data items (labels and counts)
- With over LDAP or LDIF, all entries are converted to a common format for
consistent processing.

Schema Migration
--------------------------------
- Option to completely overwrite schema on local server with whatever schema
is on remote server
- Process each attr/objectclass individually.  If the "name" exists we do NOT
attempt to migrate it.  It is skipped, unless the "overwrite" option is set.
We track stats on what attrs/objectclasses are migrated and skipped

Config Migration
--------------------------------
- Uses a "map" object (DS_CONFIG) to categorize the type of config entry we
wish to migrate.
- Each config type in the map contains attributes (singled valued and
multi-valued) that we care about.  We can not rely on schema because the core
config settings are unfortunately not in the schema.
-

Database Migration
--------------------------------
- Uses a map object (DB_OBJECTS) to identify entries and keep track of what is
updated
- First we skip entries that in the excluded list
- The entry "type" is determined by DB_OBJECTS mapping.  If the type is
  unknown then the entry is skipped.
- Skip remote server CA certificate
    - There migth be a case to keep these, but not as the main CA. TODO discuss
- Skip the remote "computer"
- Then the remote entry is cleaned -->  clean_entry()
    - Remove attributes from the ignore/strip list
    - Replace suffix/realm/hostname/domainname in all attribute values and DN
    - Remove objectclasses from groups (STRIP_OC list)  Might not be needed
    - userCertificate is removed -> if issued by IPA
    - Remove unused objectclasses
- The entry is then checked if it exists on local server.  If it does not exist
  it is added, otherwise we compare the remote and local entries and update the
  local entry --> update_local_entry()
    - Normalize attribute names to match the case of the local server's attrs
    - Loop over remote entry attributes
        - Skipping attrs from the "ignore list"
        - Check the migration mode (prod-mode & stage-mode)
            - If prod-mode, we migrate SIDs and DNA ranges
            - If stage-mode, SIDs and DNA are skipped, and dna attributes
              (uidNumber, gidNumber) are reset to the magic value
        - Check if attribute is defined in the mappings "special_attrs" list
            - If it is a special attribute then handle attribute comparison
              according to the special definition (e.g. list) and update the
              local entry. Then move on to next attribute...
        - If the attribute is not "special" then we simply compare attribute to
          attribute.
            - If requested, DNA values are reset (magic regen) at this stage
            - If attribute being updated is "single-valued" then "replace" the
              value.  If its "multi-valued" then "append" the different value.

Other
--------------------------------
There is a lot of normalization going on because we use dictionaries for
attribute names, but attribute names are CIS, we have to normalize them during
comparison, but we need to continue to use the original case when we go to
update the local entry.  So in some cases we normalize to all lowercase, but
when updatng the local entry we normalize the case of the remote attributes to
match the local entry's attribute case


What's next
 - ask trivino to skip teardown on CI so I can get data

 Some users/customers add their own entries to the db. Need more info on this
 as those entries will not be migrated by default

 after password change (but doesn't look like we can reset admin pass:
     kinit_as_user -> for admin  in IPA API somewhere

 write test from "integration" tests (new class)
"""


logger = logging.getLogger(__name__)

# Audit stats
stats = {
    # Schema
    'schema_attrs_added': 0,
    'schema_attrs_skipped': 0,
    'schema_oc_added': 0,
    'schema_oc_skipped': 0,
    'schema_processed': 0,
    # Config
    'config_processed': 0,
    'config_migrated': 0,
    # general
    'conflicts': 0,  # LDIF log entries
    'ignored_errors': 0,  # force option
    # db
    'reset_range': 0,
    'custom': 0,
    'total_db_entries': 0,
    'total_db_migrated': 0,
}


#
# Generic helper functions
#
def normalize_attr(entry_attrs, attr):
    """
    Convert all the entry attributes that match "attr" to same case as "attr"
    """
    vals = []
    nattr = attr.lower()
    for key_attr in entry_attrs:
        if key_attr.lower() == nattr:
            vals = entry_attrs[key_attr].copy()
            del entry_attrs[key_attr]
            break
    if vals:
        entry_attrs[attr] = vals


def ensure_str(val):
    """
    Convert all non-binary values to strings for easier comparision
    """
    if val is not None and type(val) is not str:
        try:
            result = val.decode('utf-8')
        except UnicodeDecodeError:
            # binary value, must return it as is
            result = val
        return result
    return val


def ensure_list_str(val):
    return [ensure_str(v) for v in val]


def decode_attr_vals(entry_attrs):
    """
    Decode all attribute values for easier processing
    """
    decoded_attrs = {}
    for attr in entry_attrs:
        vals = ensure_list_str(entry_attrs[attr])
        decoded_attrs[attr] = vals
    return decoded_attrs


def get_ldif_attr_val(attr, val):
    """
    Convert an attribute value to text we can use in an LDIF file.
    Return the LDIF format of the attribute value pair
    """
    if type(val) is str:
        return f"{attr}: {val}\n"
    try:
        val = val.decode('utf-8')
        return f"{attr}: {val}\n"
    except UnicodeDecodeError:
        val = base64.b64encode(val)
        val = val.decode('utf-8')
        return f"{attr}:: {val}\n"


def get_ldif_records(ldif_file, decode=True):
    """
    Returns a list of all the parsed records. Only run this on small LDIF
    files as all the entries go into memory (cn=config/cn=schema is ok).
    """
    content = ldif.LDIFRecordList(open(ldif_file, "r"))
    content.parse()

    # LDIF entries look like [(dn, entry), (dn, entry), ...]
    # dn = Str
    # entry = {ATTR: [b'value', b'value', ...], ATTR: [], ...}
    if decode:
        entries = []
        for dn, entry in content.all_records:
            entries.append((dn, decode_attr_vals(entry)))
        return entries
    else:
        # Return binary string as LDIFRecordList intended
        return content.all_records


def print_progress(msg):
    sys.stdout.write('\r')
    sys.stdout.write(msg)
    sys.stdout.flush()


#
# ldif.LDIFParser requires that we create our own handler for parsing records
# We need to set our class so we can call the IPAMigrate functions
#
class LDIFParser(ldif.LDIFParser):
    mc = None
    get_realm = False

    def set_class(self, obj):
        # Sets the IPAMigrate class
        self.mc = obj

    def look_for_realm(self):
        self.get_realm = True

    # Override handle() to do our specific migration work
    def handle(self, dn, entry):
        if self.mc is None:
            return

        if self.get_realm:
            # Get the realm from krb container
            if DN(("cn", "kerberos"), self.mc.remote_suffix) in DN(dn):
                # check objectclass krbrealmcontainer
                oc_attr = 'objectClass'
                if 'objectclass' in entry:
                    oc_attr = 'objectclass'
                if 'krbrealmcontainer' in ensure_list_str(entry[oc_attr]):
                    self.mc.remote_realm = ensure_str(entry['cn'][0])
                    self.mc.log_debug("Found remote realm from ldif: "
                                      f"{self.mc.remote_realm}")
        else:
            entry_attrs = decode_attr_vals(entry)
            self.mc.process_db_entry(entry_dn=dn, entry_attrs=entry_attrs)


class SensitiveStoreAction(argparse._StoreAction):
    def __init__(self, *, sensitive, **options):
        super(SensitiveStoreAction, self).__init__(**options)
        self.sensitive = sensitive

    def _get_kwargs(self):
        names = super(SensitiveStoreAction, self)._get_kwargs()
        sensitive_name = 'sensitive'
        names.extend((sensitive_name, getattr(self, sensitive_name)))
        return names


#
# Migrate IPA to IPA Class
#
class IPAMigrate():
    command_name = "ipa-migrate"
    mode = None
    args = None
    bindpw = None
    remote_suffix = None
    local_suffix = None
    log_file_name = LOG_FILE_NAME
    log_file_mode = "a"  # or "w" TBD
    local_conn = None
    remote_conn = None
    log = logger
    ldif_writer = None
    realm = None
    remote_realm = None
    dryrun = False
    dryrun_record = None
    post_notes = [
        'You will have to manually migrate IDM related configuration files.  '
        'Here are some, but not all, of the configuration files to look into:'
        '\n    - /etc/ipa/*'
        '\n    - /etc/sssd/sssd.conf'
        '\n    - /etc/named.conf'
        '\n    - /etc/named/*'
        '\n    - ...',
        'SSSD should be restarted after a successful migration',
    ]

    #
    # Argument Options (will be impacted by AdminTool)
    #
    # AdminTool uses optParse which is deprecated.  I'd like to see IPA migrate
    # over to argParse instead of reverting this code to optParse (we will see)
    #
    def add_options(self, parser):
        parser.add_argument('mode', choices=['prod-mode', 'stage-mode'],
                            help='Migration mode. Choose from "prod-mode" '
                                 'for a production server, or "stage-mode" '
                                 'for a staged server.  In "prod-mode" '
                                 'everything will be migrated including the '
                                 'current user sids and DNA ranges.  In '
                                 '"stage-mode" sids, dna ranges, etc are '
                                 'not migrated')
        parser.add_argument('hostname',
                            help='The FQDN hostname of the remote IPA '
                                 'server to migrate to this local IPA '
                                 'instance')
        parser.add_argument('-v', '--verbose', help='Verbose output',
                            action='store_true', default=False, dest='verbose')
        parser.add_argument('-D', '--bind-dn',
                            help='The Bind DN to authenticate to the remote '
                                 f'server.  The default is "{BIND_DN}"',
                            default=BIND_DN)
        parser.add_argument('-w', '--bind-pw',
                            help='Password for the Bind DN.  If a password '
                                 'is not provided then the user will be '
                                 'prompted to enter it',
                            default=None, sensitive=True,
                            action=SensitiveStoreAction)
        parser.add_argument('-j', '--bind-pw-file',
                            help='A text file containing the clear text '
                                 'password for the Bind DN', default=None)
        parser.add_argument('-Z', '--cacertfile',
                            help='File containing a CA Certificate that the '
                                 'remote server trusts',
                            default=None)
        parser.add_argument('-s', '--subtree', action='append', default=[],
                            help='Adds an additional custom database '
                                 'subtree to include in the migration.')
        parser.add_argument('-l', '--log-file',
                            help='The log file for recording the migration '
                                 f'effort. The default is "{LOG_FILE_NAME}"',
                            default=LOG_FILE_NAME)
        """
        parser.add_argument('-u', '--conflict-ldif-file',  # TODO needed?
                            help='An LDIF file containing conflict entries, '
                                 'or entries that need special attention '
                                 'before they can be migrated. The default '
                                 f'file is "{CONFLICT_FILE_NAME}"',
                            default=CONFLICT_FILE_NAME)
        """
        parser.add_argument('-S', '--skip-schema',
                            help='Do not migrate schema',
                            action='store_true', default=False)
        parser.add_argument('-C', '--skip-config',
                            help='Do not migrate the DS configuration '
                                 '(dse.ldif/cn=config)',
                            action='store_true', default=False)
        parser.add_argument('-B', '--migrate-dns',
                            help='Migrate the DNS records',
                            action='store_true', default=False)
        parser.add_argument('-x', '--dryrun',
                            help='Go through the migration process but do '
                                 'not write any data to the new IPA server',
                            action='store_true', default=False)
        parser.add_argument('-o', '--dryrun-record',
                            help='This option does the same thing as '
                                 '"--dryrun", but it will record the changes '
                                 'to an LDIF file')
        parser.add_argument('-F', '--force',
                            help='Ignore errors and continue with migration',
                            action='store_true', default=False)
        parser.add_argument('-q', '--quiet',
                            help='Only display errors during the migration',
                            action='store_true', default=False)
        parser.add_argument('-O', '--schema-overwrite',
                            help='Overwrite any matching schema definitions.',
                            action='store_true', default=False)
        parser.add_argument('-r', '--reset-range',
                            help='Reset the ID range for migrated '
                                 'users/groups. In "stage-mode" this is '
                                 'done automatically',
                            action='store_true', default=False)
        parser.add_argument('-f', '--db-ldif',
                            help='LDIF file containing the entire backend. '
                                 'If omitted the tool will query the remote '
                                 'IPA server.',
                            default=None)
        parser.add_argument('-m', '--schema-ldif',
                            help='LDIF file containing the schema. '
                                 'If omitted the tool will query the remote '
                                 'IPA server',
                            default=None)
        parser.add_argument('-g', '--config-ldif',
                            help='LDIF file containing the cn=config DIT. '
                                 'If omitted the tool will query the remote '
                                 'IPA server',
                            default=None)
        parser.add_argument('-n', '--no-prompt',
                            help='Do not prompt for confirmation before '
                                 'starting migration.  Use at your own risk!',
                            action='store_true', default=False)

        argcomplete.autocomplete(parser)
        self.args = parser.parse_args()

    def handle_error(self, msg, err=1):
        self.log_error(msg)
        sys.exit(err)

    def validate_options(self):
        # Check LDIf files are real
        if self.args.db_ldif is not None:
            if not os.path.isfile(self.args.db_ldif):
                self.handle_error('The DB LDIF file does not exist')
        if self.args.schema_ldif is not None:
            if not os.path.isfile(self.args.schema_ldif):
                self.handle_error('The Schema LDIF file does not exist')
        if self.args.config_ldif is not None:
            if not os.path.isfile(self.args.config_ldif):
                self.handle_error('The Config LDIF file does not exist')
        if self.args.db_ldif is None \
           or (self.args.schema_ldif is None and not self.args.skip_schema) \
           or (self.args.config_ldif is None and not self.args.skip_config):
            # We need a password to get all our the data from the remote server
            self.get_passwd()

        # Check custom subtrees
        for subtree in self.args.subtree:
            try:
                DN(subtree)
            except Exception:
                self.handle_error('Invalid DN used in "subtree" '
                                  f'option: {subtree}')

        # Can we write to our LDIF file?
        if self.args.dryrun_record is not None:
            try:
                f = open(self.args.dryrun_record, "w")
                f.writable()
            except FileNotFoundError:
                self.handle_error('Can not write to the dryrun ldif file')

        # Validate hostname, must be FQDN and not an IP
        hostname_value = self.args.hostname
        if hostname_value[-1] == ".":
            # strip trailing dot
            hostname_value = hostname_value[:-1]
        if '.' not in hostname_value:
            self.handle_error(
                f"Hostname '{hostname_value}' must be the FQDN of the "
                "remote server")
        # Remove all the dots, if it's a number it's an IP not a FQDN
        hostname_value = hostname_value.replace('.', '')
        if hostname_value.isnumeric() or ':' in hostname_value:
            # might be an IP, still not allowed
            self.handle_error(
                f"Hostname '{self.args.hostname}' must be the FQDN of the "
                "remote server")

        # Set the mode
        self.mode = self.args.mode

    #
    # Logging functions (will be replaced by AdminTool)
    # Make sure when this ^^^ happens that we can still set "verbose" to True
    # We don't want to lose logging all levels to the file
    #
    def setup_logging(self):
        """
        AdminTool currently uses deprecated optparse, so we can not use its
        logger since this tool is using argparse. So mimic its logger setup
        """
        root_logger = logging.getLogger()
        for handler in root_logger.handlers:
            if (isinstance(handler, logging.StreamHandler)
                    and handler.stream is sys.stderr):
                root_logger.removeHandler(handler)
                break

        if self.args.verbose:
            console_format = '%(name)s: %(levelname)s: %(message)s'
            debug = True
        else:
            console_format = '%(message)s'
            debug = False

        # Verbose is set to True so we log everything to the migration log file
        standard_logging_setup(
            self.args.log_file, console_format=console_format,
            filemode=self.log_file_mode, debug=debug, verbose=True)

    def log_info(self, msg):
        ''' write to log and stdout (unless it's quiet) '''
        if self.args.quiet:
            self.log.debug(msg)
        else:
            self.log.info(msg)

    def log_debug(self, msg):
        # log only to the log file
        if self.args.verbose:
            self.log.info(msg)
        else:
            self.log.debug(msg)

    def log_error(self, msg):
        ''' write to log and stdout '''
        self.log.error(msg)

    #
    # Helper functions
    #
    def attr_is_operational(self, attr):
        schema = self.local_conn.schema
        attr_obj = schema.get_obj(ldap.schema.AttributeType, attr)
        if attr_obj is not None:
            if attr_obj.usage == 1:
                return True
        return False

    def replace_suffix(self, entry_dn):
        """
        Replace the base DN in an entry DN
        """
        dn = DN(entry_dn)
        if self.remote_suffix in dn:
            dn_len = len(dn)
            old_len = len(self.remote_suffix)
            offset = dn_len - old_len
            dn = dn[:offset]  # Strip old base DN
            dn = dn + self.local_suffix  # Add new base DN
            return str(dn)
        else:
            # This entry DN is not in scope
            return entry_dn

    def replace_suffix_value(self, val):
        """
        Take an attribute value and replace the old suffix with the new one
        """

        # Skip bytes
        if isinstance(val, bytes):
            return val

        try:
            dn = DN(val)
            # Value is a DN
            return self.replace_suffix(str(dn))
        except ValueError:
            # Not a DN. Maybe aci or filter? Try replacing substring
            val = val.replace(str(self.remote_suffix), str(self.local_suffix))
            return val

    def replace_suffix_values(self, vals):
        """
        Replace suffix values in a list
        """
        return [self.replace_suffix_value(v) for v in vals]

    def normalize_vals(self, vals):
        """
        If the value is a DN, normalize it
        """
        new_vals = []
        for val in vals:
            try:
                dn = DN(val)
                # Value is a DN
                new_vals.append(str(dn))
            except (ValueError, TypeError):
                # Not a DN
                new_vals.append(val)
        return new_vals

    def write_update_to_ldif(self, entry, add_entry=False):
        """
        Take an LDAPEntry and write its modlist(or add op) to LDIF format so
        it can be be processed by ldapmodify
        """
        if self.args.dryrun_record is None:
            return

        ldif_entry = f"dn: {str(entry.dn)}\n"
        if add_entry:
            ldif_entry += "changetype: add\n"
            for attr in entry:
                vals = entry[attr]
                for val in vals:
                    ldif_entry += get_ldif_attr_val(attr, val)
            ldif_entry += "\n"  # end of entry
        else:
            ldif_entry += "changetype: modify\n"
            mods = entry.generate_modlist()
            for mod in mods:
                mod_type = mod[0]
                attr = mod[1]
                vals = mod[2]
                if mod_type == ldap.MOD_ADD:
                    action = "add"
                elif mod_type == ldap.MOD_DELETE:
                    action = "delete"
                else:
                    action = "replace"
                ldif_entry += f"{action}: {attr}\n"
                for val in list(vals or []):
                    ldif_entry += get_ldif_attr_val(attr, val)
                ldif_entry += "-\n"
            ldif_entry += "\n"

        self.dryrun_record.write(ldif_entry)

    def write_conflict(self, dn, attrs):
        """
        Write an entry that needs special attention to an LDIF for later
        review. Maybe we add a "post" section of the tool to evaluate it
        after migration as part of the migration, or a separate option to
        do it later, or both, or just let the admin manually do it?

        Currently this function/feature is not used...
        """
        if self.ldif_writer is None:
            self.ldif_writer = ldif.LDIFWriter(
                open(self.args.conflict_ldif_file))
        self.ldif_writer.unparse(dn, attrs)
        stats['conflicts'] += 1

    def log_stats(self, object_dict):
        """
        Print a migration stat with consisent formatting
        """
        indent = 28
        logged_something = False
        for key in object_dict:
            stat_label = object_dict[key]['label']
            line = f" - {stat_label}:"
            if len(line) >= indent:
                padding = 2
            else:
                padding = indent - len(line)
            line = line + (" " * padding)
            if self.args.verbose or object_dict[key]['count'] > 0:
                self.log_info(f"{line}{object_dict[key]['count']}")
                logged_something = True
        return logged_something

    def display_stats(self, elapsed_time):
        """
        Display the summary report of the migration
        """
        self.log_info('Migration complete!')
        if self.dryrun:
            self.log_info('\nDry Run Summary:')
        else:
            self.log_info('\nSummary:')
        self.log_info('=' * 79)

        # Basic info
        title = 'General Information'
        self.log_info("\n" + title)
        self.log_info('-' * len(title))
        self.log_info(f" - Remote Host:             {self.args.hostname}")
        self.log_info(" - Migration Duration:      "
                      f"{str(datetime.timedelta(seconds=elapsed_time))}")
        self.log_info(f" - Migration Log:           {self.args.log_file}")
        # self.log_info(" - Conflict LDIF File:      "
        #              f"{self.args.conflict_ldif_file} (entries: "
        #              f"{stats['conflicts']})")
        if self.args.dryrun_record is not None:
            self.log_info(" - Dryrun LDIF file:        "
                          f"{self.args.dryrun_record}")
        self.log_info(f" - Remote Host:             {self.args.hostname}")
        self.log_info(f" - Remote Domain:           {self.remote_domain}")
        self.log_info(f" - Local Host:              {self.local_hostname}")
        self.log_info(f" - Local Domain:            {self.local_domain}")
        self.log_info(f" - Remote Suffix:           {self.remote_suffix}")
        self.log_info(f" - Local Suffix:            {self.local_suffix}")
        self.log_info(f" - Remote Realm:            {self.remote_realm}")
        self.log_info(f" - Local Realm:             {self.realm}")
        for subtree in self.args.subtree:
            self.log_info(f" - Custom Subtree:          {subtree}")
        if self.args.force is not False:
            self.log_info(" - Ignored Errors:          "
                          f"{stats['ignored_errors']}")
        self.log_info(" - Schema Analyzed:         "
                      f"{stats['schema_processed']} definitions")
        self.log_info(" - Config Analyzed:         "
                      f"{stats['config_migrated']} entries")
        self.log_info(" - Database Anaylzed:       "
                      f"{stats['total_db_entries']} entries")

        # Schema
        total_schema = stats['schema_attrs_added'] + stats['schema_oc_added']

        title = ('\nSchema Migration (migrated '
                 f"{total_schema} definitions)")
        self.log_info(title)
        self.log_info('-' * (len(title) - 1))
        self.log_info(" - Attributes:              "
                      f"{stats['schema_attrs_added']}")
        self.log_info(" - Objectclasses:           "
                      f"{stats['schema_oc_added']}")

        # Configuration
        title = ('\nDS Configuration Migration (migrated '
                 f"{stats['config_migrated']} entries)")
        self.log_info(title)
        self.log_info('-' * (len(title) - 1))
        logged_something = self.log_stats(DS_CONFIG)
        if self.args.verbose:
            logged_something = True
        if not self.log_stats(DS_INDEXES) and not logged_something:
            self.log_info(" - No updates")

        # Database
        title = ("\nDatabase Migration (migrated "
                 f"{stats['total_db_migrated']} entries)")
        self.log_info(title)
        self.log_info('-' * (len(title) - 1))
        logged_something = False
        if self.args.verbose or self.args.reset_range:
            logged_something = self.log_info(
                f" - DNA Range Resets:        {stats['reset_range']}")
        if len(self.args.subtree) > 0:
            logged_something = self.log_info(
                f" - Custom entries:          {stats['custom']}")
        if not self.log_stats(DB_OBJECTS) and not logged_something:
            self.log_info(" - No updates")

        # Display any followup notes
        title = (f"\nAction Items ({len(self.post_notes)} items)")
        self.log_info(title)
        self.log_info('-' * (len(title) - 1))
        for note in self.post_notes:
            self.log_info(' - ' + note)

        # The end of the summary
        self.log_info('=' * 79)

    def connect_to_remote_ds(self):
        """
        Connect to the remote DS and store the conn in the class
        """
        ldapuri = f"ldap://{self.args.hostname}"
        insecure_bind = False

        if self.args.cacertfile is not None:
            # Start TLS connection (START_TLS)
            try:
                ds_conn = LDAPClient(ldapuri, cacert=self.args.cacertfile,
                                     start_tls=True)
            except ValueError:
                # Most likely invalid certificate
                self.handle_error(
                    "Failed to connect to remote server: "
                    "CA certificate is invalid"
                )
            except (
                ldap.LDAPError,
                errors.NetworkError,
                errors.DatabaseError,
                IOError
            ) as e:
                self.handle_error(
                    f"Failed to connect to remote server: {str(e)}"
                )
        else:
            # LDAP (insecure)
            ds_conn = LDAPClient(ldapuri)
            insecure_bind = True

        try:
            ds_conn.simple_bind(DN(self.args.bind_dn), self.bindpw,
                                insecure_bind=insecure_bind)
        except (
            errors.NetworkError,
            errors.ACIError,
            errors.DatabaseError
        ) as e:
            self.handle_error(f"Failed to bind to remote server: {str(e)}")

        # All set, stash the remote connection
        self.bindpw = None
        self.remote_conn = ds_conn

    def connect_to_local_ds(self):
        """
        Connect to the local DS over ldapi
        """
        try:
            ds_conn = LDAPClient(self.ldapiuri, force_schema_updates=True)
            ds_conn.external_bind()
            ds_conn._get_schema()
        except (ldap.SERVER_DOWN, ldap.CONNECT_ERROR, errors.NetworkError):
            self.handle_error(
                "Local server is not running, or is unreachable.")
        except ldap.LDAPError as e:
            self.handle_error(
                f"Failed to bind to local server: {str(e)}")

        # All set, stash the local conn
        self.local_conn = ds_conn

    def get_remote_realm(self):
        """
        Get the remote realm from cn=REALM,cn=kerberos,$SUFFIX
        """
        if self.args.db_ldif is not None:
            ldifParser = LDIFParser(open(self.args.db_ldif, "r"))
            ldifParser.set_class(self)
            ldifParser.look_for_realm()
            self.log_debug('Getting realm from LDIF file ...')
            ldifParser.parse_entry_records()
            if self.remote_realm is None:
                self.handle_error("Unable to find realm from remote LDIF",
                                  err=2)
            self.log_debug('Done getting realm from LDIF file')
        else:
            krb_entry = self.remote_conn.get_entries(
                DN(f"cn=kerberos,{self.remote_suffix}"),
                filter="objectclass=krbrealmcontainer")
            if len(krb_entry) == 1:
                self.remote_realm = ensure_str(krb_entry[0]['cn'][0])
                self.log_debug("Found realm from remote server: "
                               f"{self.remote_realm}")
            else:
                if len(krb_entry) == 0:
                    self.handle_error("Failed to find remote realm", err=2)
                else:
                    # Found too many realms (should not possible)
                    self.handle_error("Found multiple realms, can not proceed",
                                      err=2)

    def get_passwd(self):
        """
        Get/set the migration password.  Check usage arg & pw file, and if not
        found prompt user for it.
        """
        if self.args.bind_pw is not None:
            self.bindpw = self.args.bind_pw
        else:
            if self.args.bind_pw_file is not None:
                # Read password from file
                try:
                    with open(self.args.bind_pw_file, "r") as f:
                        self.bindpw = f.readline().rstrip()
                        f.close()
                except EnvironmentError as e:
                    self.handle_error(
                        "Failed to open password file: " + str(e))
            else:
                # Prompt for password
                while self.bindpw is None or self.bindpw == "":
                    self.bindpw = getpass.getpass(
                        f'Enter the password for {self.args.bind_dn}: ')

    def get_base_dn(self, remote=False):
        """
        Search the Root DSE for the default naming context
        """
        if not remote:
            # Get the local server's base dn
            conn = self.local_conn
            if conn is None:
                self.handle_error(
                    'There is no connection to the local server')
        else:
            # Get base DN from remote server.  Check online or by LDIF
            conn = self.remote_conn
            if conn is None:
                if self.args.db_ldif is not None:
                    # Get the base DN from DB ldif itself
                    with open(self.args.db_ldif, "r") as ldif:
                        for line in ldif:
                            # The first DN should be the root node
                            if line.startswith('dn: '):
                                return DN(line.replace('dn: ', ''))
                    self.handle_error('The db ldif file does not appear to '
                                      'be a valid ldif file')
                else:
                    self.handle_error('There is no connection to the remote '
                                      'server or an LDIF file to process')

        # We have our connection to the server, get the base dn from root DSE
        try:
            if remote:
                server_type = "remote"
            else:
                server_type = "local"
            entry = conn.get_entry(DN(""),
                                   attrs_list=['namingcontexts',
                                               'defaultnamingcontext'])

            if 'defaultnamingcontext' in entry:
                suffix = entry['defaultnamingcontext'][0]
                suffix_entry = conn.get_entry(DN(suffix), attrs_list=['info'])
                if 'info' not in suffix_entry or \
                        'IPA V2' not in suffix_entry['info'][0]:
                    self.handle_error(f'The {server_type} server does not '
                                      'appear to be an IPA server', err=2)
                return DN(suffix)
            else:
                for suffix in entry['namingcontexts']:
                    # Ignore o=ipaca and cn=changelog
                    if suffix.lower() != "o=ipaca" and \
                            suffix.lower() != "cn=changelog":
                        try:

                            suffix_entry = conn.get_entry(DN(suffix),
                                                          attrs_list=['info'])
                            if 'info' not in suffix_entry or \
                                    'IPA V2' not in suffix_entry['info'][0]:
                                self.handle_error(f'The {server_type} server '
                                                  'does not appear to be '
                                                  'an IPA server', err=2)
                            return DN(suffix)
                        except (IndexError, KeyError) as e:
                            self.handle_error(
                                "Failed to find naming context: " + str(e))
                # If we got here there is no userroot
                self.handle_error(
                    "Failed to get database base DN as it does not exist")
        except ldap.LDAPError as e:
            self.handle_error(
                "Failed to search Root DSE on remote server: " + str(e))

        return None

    def return_type(self, db_item):
        """ Check our migration mode and return None if this entry should be
        skipped
        """
        if db_item[1]['mode'] == "production" and self.mode != "prod-mode":
            # Production only type, but we are not in production mode
            return None

        # This entry can be migrated
        return db_item[0]

    def get_entry_type(self, entry_dn, entry_attrs):
        """
        Get the type of entry from its objectclasses and DN
        """
        oc_attr = 'objectClass'
        if 'objectclass' in entry_attrs:
            oc_attr = 'objectclass'
        for oc in entry_attrs[oc_attr]:
            oc = oc.lower()
            for db_item in DB_OBJECTS.items():
                db_obj = db_item[1]
                obj_ocs = db_obj['oc']
                # Do the suffix and realm substitution
                obj_subtree = db_obj['subtree'].replace(
                    '$SUFFIX', str(self.remote_suffix))
                obj_subtree = obj_subtree.replace('$REALM', self.realm)
                if len(obj_ocs) > 0:
                    for obj_oc in obj_ocs:
                        if oc == obj_oc:
                            # OC matches, check if we have a subtree to check
                            if 'not_oc' in db_obj:
                                # We have to filter out entries that have a
                                # not_oc
                                ocs = [x.lower() for x in entry_attrs[oc_attr]]
                                for not_oc in db_obj['not_oc']:
                                    if not_oc in ocs:
                                        return None
                            if obj_subtree is not None:
                                if obj_subtree[0] == ",":
                                    # Match child entries
                                    obj_subtree = obj_subtree[1:]
                                    if DN(obj_subtree) != DN(entry_dn) and \
                                       DN(obj_subtree) in DN(entry_dn):
                                        return self.return_type(db_item)
                                else:
                                    # Match DN exactly
                                    if DN(obj_subtree) == DN(entry_dn):
                                        return self.return_type(db_item)
                            else:
                                return self.return_type(db_item)
                else:
                    if obj_subtree[0] == ",":
                        # Match child entries
                        obj_subtree = obj_subtree[1:]
                        if DN(obj_subtree) != DN(entry_dn) and \
                           DN(obj_subtree) in DN(entry_dn):
                            return self.return_type(db_item)
                    else:
                        # Match DN exactly
                        if DN(obj_subtree) == DN(entry_dn):
                            return self.return_type(db_item)

        # Check custom subtrees
        for subtree in self.args.subtree:
            if DN(subtree) == DN(entry_dn) or \
               DN(subtree) in DN(entry_dn):
                return 'custom'

        # We don't know this entry, so we can ignore it
        return None

    #
    # DB Migration
    #
    def get_cert_issuer(self, cert_value):
        cert = crypto_x509.load_der_x509_certificate(cert_value)
        ipacert = IPACertificate(cert)
        issuer = str(DN(ipacert.issuer))
        return issuer

    def remove_usercert(self, entry_dn, cert_values):
        """
        If the usercertificate was issued by IPA then mark it to be removed,
        otherwise we keep it
        """
        remove_vals = []
        for cert_val in cert_values:
            issuer = self.get_cert_issuer(cert_val)
            REALM_LIST = [self.realm, self.remote_realm]
            cert_removed = False
            for realm in REALM_LIST:
                if issuer == f"CN=Certificate Authority,O={realm}":
                    # This is an IPA issued cert, remove it
                    remove_vals.append(cert_val)
                    self.log_debug("Removed IPA issued userCertificate "
                                   f"from: {entry_dn}")
                    cert_removed = True
                    break
            if not cert_removed:
                self.log_debug("Keeping userCertificate issued by "
                               f"'{issuer}' in entry: {entry_dn}")

        # Now remove the values from cert_vals
        for val in remove_vals:
            cert_values.remove(val)

        return len(cert_values) == 0

    def convert_value(self, val, dns=False):
        """
        Replace suffix, hostname, domain, and realm from a string
        """
        if isinstance(val, bytes) or isinstance(val, DN):
            return val

        # Replace base DN
        val = self.replace_suffix_value(val)

        # For DNS DN we only replace suffix
        if dns:
            return val

        # Replace host
        if self.args.hostname in val:
            val = val.replace(self.args.hostname, self.local_hostname)

        # Replace domain
        if self.remote_domain in val and self.local_domain not in val:
            val = val.replace(self.remote_domain, self.local_domain)

        # Replace realm
        val = val.replace(self.remote_realm, self.realm)

        return val

    def convert_values(self, values, dns=False):
        """
        Replace suffix, hostname, domain, and realm in a list
        """
        new_values = []
        for val in values:
            new_values.append(self.convert_value(val, dns))

        # normalize DN values
        return self.normalize_vals(new_values)

    def get_ldapentry_attr_vals(self, entry, attr):
        """
        Get the raw attribute values from IPA's LDAPEntry
        """
        vals = []
        attr_vals = entry.raw.get(attr)
        for val in attr_vals:
            if isinstance(val, bytes):
                vals.append(ensure_str(val))
            elif not isinstance(val, str):
                val = str(val)
                vals.append(ensure_str(val))
            else:
                # Just a string
                vals.append(val)

        return self.normalize_vals(vals)

    def build_ldap_entry(self, dn, attrs):
        """
        Take a DN and some attributes and build an LDAPEntry.  Used when
        adding entries to the local server
        """
        entry = LDAPEntry(self.local_conn, DN(dn))
        range_reset = False
        for attr, values in attrs.items():
            if (self.args.reset_range or self.mode == "stage-mode") and \
                    attr.lower() in DNA_REGEN_ATTRS:
                # Set the magic regen value
                values = [DNA_REGEN_VAL]
                self.log_debug(f"Resetting DNA range for new entry: {dn}")
                range_reset = True
            entry[attr] = values
        if range_reset:
            stats['reset_range'] += 1
        return entry

    def attr_is_required(self, attr, entry):
        """
        Check if an attribute is required in this entry
        """
        entry_oc = entry['objectClass']
        for oc in entry_oc:
            required_attrs = self.local_conn.get_allowed_attributes(
                [oc], raise_on_unknown=False, attributes="must")
            if attr.lower() in required_attrs:
                return True
        return False

    def clean_entry(self, entry_dn, entry_type, entry_attrs):
        """
        Clean up the entry from the remote server

        - Remove attributes from the ignore/strip list
        - Reset suffix in all attributes
        - If REALM was changed reset it to the new value
        - Remove objectclasses from groups (STRIP_OC list)
        - userCertificate is removed if issued by IPA
        - Remove unused objectclasses
        """

        # Don't clean DNS entries
        if entry_type.startswith("dns"):
            return entry_attrs

        # Set the attrs we want to remove
        remove_list = []
        remove_attrs = STRIP_ATTRS + STRIP_OP_ATTRS
        if self.args.mode != "prod-mode":
            remove_attrs += PROD_ATTRS

        # Need to remove the remote host member from the ipaserver host group
        remove_member = False
        if entry_type == "host_groups" and \
                entry_dn.startswith("cn=ipaservers,"):
            # We need remove any members that match the old host
            remove_member = True

        # Walk the entry normalizing and marking attrs to remove as needed
        for attr in entry_attrs:
            if attr.lower() in remove_attrs:
                remove_list.append(attr)
                continue

            # remove remote server hostgroup member
            if remove_member and attr == "member":
                new_vals = []
                for val in entry_attrs[attr]:
                    if val.startswith("fqdn=" + self.local_hostname):
                        new_vals.append(val)
                    else:
                        self.log_debug(
                            f"Skipping remote host '{val}' from '{entry_dn}'")
                        remove_member = False
                entry_attrs[attr] = new_vals

            # Replace suffix/realm/host/domain in all values
            entry_attrs[attr] = self.convert_values(entry_attrs[attr])

            # Check userCertificate issuer and remove IPA CA certs
            if attr.lower() == "usercertificate" and \
               self.remove_usercert(entry_dn, entry_attrs[attr]):
                # This cert was issued by IPA, remove it
                remove_list.append(attr)

        # Cleanup up entry attributes
        for remove_attr in remove_list:
            del entry_attrs[remove_attr]

        # Normalize the objectclass name -> objectClass
        normalize_attr(entry_attrs, 'objectClass')

        # Cleanup objectclasses from groups (users too?)
        if entry_type == "group":
            for oc in ensure_list_str(entry_attrs['objectClass']):
                if oc.lower() in STRIP_OC:
                    entry_attrs['objectClass'].remove(oc.encode())

        # Cleanup unused objectclasses. We removed some attributes, so there
        # might be objectclasses we don't need
        entry_oc = ensure_list_str(entry_attrs['objectClass'])
        for oc in entry_oc:
            found = False
            required_attrs = self.local_conn.get_allowed_attributes(
                [oc], raise_on_unknown=False, attributes="must")
            if len(required_attrs) == 0:
                # This objectclass does not require any attributes, move on
                continue
            for attr in required_attrs:
                for entry_attr in entry_attrs:
                    if entry_attr.lower().startswith(attr.lower()):
                        # The startswith approach allows for attr extensions
                        found = True
                        break
                if found:
                    break

            if not found:
                # Ok, there were no attributes that require this objectclass
                entry_attrs['objectClass'].remove(oc)

        return entry_attrs

    def update_local_entry(self, entry_type, local_dn, local_entry,
                           remote_attrs):
        """
        Go through the remote entry (which has already been cleaned up) and
        convert remote attribute names to the same case as the local entry.
        Then create the mod list
        """
        entry_updated = False
        range_reset = False

        # Reset the remote attribute name to match the same case as the local
        # attributes.
        for remote_attr in list(remote_attrs):
            for local_attr in local_entry:
                if local_attr.lower() == remote_attr.lower() and \
                   local_attr != remote_attr:
                    # The case is different, reset remote to match local
                    vals = remote_attrs[remote_attr].copy()
                    del remote_attrs[remote_attr]
                    remote_attrs[local_attr] = vals

        # For non-admin users we need to strip krb attributes so userpassword
        # can be migrated
        if entry_type == "users":
            updated = False
            for attr in DB_OBJECTS['users']['strip_attrs']:
                if attr in local_entry:
                    del local_entry[attr]
                    updated = True
            if updated:
                self.write_update_to_ldif(local_entry)
                self.local_conn.update_entry(local_entry)
                local_entry = self.local_conn.get_entry(DN(local_dn),
                                                        attrs_list=['*', '+'])

        # Loop over the remote entry, and add whatever attr and/or value is
        # missing from the local entry
        for attr in remote_attrs:
            if attr.lower() in IGNORE_ATTRS:
                # We are not merging this attribute, just move on unless..
                if self.mode == "prod-mode":
                    if attr.lower() not in PROD_ATTRS:
                        # We are in production mode, but this attr can still be
                        # skipped
                        continue
                else:
                    continue

            if entry_type == "admin" and attr.lower() == "userpassword":
                # Can not modify userpassword on admin, skip it
                self.post_notes.append(
                    "The admin password is not migrated from the remote "
                    "server. Reset it manually if needed.")
                continue

            if attr in local_entry:
                # Check if we have special attributes to process.
                # These attributes need their values handled in a special way.
                # The attrs are a tuple of attr name and type.  Based on the
                # type of the attribute we will handle the value comparision
                # differently.
                if 'special_attrs' in DB_OBJECTS[entry_type]:
                    goto_next_attr = False
                    for sp_attr in DB_OBJECTS[entry_type]['special_attrs']:
                        if attr.lower() == sp_attr[0]:
                            local_attr_vals = self.get_ldapentry_attr_vals(
                                local_entry, attr)
                            if 'list' == sp_attr[1]:
                                # These attributes are single valued. Split
                                # them up into parts and compare
                                remote_items = remote_attrs[attr][0].lower() \
                                    .split(',')
                                local_items = local_attr_vals[0].lower() \
                                    .split(',')

                                # Track what is missing
                                new_items = []
                                for remote_item in remote_items:
                                    if remote_item not in local_items:
                                        new_items.append(remote_item)

                                # Add the missing values to the current value
                                # (preserves case of the original value)
                                old_value = local_entry[attr][0]
                                for item in new_items:
                                    local_entry[attr][0] += f",{item}"
                                if len(new_items) > 0:
                                    entry_updated = True
                                    self.log_debug("Entry is different and "
                                                   "will be updated: "
                                                   f"'{local_dn}' attribute "
                                                   f"'{attr}' old value "
                                                   f"'{old_value}' "
                                                   "new value "
                                                   f"'{local_entry[attr][0]}'")
                            elif 'single' == sp_attr[1]:
                                # The attribute is defined as multivalued, but
                                # we really need to treat it as single valued
                                self.log_debug("Entry is different and will "
                                               f"be updated: '{local_dn}' "
                                               f"attribute '{attr}' replaced "
                                               "with val "
                                               f"'{remote_attrs[attr][0]}' "
                                               "old value: "
                                               f"{local_entry[attr][0]}")
                                local_entry[attr][0] = remote_attrs[attr][0]
                            goto_next_attr = True
                            break

                    if goto_next_attr:
                        continue

                # merge values
                for val in remote_attrs[attr]:
                    local_attr_vals = self.get_ldapentry_attr_vals(local_entry,
                                                                   attr)
                    if val not in local_attr_vals:
                        # Check if we should reset the DNA range for this entry
                        if (
                            self.args.reset_range
                            or self.mode == "stage-mode"
                        ) and attr.lower() in DNA_REGEN_ATTRS:
                            # Skip dna attributes from managed entries
                            if 'mepManagedBy' in local_entry:
                                break
                            # Ok, set the magic regen value
                            local_entry[attr] = [DNA_REGEN_VAL]
                            self.log_debug("Resetting the DNA range for: "
                                           f"{local_dn}")
                            range_reset = True
                        elif self.local_conn.get_attribute_single_value(attr):
                            # Must "replace" single valued attribute
                            local_entry[attr] = remote_attrs[attr]
                            self.log_debug("Entry is different and will be "
                                           f"updated: '{local_dn}' attribute "
                                           f"'{attr}' replaced with val "
                                           f"'{val}' old value: "
                                           f"{str(local_attr_vals)}")
                        else:
                            # Ok, "append" multivalued attribute value
                            local_entry[attr].append(val)
                            self.log_debug("Entry is different and will be "
                                           f"updated: '{local_dn}' attribute "
                                           f"'{attr}' add val '{val}' not "
                                           f"in {str(local_attr_vals)}")
                        entry_updated = True
            else:
                # Attribute does not exist in the local entry, copy the
                # entire attribute/valueset over
                local_entry[attr] = remote_attrs[attr]
                entry_updated = True

        # Remove attributes in the local entry that do not exist in the
        # remote entry
        remove_attrs = []
        for attr in local_entry:
            if (self.attr_is_operational(attr)
                and attr.lower() not in POLICY_OP_ATTRS) or \
               attr.lower() in IGNORE_ATTRS or \
               attr.lower() in STRIP_ATTRS or \
               attr.lower() == "usercertificate":
                # This is an attribute that we do not want to remove
                continue

            if attr not in remote_attrs and \
               not self.attr_is_required(attr, local_entry):
                # Mark this attribute for deletion
                remove_attrs.append(attr)
                entry_updated = True

        # Remove attributes
        for remove_attr in remove_attrs:
            self.log_debug("Entry is different and will be updated: "
                           f"'{local_dn}' attribute '{remove_attr}' "
                           "is being removed")
            del local_entry[remove_attr]

        if range_reset:
            stats['reset_range'] += 1

        # return updated local entry
        if entry_updated:
            return local_entry
        else:
            return None

    def process_db_entry(self, entry_dn, entry_attrs):
        """
        Process chunks of remote entries from a paged results search

        entry_dn = the remote entry DN
        entry_attrs = the remote entry's attributes stored in a dict

        Identify entry type
        Process entry (removing/change attr/val/schema)
        Compare processed remote entry with local entry, merge/overwrite?
        Add/replace local entry
        ...
        """
        stats['total_db_entries'] += 1

        if stats['total_db_entries'] % 1000 == 0:
            print_progress(
                f"Processed {stats['total_db_entries']} entries... ")

        # First just skip entries we are excluding
        for exclude_dn in DB_EXCLUDE_TREES:
            exclude_dn = exclude_dn.replace("$SUFFIX",
                                            str(self.remote_suffix))
            if DN(exclude_dn) in DN(entry_dn):
                return

        # Skip tombstones
        if 'nsTombstone' in entry_attrs['objectClass']:
            return

        # Determine entry type: user, group, hbac, etc
        entry_type = self.get_entry_type(entry_dn, entry_attrs)
        if entry_type is None:
            # We are not interested in this entry
            return

        if entry_type.startswith("dns") and not self.args.migrate_dns:
            # Ok skipping dns
            return

        if entry_type == 'certificate':
            # Ok we need to skip remote CA Cert (in all cases? TODO)
            if 'cACertificate;binary' in entry_attrs:
                issuer = self.get_cert_issuer(
                    entry_attrs['cACertificate;binary'][0])
                if issuer == f"CN=Certificate Authority,O={self.remote_realm}":
                    self.log_debug("Skipping remote certificate entry: "
                                   f"'{entry_dn}' Issuer: {issuer}")
                    return

        if entry_type == "computer":
            if entry_attrs['fqdn'] == self.args.hostname:
                # We do not migrate the remote computer
                return

        # Cleanup the remote entry before merging/adding
        remote_attrs = self.clean_entry(entry_dn, entry_type, entry_attrs)

        # First we need to convert dn to match local server
        local_dn = self.convert_value(str(entry_dn),
                                      dns=entry_type.startswith("dns"))

        #
        # Based on the entry type do additional work
        #

        # For entries with alternate identifying needs we need to rebuild the
        # local dn. Typically this is for entries that use ipaUniqueId as the
        # RDN attr
        if entry_type != "custom" and 'alt_id' in DB_OBJECTS[entry_type]:
            attr = DB_OBJECTS[entry_type]['alt_id']['attr']
            base = DB_OBJECTS[entry_type]['alt_id']['base']
            srch_filter = f'({attr}={entry_attrs[attr][0]})'
            if DB_OBJECTS[entry_type]['alt_id']['isDN'] is True:
                # Convert the filter to match the local suffix
                srch_filter = self.replace_suffix_value(srch_filter)
            srch_base = base + str(self.local_suffix)

            try:
                entries = self.local_conn.get_entries(DN(srch_base),
                                                      filter=srch_filter)
                if len(entries) == 1:
                    local_dn = entries[0].dn
                elif len(entries) == 0:
                    # Not found, no problem just proceed and we will add it
                    pass
                else:
                    # Found too many entries - should not happen
                    self.log_error('Found too many local matching entries '
                                   f'for "{local_dn}"')
                    if self.args.force:
                        stats['ignored_errors'] += 1
                        return
                    else:
                        sys.exit(1)
            except errors.EmptyResult:
                # Not found, no problem just proceed and we will add it later
                pass
            except (errors.NetworkError, errors.DatabaseError) as e:
                self.log_error('Failed to find a local matching entry for '
                               f'"{local_dn}" error: {str(e)}')
                if self.args.force:
                    stats['ignored_errors'] += 1
                    return
                else:
                    sys.exit(1)

        # See if the entry exists on the local server
        try:
            local_entry = self.local_conn.get_entry(DN(local_dn),
                                                    attrs_list=['*', '+'])

            # Merge the two entry's attributes
            local_entry = self.update_local_entry(entry_type,
                                                  local_dn,
                                                  local_entry,
                                                  remote_attrs)
            if local_entry is None:
                return

            if self.dryrun:
                self.write_update_to_ldif(local_entry)
                if entry_type == "custom":
                    stats['custom'] += 1
                else:
                    DB_OBJECTS[entry_type]['count'] += 1
                stats['total_db_migrated'] += 1
                return

            # Update the local entry
            try:
                self.local_conn.update_entry(local_entry)
                if entry_type == "custom":
                    stats['custom'] += 1
                else:
                    DB_OBJECTS[entry_type]['count'] += 1
            except errors.MidairCollision as e:
                # Typically means no such attribute, ok to ignore
                self.log_debug(f'Failed to update "{local_dn}" error: '
                               f'{str(e)} - ok to ignore')
            except errors.ExecutionError as e:
                self.log_error(f'Failed to update "{local_dn}" error: '
                               f'{str(e)}')
                if self.args.force:
                    stats['ignored_errors'] += 1
                    return
                else:
                    sys.exit(1)
        except errors.NotFound:
            # Entry does not exist on the local server, add it
            try:
                add_entry = self.build_ldap_entry(local_dn, remote_attrs)
                if self.dryrun:
                    self.log_debug(f"Add db entry '{local_dn} - {entry_type}'")
                    self.write_update_to_ldif(add_entry, add_entry=True)
                    if entry_type == "custom":
                        stats['custom'] += 1
                    else:
                        DB_OBJECTS[entry_type]['count'] += 1
                    stats['total_db_migrated'] += 1
                    return

                self.local_conn.add_entry(add_entry)
                if entry_type == "custom":
                    stats['custom'] += 1
                else:
                    DB_OBJECTS[entry_type]['count'] += 1
                self.log_debug(f"Added entry: {local_dn}")
            except errors.ExecutionError as e:
                self.log_error(f'Failed to add "{local_dn}" error: {str(e)}')
                if self.args.force:
                    stats['ignored_errors'] += 1
                    return
                else:
                    sys.exit(1)

        stats['total_db_migrated'] += 1

    def processDBOffline(self):
        """
        Call our LDIFParser to go through each LDIF entry one at a time to
        avoid loading the entries LDIF into memory
        """
        ldifParser = LDIFParser(open(self.args.db_ldif, "r"),
                                ignored_attr_types=STRIP_OP_ATTRS)
        ldifParser.set_class(self)
        ldifParser.parse_entry_records()

    def processDBOnline(self):
        """
        Search UserRoot using a Paged Result search.  This prevents loading
        too many entries into memory at one time
        """
        results_done = False
        paged_ctrl = SimplePagedResultsControl(True, size=500, cookie='')
        controls = [paged_ctrl]
        req_pr_ctrl = controls[0]
        db_filter = ("(objectclass=*)")

        # Start the paged results search
        try:
            remote_msgid = self.remote_conn.conn.search_ext(
                str(self.remote_suffix),
                ldap.SCOPE_SUBTREE,
                db_filter,
                ['*', 'nsaccountlock'],
                serverctrls=controls)
        except ldap.LDAPError as e:
            self.log_error(f"Failed to get remote entries: {str(e)}")
            sys.exit(1)

        while not results_done:
            try:
                if not results_done:
                    type, db_data, db_msgid, db_ctrls = \
                        self.remote_conn.conn.result3(remote_msgid)
                    if self.args.verbose:
                        self.log_debug("Database search succeeded: "
                                       f"type {type} msgid {db_msgid}")
            except ldap.LDAPError as e:
                self.handle_error("Database search failed: "
                                  f"{str(e)} type {type} msgid {db_msgid}")

            #
            # Process this chunk of remote entries
            #
            for entry in db_data:
                entry_dn = entry[0]
                entry_attrs = decode_attr_vals(entry[1])
                self.process_db_entry(entry_dn, entry_attrs)

            # Get the next batch of entries
            dbctrls = [
                c
                for c in db_ctrls
                if c.controlType == SimplePagedResultsControl.controlType
            ]
            if dbctrls and dbctrls[0].cookie:
                try:
                    req_pr_ctrl.cookie = dbctrls[0].cookie
                    controls = [req_pr_ctrl]
                    remote_msgid = self.remote_conn.conn.search_ext(
                        str(self.remote_suffix),
                        ldap.SCOPE_SUBTREE,
                        db_filter,
                        ['*', 'nsaccountlock'],
                        serverctrls=controls)
                except ldap.LDAPError as e:
                    self.handle_error("Problem searching the remote server: "
                                      f"{str(e)}")

            else:
                results_done = True

    def migrateDB(self):
        """
        Used paged search for online method to avoid large memory footprint
        """
        self.log_info("Migrating database ... (this may take a while)")
        if self.args.db_ldif is not None:
            self.processDBOffline()
        else:
            self.processDBOnline()
        print_progress(f"Processed {stats['total_db_entries']} entries.\n")

    #
    # Schema Migration
    #
    def migrateSchema(self):
        """
        Add any missing schema definitions to this server
        """
        self.log_info("Migrating schema ...")

        if self.args.schema_ldif is not None:
            self.log_debug("Getting schema from LDIF file ...")
            schema_entry = get_ldif_records(self.args.schema_ldif)
            # Grab attribute list
            normalize_attr(schema_entry[0][1], 'attributeTypes')
            attributes = schema_entry[0][1]['attributeTypes']
            # Grab objectclass list
            normalize_attr(schema_entry[0][1], 'objectClasses')
            objectclasses = schema_entry[0][1]['objectClasses']
        else:
            # Query the remote server for its schema
            self.log_debug("Getting schema from the remote server ...")
            schema = self.remote_conn._get_schema()
            schema_entry = schema.ldap_entry()
            # Grab attribute list
            normalize_attr(schema_entry, 'attributeTypes')
            attributes = ensure_list_str(schema_entry['attributeTypes'])
            # Grab objectclass list
            normalize_attr(schema_entry, 'objectClasses')
            objectclasses = ensure_list_str(schema_entry['objectClasses'])

        self.log_debug(f"Retrieved {len(attributes)} attributes and "
                       f"{len(objectclasses)} objectClasses")

        # Loop over attributes and objectclasses and count them
        schema = self.local_conn.schema
        local_schema = schema.ldap_entry()
        for schema_type in [(attributes, "attributeTypes"),
                            (objectclasses, "objectClasses")]:
            for attr_val in schema_type[0]:
                stats['schema_processed'] += 1
                if not self.args.schema_overwrite:
                    # Check if this attribute exists in the local server,
                    # if so skip it.
                    remote_name = attr_val.split()[3].lower()
                    skip_value = False

                    # Loop over all the attributes and check for a match
                    normalize_attr(local_schema, schema_type[1])
                    for local_val in ensure_list_str(
                            local_schema[schema_type[1]]):
                        local_name = local_val.split()[3].lower()
                        if local_name == remote_name:
                            # Found a match, skip it
                            skip_value = True
                            break
                    if skip_value:
                        if schema_type[1] == "attributeTypes":
                            stats['schema_attrs_skipped'] += 1
                        else:
                            stats['schema_oc_skipped'] += 1
                        continue

                try:
                    if self.dryrun:
                        self.log_debug("Schema add "
                                       f"{schema_type[1]}: {attr_val}")
                        if schema_type[1] == "attributeTypes":
                            stats['schema_attrs_added'] += 1
                        else:
                            stats['schema_oc_added'] += 1

                        # Write schema update to ldif file
                        if self.dryrun_record is not None:
                            schema_update = "dn: cn=schema\n"
                            schema_update += "changetype: modify\n"
                            schema_update += f"add: {schema_type[1]}\n"
                            schema_update += f"{schema_type[1]}: attr_val\n\n"
                            self.dryrun_record.write(schema_update)
                        continue

                    self.local_conn.conn.modify_ext_s(
                        "cn=schema", [(
                            ldap.MOD_ADD,
                            schema_type[1],
                            bytes(attr_val, 'utf-8')
                        )]
                    )
                    if schema_type[1] == "attributeTypes":
                        stats['schema_attrs_added'] += 1
                    else:
                        stats['schema_oc_added'] += 1
                    self.log_debug(
                        f"Added schema - {schema_type[1]}: {attr_val}")
                except ldap.TYPE_OR_VALUE_EXISTS:
                    # Error 16 - this attribute already exists, move on
                    if schema_type[1] == "attributeTypes":
                        stats['schema_attrs_skipped'] += 1
                    else:
                        stats['schema_oc_skipped'] += 1
                except ldap.LDAPError as e:
                    if self.args.force:
                        self.log_debug(
                            "Skipping schema value that triggered an "
                            f"error: '{attr_val}' - {str(e)}")
                        if schema_type[1] == "attributeTypes":
                            stats['schema_attrs_skipped'] += 1
                        else:
                            stats['schema_oc_skipped'] += 1
                        stats['ignored_errors'] += 1
                    else:
                        self.handle_error("Failed to add schema value: "
                                          f"'{attr_val}' - {str(e)}")

        # Flush the schema cache
        self.local_conn._flush_schema()

        self.log_debug(f"Migrated {stats['schema_attrs_added']} attributes "
                       f"and {stats['schema_oc_added']} objectClasses")
        self.log_debug(f"Skipped {stats['schema_attrs_skipped']} attributes "
                       f"and {stats['schema_oc_skipped']} objectClasses")

    #
    # Configuration Migration
    #
    def process_config_entry(self, dn, remote_attrs, ds_config,
                             add_missing=False):
        """
        Get the local entry, and check the attributes in ds_config
        for any differences and apply them
        """
        all_attrs = ds_config['attrs'] + ds_config['multivalued']
        updated_entry = False
        try:
            local_entry = self.local_conn.get_entry(DN(dn))
            for check_attr in all_attrs:
                # Because the attribute case could be different we have to do
                # all these "for" loops to properly check and properly update
                # the local entry
                for remote_attr in remote_attrs:
                    if remote_attr.lower() == check_attr.lower():
                        # The remote entry has this attribute, proceed
                        attr_exists = False
                        for local_attr in local_entry:
                            if check_attr.lower() == local_attr.lower():
                                # The local entry also has this attr, proceed
                                attr_exists = True
                                remote_vals = self.convert_values(
                                    remote_attrs[remote_attr])
                                local_vals = self.normalize_vals(
                                    local_entry[local_attr])
                                for rval in remote_vals:
                                    # Check values
                                    if rval not in local_vals:
                                        updated_entry = True
                                        if check_attr in ds_config[
                                            'multivalued'
                                        ]:
                                            # Append value
                                            local_entry[local_attr].append(
                                                rval)
                                            self.log_debug("Config setting "
                                                           f"{local_attr}' "
                                                           "added value "
                                                           f"'{rval}'"
                                                           f" in '{dn}'")
                                        else:
                                            # Replace attr value
                                            old_vals = local_entry[
                                                local_attr
                                            ]
                                            local_entry[local_attr] = \
                                                remote_vals
                                            val = remote_vals[0]
                                            self.log_debug("Config setting '"
                                                           f"{local_attr}' "
                                                           "replaced "
                                                           f"'{str(old_vals)}'"
                                                           f" with '{val}'"
                                                           f" in '{dn}'")
                                            break
                        if not attr_exists:
                            # local entry is missing this attribute, add it
                            remote_vals = self.convert_values(
                                remote_attrs[remote_attr])
                            local_entry[remote_attr] = remote_vals
                            self.log_debug("Config setting '"
                                           f"{remote_attr}' "
                                           "added: '{remote_vals}'"
                                           f" under '{dn}'")
            if updated_entry:
                if not self.dryrun:
                    try:
                        self.local_conn.update_entry(local_entry)
                    except Exception as e:
                        if not self.args.force:
                            self.handle_error(
                                f"Error updating local entry: {str(e)}")
                        else:
                            self.log_error(
                                f"Error updating local entry: {str(e)}")
                            stats['ignored_errors'] += 1

                self.write_update_to_ldif(local_entry)
                ds_config['count'] += 1
                stats['config_migrated'] += 1

        except errors.NotFound:
            # This entry does not exist in the local server
            if add_missing:
                # Add the missing entry
                add_entry = self.build_ldap_entry(dn, remote_attrs)
                if not self.dryrun:
                    self.local_conn.add_entry(add_entry)
                self.write_update_to_ldif(add_entry, add_entry=True)
                ds_config['count'] += 1
                stats['config_migrated'] += 1
                self.log_debug(f"Added config entry: {dn}")

    def migrateConfig(self):
        """
        Process and migrate settings and entries from cn=config(dse.ldif)
        """
        self.log_info("Migrating configuration ...")

        remote_dse = []
        if self.args.config_ldif is not None:
            self.log_debug("Getting config from LDIF file ...")
            dse_entries = get_ldif_records(self.args.config_ldif)
            for entry in dse_entries:
                if str(entry[0]) == '':
                    continue
                remote_dse.append({
                    'dn': entry[0],
                    'attrs': entry[1]
                })
        else:
            self.log_debug("Getting config from the remote server ...")
            config_entries = self.remote_conn.get_entries(DN("cn=config"))
            for entry in config_entries:
                attrs = {}
                for attr in entry:
                    attrs[attr] = self.get_ldapentry_attr_vals(entry, attr)
                remote_dse.append({
                    'dn': str(entry.dn),
                    'attrs': attrs,
                })

        # Now we have a uniform representation of the remote dse, start
        # processing the entries
        for entry in remote_dse:
            for dse_item in DS_CONFIG.items():
                if dse_item[0] == "dna" and self.mode == "stage-mode":
                    # Do not migrate DNA ranges in staging mode
                    continue
                dse = dse_item[1]
                for dn in dse['dn']:
                    if DN(dn) == DN(entry['dn']):
                        # We found an entry to migrate
                        self.process_config_entry(
                            dn, entry['attrs'], dse)
                        stats['config_processed'] += 1

            # Now do indexes/attr encryption (need to process child entries
            # compared to DS_CONFIG entries)
            for dse_item in DS_INDEXES.items():
                dse = dse_item[1]
                if dse['dn'] in entry['dn'].lower():
                    # We found an index/encrypted attr to migrate
                    self.process_config_entry(
                        entry['dn'], entry['attrs'], dse,
                        add_missing=True)
                    stats['config_processed'] += 1

    #
    # Migration
    #
    def do_migration(self):
        """
        Get the data and convert it all to LDIF files which we will parse later
        """
        start_time = time.time()

        # Log header with all the config settings
        self.log_debug('=' * 80)
        self.log_info('IPA to IPA migration starting ...')
        self.log_debug('Migration options:')
        for arg in vars(self.args):
            narg = arg.replace('_', '-')
            if narg != "bind-pw":
                self.log_debug(f'--{narg}={getattr(self.args, arg)}')

        # Initialize our connections
        self.connect_to_local_ds()
        if ((self.args.config_ldif is None and not self.args.skip_config)
                or (self.args.schema_ldif is None
                    and not self.args.skip_schema)
                or self.args.db_ldif is None):
            # Need to query remote DS so lets connect to it
            self.connect_to_remote_ds()

        # Check if schema checking is disabled on remote server
        local_config = self.local_conn.get_entry(DN("cn=config"),
                                                 ['nsslapd-schemacheck'])
        if self.remote_conn is not None:
            remote_config = self.remote_conn.get_entry(
                DN("cn=config"), ['nsslapd-schemacheck'])
            if remote_config['nsslapd-schemacheck'][0].lower() == "off" and \
               local_config['nsslapd-schemacheck'][0].lower() == "on":
                self.log_info("WARNING - Schema checking is disabled on the "
                              "remote server, but it is enabled on the local "
                              "server. This could cause failures when "
                              "migrating the database.")

        # Get the suffixes for each server
        self.local_suffix = self.get_base_dn()
        self.remote_suffix = self.get_base_dn(remote=True)

        # Make sure local IPA server is in migration mode
        if not self.dryrun:
            config_dn = f"cn=ipaconfig,cn=etc,{self.local_suffix}"
            ldap = api.Backend.ldap2
            config = ldap.get_entry(DN(config_dn), ['ipaMigrationEnabled'])
            if not config['ipaMigrationEnabled'][0]:
                config['ipaMigrationEnabled'] = ["TRUE"]
                ldap.update_entry(config)
                self.post_notes.append("The local server has been put into "
                                       "migration mode. Once all migration "
                                       "tasks are done you will have to take "
                                       "the server out of migration mode.")
            else:
                self.post_notes.append("The local server is in migration "
                                       "mode. Once all migration tasks are "
                                       "done you will have to take the "
                                       "server out of migration mode.")

        # Get the remote domain
        domain_parts = self.args.hostname.split(".")[1:]
        self.remote_domain = '.'.join(domain_parts)

        # Get the remote realm
        self.get_remote_realm()

        # Open dryrun ldif file
        if self.args.dryrun_record is not None:
            self.dryrun_record = open(self.args.dryrun_record, "w")

        if self.args.skip_schema:
            self.log_info("Skipping schema migration")
        else:
            # Do the schema
            self.migrateSchema()

        if self.args.skip_config:
            self.log_info("Skipping configuration migration")
        else:
            # Do the DS config
            self.migrateConfig()

        # Do the Database
        self.migrateDB()

        # Close dryrun ldif file
        if self.dryrun_record is not None:
            self.dryrun_record.close()

        #
        # Do the remaining 1% ...
        #

        # Run ipa-server-upgrade
        self.log_info("Running ipa-server-upgrade ... "
                      "(this may take a while)")
        if self.dryrun:
            self.log_info("Skipping ipa-server-upgrade in dryrun mode.")
        else:
            popen = subprocess.Popen(["/usr/sbin/ipa-server-upgrade"],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     universal_newlines=True)
            for stdout_line in iter(popen.stdout.readline, ""):
                self.log_debug(stdout_line.rstrip())
            for stdout_line in iter(popen.stderr.readline, ""):
                self.log_debug(stdout_line.rstrip())
            popen.stdout.close()
            return_code = popen.wait()
            if return_code:
                self.log_error(f"ipa-server-upgrade failed: {return_code}")
                self.post_notes.append("ipa-server-upgrade failed, "
                                       "needs investigation")

        # Run SIDGEN task
        self.log_info("Running SIDGEN task ...")
        if self.dryrun:
            self.log_info("Skipping SIDGEN task in dryrun mode.")
        else:
            try:
                cmd = ["/usr/bin/ipa config-mod --enable-sid --add-sids"]
                result = subprocess.run(cmd, shell=True, check=True,
                                        capture_output=True, text=True)
                self.log_debug("SIDGEN task:\n" + result.stdout)
            except subprocess.CalledProcessError as e:
                self.log_error("SIDGEN task failed: " + str(e))
                self.post_notes.append("SIDGEN task failed, "
                                       "needs investigation.")

        # TODO handle the LDIF conflict entries? (not used yet)

        # Wrap it up with the summary report
        self.display_stats(round(time.time() - start_time))

    def run(self):
        """
        Run the IPA to IPA migration tool
        """

        # Validate user and setup
        if not is_ipa_configured():
            self.handle_error('IPA is not configured', err=2)

        if os.getegid() != 0:
            self.handle_error(f'Must be root to run {self.command_name}')

        # Setup the arguments
        desc = 'IPA to IPA Migration Tool'
        parser = argparse.ArgumentParser(description=desc, allow_abbrev=True)
        self.add_options(parser)
        self.validate_options()
        admin_cleanup_global_argv(parser, self.args, sys.argv)

        # Check for dryrun mode
        if self.args.dryrun or self.args.dryrun_record is not None:
            self.dryrun = True

        # Prompt for confirmation
        if not self.args.no_prompt and not self.dryrun:
            print('Warning - the migration process is irreversible!  Make '
                  'sure you have a backup of the local IPA server before '
                  'doing the migration')
            answer = input('To proceed type "yes": ')
            if answer.lower() != "yes":
                self.handle_error('Aborting migration.')

        print("Initializing ...")
        # Init the API
        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        try:
            api.finalize()
        except Exception as e:
            self.handle_error(f'Problem with IPA installation: {str(e)}',
                              err=2)

        print("Connecting to local server ...")
        api.Backend.ldap2.connect()
        self.ldapiuri = realm_to_ldapi_uri(api.env.realm)
        self.realm = api.env.realm
        self.api = api
        self.local_hostname = socket.getfqdn()
        domain_parts = self.local_hostname.split(".")[1:]
        self.local_domain = '.'.join(domain_parts)

        # Check that we have kerberos credentials
        try:
            subprocess.run(["/usr/bin/ipa server-show "
                            + self.local_hostname],
                           capture_output=True,
                           shell=True, check=True)
        except subprocess.CalledProcessError:
            self.handle_error("Did not receive Kerberos credentials")

        # Setup our logging
        self.setup_logging()

        # Let's do the migration
        self.do_migration()
