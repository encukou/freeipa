# Authors:
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2009  Red Hat
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
"""
Base classes for LDAP plugins.
"""

import re
import time
from copy import deepcopy
import base64

import six

from ipalib import api, crud, errors
from ipalib import Method, Object
from ipalib import Flag, Int, Str
from ipalib.cli import to_cli
from ipalib import output
from ipalib.text import _
from ipalib.util import json_serialize, validate_hostname
from ipalib.capabilities import client_has_capability
from ipalib.messages import add_message, SearchResultTruncated
from ipalib.plugable import Registry
from ipapython.dn import DN, RDN
from ipapython.version import API_VERSION

if six.PY3:
    unicode = str

DNA_MAGIC = -1

global_output_params = (
    Flag('has_password',
        label=_('Password'),
    ),
    Str('member',
        label=_('Failed members'),
    ),
    Str('member_user?',
        label=_('Member users'),
    ),
    Str('member_group?',
        label=_('Member groups'),
    ),
    Str('memberof_group?',
        label=_('Member of groups'),
    ),
    Str('member_host?',
        label=_('Member hosts'),
    ),
    Str('member_hostgroup?',
        label=_('Member host-groups'),
    ),
    Str('memberof_hostgroup?',
        label=_('Member of host-groups'),
    ),
    Str('memberof_permission?',
        label=_('Permissions'),
    ),
    Str('memberof_privilege?',
        label='Privileges',
    ),
    Str('memberof_role?',
        label=_('Roles'),
    ),
    Str('memberof_sudocmdgroup?',
        label=_('Sudo Command Groups'),
    ),
    Str('member_privilege?',
        label='Granted to Privilege',
    ),
    Str('member_role?',
        label=_('Granting privilege to roles'),
    ),
    Str('member_netgroup?',
        label=_('Member netgroups'),
    ),
    Str('memberof_netgroup?',
        label=_('Member of netgroups'),
    ),
    Str('member_service?',
        label=_('Member services'),
    ),
    Str('member_servicegroup?',
        label=_('Member service groups'),
    ),
    Str('memberof_servicegroup?',
        label='Member of service groups',
    ),
    Str('member_hbacsvc?',
        label=_('Member HBAC service'),
    ),
    Str('member_hbacsvcgroup?',
        label=_('Member HBAC service groups'),
    ),
    Str('memberof_hbacsvcgroup?',
        label='Member of HBAC service groups',
    ),
    Str('member_sudocmd?',
        label='Member Sudo commands',
    ),
    Str('memberof_sudorule?',
        label='Member of Sudo rule',
    ),
    Str('memberof_hbacrule?',
        label='Member of HBAC rule',
    ),
    Str('memberof_subid?',
        label='Subordinate ids',),
    Str('member_idoverrideuser?',
        label=_('Member ID user overrides'),),
    Str('memberindirect_idoverrideuser?',
        label=_('Indirect Member ID user overrides'),),
    Str('memberindirect_user?',
        label=_('Indirect Member users'),
    ),
    Str('memberindirect_group?',
        label=_('Indirect Member groups'),
    ),
    Str('memberindirect_host?',
        label=_('Indirect Member hosts'),
    ),
    Str('memberindirect_hostgroup?',
        label=_('Indirect Member host-groups'),
    ),
    Str('memberindirect_role?',
        label=_('Indirect Member of roles'),
    ),
    Str('memberindirect_permission?',
        label=_('Indirect Member permissions'),
    ),
    Str('memberindirect_hbacsvc?',
        label=_('Indirect Member HBAC service'),
    ),
    Str('memberindirect_hbacsvcgrp?',
        label=_('Indirect Member HBAC service group'),
    ),
    Str('memberindirect_netgroup?',
        label=_('Indirect Member netgroups'),
    ),
    Str('memberofindirect_group?',
        label='Indirect Member of group',
    ),
    Str('memberofindirect_netgroup?',
        label='Indirect Member of netgroup',
    ),
    Str('memberofindirect_hostgroup?',
        label='Indirect Member of host-group',
    ),
    Str('memberofindirect_role?',
        label='Indirect Member of role',
    ),
    Str('memberofindirect_sudorule?',
        label='Indirect Member of Sudo rule',
    ),
    Str('memberofindirect_hbacrule?',
        label='Indirect Member of HBAC rule',
    ),
    Str('sourcehost',
        label=_('Failed source hosts/hostgroups'),
    ),
    Str('memberhost',
        label=_('Failed hosts/hostgroups'),
    ),
    Str('memberuser',
        label=_('Failed users/groups'),
    ),
    Str('memberservice',
        label=_('Failed service/service groups'),
    ),
    Str('failed',
        label=_('Failed to remove'),
        flags=['suppress_empty'],
    ),
    Str('ipasudorunas',
        label=_('Failed RunAs'),
    ),
    Str('ipasudorunasgroup',
        label=_('Failed RunAsGroup'),
    ),
)


def validate_add_attribute(ugettext, attr):
    validate_attribute(ugettext, 'addattr', attr)

def validate_set_attribute(ugettext, attr):
    validate_attribute(ugettext, 'setattr', attr)

def validate_del_attribute(ugettext, attr):
    validate_attribute(ugettext, 'delattr', attr)

def validate_attribute(ugettext, name, attr):
    m = re.match(r"\s*(.*?)\s*=\s*(.*?)\s*$", attr)
    if not m or len(m.groups()) != 2:
        raise errors.ValidationError(
            name=name, error=_('Invalid format. Should be name=value'))

def get_effective_rights(ldap, dn, attrs=None):
    assert isinstance(dn, DN)
    if attrs is None:
        attrs = ['*', 'nsaccountlock', 'cospriority']
    rights = ldap.get_effective_rights(dn, attrs)
    rdict = {}
    if 'attributelevelrights' in rights:
        rights = rights['attributelevelrights']
        rights = rights[0].split(', ')
        for r in rights:
            (k,v) = r.split(':')
            if v == 'none':
                # the string "none" means "no rights found"
                # see https://fedorahosted.org/freeipa/ticket/4359
                v = u''
            rdict[k.strip().lower()] = v

    return rdict

def entry_from_entry(entry, newentry):
    """
    Python is more or less pass-by-value except for immutable objects. So if
    you pass in a dict to a function you are free to change members of that
    dict but you can't create a new dict in the function and expect to replace
    what was passed in.

    In some post-op plugins that is exactly what we want to do, so here is a
    clumsy way around the problem.
    """

    # Wipe out the current data
    for e in list(entry):
        del entry[e]

    # Re-populate it with new wentry
    for e in newentry.keys():
        entry[e] = newentry[e]

def entry_to_dict(entry, **options):
    if options.get('raw', False):
        result = {}
        for attr in entry:
            if attr.lower() == 'attributelevelrights':
                value = entry[attr]
            elif entry.conn.get_attribute_type(attr) is bytes:
                value = entry.raw[attr]
            else:
                value = list(entry.raw[attr])
                for (i, v) in enumerate(value):
                    try:
                        value[i] = v.decode('utf-8')
                    except UnicodeDecodeError:
                        pass
            result[attr] = value
    else:
        result = dict((k.lower(), v) for (k, v) in entry.items())
    if options.get('all', False):
        result['dn'] = entry.dn
    return result

def pkey_to_unicode(key):
    if key is None:
        key = []
    elif not isinstance(key, (tuple, list)):
        key = [key]
    key = u','.join(unicode(k) for k in key)
    return key

def pkey_to_value(key, options):
    version = options.get('version', API_VERSION)
    if client_has_capability(version, 'primary_key_types'):
        return key
    return pkey_to_unicode(key)

def wait_for_value(ldap, dn, attr, value):
    """
    389-ds postoperation plugins are executed after the data has been
    returned to a client. This means that plugins that add data in a
    postop are not included in data returned to the user.

    The downside of waiting is that this increases the time of the
    command.

    The updated entry is returned.
    """
    # Loop a few times to give the postop-plugin a chance to complete
    # Don't sleep for more than 6 seconds.
    x = 0
    while x < 20:
        # sleep first because the first search, even on a quiet system,
        # almost always fails.
        time.sleep(.3)
        x = x + 1

        # FIXME: put a try/except around here? I think it is probably better
        # to just let the exception filter up to the caller.
        entry_attrs = ldap.get_entry(dn, ['*'])
        if attr in entry_attrs:
            if isinstance(entry_attrs[attr], (list, tuple)):
                values = [y.lower() for y in entry_attrs[attr]]
                if value.lower() in values:
                    break
            else:
                if value.lower() == entry_attrs[attr].lower():
                    break

    return entry_attrs


def validate_externalhost(ugettext, hostname):
    try:
        validate_hostname(hostname, check_fqdn=False, allow_underscore=True)
    except ValueError as e:
        return unicode(e)
    return None


external_host_param = Str('externalhost*', validate_externalhost,
        label=_('External host'),
        flags=['no_option'],
)

# Registry to store member validators called through add_external_pre_callback
# Each validator should be defined as foo(ldap, dn, keys, options, value)
# where (ldap, dn, keys, options) are part of the signature for the
# add_external_pre_callback()
member_validator = Registry()


# validate hostname with allowed underscore characters, non-fqdn
# hostnames are allowed
@member_validator(membertype='host')
def validate_host(ldap, dn, keys, options, hostname):
    validate_hostname(hostname, check_fqdn=False, allow_underscore=True)

def add_external_pre_callback(membertype, ldap, dn, keys, options):
    """
    Pre callback to validate external members.

    This should be called by a command pre callback directly.

    membertype is the type of member
    """
    assert isinstance(dn, DN)


    if options.get(membertype):
        validator = None
        for cb in member_validator:
            if 'membertype' in cb and cb['membertype'] == membertype:
                validator = cb['plugin']
        if validator is None:
            param = api.Object[membertype].primary_key

            def generic_validator(ldap, dn, keys, options, value):
                value = param(value)
                param.validate(value)

            validator = generic_validator

        for value in options[membertype]:
            try:
                validator(ldap, dn, keys, options, value)
            except errors.ValidationError as e:
                raise errors.ValidationError(name=membertype, error=e.error)
            except ValueError as e:
                raise errors.ValidationError(name=membertype, error=e)
    return dn


EXTERNAL_OBJ_PREFIX = 'external '


def pre_callback_process_external_objects(member_attr, object_desc,
                                          ldap, dn, found, not_found,
                                          *keys, **options):
    """
    Takes the following arguments:
        member_attr - member attribute to process external members for
        object_desc - a tuple (type, prefix) to identify a type of an object
                      ('user', 'group', ...) to associate and a prefix to skip
                      when comparing with an external object. Prefix should be
                      None for objects that do not have prefixes.
        found - the dictionary with all members that were found
        not_found - the dictionary with all members which weren't found
        keys - list of arguments to the command where this callback is used
        options - list of options to the command where this callback is used.

    The callback performs validation of objects as external (not existing in
    IPA LDAP) and then adds them to a list of not found objects with a mark
    'external ..' object if they were resolved as an object from a trusted
    domain.

    Returns a DN object used for processing dn.
    """

    (o_type, o_prefix) = object_desc

    if o_type not in options:
        return dn

    dn = add_external_pre_callback(o_type, ldap, dn, keys, options)
    if 'trusted_objects' in options:
        trusted_objects = options.pop('trusted_objects')
        found_members = found.get(member_attr, {})
        found_objects = found_members.get(o_type, [])
        filtered_objects = []
        for o_id in found_objects:
            for obj in trusted_objects:
                m = obj
                if o_prefix is not None and obj.startswith(o_prefix):
                    m = obj[len(o_prefix):]
                if o_id[0].value.lower() == m.lower():
                    filtered_objects.append(o_id)
        found[member_attr][o_type] = list(
            set(found_objects) - set(filtered_objects))
        notfound_members = not_found.get(member_attr, {})
        notfound_objects = notfound_members.get(o_type, [])
        notfound_objects.extend(
            [(m, EXTERNAL_OBJ_PREFIX + o_type) for m in trusted_objects])
        notfound_members[o_type] = notfound_objects

    return dn

def add_external_post_callback(ldap, dn, entry_attrs, failed, completed,
                               memberattr, membertype, externalattr,
                               normalize=True, reject_failures=False):
    """
    Takes the following arguments:
        failed - the list of failed entries, these are candidates for possible
                 external entries to add
        completed - the number of successfully added entries so far
        memberattr - the attribute name that IPA uses for membership natively
                     (e.g. memberhost)
        membertype - the object type of the member (e.g. host)
        externalattr - the attribute name that IPA uses to store the membership
                       of the entries that are not managed by IPA
                       (e.g. externalhost)

    Returns the number of completed entries so far (the number of entries
    handled by IPA incremented by the number of handled external entries) and
    dn.
    """
    assert isinstance(dn, DN)

    completed_external = 0

    # Sift through the failures. We assume that these are all
    # entries that aren't stored in IPA, aka external entries.
    if memberattr in failed and membertype in failed[memberattr]:
        entry_attrs_ = ldap.get_entry(dn, [externalattr])
        dn = entry_attrs_.dn
        members = entry_attrs.get(memberattr, [])
        external_entries = entry_attrs_.get(externalattr, [])
        lc_external_entries = set(e.lower() for e in external_entries)

        failed_entries = []
        for entry in failed[memberattr][membertype]:
            # entry is a tuple (name, error)
            membername = entry[0].lower()
            member_dn = api.Object[membertype].get_dn(membername)
            assert isinstance(member_dn, DN)

            if (membername not in lc_external_entries and
                member_dn not in members):
                # Not an IPA entry, only add if it has been marked
                # as an external entry during the pre-callback validation
                # or if we are not asked to reject failures
                if (reject_failures and not entry[1].startswith(
                        EXTERNAL_OBJ_PREFIX)):

                    failed_entries.append(membername)
                    continue
                if normalize:
                    external_entries.append(membername)
                else:
                    external_entries.append(entry[0])
                lc_external_entries.add(membername)
                completed_external += 1
            elif (membername in lc_external_entries and
               member_dn not in members):
                # Already an external member, reset the error message
                msg = unicode(errors.AlreadyGroupMember())
                newerror = (entry[0], msg)
                ind = failed[memberattr][membertype].index(entry)
                failed[memberattr][membertype][ind] = newerror
                failed_entries.append(membername)
            else:
                # Really a failure
                failed_entries.append(membername)

        if completed_external:
            entry_attrs_[externalattr] = external_entries
            try:
                ldap.update_entry(entry_attrs_)
            except errors.EmptyModlist:
                pass
            failed[memberattr][membertype] = failed_entries
            entry_attrs[externalattr] = external_entries

    return (completed + completed_external, dn)


def remove_external_post_callback(ldap, dn, entry_attrs, failed, completed,
                                  memberattr, membertype, externalattr):
    """
    Takes the following arguments:
        failed - the list of failed entries, these are candidates for possible
                 external entries to remove
        completed - the number of successfully removed entries so far
        memberattr - the attribute name that IPA uses for membership natively
                     (e.g. memberhost)
        membertype - the object type of the member (e.g. host)
        externalattr - the attribute name that IPA uses to store the membership
                       of the entries that are not managed by IPA
                       (e.g. externalhost)

    Returns the number of completed entries so far (the number of entries
    handled by IPA incremented by the number of handled external entries) and
    dn.
    """

    assert isinstance(dn, DN)

    # Run through the failures and gracefully remove any member defined
    # as an external member.
    completed_external = 0
    if memberattr in failed and membertype in failed[memberattr]:
        entry_attrs_ = ldap.get_entry(dn, [externalattr])
        dn = entry_attrs_.dn
        external_entries = entry_attrs_.get(externalattr, [])
        failed_entries = []

        for entry in failed[memberattr][membertype]:
            membername = entry[0].lower()
            if membername in external_entries or entry[0] in external_entries:
                try:
                    external_entries.remove(membername)
                except ValueError:
                    external_entries.remove(entry[0])
                completed_external += 1
            else:
                msg = unicode(errors.NotGroupMember())
                newerror = (entry[0], msg)
                ind = failed[memberattr][membertype].index(entry)
                failed[memberattr][membertype][ind] = newerror
                failed_entries.append(membername)

        if completed_external:
            entry_attrs_[externalattr] = external_entries
            try:
                ldap.update_entry(entry_attrs_)
            except errors.EmptyModlist:
                pass
            failed[memberattr][membertype] = failed_entries
            entry_attrs[externalattr] = external_entries

    return (completed + completed_external, dn)


def host_is_master(ldap, fqdn):
    """
    Check to see if this host is a master.

    Raises an exception if a master, otherwise returns nothing.
    """
    master_dn = DN(('cn', fqdn), api.env.container_masters, api.env.basedn)
    try:
        ldap.get_entry(master_dn, ['objectclass'])
        raise errors.ValidationError(name='hostname', error=_('An IPA master host cannot be deleted or disabled'))
    except errors.NotFound:
        # Good, not a master
        pass


def add_missing_object_class(ldap, objectclass, dn, entry_attrs=None, update=True):
    """
    Add object class if missing into entry. Fetches entry if not passed. Updates
    the entry by default.

    Returns the entry
    """

    if not entry_attrs:
        entry_attrs = ldap.get_entry(dn, ['objectclass'])
    if (objectclass.lower() not in (o.lower() for o in entry_attrs['objectclass'])):
        entry_attrs['objectclass'].append(objectclass)
        if update:
            ldap.update_entry(entry_attrs)
    return entry_attrs


class LDAPObject(Object):
    """
    Object representing a LDAP entry.
    """
    backend_name = 'ldap2'

    parent_object = ''
    container_dn = ''
    object_name = _('entry')
    object_name_plural = _('entries')
    object_class = []
    object_class_config = None
    # If an objectclass is possible but not default in an entry. Needed for
    # collecting attributes for ACI UI.
    possible_objectclasses = []
    limit_object_classes = [] # Only attributes in these are allowed
    disallow_object_classes = [] # Disallow attributes in these
    permission_filter_objectclasses = None
    search_attributes = []
    search_attributes_config = None
    default_attributes = []
    search_display_attributes = [] # attributes displayed in LDAPSearch
    hidden_attributes = ['objectclass', 'aci']
    # set rdn_attribute only if RDN attribute differs from primary key!
    rdn_attribute = ''
    uuid_attribute = ''
    attribute_members = {}
    allow_rename = False
    password_attributes = []
    # Can bind as this entry (has userPassword or krbPrincipalKey)
    bindable = False
    relationships = {
        # attribute: (label, inclusive param prefix, exclusive param prefix)
        'member': ('Member', '', 'no_'),
        'memberof': ('Member Of', 'in_', 'not_in_'),
        'memberindirect': (
            'Indirect Member', None, 'no_indirect_'
        ),
        'memberofindirect': (
            'Indirect Member Of', None, 'not_in_indirect_'
        ),
        'membermanager': (
            'Group membership managed by',
            'membermanager_',
            'not_membermanager_'
        ),
    }
    label = _('Entry')
    label_singular = _('Entry')
    managed_permissions = {}

    container_not_found_msg = _('container entry (%(container)s) not found')
    parent_not_found_msg = _('%(parent)s: %(oname)s not found')
    object_not_found_msg = _('%(pkey)s: %(oname)s not found')
    already_exists_msg = _('%(oname)s with name "%(pkey)s" already exists')

    def get_dn(self, *keys, **kwargs):
        if self.parent_object:
            parent_dn = self.api.Object[self.parent_object].get_dn(*keys[:-1])
        else:
            parent_dn = DN(self.container_dn, api.env.basedn)
        if self.rdn_attribute:
            try:
                entry_attrs = self.backend.find_entry_by_attr(
                    self.primary_key.name, keys[-1], self.object_class, [''],
                    DN(self.container_dn, api.env.basedn)
                )
            except errors.NotFound:
                pass
            else:
                return entry_attrs.dn
        if self.primary_key and keys[-1] is not None:
            return self.backend.make_dn_from_attr(
                self.primary_key.name, keys[-1], parent_dn
            )
        assert isinstance(parent_dn, DN)
        return parent_dn

    def get_dn_if_exists(self, *keys, **kwargs):
        dn = self.get_dn(*keys, **kwargs)
        entry = self.backend.get_entry(dn, [''])
        return entry.dn

    def get_primary_key_from_dn(self, dn):
        assert isinstance(dn, DN)
        try:
            if self.rdn_attribute:
                entry_attrs = self.backend.get_entry(
                    dn, [self.primary_key.name]
                )
                try:
                    return entry_attrs[self.primary_key.name][0]
                except (KeyError, IndexError):
                    return ''
        except errors.NotFound:
            pass
        try:
            return dn[self.primary_key.name]
        except KeyError:
            # The primary key is not in the DN.
            # This shouldn't happen, but we don't want a "show" command to
            # crash.
            # Just return the entire DN, it's all we have if the entry
            # doesn't exist
            return unicode(dn)

    def get_ancestor_primary_keys(self):
        if self.parent_object:
            parent_obj = self.api.Object[self.parent_object]
            for key in parent_obj.get_ancestor_primary_keys():
                yield key
            if parent_obj.primary_key:
                pkey = parent_obj.primary_key
                yield pkey.clone_rename(
                    parent_obj.name + pkey.name, required=True, query=True,
                    cli_name=parent_obj.name, label=pkey.label
                )

    def has_objectclass(self, classes, objectclass):
        oc = [x.lower() for x in classes]
        return objectclass.lower() in oc

    def convert_attribute_members(self, entry_attrs, *keys, **options):
        if options.get('raw', False):
            return

        container_dns = {}
        new_attrs = {}

        for attr, members in self.attribute_members.items():
            try:
                value = entry_attrs.raw[attr]
            except KeyError:
                continue
            del entry_attrs[attr]

            for member in value:
                memberdn = DN(member.decode('utf-8'))
                for ldap_obj_name in members:
                    ldap_obj = self.api.Object[ldap_obj_name]
                    try:
                        container_dn = container_dns[ldap_obj_name]
                    except KeyError:
                        container_dn = DN(ldap_obj.container_dn, api.env.basedn)
                        container_dns[ldap_obj_name] = container_dn

                    if memberdn.endswith(container_dn):
                        new_value = ldap_obj.get_primary_key_from_dn(memberdn)
                        new_attr_name = '%s_%s' % (attr, ldap_obj.name)
                        try:
                            new_attr = new_attrs[new_attr_name]
                        except KeyError:
                            new_attr = entry_attrs.setdefault(new_attr_name, [])
                            new_attrs[new_attr_name] = new_attr
                        new_attr.append(new_value)
                        break

    def get_indirect_members(self, entry_attrs, attrs_list):
        if 'memberindirect' in attrs_list:
            self.get_memberindirect(entry_attrs)
        if 'memberofindirect' in attrs_list:
            self.get_memberofindirect(entry_attrs)

    def get_memberindirect(self, group_entry):
        """
        Get indirect members
        """

        mo_filter = self.backend.make_filter({'memberof': group_entry.dn})
        filter = self.backend.combine_filters(
            ('(member=*)', mo_filter), self.backend.MATCH_ALL)
        try:
            result = self.backend.get_entries(
                self.api.env.basedn,
                filter=filter,
                attrs_list=['member'],
                size_limit=-1, # paged search will get everything anyway
                paged_search=True)
        except errors.NotFound:
            result = []

        indirect = set()
        for entry in result:
            indirect.update(entry.raw.get('member', []))
        indirect.difference_update(group_entry.raw.get('member', []))

        if indirect:
            group_entry.raw['memberindirect'] = list(indirect)

    def get_memberofindirect(self, entry):

        dn = entry.dn
        filter = self.backend.make_filter(
            {
                'member': dn,
                'memberuser': dn,
                'memberhost': dn,
                'ipaowner': dn
            }
        )
        try:
            result = self.backend.get_entries(
                self.api.env.basedn,
                filter=filter,
                attrs_list=[''],
                size_limit=-1,  # paged search will get everything anyway
                paged_search=True)
        except errors.NotFound:
            result = []

        direct = set()
        indirect = set(entry.raw.get('memberof', []))
        for group_entry in result:
            dn = str(group_entry.dn).encode('utf-8')
            if dn in indirect:
                indirect.remove(dn)
                direct.add(dn)

        entry.raw['memberof'] = list(direct)
        if indirect:
            entry.raw['memberofindirect'] = list(indirect)

    def get_password_attributes(self, ldap, dn, entry_attrs):
        """
        Search on the entry to determine if it has a password or
        keytab set.

        A tuple is used to determine which attribute is set
        in entry_attrs. The value is set to True/False whether a
        given password type is set.
        """
        for (pwattr, attr) in self.password_attributes:
            search_filter = '(%s=*)' % pwattr
            try:
                ldap.find_entries(
                    search_filter, [pwattr], dn, ldap.SCOPE_BASE
                )
                entry_attrs[attr] = True
            except errors.NotFound:
                entry_attrs[attr] = False

    def handle_not_found(self, *keys):
        """Handle NotFound exception

        Must raise errors.NotFound again.
        """
        pkey = ''
        if self.primary_key:
            pkey = keys[-1]
        raise errors.NotFound(
            reason=self.object_not_found_msg % {
                'pkey': pkey, 'oname': self.object_name,
            }
        )

    def handle_duplicate_entry(self, *keys):
        try:
            pkey = keys[-1]
        except IndexError:
            pkey = ''
        raise errors.DuplicateEntry(
            message=self.already_exists_msg % {
                'pkey': pkey, 'oname': self.object_name,
            }
        )

    # list of attributes we want exported to JSON
    json_friendly_attributes = (
        'parent_object', 'container_dn', 'object_name', 'object_name_plural',
        'object_class', 'object_class_config', 'default_attributes', 'label', 'label_singular',
        'hidden_attributes', 'uuid_attribute', 'attribute_members', 'name',
        'takes_params', 'rdn_attribute', 'bindable', 'relationships',
    )

    def __json__(self):
        ldap = self.backend
        json_dict = dict(
            (a, json_serialize(getattr(self, a))) for a in self.json_friendly_attributes
        )
        if self.primary_key:
            json_dict['primary_key'] = self.primary_key.name
        objectclasses = self.object_class
        if self.object_class_config:
            config = ldap.get_ipa_config()
            objectclasses = deepcopy(config.get(
                self.object_class_config, objectclasses
            ))
        objectclasses = objectclasses + self.possible_objectclasses
        # Get list of available attributes for this object for use
        # in the ACI UI.
        attrs = self.api.Backend.ldap2.schema.attribute_types(objectclasses)
        attrlist = []
        # Go through the MUST first
        for attr in attrs[0].values():
            attrlist.append(attr.names[0].lower())
        # And now the MAY
        for attr in attrs[1].values():
            attrlist.append(attr.names[0].lower())
        json_dict['aciattrs'] = attrlist
        attrlist.sort()
        json_dict['methods'] = list(self.methods)
        json_dict['can_have_permissions'] = bool(
            self.permission_filter_objectclasses)
        return json_dict


# addattr can cause parameters to have more than one value even if not defined
# as multivalue, make sure this isn't the case
def _check_single_value_attrs(params, entry_attrs):
    for (a, v) in entry_attrs.items():
        if isinstance(v, (list, tuple)) and len(v) > 1:
            if a in params and not params[a].multivalue:
                raise errors.OnlyOneValueAllowed(attr=a)

# setattr or --option='' can cause parameters to be empty that are otherwise
# required, make sure we enforce that.
def _check_empty_attrs(params, entry_attrs):
    for (a, v) in entry_attrs.items():
        if v is None or (isinstance(v, str) and len(v) == 0):
            if a in params and params[a].required:
                raise errors.RequirementError(name=a)


def _check_limit_object_class(attributes, attrs, allow_only):
    """
    If the set of objectclasses is limited enforce that only those
    are updated in entry_attrs (plus dn)

    allow_only tells us what mode to check in:

    If True then we enforce that the attributes must be in the list of
    allowed.

    If False then those attributes are not allowed.
    """
    if len(attributes[0]) == 0 and len(attributes[1]) == 0:
        return
    # Remove options from the attributes names before validating
    # LDAP schema does not enforce any of LDAP attribute options
    # (e.g. attribute;option), thus we should avoid comparing
    # attribute names with options directly.
    limitattrs = {x.split(';')[0].lower() for x in attrs}
    # Go through the MUST first
    for attr in attributes[0].values():
        if attr.names[0].lower() in limitattrs:
            if not allow_only:
                raise errors.ObjectclassViolation(
                    info=_('attribute "%(attribute)s" not allowed') % dict(
                        attribute=attr.names[0].lower()))
            limitattrs.remove(attr.names[0].lower())
    # And now the MAY
    for attr in attributes[1].values():
        if attr.names[0].lower() in limitattrs:
            if not allow_only:
                raise errors.ObjectclassViolation(
                    info=_('attribute "%(attribute)s" not allowed') % dict(
                        attribute=attr.names[0].lower()))
            limitattrs.remove(attr.names[0].lower())
    if len(limitattrs) > 0 and allow_only:
        raise errors.ObjectclassViolation(
            info=_('these attributes are not allowed: %(attrs)s') % dict(
                attrs=", ".join(sorted(limitattrs))))


class BaseLDAPCommand(Method):
    """
    Base class for Base LDAP Commands.
    """
    setattr_option = Str('setattr*', validate_set_attribute,
                         cli_name='setattr',
                         doc=_("""Set an attribute to a name/value pair. Format is attr=value.
For multi-valued attributes, the command replaces the values already present."""),
                         exclude='webui',
                        )
    addattr_option = Str('addattr*', validate_add_attribute,
                         cli_name='addattr',
                         doc=_("""Add an attribute/value pair. Format is attr=value. The attribute
must be part of the schema."""),
                         exclude='webui',
                        )
    delattr_option = Str('delattr*', validate_del_attribute,
                         cli_name='delattr',
                         doc=_("""Delete an attribute/value pair. The option will be evaluated
last, after all sets and adds."""),
                         exclude='webui',
                        )

    callback_types = Method.callback_types + ('pre',
                                              'post',
                                              'exc')

    def get_summary_default(self, output):
        if 'value' in output:
            output = dict(output)
            output['value'] = pkey_to_unicode(output['value'])
        return super(BaseLDAPCommand, self).get_summary_default(output)

    def _convert_2_dict(self, ldap, attrs):
        """
        Convert a string in the form of name/value pairs into a dictionary.

        :param attrs: A list of name/value pair strings, in the "name=value"
            format. May also be a single string, or None.
        """

        newdict = {}
        if attrs is None:
            attrs = []
        elif type(attrs) not in (list, tuple):
            attrs = [attrs]
        for a in attrs:
            m = re.match(r"\s*(.*?)\s*=\s*(.*?)\s*$", a)
            attr = str(m.group(1)).lower()
            value = m.group(2)
            if attr in self.obj.params and attr not in self.params:
                # The attribute is managed by IPA, but it didn't get cloned
                # to the command. This happens with no_update/no_create attrs.
                raise errors.ValidationError(
                    name=attr, error=_('attribute is not configurable'))
            if len(value) == 0:
                # None means "delete this attribute"
                value = None

            if attr in newdict:
                if type(value) in (tuple,):
                    newdict[attr] += list(value)
                else:
                    newdict[attr].append(value)
            else:
                if type(value) in (tuple,):
                    newdict[attr] = list(value)
                else:
                    newdict[attr] = [value]
        return newdict

    def process_attr_options(self, entry_attrs, dn, keys, options):
        """
        Process all --setattr, --addattr, and --delattr options and add the
        resulting value to the list of attributes. --setattr is processed first,
        then --addattr and finally --delattr.

        When --setattr is not used then the original LDAP object is looked up
        (of course, not when dn is None) and the changes are applied to old
        object values.

        Attribute values deleted by --delattr may be deleted from attribute
        values set or added by --setattr, --addattr. For example, the following
        attributes will result in a NOOP:

        --addattr=attribute=foo --delattr=attribute=foo

        AttrValueNotFound exception may be raised when an attribute value was
        not found either by --setattr and --addattr nor in existing LDAP object.

        :param entry_attrs: A list of attributes that will be updated
        :param dn: dn of updated LDAP object or None if a new object is created
        :param keys: List of command arguments
        :param options: List of options
        """

        if all(k not in options for k in ("setattr", "addattr", "delattr")):
            return

        ldap = self.obj.backend

        adddict = self._convert_2_dict(ldap, options.get('addattr', []))
        setdict = self._convert_2_dict(ldap, options.get('setattr', []))
        deldict = self._convert_2_dict(ldap, options.get('delattr', []))

        setattrs = set(setdict)
        addattrs = set(adddict)
        delattrs = set(deldict)

        if dn is None:
            direct_add = addattrs
            direct_del = delattrs
            needldapattrs = []
        else:
            assert isinstance(dn, DN)
            direct_add = setattrs & addattrs
            direct_del = setattrs & delattrs
            needldapattrs = list((addattrs | delattrs) - setattrs)

        for attr, val in setdict.items():
            entry_attrs[attr] = val

        for attr in direct_add:
            try:
                val = entry_attrs[attr]
            except KeyError:
                val = []
            else:
                if not isinstance(val, (list, tuple)):
                    val = [val]
                elif isinstance(val, tuple):
                    val = list(val)
            val.extend(adddict[attr])
            entry_attrs[attr] = val

        for attr in direct_del:
            for delval in deldict[attr]:
                try:
                    entry_attrs[attr].remove(delval)
                except ValueError:
                    raise errors.AttrValueNotFound(attr=attr, value=delval)

        if needldapattrs:
            try:
                old_entry = self._exc_wrapper(keys, options, ldap.get_entry)(
                    dn, needldapattrs
                )
            except errors.NotFound:
                raise self.obj.handle_not_found(*keys)

            # Provide a nice error message when user tries to delete an
            # attribute that does not exist on the entry (and user is not
            # adding it)
            names = set(n.lower() for n in old_entry)
            del_nonexisting = delattrs - (names | setattrs | addattrs)
            if del_nonexisting:
                raise errors.ValidationError(name=del_nonexisting.pop(),
                    error=_('No such attribute on this entry'))

            for attr in needldapattrs:
                entry_attrs[attr] = old_entry.get(attr, [])

                if attr in addattrs:
                    entry_attrs[attr].extend(adddict.get(attr, []))

                for delval in deldict.get(attr, []):
                    try:
                        try:
                            val = ldap.decode(delval.encode('utf-8'), attr)
                            entry_attrs[attr].remove(val)
                        except ValueError:
                            entry_attrs[attr].remove(delval)
                    except ValueError:
                        if isinstance(delval, bytes):
                            # This is a Binary value, base64 encode it
                            delval = base64.b64encode(delval).decode('ascii')
                        raise errors.AttrValueNotFound(attr=attr, value=delval)

        # normalize all values
        changedattrs = setattrs | addattrs | delattrs
        for attr in changedattrs:
            if attr in self.params and self.params[attr].attribute:
                # convert single-value params to scalars
                param = self.params[attr]
                value = entry_attrs[attr]
                if not param.multivalue:
                    if len(value) == 1:
                        value = value[0]
                    elif not value:
                        value = None
                    else:
                        raise errors.OnlyOneValueAllowed(attr=attr)
                # validate, convert and encode params
                try:
                    value = param(value)
                    param.validate(value)
                except errors.ValidationError as err:
                    raise errors.ValidationError(name=attr, error=err.error)
                except errors.ConversionError as err:
                    raise errors.ConversionError(name=attr, error=err.error)
                if isinstance(value, tuple):
                    value = list(value)
                entry_attrs[attr] = value
            else:
                # unknown attribute: remove duplicite and invalid values
                entry_attrs[attr] = list(
                    {val for val in entry_attrs[attr] if val}
                )
                if not entry_attrs[attr]:
                    entry_attrs[attr] = None
                elif isinstance(entry_attrs[attr], (tuple, list)) and len(entry_attrs[attr]) == 1:
                    entry_attrs[attr] = entry_attrs[attr][0]

    @classmethod
    def register_pre_callback(cls, callback, first=False):
        """Shortcut for register_callback('pre', ...)"""
        cls.register_callback('pre', callback, first)

    @classmethod
    def register_post_callback(cls, callback, first=False):
        """Shortcut for register_callback('post', ...)"""
        cls.register_callback('post', callback, first)

    @classmethod
    def register_exc_callback(cls, callback, first=False):
        """Shortcut for register_callback('exc', ...)"""
        cls.register_callback('exc', callback, first)

    def _exc_wrapper(self, keys, options, call_func):
        """Function wrapper that automatically calls exception callbacks"""
        def wrapped(*call_args, **call_kwargs):
            # call call_func first
            func = call_func
            callbacks = list(self.get_callbacks('exc'))
            while True:
                try:
                    return func(*call_args, **call_kwargs)
                except errors.ExecutionError as exc:
                    e = exc
                    if not callbacks:
                        raise
                    # call exc_callback in the next loop
                    callback = callbacks.pop(0)
                    def exc_func(*args, **kwargs):
                        return callback(
                            self, keys, options, e, call_func, *args, **kwargs)
                    func = exc_func
        return wrapped

    def get_options(self):
        for param in super(BaseLDAPCommand, self).get_options():
            yield param
        if self.obj.attribute_members:
            for o in self.has_output:
                if isinstance(o, (output.Entry, output.ListOfEntries)):
                    yield Flag('no_members',
                        doc=_('Suppress processing of membership attributes.'),
                        exclude='webui',
                        flags={'no_output'},
                    )
                    break

class LDAPCreate(BaseLDAPCommand, crud.Create):
    """
    Create a new entry in LDAP.
    """
    takes_options = (BaseLDAPCommand.setattr_option, BaseLDAPCommand.addattr_option)

    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key
        for arg in super(LDAPCreate, self).get_args():
            yield arg

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)
        entry_attrs = ldap.make_entry(
            dn, self.args_options_2_entry(*keys, **options))

        entry_attrs['objectclass'] = deepcopy(self.obj.object_class)

        self.process_attr_options(entry_attrs, None, keys, options)

        if self.obj.object_class_config:
            config = ldap.get_ipa_config()
            entry_attrs['objectclass'] = deepcopy(config.get(
                self.obj.object_class_config, entry_attrs['objectclass']
            ))

        if self.obj.uuid_attribute:
            entry_attrs[self.obj.uuid_attribute] = 'autogenerate'

        if self.obj.rdn_attribute:
            try:
                dn_attr = dn[0].attr
            except (IndexError, KeyError):
                dn_attr = None
            if dn_attr != self.obj.primary_key.name:
                self.obj.handle_duplicate_entry(*keys)
            entry_attrs.dn = ldap.make_dn(
                entry_attrs, self.obj.rdn_attribute,
                DN(self.obj.container_dn, api.env.basedn))

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = set(self.obj.default_attributes)
            attrs_list.update(entry_attrs.keys())
            if options.get('no_members', False):
                attrs_list.difference_update(self.obj.attribute_members)
            attrs_list = list(attrs_list)

        for callback in self.get_callbacks('pre'):
            entry_attrs.dn = callback(
                self, ldap, entry_attrs.dn, entry_attrs, attrs_list,
                *keys, **options)

        _check_single_value_attrs(self.params, entry_attrs)
        _check_limit_object_class(self.api.Backend.ldap2.schema.attribute_types(self.obj.limit_object_classes), list(entry_attrs), allow_only=True)
        _check_limit_object_class(self.api.Backend.ldap2.schema.attribute_types(self.obj.disallow_object_classes), list(entry_attrs), allow_only=False)

        try:
            self._exc_wrapper(keys, options, ldap.add_entry)(entry_attrs)
        except errors.NotFound:
            parent = self.obj.parent_object
            if parent:
                raise errors.NotFound(
                    reason=self.obj.parent_not_found_msg % {
                        'parent': keys[-2],
                        'oname': self.api.Object[parent].object_name,
                    }
                )
            raise errors.NotFound(
                reason=self.obj.container_not_found_msg % {
                    'container': self.obj.container_dn,
                }
            )
        except errors.DuplicateEntry:
            self.obj.handle_duplicate_entry(*keys)

        try:
            if self.obj.rdn_attribute:
                # make sure objectclass is either set or None
                if self.obj.object_class:
                    object_class = self.obj.object_class
                else:
                    object_class = None
                entry_attrs = self._exc_wrapper(keys, options, ldap.find_entry_by_attr)(
                    self.obj.primary_key.name, keys[-1], object_class, attrs_list,
                    DN(self.obj.container_dn, api.env.basedn)
                )
            else:
                entry_attrs = self._exc_wrapper(keys, options, ldap.get_entry)(
                    entry_attrs.dn, attrs_list)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        self.obj.get_indirect_members(entry_attrs, attrs_list)

        for callback in self.get_callbacks('post'):
            entry_attrs.dn = callback(
                self, ldap, entry_attrs.dn, entry_attrs, *keys, **options)

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)

        dn = entry_attrs.dn
        entry_attrs = entry_to_dict(entry_attrs, **options)
        entry_attrs['dn'] = dn

        if self.obj.primary_key:
            pkey = keys[-1]
        else:
            pkey = None

        return dict(result=entry_attrs, value=pkey_to_value(pkey, options))

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPQuery(BaseLDAPCommand, crud.PKQuery):
    """
    Base class for commands that need to retrieve an existing entry.
    """
    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key
        for arg in super(LDAPQuery, self).get_args():
            yield arg


class LDAPMultiQuery(LDAPQuery):
    """
    Base class for commands that need to retrieve one or more existing entries.
    """
    takes_options = (
        Flag('continue',
            cli_name='continue',
            doc=_('Continuous mode: Don\'t stop on errors.'),
        ),
    )

    def get_args(self):
        for arg in super(LDAPMultiQuery, self).get_args():
            if self.obj.primary_key and arg.name == self.obj.primary_key.name:
                yield arg.clone(multivalue=True)
            else:
                yield arg


class LDAPRetrieve(LDAPQuery):
    """
    Retrieve an LDAP entry.
    """
    has_output = output.standard_entry
    has_output_params = global_output_params

    takes_options = (
        Flag('rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
        ),
    )

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)
        assert isinstance(dn, DN)

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = set(self.obj.default_attributes)
            if options.get('no_members', False):
                attrs_list.difference_update(self.obj.attribute_members)
            attrs_list = list(attrs_list)

        for callback in self.get_callbacks('pre'):
            dn = callback(self, ldap, dn, attrs_list, *keys, **options)
            assert isinstance(dn, DN)

        try:
            entry_attrs = self._exc_wrapper(keys, options, ldap.get_entry)(
                dn, attrs_list
            )
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        self.obj.get_indirect_members(entry_attrs, attrs_list)

        if options.get('rights', False) and options.get('all', False):
            entry_attrs['attributelevelrights'] = get_effective_rights(
                ldap, entry_attrs.dn)

        for callback in self.get_callbacks('post'):
            entry_attrs.dn = callback(
                self, ldap, entry_attrs.dn, entry_attrs, *keys, **options)

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)

        dn = entry_attrs.dn
        entry_attrs = entry_to_dict(entry_attrs, **options)
        entry_attrs['dn'] = dn

        if self.obj.primary_key:
            pkey = keys[-1]
        else:
            pkey = None

        return dict(result=entry_attrs, value=pkey_to_value(pkey, options))

    def pre_callback(self, ldap, dn, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPUpdate(LDAPQuery, crud.Update):
    """
    Update an LDAP entry.
    """

    takes_options = (
        BaseLDAPCommand.setattr_option,
        BaseLDAPCommand.addattr_option,
        BaseLDAPCommand.delattr_option,
        Flag('rights',
            label=_('Rights'),
            doc=_('Display the access rights of this entry (requires --all). See ipa man page for details.'),
        ),
    )

    has_output_params = global_output_params

    def _get_rename_option(self):
        rdnparam = getattr(self.obj.params, self.obj.primary_key.name)
        return rdnparam.clone_rename('rename',
            cli_name='rename', required=False, label=_('Rename'),
            doc=_('Rename the %(ldap_obj_name)s object') % dict(
                ldap_obj_name=self.obj.object_name
            )
        )

    def get_options(self):
        for option in super(LDAPUpdate, self).get_options():
            yield option
        if self.obj.allow_rename:
            yield self._get_rename_option()

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        if len(options) == 2: # 'all' and 'raw' are always sent
            raise errors.EmptyModlist()

        dn = self.obj.get_dn(*keys, **options)
        entry_attrs = ldap.make_entry(dn, self.args_options_2_entry(**options))

        self.process_attr_options(entry_attrs, dn, keys, options)

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = set(self.obj.default_attributes)
            attrs_list.update(entry_attrs.keys())
            if options.get('no_members', False):
                attrs_list.difference_update(self.obj.attribute_members)
            attrs_list = list(attrs_list)

        _check_single_value_attrs(self.params, entry_attrs)
        _check_empty_attrs(self.obj.params, entry_attrs)

        for callback in self.get_callbacks('pre'):
            entry_attrs.dn = callback(
                self, ldap, entry_attrs.dn, entry_attrs, attrs_list,
                *keys, **options)

        _check_limit_object_class(self.api.Backend.ldap2.schema.attribute_types(self.obj.limit_object_classes), list(entry_attrs), allow_only=True)
        _check_limit_object_class(self.api.Backend.ldap2.schema.attribute_types(self.obj.disallow_object_classes), list(entry_attrs), allow_only=False)

        rdnupdate = False
        if 'rename' in options:
            if not options['rename']:
                raise errors.ValidationError(
                    name='rename', error=u'can\'t be empty')
            entry_attrs[self.obj.primary_key.name] = options['rename']

        # if setattr was used to change the RDN, the primary_key.name is
        # already in entry_attrs
        if self.obj.allow_rename and self.obj.primary_key.name in entry_attrs:
            # perform RDN change if the primary key is also RDN
            if (RDN((self.obj.primary_key.name, keys[-1])) ==
                    entry_attrs.dn[0]):
                try:
                    new_dn = DN((self.obj.primary_key.name,
                                 entry_attrs[self.obj.primary_key.name]),
                                *entry_attrs.dn[1:])
                    self._exc_wrapper(keys, options, ldap.move_entry)(
                        entry_attrs.dn,
                        new_dn)

                    rdnkeys = (keys[:-1] +
                               (entry_attrs[self.obj.primary_key.name], ))
                    entry_attrs.dn = self.obj.get_dn(*rdnkeys)
                    options['rdnupdate'] = True
                    rdnupdate = True
                except errors.EmptyModlist:
                    # Attempt to rename to the current name, ignore
                    pass
                except errors.NotFound:
                    raise self.obj.handle_not_found(*keys)
                finally:
                    # Delete the primary_key from entry_attrs either way
                    del entry_attrs[self.obj.primary_key.name]

        try:
            # Exception callbacks will need to test for options['rdnupdate']
            # to decide what to do. An EmptyModlist in this context doesn't
            # mean an error occurred, just that there were no other updates to
            # perform.
            update = self._exc_wrapper(keys, options, ldap.get_entry)(
                entry_attrs.dn, list(entry_attrs))
            update.update(entry_attrs)

            self._exc_wrapper(keys, options, ldap.update_entry)(update)
        except errors.EmptyModlist as e:
            if not rdnupdate:
                raise e
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        try:
            entry_attrs = self._exc_wrapper(keys, options, ldap.get_entry)(
                entry_attrs.dn, attrs_list)
        except errors.NotFound:
            raise errors.MidairCollision(
                message=_('the entry was deleted while being modified')
            )

        self.obj.get_indirect_members(entry_attrs, attrs_list)

        if options.get('rights', False) and options.get('all', False):
            entry_attrs['attributelevelrights'] = get_effective_rights(
                ldap, entry_attrs.dn)

        for callback in self.get_callbacks('post'):
            entry_attrs.dn = callback(
                self, ldap, entry_attrs.dn, entry_attrs, *keys, **options)

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)

        entry_attrs = entry_to_dict(entry_attrs, **options)

        if self.obj.primary_key:
            pkey = keys[-1]
        else:
            pkey = None

        return dict(result=entry_attrs, value=pkey_to_value(pkey, options))

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPDelete(LDAPMultiQuery):
    """
    Delete an LDAP entry and all of its direct subentries.
    """
    has_output = output.standard_multi_delete

    has_output_params = global_output_params

    subtree_delete = True

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        def delete_entry(pkey):
            nkeys = keys[:-1] + (pkey, )
            dn = self.obj.get_dn(*nkeys, **options)
            assert isinstance(dn, DN)

            for callback in self.get_callbacks('pre'):
                dn = callback(self, ldap, dn, *nkeys, **options)
                assert isinstance(dn, DN)

            def delete_subtree(base_dn):
                assert isinstance(base_dn, DN)
                truncated = True
                while truncated:
                    try:
                        (subentries, truncated) = ldap.find_entries(
                            None, [''], base_dn, ldap.SCOPE_ONELEVEL
                        )
                    except errors.NotFound:
                        break
                    else:
                        for entry_attrs in subentries:
                            delete_subtree(entry_attrs.dn)
                try:
                    self._exc_wrapper(nkeys, options, ldap.delete_entry)(
                        base_dn
                    )
                except errors.NotFound:
                    raise self.obj.handle_not_found(*nkeys)

            try:
                self._exc_wrapper(nkeys, options, ldap.delete_entry)(dn)
            except errors.NotFound:
                raise self.obj.handle_not_found(*nkeys)
            except errors.NotAllowedOnNonLeaf:
                if not self.subtree_delete:
                    raise
                # this entry is not a leaf entry, delete all child nodes
                delete_subtree(dn)

            for callback in self.get_callbacks('post'):
                result = callback(self, ldap, dn, *nkeys, **options)

            return result

        if self.obj.primary_key and isinstance(keys[-1], (list, tuple)):
            pkeyiter = keys[-1]
        elif keys[-1] is not None:
            pkeyiter = [keys[-1]]
        else:
            pkeyiter = []

        deleted = []
        failed = []
        for pkey in pkeyiter:
            try:
                delete_entry(pkey)
            except errors.ExecutionError:
                if not options.get('continue', False):
                    raise
                failed.append(pkey)
            else:
                deleted.append(pkey)
        deleted = pkey_to_value(deleted, options)
        failed = pkey_to_value(failed, options)

        return dict(result=dict(failed=failed), value=deleted)

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        return True

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPModMember(LDAPQuery):
    """
    Base class for member manipulation.
    """
    member_attributes = ['member']
    member_param_doc = _('%s')
    member_param_label = _('member %s')
    member_count_out = ('%i member processed.', '%i members processed.')

    def get_options(self):
        for option in super(LDAPModMember, self).get_options():
            yield option
        for attr in self.member_attributes:
            for ldap_obj_name in self.obj.attribute_members[attr]:
                ldap_obj = self.api.Object[ldap_obj_name]
                name = to_cli(ldap_obj_name)
                doc = self.member_param_doc % ldap_obj.object_name_plural
                label = self.member_param_label % ldap_obj.object_name
                yield Str('%s*' % name, cli_name='%ss' % name, doc=doc,
                          label=label, alwaysask=True)

    def get_member_dns(self, **options):
        dns = {}
        failed = {}
        for attr in self.member_attributes:
            dns[attr] = {}
            failed[attr] = {}
            for ldap_obj_name in self.obj.attribute_members[attr]:
                dns[attr][ldap_obj_name] = []
                failed[attr][ldap_obj_name] = []
                names = options.get(to_cli(ldap_obj_name), [])
                if not names:
                    continue
                for name in names:
                    if not name:
                        continue
                    ldap_obj = self.api.Object[ldap_obj_name]
                    try:
                        dns[attr][ldap_obj_name].append(ldap_obj.get_dn(name))
                    except errors.PublicError as e:
                        failed[attr][ldap_obj_name].append((name, unicode(e)))
        return (dns, failed)


class LDAPAddMember(LDAPModMember):
    """
    Add other LDAP entries to members.
    """
    member_param_doc = _('%s to add')
    member_count_out = ('%i member added.', '%i members added.')
    allow_same = False

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be added'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of members added'),
        ),
    )

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        (member_dns, failed) = self.get_member_dns(**options)

        dn = self.obj.get_dn(*keys, **options)
        assert isinstance(dn, DN)

        for callback in self.get_callbacks('pre'):
            dn = callback(self, ldap, dn, member_dns, failed, *keys, **options)
            assert isinstance(dn, DN)

        completed = 0
        for (attr, objs) in member_dns.items():
            for ldap_obj_name in objs:
                for m_dn in objs[ldap_obj_name]:
                    assert isinstance(m_dn, DN)
                    if not m_dn:
                        continue
                    try:
                        ldap.add_entry_to_group(m_dn, dn, attr, allow_same=self.allow_same)
                    except errors.PublicError as e:
                        ldap_obj = self.api.Object[ldap_obj_name]
                        failed[attr][ldap_obj_name].append((
                            ldap_obj.get_primary_key_from_dn(m_dn),
                            unicode(e),)
                        )
                    else:
                        completed += 1

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = set(self.obj.default_attributes)
            attrs_list.update(member_dns.keys())
            if options.get('no_members', False):
                attrs_list.difference_update(self.obj.attribute_members)
            attrs_list = list(attrs_list)

        try:
            entry_attrs = self._exc_wrapper(keys, options, ldap.get_entry)(
                dn, attrs_list
            )
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        self.obj.get_indirect_members(entry_attrs, attrs_list)

        for callback in self.get_callbacks('post'):
            (completed, entry_attrs.dn) = callback(
                self, ldap, completed, failed, entry_attrs.dn, entry_attrs,
                *keys, **options)

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)

        dn = entry_attrs.dn
        entry_attrs = entry_to_dict(entry_attrs, **options)
        entry_attrs['dn'] = dn

        return dict(
            completed=completed,
            failed=failed,
            result=entry_attrs,
        )

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return (completed, dn)

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPRemoveMember(LDAPModMember):
    """
    Remove LDAP entries from members.
    """
    member_param_doc = _('%s to remove')
    member_count_out = ('%i member removed.', '%i members removed.')

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be removed'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of members removed'),
        ),
    )

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        (member_dns, failed) = self.get_member_dns(**options)

        dn = self.obj.get_dn(*keys, **options)
        assert isinstance(dn, DN)

        for callback in self.get_callbacks('pre'):
            dn = callback(self, ldap, dn, member_dns, failed, *keys, **options)
            assert isinstance(dn, DN)

        completed = 0
        for (attr, objs) in member_dns.items():
            for ldap_obj_name, m_dns in objs.items():
                for m_dn in m_dns:
                    assert isinstance(m_dn, DN)
                    if not m_dn:
                        continue
                    try:
                        ldap.remove_entry_from_group(m_dn, dn, attr)
                    except errors.PublicError as e:
                        ldap_obj = self.api.Object[ldap_obj_name]
                        failed[attr][ldap_obj_name].append((
                            ldap_obj.get_primary_key_from_dn(m_dn),
                            unicode(e),)
                        )
                    else:
                        completed += 1

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = set(self.obj.default_attributes)
            attrs_list.update(member_dns.keys())
            if options.get('no_members', False):
                attrs_list.difference_update(self.obj.attribute_members)
            attrs_list = list(attrs_list)

        # Give memberOf a chance to update entries
        time.sleep(.3)

        try:
            entry_attrs = self._exc_wrapper(keys, options, ldap.get_entry)(
                dn, attrs_list
            )
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        self.obj.get_indirect_members(entry_attrs, attrs_list)

        for callback in self.get_callbacks('post'):
            (completed, entry_attrs.dn) = callback(
                self, ldap, completed, failed, entry_attrs.dn, entry_attrs,
                *keys, **options)

        self.obj.convert_attribute_members(entry_attrs, *keys, **options)

        dn = entry_attrs.dn
        entry_attrs = entry_to_dict(entry_attrs, **options)
        entry_attrs['dn'] = dn

        return dict(
            completed=completed,
            failed=failed,
            result=entry_attrs,
        )

    def pre_callback(self, ldap, dn, found, not_found, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return (completed, dn)

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


def gen_pkey_only_option(cli_name):
    return Flag('pkey_only?',
                label=_('Primary key only'),
                doc=_('Results should contain primary key attribute only ("%s")') \
                    % to_cli(cli_name),)

class LDAPSearch(BaseLDAPCommand, crud.Search):
    """
    Retrieve all LDAP entries matching the given criteria.
    """
    member_attributes = []
    member_param_incl_doc = _('Search for %(searched_object)s with these %(relationship)s %(ldap_object)s.')
    member_param_excl_doc = _('Search for %(searched_object)s without these %(relationship)s %(ldap_object)s.')

    # LDAPSearch sorts all matched records in the end using their primary key
    # as a key attribute
    # Set the following attribute to False to turn sorting off
    sort_result_entries = True

    takes_options = (
        Int('timelimit?',
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
        Int('sizelimit?',
            label=_('Size Limit'),
            doc=_('Maximum number of entries returned (0 is unlimited)'),
            flags=['no_display'],
            minvalue=0,
            autofill=False,
        ),
    )

    def get_args(self):
        for key in self.obj.get_ancestor_primary_keys():
            yield key
        for arg in super(LDAPSearch, self).get_args():
            yield arg

    def get_member_options(self, attr):
        for ldap_obj_name in self.obj.attribute_members[attr]:
            ldap_obj = self.api.Object[ldap_obj_name]
            relationship = self.obj.relationships.get(
                attr, ['member', '', 'no_']
            )
            doc = self.member_param_incl_doc % dict(
                searched_object=self.obj.object_name_plural,
                relationship=relationship[0].lower(),
                ldap_object=ldap_obj.object_name_plural
            )
            name = '%s%s' % (relationship[1], to_cli(ldap_obj_name))
            yield ldap_obj.primary_key.clone_rename(
                '%s' % name, cli_name='%ss' % name, doc=doc,
                label=ldap_obj.object_name, multivalue=True, query=True,
                required=False, primary_key=False
            )
            doc = self.member_param_excl_doc % dict(
                searched_object=self.obj.object_name_plural,
                relationship=relationship[0].lower(),
                ldap_object=ldap_obj.object_name_plural
            )
            name = '%s%s' % (relationship[2], to_cli(ldap_obj_name))
            yield ldap_obj.primary_key.clone_rename(
                '%s' % name, cli_name='%ss' % name, doc=doc,
                label=ldap_obj.object_name, multivalue=True, query=True,
                required=False, primary_key=False
            )

    def get_options(self):
        for option in super(LDAPSearch, self).get_options():
            if option.name == 'no_members':
                # no_members are always true for find commands, do not
                # show option in CLI but keep API compatibility
                option = option.clone(
                    default=True, flags=option.flags | {"no_option"})
            yield option
        if self.obj.primary_key and \
                'no_output' not in self.obj.primary_key.flags:
            yield gen_pkey_only_option(self.obj.primary_key.cli_name)
        for attr in self.member_attributes:
            for option in self.get_member_options(attr):
                yield option

    def get_attr_filter(self, ldap, **options):
        """
        Returns a MATCH_ALL filter containing all required attributes from the
        options
        """
        search_kw = self.args_options_2_entry(**options)
        search_kw['objectclass'] = self.obj.object_class

        filters = []
        for name, value in search_kw.items():
            default = self.get_default_of(name, **options)
            fltr = ldap.make_filter_from_attr(name, value, ldap.MATCH_ALL)
            if default is not None and value == default:
                fltr = ldap.combine_filters([fltr, '(!({}=*))'.format(name)])
            filters.append(fltr)

        return ldap.combine_filters(filters, rules=ldap.MATCH_ALL)

    def get_term_filter(self, ldap, term):
        """
        Returns a filter to search for a value (term) in any of the
        search attributes of an entry.
        """
        if self.obj.search_attributes:
            search_attrs = self.obj.search_attributes
        else:
            search_attrs = self.obj.default_attributes
        if self.obj.search_attributes_config:
            config = ldap.get_ipa_config()
            config_attrs = config.get(
                self.obj.search_attributes_config, [])
            if len(config_attrs) == 1 and (
                    isinstance(config_attrs[0], str)):
                search_attrs = config_attrs[0].split(',')

        search_kw = {}
        for a in search_attrs:
            search_kw[a] = term

        return ldap.make_filter(search_kw, exact=False)

    def get_member_filter(self, ldap, **options):
        filter = ''
        for attr in self.member_attributes:
            for ldap_obj_name in self.obj.attribute_members[attr]:
                ldap_obj = self.api.Object[ldap_obj_name]
                relationship = self.obj.relationships.get(
                    attr, ['member', '', 'no_']
                )
                # Handle positive (MATCH_ALL) and negative (MATCH_NONE)
                # searches similarly
                param_prefixes = relationship[1:]  # e.g. ('in_', 'not_in_')
                rules = ldap.MATCH_ALL, ldap.MATCH_NONE
                for param_prefix, rule in zip(param_prefixes, rules):
                    param_name = '%s%s' % (param_prefix, to_cli(ldap_obj_name))
                    if options.get(param_name):
                        dns = []
                        for pkey in options[param_name]:
                            dns.append(ldap_obj.get_dn(pkey))
                        flt = ldap.make_filter_from_attr(attr, dns, rule)
                        filter = ldap.combine_filters(
                            (filter, flt), ldap.MATCH_ALL
                        )
        return filter

    has_output_params = global_output_params

    def execute(self, *args, **options):
        ldap = self.obj.backend

        index = tuple(self.args).index('criteria')
        keys = args[:index]
        try:
            term = args[index]
        except IndexError:
            term = None
        if self.obj.parent_object:
            base_dn = self.api.Object[self.obj.parent_object].get_dn(*keys)
        else:
            base_dn = DN(self.obj.container_dn, api.env.basedn)
        assert isinstance(base_dn, DN)

        search_kw = self.args_options_2_entry(**options)

        if self.obj.search_display_attributes:
            defattrs = self.obj.search_display_attributes
        else:
            defattrs = self.obj.default_attributes

        if options.get('pkey_only', False):
            attrs_list = [self.obj.primary_key.name]
        elif options.get('all', False):
            attrs_list = ['*'] + defattrs
        else:
            attrs_list = set(defattrs)
            attrs_list.update(search_kw.keys())
            if options.get('no_members', False):
                attrs_list.difference_update(self.obj.attribute_members)
            attrs_list = list(attrs_list)

        attr_filter = self.get_attr_filter(ldap, **options)
        term_filter = self.get_term_filter(ldap, term)
        member_filter = self.get_member_filter(ldap, **options)

        filter = ldap.combine_filters(
            (term_filter, attr_filter, member_filter), rules=ldap.MATCH_ALL
        )

        scope = ldap.SCOPE_ONELEVEL
        for callback in self.get_callbacks('pre'):
            (filter, base_dn, scope) = callback(
                self, ldap, filter, attrs_list, base_dn, scope, *args, **options)
            assert isinstance(base_dn, DN)

        try:
            (entries, truncated) = self._exc_wrapper(args, options, ldap.find_entries)(
                filter, attrs_list, base_dn, scope,
                time_limit=options.get('timelimit', None),
                size_limit=options.get('sizelimit', None)
            )
        except errors.EmptyResult:
            (entries, truncated) = ([], False)
        except errors.NotFound:
            return self.api.Object[self.obj.parent_object].handle_not_found(
                *keys)

        for callback in self.get_callbacks('post'):
            truncated = callback(
                self, ldap, entries, truncated, *args, **options
            )

        if self.sort_result_entries:
            if self.obj.primary_key:
                def sort_key(x):
                    return self.obj.primary_key.sort_key(
                        x[self.obj.primary_key.name][0])
                entries.sort(key=sort_key)

        if not options.get('raw', False):
            for entry in entries:
                self.obj.get_indirect_members(entry, attrs_list)
                self.obj.convert_attribute_members(entry, *args, **options)

        for (i, e) in enumerate(entries):
            entries[i] = entry_to_dict(e, **options)
            entries[i]['dn'] = e.dn

        result = dict(
            result=entries,
            count=len(entries),
            truncated=bool(truncated),
        )

        try:
            ldap.handle_truncated_result(truncated)
        except errors.LimitsExceeded as exc:
            add_message(options['version'], result, SearchResultTruncated(
                reason=exc))

        return result

    def pre_callback(self, ldap, filters, attrs_list, base_dn, scope, *args, **options):
        assert isinstance(base_dn, DN)
        return (filters, base_dn, scope)

    def post_callback(self, ldap, entries, truncated, *args, **options):
        return truncated

    def exc_callback(self, args, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPModReverseMember(LDAPQuery):
    """
    Base class for reverse member manipulation.
    """
    reverse_attributes = ['member']
    reverse_param_doc = _('%s')
    reverse_count_out = ('%i member processed.', '%i members processed.')

    has_output_params = global_output_params

    def get_options(self):
        for option in super(LDAPModReverseMember, self).get_options():
            yield option
        for attr in self.reverse_attributes:
            for ldap_obj_name in self.obj.reverse_members[attr]:
                ldap_obj = self.api.Object[ldap_obj_name]
                name = to_cli(ldap_obj_name)
                doc = self.reverse_param_doc % ldap_obj.object_name_plural
                yield Str('%s*' % name, cli_name='%ss' % name, doc=doc,
                          label=ldap_obj.object_name, alwaysask=True)


class LDAPAddReverseMember(LDAPModReverseMember):
    """
    Add other LDAP entries to members in reverse.

    The call looks like "add A to B" but in fact executes
    add B to A to handle reverse membership.
    """
    member_param_doc = _('%s to add')
    member_count_out = ('%i member added.', '%i members added.')

    show_command = None
    member_command = None
    reverse_attr = None
    member_attr = None

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be added'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of members added'),
        ),
    )

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        # Ensure our target exists
        result = self.api.Command[self.show_command](keys[-1])['result']
        dn = result['dn']
        assert isinstance(dn, DN)

        for callback in self.get_callbacks('pre'):
            dn = callback(self, ldap, dn, *keys, **options)
            assert isinstance(dn, DN)

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = set(self.obj.default_attributes)
            if options.get('no_members', False):
                attrs_list.difference_update(self.obj.attribute_members)
            attrs_list = list(attrs_list)

        completed = 0
        failed = {'member': {self.reverse_attr: []}}
        for attr in options.get(self.reverse_attr) or []:
            try:
                options = {'%s' % self.member_attr: keys[-1]}
                try:
                    result = self._exc_wrapper(keys, options, self.api.Command[self.member_command])(attr, **options)
                    if result['completed'] == 1:
                        completed = completed + 1
                    else:
                        failed['member'][self.reverse_attr].append((attr, result['failed']['member'][self.member_attr][0][1]))
                except errors.NotFound as e:
                    msg = str(e)
                    (attr, msg) = msg.split(':', 1)
                    failed['member'][self.reverse_attr].append((attr, unicode(msg.strip())))

            except errors.PublicError as e:
                failed['member'][self.reverse_attr].append((attr, unicode(e)))

        # Update the member data.
        entry_attrs = ldap.get_entry(dn, attrs_list)
        self.obj.convert_attribute_members(entry_attrs, *keys, **options)

        for callback in self.get_callbacks('post'):
            (completed, entry_attrs.dn) = callback(
                self, ldap, completed, failed, entry_attrs.dn, entry_attrs,
                *keys, **options)

        dn = entry_attrs.dn
        entry_attrs = entry_to_dict(entry_attrs, **options)
        entry_attrs['dn'] = dn

        return dict(
            completed=completed,
            failed=failed,
            result=entry_attrs,
        )

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return (completed, dn)

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class LDAPRemoveReverseMember(LDAPModReverseMember):
    """
    Remove other LDAP entries from members in reverse.

    The call looks like "remove A from B" but in fact executes
    remove B from A to handle reverse membership.
    """
    member_param_doc = _('%s to remove')
    member_count_out = ('%i member removed.', '%i members removed.')

    show_command = None
    member_command = None
    reverse_attr = None
    member_attr = None

    has_output = (
        output.Entry('result'),
        output.Output('failed',
            type=dict,
            doc=_('Members that could not be removed'),
        ),
        output.Output('completed',
            type=int,
            doc=_('Number of members removed'),
        ),
    )

    has_output_params = global_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        # Ensure our target exists
        result = self.api.Command[self.show_command](keys[-1])['result']
        dn = result['dn']
        assert isinstance(dn, DN)

        for callback in self.get_callbacks('pre'):
            dn = callback(self, ldap, dn, *keys, **options)
            assert isinstance(dn, DN)

        if options.get('all', False):
            attrs_list = ['*'] + self.obj.default_attributes
        else:
            attrs_list = set(self.obj.default_attributes)
            if options.get('no_members', False):
                attrs_list.difference_update(self.obj.attribute_members)
            attrs_list = list(attrs_list)

        completed = 0
        failed = {'member': {self.reverse_attr: []}}
        for attr in options.get(self.reverse_attr) or []:
            try:
                options = {'%s' % self.member_attr: keys[-1]}
                try:
                    result = self._exc_wrapper(keys, options, self.api.Command[self.member_command])(attr, **options)
                    if result['completed'] == 1:
                        completed = completed + 1
                    else:
                        failed['member'][self.reverse_attr].append((attr, result['failed']['member'][self.member_attr][0][1]))
                except errors.NotFound as e:
                    msg = str(e)
                    (attr, msg) = msg.split(':', 1)
                    failed['member'][self.reverse_attr].append((attr, unicode(msg.strip())))

            except errors.PublicError as e:
                failed['member'][self.reverse_attr].append((attr, unicode(e)))

        # Update the member data.
        entry_attrs = ldap.get_entry(dn, attrs_list)
        self.obj.convert_attribute_members(entry_attrs, *keys, **options)

        for callback in self.get_callbacks('post'):
            (completed, entry_attrs.dn) = callback(
                self, ldap, completed, failed, entry_attrs.dn, entry_attrs,
                *keys, **options)

        dn = entry_attrs.dn
        entry_attrs = entry_to_dict(entry_attrs, **options)
        entry_attrs['dn'] = dn

        return dict(
            completed=completed,
            failed=failed,
            result=entry_attrs,
        )

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, completed, failed, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return (completed, dn)

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


class BaseLDAPModAttribute(LDAPQuery):

    attribute = None

    has_output = output.standard_entry

    def _get_attribute_param(self):
        arg = self.obj.params[self.attribute]
        attribute = 'virtual_attribute' not in arg.flags
        return arg.clone(required=True, attribute=attribute, alwaysask=True)

    def _update_attrs(self, update, entry_attrs):
        raise NotImplementedError(
            "%s.update_attrs()" % self.__class__.__name__
        )

    def execute(self, *keys, **options):
        ldap = self.obj.backend
        try:
            index = tuple(self.args).index(self.attribute)
        except ValueError:
            obj_keys = keys
        else:
            obj_keys = keys[:index]

        dn = self.obj.get_dn(*obj_keys, **options)
        entry_attrs = ldap.make_entry(dn, self.args_options_2_entry(
            *keys, **options))

        entry_attrs.pop(self.obj.primary_key.name, None)

        if options.get('all', False):
            attrs_list = ['*', self.obj.primary_key.name]
        else:
            attrs_list = {self.obj.primary_key.name}
            attrs_list.update(entry_attrs.keys())
            attrs_list = list(attrs_list)

        for callback in self.get_callbacks('pre'):
            entry_attrs.dn = callback(
                self, ldap, entry_attrs.dn, entry_attrs, attrs_list,
                *keys, **options)

        try:
            update = self._exc_wrapper(keys, options, ldap.get_entry)(
                entry_attrs.dn, list(entry_attrs))

            self._update_attrs(update, entry_attrs)

            self._exc_wrapper(keys, options, ldap.update_entry)(update)
        except errors.NotFound:
            raise self.obj.handle_not_found(*keys)

        try:
            entry_attrs = self._exc_wrapper(keys, options, ldap.get_entry)(
                entry_attrs.dn, attrs_list)
        except errors.NotFound:
            raise errors.MidairCollision(
                message=_('the entry was deleted while being modified')
            )

        for callback in self.get_callbacks('post'):
            entry_attrs.dn = callback(
                self, ldap, entry_attrs.dn, entry_attrs, *keys, **options)

        entry_attrs = entry_to_dict(entry_attrs, **options)

        if self.obj.primary_key:
            pkey = obj_keys[-1]
        else:
            pkey = None

        return dict(result=entry_attrs, value=pkey_to_value(pkey, options))

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys,
                     **options):
        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def exc_callback(self, keys, options, exc, call_func, *call_args,
                     **call_kwargs):
        raise exc


class BaseLDAPAddAttribute(BaseLDAPModAttribute):
    msg_summary = _('added attribute value to entry %(value)s')

    def _update_attrs(self, update, entry_attrs):
        for name, value in entry_attrs.items():
            old_value = set(update.get(name, []))
            value_to_add = set(value)

            if not old_value.isdisjoint(value_to_add):
                raise errors.AlreadyContainsValueError(attr=name)

            update[name] = list(old_value | value_to_add)


class BaseLDAPRemoveAttribute(BaseLDAPModAttribute):
    msg_summary = _('removed attribute values from entry %(value)s')

    def _update_attrs(self, update, entry_attrs):
        for name, value in entry_attrs.items():
            old_value = set(update.get(name, []))
            value_to_remove = set(value)

            if not value_to_remove.issubset(old_value):
                raise errors.AttrValueNotFound(
                    attr=name, value=_("one or more values to remove"))

            update[name] = list(old_value - value_to_remove)


class LDAPModAttribute(BaseLDAPModAttribute):

    def get_args(self):
        for arg in super(LDAPModAttribute, self).get_args():
            yield arg

        yield self._get_attribute_param()


class LDAPAddAttribute(LDAPModAttribute, BaseLDAPAddAttribute):
    pass


class LDAPRemoveAttribute(LDAPModAttribute, BaseLDAPRemoveAttribute):
    pass


class LDAPModAttributeViaOption(BaseLDAPModAttribute):

    def get_options(self):
        for option in super(LDAPModAttributeViaOption, self).get_options():
            yield option

        yield self._get_attribute_param()


class LDAPAddAttributeViaOption(LDAPModAttributeViaOption,
                                BaseLDAPAddAttribute):
    pass


class LDAPRemoveAttributeViaOption(LDAPModAttributeViaOption,
                                   BaseLDAPRemoveAttribute):
    pass
