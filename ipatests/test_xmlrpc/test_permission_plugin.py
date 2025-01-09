# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#
# Copyright (C) 2010  Red Hat
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
Test the `ipaserver/plugins/permission.py` module.
"""
from __future__ import print_function

import os

from ipalib import api, errors
from ipatests.test_xmlrpc import objectclasses
from ipatests.test_xmlrpc.xmlrpc_test import Declarative
from ipapython.dn import DN
import inspect
import pytest

try:
    from ipaserver.plugins.ldap2 import ldap2
except ImportError:
    have_ldap2 = False
else:
    have_ldap2 = True

permission1 = u'testperm'
permission1_dn = DN(('cn',permission1),
                    api.env.container_permission,api.env.basedn)


permission1_renamed = u'testperm1_rn'
permission1_renamed_dn = DN(('cn',permission1_renamed),
                            api.env.container_permission,api.env.basedn)

permission1_renamed_ucase = u'Testperm_RN'
permission1_renamed_ucase_dn = DN(('cn',permission1_renamed_ucase),
                            api.env.container_permission,api.env.basedn)


permission2 = u'testperm2'
permission2_dn = DN(('cn',permission2),
                    api.env.container_permission,api.env.basedn)

permission3 = u'testperm3'
permission3_dn = DN(('cn',permission3),
                    api.env.container_permission,api.env.basedn)
permission3_attributelevelrights = {
                                    'member': u'rscwo',
                                    'seealso': u'rscwo',
                                    'ipapermissiontype': u'rscwo',
                                    'cn': u'rscwo',
                                    'businesscategory': u'rscwo',
                                    'objectclass': u'rscwo',
                                    'memberof': u'rscwo',
                                    'aci': u'rscwo',
                                    'ipapermlocation': u'rscwo',
                                    'o': u'rscwo',
                                    'ipapermincludedattr': u'rscwo',
                                    'ipapermdefaultattr': u'rscwo',
                                    'ipapermexcludedattr': u'rscwo',
                                    'owner': u'rscwo',
                                    'ou': u'rscwo',
                                    'ipapermright': u'rscwo',
                                    'nsaccountlock': u'rscwo',
                                    'description': u'rscwo',
                                    'ipapermtargetfilter': u'rscwo',
                                    'ipapermtargetto': u'rscwo',
                                    'ipapermtargetfrom': u'rscwo',
                                    'ipapermbindruletype': u'rscwo',
                                    'ipapermtarget': u'rscwo',
                                    'type': u'rscwo',
                                    'targetgroup': u'rscwo',
                                    'attrs': u'rscwo',
                                   }

privilege1 = u'testpriv1'
privilege1_dn = DN(('cn',privilege1),
                   api.env.container_privilege,api.env.basedn)

invalid_permission1 = u'bad;perm'


users_dn = DN(api.env.container_user, api.env.basedn)
groups_dn = DN(api.env.container_group, api.env.basedn)
etc_dn = DN('cn=etc', api.env.basedn)
nonexistent_dn = DN('cn=does not exist', api.env.basedn)
admin_dn = DN('uid=admin', users_dn)

group_filter = u'(|(objectclass=ipausergroup)(objectclass=posixgroup))'


def verify_permission_aci(name, dn, acistring):
    """Return test dict that verifies the ACI at the given location"""
    return dict(
        desc="Verify ACI of %s #(%s)" % (name, lineinfo(2)),
        command=('aci_show', [name], dict(
            aciprefix=u'permission', location=dn, raw=True)),
        expected=dict(
            result=dict(aci=acistring),
            summary=None,
            value=name,
        ),
    )


def verify_permission_aci_missing(name, dn):
    """Return test dict that checks the ACI at the given location is missing"""
    return dict(
        desc="Verify ACI of %s is missing #(%s)" % (name, lineinfo(2)),
        command=('aci_show', [name], dict(
            aciprefix=u'permission', location=dn, raw=True)),
        expected=errors.NotFound(
            reason='ACI with name "%s" not found' % name),
    )


def lineinfo(level):
    """Return "filename:lineno" for `level`-th caller"""
    # Declarative tests hide tracebacks.
    # Including this info in the test name makes it possible
    # to locate failing tests.
    frame = inspect.currentframe()
    for _i in range(level):
        frame = frame.f_back
    lineno = frame.f_lineno
    filename = os.path.basename(frame.f_code.co_filename)
    return '%s:%s' % (filename, lineno)


@pytest.mark.tier1
class test_permission_negative(Declarative):
    """Make sure invalid operations fail"""

    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    tests = [
        dict(
            desc='Try to retrieve non-existent %r' % permission1,
            command=('permission_show', [permission1], {}),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),

        dict(
            desc='Try to update non-existent %r' % permission1,
            command=('permission_mod', [permission1], dict(ipapermright=u'all')),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),


        dict(
            desc='Try to delete non-existent %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),

        dict(
            desc='Search for non-existent %r' % permission1,
            command=('permission_find', [permission1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
            ),
        ),

        dict(
            desc='Try creating %r with no ipapermright' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    attrs=[u'sn'],
                )
            ),
            expected=errors.RequirementError(name='right'),
        ),

        dict(
            desc='Try creating %r with no target option' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    ipapermright=u'write',
                )
            ),
            expected=errors.ValidationError(
                name='target',
                error='there must be at least one target entry specifier '
                      '(e.g. target, targetfilter, attrs)'),
        ),

        verify_permission_aci_missing(permission1, api.env.basedn),

        dict(
            desc='Try to create invalid %r' % invalid_permission1,
            command=('permission_add', [invalid_permission1], dict(
                    type=u'user',
                    ipapermright=u'write',
                )),
            expected=errors.ValidationError(name='name',
                error='May only contain letters, numbers, -, _, ., and space'),
        ),

        verify_permission_aci_missing(permission1, users_dn),

        dict(
            desc='Try creating %r with bad attribute name' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=u'write',
                    attrs=u'bogusattr',
                )
            ),
            expected=errors.InvalidSyntax(
                attr=r'targetattr "bogusattr" does not exist in schema. '
                     r'Please add attributeTypes "bogusattr" to '
                     r'schema if necessary. '
                     r'ACL Syntax Error(-5):'
                     r'(targetattr = \22bogusattr\22)'
                     r'(targetfilter = \22(objectclass=posixaccount)\22)'
                     r'(version 3.0;acl \22permission:%(name)s\22;'
                     r'allow (write) groupdn = \22ldap:///%(dn)s\22;)' % dict(
                        name=permission1,
                        dn=permission1_dn),
            ),
        ),

        verify_permission_aci_missing(permission1, users_dn),

        dict(
            desc='Try to create permission with : in the name',
            command=('permission_add', ['bad:' + permission1], dict(
                    type=u'user',
                    ipapermright=u'write',
                )),
            expected=errors.ValidationError(name='name',
                error='May only contain letters, numbers, -, _, ., and space'),
        ),

        verify_permission_aci_missing(permission1, users_dn),

        dict(
            desc='Try to create permission with full and extra target filter',
            command=('permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=u'write',
                    ipapermtargetfilter=u'(cn=*)',
                    extratargetfilter=u'(sn=*)',
                )),
            expected=errors.ValidationError(name='ipapermtargetfilter',
                error='cannot specify full target filter and extra target '
                      'filter simultaneously'),
        ),

        verify_permission_aci_missing(permission1, users_dn),

        dict(
            desc='Create %r so we can try breaking it' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        dict(
            desc='Try remove ipapermright from %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermright=None,
                )
            ),
            expected=errors.RequirementError(name='right'),
        ),

        dict(
            desc='Try to remove type from %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    attrs=None,
                    type=None,
                )
            ),
            expected=errors.ValidationError(
                name='target',
                error='there must be at least one target entry specifier '
                      '(e.g. target, targetfilter, attrs)'),
        ),

        dict(
            desc='Try to "remove" empty memberof from %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    memberof=None,
                )
            ),
            expected=errors.EmptyModlist(),
        ),

        dict(
            desc='Try to remove targetfilter and memberof from %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    attrs=None,
                    ipapermtargetfilter=None,
                )
            ),
            expected=errors.ValidationError(
                name='target',
                error='there must be at least one target entry specifier '
                      '(e.g. target, targetfilter, attrs)'),
        ),

        dict(
            desc='Try to rename %r to invalid %r' % (
                permission1, invalid_permission1),
            command=('permission_mod', [permission1], dict(
                    rename=invalid_permission1,
                )),
            expected=errors.ValidationError(name='rename',
                error='May only contain letters, numbers, -, _, ., and space'),
        ),

        dict(
            desc='Try setting ipapermexcludedattr on %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermexcludedattr=[u'cn'],
                )
            ),
            expected=errors.ValidationError(
                name='ipapermexcludedattr',
                error='only available on managed permissions'),
        ),

        dict(
            desc='Try to setting both full and extra target filter on %s' % permission1,
            command=('permission_mod', [permission1], dict(
                    ipapermtargetfilter=u'(cn=*)',
                    extratargetfilter=u'(sn=*)',
                )),
            expected=errors.ValidationError(name='ipapermtargetfilter',
                error='cannot specify full target filter and extra target '
                      'filter simultaneously'),
        ),

    ]


@pytest.mark.tier1
class test_permission(Declarative):
    """Misc. tests for the permission plugin"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
        ('permission_del', [permission2], {'force': True}),
        ('permission_del', [permission3], {'force': True}),
        ('permission_del', [permission1_renamed], {'force': True}),
        ('permission_del', [permission1_renamed_ucase], {'force': True}),
        ('privilege_del', [privilege1], {}),
    ]

    tests = [

        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Try to create duplicate %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                ),
            ),
            expected=errors.DuplicateEntry(
                message='permission with name "%s" already exists' % permission1),
        ),


        dict(
            desc='Create %r' % privilege1,
            command=('privilege_add', [privilege1],
                dict(description=u'privilege desc. 1')
            ),
            expected=dict(
                value=privilege1,
                summary=u'Added privilege "%s"' % privilege1,
                result=dict(
                    dn=privilege1_dn,
                    cn=[privilege1],
                    description=[u'privilege desc. 1'],
                    objectclass=objectclasses.privilege,
                ),
            ),
        ),


        dict(
            desc='Add permission %r to privilege %r' % (permission1, privilege1),
            command=('privilege_add_permission', [privilege1],
                dict(permission=permission1)
            ),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        permission=[],
                    ),
                ),
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': [u'privilege desc. 1'],
                    'memberof_permission': [permission1],
                }
            ),
        ),


        dict(
            desc='Retrieve %r' % permission1,
            command=('permission_show', [permission1], {}),
            expected=dict(
                value=permission1,
                summary=None,
                result={
                    'dn': permission1_dn,
                    'cn': [permission1],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': [u'user'],
                    'ipapermright': [u'write'],
                    'attrs': [u'sn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                },
            ),
        ),


        dict(
            desc='Retrieve %r with --raw' % permission1,
            command=('permission_show', [permission1], {'raw': True}),
            expected=dict(
                value=permission1,
                summary=None,
                result={
                    'dn': permission1_dn,
                    'cn': [permission1],
                    'objectclass': objectclasses.permission,
                    'member': [privilege1_dn],
                    'ipapermincludedattr': [u'sn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermright': [u'write'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                    'ipapermtargetfilter': [u'(objectclass=posixaccount)'],
                    'aci': ['(targetattr = "sn")'
                            '(targetfilter = "(objectclass=posixaccount)")' +
                            '(version 3.0;acl "permission:%(name)s";'
                            'allow (write) groupdn = "ldap:///%(pdn)s";)' %
                            {'name': permission1,
                             'pdn': permission1_dn}],
                },
            ),
        ),


        dict(
            desc='Search for %r with members' % permission1,
            command=('permission_find', [permission1], {'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % permission1,
            command=('permission_find', [permission1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r using --name with members' % permission1,
            command=('permission_find', [], {
                'cn': permission1, 'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r using --name' % permission1,
            command=('permission_find', [], {'cn': permission1}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for non-existent permission using --name',
            command=('permission_find', [], {'cn': u'notfound'}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
            ),
        ),


        dict(
            desc='Search for %r with members' % privilege1,
            command=('permission_find', [privilege1], {'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % privilege1,
            command=('permission_find', [privilege1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --raw with members' % permission1,
            command=('permission_find', [permission1], {
                'raw': True, 'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member': [privilege1_dn],
                        'ipapermincludedattr': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermright': [u'write'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtargetfilter': [u'(objectclass=posixaccount)'],
                        'aci': ['(targetattr = "sn")'
                                '(targetfilter = "(objectclass=posixaccount)")' +
                                '(version 3.0;acl "permission:%(name)s";'
                                'allow (write) groupdn = "ldap:///%(pdn)s";)' %
                                {'name': permission1,
                                 'pdn': permission1_dn}],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --raw' % permission1,
            command=('permission_find', [permission1], {'raw': True}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'ipapermincludedattr': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermright': [u'write'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                        'ipapermtargetfilter': [u'(objectclass=posixaccount)'],
                        'aci': ['(targetattr = "sn")'
                                '(targetfilter = "(objectclass=posixaccount)")' +
                                '(version 3.0;acl "permission:%(name)s";'
                                'allow (write) groupdn = "ldap:///%(pdn)s";)' %
                                {'name': permission1,
                                 'pdn': permission1_dn}],
                    },
                ],
            ),
        ),


        dict(
            desc='Create %r' % permission2,
            command=(
                'permission_add', [permission2], dict(
                    type=u'user',
                    ipapermright=u'write',
                    setattr=u'owner=cn=test',
                    addattr=u'owner=cn=test2',
                    attrs=[u'cn'],
                )
            ),
            expected=dict(
                value=permission2,
                summary=u'Added permission "%s"' % permission2,
                result=dict(
                    dn=permission2_dn,
                    cn=[permission2],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    owner=[u'cn=test', u'cn=test2'],
                    attrs=[u'cn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission2, users_dn,
            '(targetattr = "cn")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission2 +
            'allow (write) groupdn = "ldap:///%s";)' % permission2_dn,
        ),

        dict(
            desc='Search for %r with members' % permission1,
            command=('permission_find', [permission1], {
                'no_members': False}),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'cn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % permission1,
            command=('permission_find', [permission1], {}),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'cn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with --pkey-only' % permission1,
            command=('permission_find', [permission1], {'pkey_only' : True}),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                    },
                ],
            ),
        ),


        dict(
            desc='Search by ACI attribute with --pkey-only',
            command=('permission_find', [], {'pkey_only': True,
                                             'attrs': [u'krbminpwdlife']}),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 permissions matched',
                result=[
                    {
                        'dn': DN(('cn', 'System: Modify Group Password Policy'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'System: Modify Group Password Policy'],
                    },
                    {
                        'dn': DN(('cn', 'System: Read Group Password Policy'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'System: Read Group Password Policy'],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r with members' % privilege1,
            command=('privilege_find', [privilege1], {'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 privilege matched',
                result=[
                    {
                        'dn': privilege1_dn,
                        'cn': [privilege1],
                        'description': [u'privilege desc. 1'],
                        'memberof_permission': [permission1],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r' % privilege1,
            command=('privilege_find', [privilege1], {}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 privilege matched',
                result=[
                    {
                        'dn': privilege1_dn,
                        'cn': [privilege1],
                        'description': [u'privilege desc. 1'],
                    },
                ],
            ),
        ),


        dict(
            desc=('Search for %r with a limit of 1 (truncated) with members' %
                  permission1),
            command=('permission_find', [permission1],
                dict(sizelimit=1, no_members=False)),
            expected=dict(
                count=1,
                truncated=True,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [privilege1],
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
                messages=(
                    {
                        'message': (u'Search result has been truncated: '
                                    u'Configured size limit exceeded'),
                        'code': 13017,
                        'type': u'warning',
                        'name': u'SearchResultTruncated',
                        'data': {
                            'reason': u"Configured size limit exceeded"
                        }
                    },
                ),
            ),
        ),


        dict(
            desc='Search for %r with a limit of 1 (truncated)' % permission1,
            command=('permission_find', [permission1], dict(sizelimit=1)),
            expected=dict(
                count=1,
                truncated=True,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
                messages=(
                    {
                        'message': (u'Search result has been truncated: '
                                    u'Configured size limit exceeded'),
                        'code': 13017,
                        'type': u'warning',
                        'name': u'SearchResultTruncated',
                        'data': {
                            'reason': u"Configured size limit exceeded"
                        }
                    },
                ),
            ),
        ),


        dict(
            desc='Search for %r with a limit of 2' % permission1,
            command=('permission_find', [permission1], dict(sizelimit=2)),
            expected=dict(
                count=2,
                truncated=False,
                summary=u'2 permissions matched',
                result=[
                    {
                        'dn': permission1_dn,
                        'cn': [permission1],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                    {
                        'dn': permission2_dn,
                        'cn': [permission2],
                        'objectclass': objectclasses.permission,
                        'type': [u'user'],
                        'ipapermright': [u'write'],
                        'attrs': [u'cn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                        'ipapermlocation': [users_dn],
                    },
                ],
            ),
        ),


        # This tests setting truncated to True in the post_callback of
        # permission_find(). The return order in LDAP is not guaranteed
        # so do not check the actual entry.
        dict(
            desc='Search for permissions by attr with a limit of 1 (truncated)',
            command=('permission_find', [u'Modify'],
                     dict(attrs=u'ipaenabledflag', sizelimit=1)),
            expected=dict(
                count=1,
                truncated=True,
                summary=u'1 permission matched',
                result=[lambda res:
                    DN(res['dn']).endswith(DN(api.env.container_permission,
                                              api.env.basedn)) and
                    'ipapermission' in res['objectclass']],
                messages=(
                    {
                        'message': (u'Search result has been truncated: '
                                    u'Configured size limit exceeded'),
                        'code': 13017,
                        'type': u'warning',
                        'name': u'SearchResultTruncated',
                        'data': {
                            'reason': u"Configured size limit exceeded"
                        }
                    },
                ),
            ),
        ),

        dict(
            desc='Update %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermright=u'read',
                    memberof=u'ipausers',
                    setattr=u'owner=cn=other-test',
                    addattr=u'owner=cn=other-test2',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    member_privilege=[privilege1],
                    type=[u'user'],
                    ipapermright=[u'read'],
                    memberof=[u'ipausers'],
                    owner=[u'cn=other-test', u'cn=other-test2'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&' +
                '(memberOf=%s)' % DN('cn=ipausers', groups_dn) +
                '(objectclass=posixaccount))")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (read) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Retrieve %r to verify update' % permission1,
            command=('permission_show', [permission1], {}),
            expected=dict(
                value=permission1,
                summary=None,
                result={
                    'dn': permission1_dn,
                    'cn': [permission1],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': [u'user'],
                    'ipapermright': [u'read'],
                    'memberof': [u'ipausers'],
                    'attrs': [u'sn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                },
            ),
        ),

        dict(
            desc='Try to rename %r to existing permission %r' % (permission1,
                                                                 permission2),
            command=(
                'permission_mod', [permission1], dict(rename=permission2,
                                                      ipapermright=u'all',)
            ),
            expected=errors.DuplicateEntry(),
        ),

        dict(
            desc='Try to rename %r to empty name' % (permission1),
            command=(
                'permission_mod', [permission1], dict(rename=u'',
                                                      ipapermright=u'all',)
            ),
            expected=errors.ValidationError(name='rename',
                                    error=u'New name can not be empty'),
        ),

        dict(
            desc='Check integrity of original permission %r' % permission1,
            command=('permission_show', [permission1], {}),
            expected=dict(
                value=permission1,
                summary=None,
                result={
                    'dn': permission1_dn,
                    'cn': [permission1],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': [u'user'],
                    'ipapermright': [u'read'],
                    'memberof': [u'ipausers'],
                    'attrs': [u'sn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                },
            ),
        ),


        dict(
            desc='Rename %r to permission %r' % (permission1,
                                                 permission1_renamed),
            command=(
                'permission_mod', [permission1], dict(rename=permission1_renamed,
                                                      ipapermright= u'all',)
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result={
                    'dn': permission1_renamed_dn,
                    'cn': [permission1_renamed],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': [u'user'],
                    'ipapermright': [u'all'],
                    'memberof': [u'ipausers'],
                    'attrs': [u'sn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                },
            ),
        ),

        verify_permission_aci_missing(permission1, users_dn),

        verify_permission_aci(
            permission1_renamed, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&' +
                '(memberOf=%s)' % DN('cn=ipausers', groups_dn) +
                '(objectclass=posixaccount))")' +
            '(version 3.0;acl "permission:%s";' % permission1_renamed +
            'allow (all) groupdn = "ldap:///%s";)' % permission1_renamed_dn,
        ),


        dict(
            desc='Rename %r to permission %r' % (permission1_renamed,
                                                 permission1_renamed_ucase),
            command=(
                'permission_mod', [permission1_renamed], dict(rename=permission1_renamed_ucase,
                                                      ipapermright= u'write',)
            ),
            expected=dict(
                value=permission1_renamed,
                summary=u'Modified permission "%s"' % permission1_renamed,
                result={
                    'dn': permission1_renamed_ucase_dn,
                    'cn': [permission1_renamed_ucase],
                    'objectclass': objectclasses.permission,
                    'member_privilege': [privilege1],
                    'type': [u'user'],
                    'ipapermright': [u'write'],
                    'memberof': [u'ipausers'],
                    'attrs': [u'sn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                },
            ),
        ),

        verify_permission_aci_missing(permission1_renamed, users_dn),

        verify_permission_aci(
            permission1_renamed_ucase, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&' +
                '(memberOf=%s)' % DN('cn=ipausers', groups_dn) +
                '(objectclass=posixaccount))")' +
            '(version 3.0;acl "permission:%s";' % permission1_renamed_ucase +
            'allow (write) groupdn = "ldap:///%s";)' %
                permission1_renamed_ucase_dn,
        ),

        dict(
            desc='Change %r to a subtree type' % permission1_renamed_ucase,
            command=(
                'permission_mod', [permission1_renamed_ucase],
                dict(ipapermlocation=users_dn, type=None)
            ),
            expected=dict(
                value=permission1_renamed_ucase,
                summary=u'Modified permission "%s"' % permission1_renamed_ucase,
                result=dict(
                    dn=permission1_renamed_ucase_dn,
                    cn=[permission1_renamed_ucase],
                    objectclass=objectclasses.permission,
                    member_privilege=[privilege1],
                    ipapermlocation=[users_dn],
                    ipapermright=[u'write'],
                    memberof=[u'ipausers'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1_renamed_ucase, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(memberOf=%s)")' % DN('cn=ipausers', groups_dn) +
            '(version 3.0;acl "permission:%s";' % permission1_renamed_ucase +
            'allow (write) groupdn = "ldap:///%s";)' %
                permission1_renamed_ucase_dn,
        ),

        dict(
            desc='Reset --subtree of %r' % permission2,
            command=(
                'permission_mod', [permission2],
                dict(ipapermlocation=api.env.basedn)
            ),
            expected=dict(
                value=permission2,
                summary=u'Modified permission "%s"' % permission2,
                result={
                    'dn': permission2_dn,
                    'cn': [permission2],
                    'objectclass': objectclasses.permission,
                    'ipapermright': [u'write'],
                    'attrs': [u'cn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'extratargetfilter': [u'(objectclass=posixaccount)'],
                    'ipapermlocation': [api.env.basedn],
                },
            ),
        ),

        verify_permission_aci(
            permission2, api.env.basedn,
            '(targetattr = "cn")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission2 +
            'allow (write) groupdn = "ldap:///%s";)' % permission2_dn,
        ),

        dict(
            desc='Change subtree of %r to admin' % permission1_renamed_ucase,
            command=(
                'permission_mod', [permission1_renamed_ucase],
                dict(ipapermlocation=admin_dn)
            ),
            expected=dict(
                value=permission1_renamed_ucase,
                summary=u'Modified permission "%s"' % permission1_renamed_ucase,
                result=dict(
                    dn=permission1_renamed_ucase_dn,
                    cn=[permission1_renamed_ucase],
                    objectclass=objectclasses.permission,
                    member_privilege=[privilege1],
                    ipapermlocation=[admin_dn],
                    ipapermright=[u'write'],
                    memberof=[u'ipausers'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1_renamed_ucase, admin_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(memberOf=%s)")' % DN('cn=ipausers', groups_dn) +
            '(version 3.0;acl "permission:%s";' % permission1_renamed_ucase +
            'allow (write) groupdn = "ldap:///%s";)' %
                permission1_renamed_ucase_dn,
        ),

        dict(
            desc=('Search for %r using --subtree with membes' %
                  permission1_renamed_ucase),
            command=('permission_find', [],
                     {'ipapermlocation': u'ldap:///%s' % admin_dn,
                     'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn':permission1_renamed_ucase_dn,
                        'cn':[permission1_renamed_ucase],
                        'objectclass': objectclasses.permission,
                        'member_privilege':[privilege1],
                        'ipapermlocation': [admin_dn],
                        'ipapermright':[u'write'],
                        'memberof':[u'ipausers'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                    },
                ],
            ),
        ),


        dict(
            desc='Search for %r using --subtree' % permission1_renamed_ucase,
            command=('permission_find', [],
                     {'ipapermlocation': u'ldap:///%s' % admin_dn}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn':permission1_renamed_ucase_dn,
                        'cn':[permission1_renamed_ucase],
                        'objectclass': objectclasses.permission,
                        'ipapermlocation': [admin_dn],
                        'ipapermright':[u'write'],
                        'memberof':[u'ipausers'],
                        'attrs': [u'sn'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermissiontype': [u'SYSTEM', u'V2'],
                    },
                ],
            ),
        ),


        dict(
            desc='Search using nonexistent --subtree',
            command=('permission_find', [], {'ipapermlocation': u'foo'}),
            expected=errors.ConversionError(
                name='subtree', error='malformed RDN string = "foo"'),
        ),


        dict(
            desc='Search using --targetgroup with members',
            command=('permission_find', [], {
                'targetgroup': u'ipausers', 'no_members': False}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': DN(('cn', 'System: Add User to default group'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'System: Add User to default group'],
                        'objectclass': objectclasses.permission,
                        'member_privilege': [u'User Administrators'],
                        'attrs': [u'member'],
                        'targetgroup': [u'ipausers'],
                        'memberindirect_role': [u'User Administrator'],
                        'ipapermright': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermtarget': [DN(
                            'cn=ipausers', api.env.container_group,
                            api.env.basedn)],
                        'ipapermlocation': [groups_dn],
                        'ipapermdefaultattr': [u'member'],
                        'ipapermissiontype': [u'V2', u'MANAGED', u'SYSTEM'],
                    }
                ],
            ),
        ),


        dict(
            desc='Search using --targetgroup',
            command=('permission_find', [], {'targetgroup': u'ipausers'}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    {
                        'dn': DN(('cn', 'System: Add User to default group'),
                                 api.env.container_permission, api.env.basedn),
                        'cn': [u'System: Add User to default group'],
                        'objectclass': objectclasses.permission,
                        'attrs': [u'member'],
                        'targetgroup': [u'ipausers'],
                        'ipapermright': [u'write'],
                        'ipapermbindruletype': [u'permission'],
                        'ipapermtarget': [DN(
                            'cn=ipausers', api.env.container_group,
                            api.env.basedn)],
                        'ipapermlocation': [groups_dn],
                        'ipapermdefaultattr': [u'member'],
                        'ipapermissiontype': [u'V2', u'MANAGED', u'SYSTEM'],
                    }
                ],
            ),
        ),

        dict(
            desc='Delete %r' % permission1_renamed_ucase,
            command=('permission_del', [permission1_renamed_ucase], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[permission1_renamed_ucase],
                summary=u'Deleted permission "%s"' % permission1_renamed_ucase,
            )
        ),

        verify_permission_aci_missing(permission1_renamed_ucase, users_dn),

        dict(
            desc='Try to delete non-existent %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),


        dict(
            desc='Try to retrieve non-existent %r' % permission1,
            command=('permission_show', [permission1], {}),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),


        dict(
            desc='Try to update non-existent %r' % permission1,
            command=('permission_mod', [permission1], dict(rename=u'Foo')),
            expected=errors.NotFound(
                reason=u'%s: permission not found' % permission1),
        ),


        dict(
            desc='Delete %r' % permission2,
            command=('permission_del', [permission2], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[permission2],
                summary=u'Deleted permission "%s"' % permission2,
            )
        ),

        verify_permission_aci_missing(permission2, users_dn),

        dict(
            desc='Search for %r' % permission1,
            command=('permission_find', [permission1], {}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
            ),
        ),


        dict(
            desc='Delete %r' % privilege1,
            command=('privilege_del', [privilege1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[privilege1],
                summary=u'Deleted privilege "%s"' % privilege1,
            )
        ),

        dict(
            desc='Try to create permission %r with non-existing memberof' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    memberof=u'nonexisting',
                    ipapermright=u'write',
                    attrs=[u'cn'],
                )
            ),
            expected=errors.NotFound(reason=u'nonexisting: group not found'),
        ),

        dict(
            desc='Create memberof permission %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    memberof=u'editors',
                    ipapermright=u'write',
                    type=u'user',
                    attrs=[u'sn'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    memberof=[u'editors'],
                    ipapermright=[u'write'],
                    type=[u'user'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&(memberOf=%s)' % DN('cn=editors', groups_dn) +
                '(objectclass=posixaccount))")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Try to update non-existent memberof of %r' % permission1,
            command=('permission_mod', [permission1], dict(
                memberof=u'nonexisting')),
            expected=errors.NotFound(reason=u'nonexisting: group not found'),
        ),

        dict(
            desc='Update memberof permission %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    memberof=u'admins',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    memberof=[u'admins'],
                    ipapermright=[u'write'],
                    type=[u'user'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&' +
                '(memberOf=%s)' % DN('cn=admins', groups_dn) +
                '(objectclass=posixaccount))")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Unset memberof of permission %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    memberof=None,
                )
            ),
            expected=dict(
                summary=u'Modified permission "%s"' % permission1,
                value=permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    type=[u'user'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Delete %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[permission1],
                summary=u'Deleted permission "%s"' % permission1,
            )
        ),

        verify_permission_aci_missing(permission1, users_dn),

        dict(
            desc='Create targetgroup permission %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    targetgroup=u'editors',
                    ipapermright=u'write',
                    attrs=[u'sn'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    targetgroup=[u'editors'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermtarget=[DN(('cn', 'editors'), groups_dn)],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(target = "ldap:///%s")' % DN('cn=editors', groups_dn) +
            '(targetattr = "sn")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Create %r' % permission3,
            command=(
                'permission_add', [permission3], dict(
                    type=u'user',
                    ipapermright=u'write',
                    attrs=[u'cn']
                )
            ),
            expected=dict(
                value=permission3,
                summary=u'Added permission "%s"' % permission3,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=(u'cn',),
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission3, users_dn,
            '(targetattr = "cn")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission3 +
            'allow (write) groupdn = "ldap:///%s";)' % permission3_dn,
        ),

        dict(
            desc='Retrieve %r with --all --rights' % permission3,
            command=('permission_show', [permission3], {'all' : True, 'rights' : True}),
            expected=dict(
                value=permission3,
                summary=None,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    attrs=[u'cn'],
                    ipapermincludedattr=[u'cn'],
                    ipapermright=[u'write'],
                    attributelevelrights=permission3_attributelevelrights,
                    ipapermbindruletype=[u'permission'],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        dict(
            desc='Modify %r with --all --rights' % permission3,
            command=('permission_mod', [permission3], {
                'all': True, 'rights': True,
                'attrs': [u'cn', u'uid']}),
            expected=dict(
                value=permission3,
                summary=u'Modified permission "%s"' % permission3,
                result=dict(
                    dn=permission3_dn,
                    cn=[permission3],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    attrs=[u'cn', u'uid'],
                    ipapermincludedattr=[u'cn', u'uid'],
                    ipapermright=[u'write'],
                    attributelevelrights=permission3_attributelevelrights,
                    ipapermbindruletype=[u'permission'],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission3, users_dn,
            '(targetattr = "cn || uid")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission3 +
            'allow (write) groupdn = "ldap:///%s";)' % permission3_dn,
        ),

        dict(
            desc='Try to modify %r with naked targetfilter' % permission1,
            command=('permission_mod', [permission1],
                     {'ipapermtargetfilter': u"cn=admin"}),
            expected=errors.ValidationError(
                name='rawfilter',
                error='must be enclosed in parentheses'),
        ),

        dict(
            desc='Try to modify %r with invalid targetfilter' % permission1,
            command=('permission_mod', [permission1],
                     {'ipapermtargetfilter': u"(ceci n'est pas un filtre)"}),
            expected=errors.ValidationError(
                name='ipapermtargetfilter',
                error='Bad search filter'),
        ),

        dict(
            desc='Try setting nonexisting location on %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermlocation=nonexistent_dn,
                )
            ),
            expected=errors.ValidationError(
                name='ipapermlocation',
                error='Entry %s does not exist' % nonexistent_dn)
        ),

        dict(
            desc='Search for nonexisting permission with ":" in the name',
            command=(
                'permission_find', ['doesnotexist:' + permission1], {}
            ),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
            ),
        ),
    ]


class test_permission_rollback(Declarative):
    """Test rolling back changes after failed update"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    _verifications = [
        dict(
            desc='Retrieve %r' % permission1,
            command=('permission_show', [permission1], {}),
            expected=dict(
                value=permission1,
                summary=None,
                result={
                    'dn': permission1_dn,
                    'cn': [permission1],
                    'objectclass': objectclasses.permission,
                    'ipapermright': [u'write'],
                    'attrs': [u'sn'],
                    'ipapermbindruletype': [u'permission'],
                    'ipapermissiontype': [u'SYSTEM', u'V2'],
                    'ipapermlocation': [users_dn],
                    'ipapermtarget': [DN(('uid', 'admin'), users_dn)],
                },
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(target = "ldap:///%s")' % DN(('uid', 'admin'), users_dn) +
            '(targetattr = "sn")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        verify_permission_aci_missing(permission1, etc_dn)
    ]

    tests = [
        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    ipapermlocation=users_dn,
                    ipapermtarget=DN('uid=admin', users_dn),
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtarget=[DN(('uid', 'admin'), users_dn)],
                ),
            ),
        ),

    ] + _verifications + [

        dict(
            desc='Move %r to non-existent DN' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermlocation=DN('foo=bar'),
                )
            ),
            expected=errors.ValidationError(
                name='ipapermlocation',
                error='Entry foo=bar does not exist'),
        ),

    ] + _verifications + [

        dict(
            desc='Move %r to another DN' % permission1,
            command=('permission_mod', [permission1],
                     dict(ipapermlocation=etc_dn)
            ),
            expected=errors.InvalidSyntax(
                attr=r'ACL Invalid Target Error(-8): '
                    r'Target is beyond the scope of the ACL'
                    r'(SCOPE:%(sdn)s) '
                    r'(targetattr = \22sn\22)'
                    r'(target = \22ldap:///%(tdn)s\22)'
                    r'(version 3.0;acl \22permission:testperm\22;'
                    r'allow (write) groupdn = \22ldap:///%(pdn)s\22;)' % dict(
                        sdn=etc_dn,
                        tdn=DN('uid=admin', users_dn),
                        pdn=permission1_dn)),
        ),

    ] + _verifications + [

        dict(
            desc='Try adding an invalid attribute on %r with --all --rights' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    attrs=[u'cn', u'bogusattributexyz'],
                    rights=True,
                    all=True,
                )
            ),
            expected=errors.InvalidSyntax(
                attr=r'targetattr "bogusattributexyz" does not exist '
                    r'in schema. Please add attributeTypes '
                    r'"bogusattributexyz" to schema if necessary. ACL Syntax '
                    r'Error(-5):(targetattr = \22bogusattributexyz || cn\22)'
                    r'(target = \22ldap:///%(tdn)s\22)'
                    r'(version 3.0;acl \22permission:%(name)s\22;'
                    r'allow (write) groupdn = \22ldap:///%(dn)s\22;)' % dict(
                        tdn=DN('uid=admin', users_dn),
                        name=permission1,
                        dn=permission1_dn),
            ),
        ),

    ] + _verifications


@pytest.mark.tier1
class test_permission_sync_attributes(Declarative):
    """Test the effects of setting permission attributes"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    tests = [
        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    ipapermlocation=users_dn,
                    ipapermright=u'write',
                    attrs=u'sn',
                    ipapermtargetfilter=[
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=posixaccount)'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&(memberOf=%s)' % DN('cn=admins', groups_dn) +
                '(objectclass=posixaccount))")'
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Unset location on %r, verify type is gone' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermlocation=None,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    extratargetfilter=[
                        u'(objectclass=posixaccount)'],
                    memberof=[u'admins'],
                    ipapermlocation=[api.env.basedn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&(memberOf=%s)' % DN('cn=admins', groups_dn) +
                '(objectclass=posixaccount))")'
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        verify_permission_aci_missing(permission1, users_dn),

        dict(
            desc='Reset location on %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermlocation=users_dn,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&(memberOf=%s)' % DN('cn=admins', groups_dn) +
                '(objectclass=posixaccount))")'
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        verify_permission_aci_missing(permission1, api.env.basedn),

        dict(
            desc='Unset objectclass filter on %r, verify type is gone' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermtargetfilter=u'(memberOf=%s)' % DN(('cn', 'admins'),
                                                              groups_dn),
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(memberOf=%s)")' % DN('cn=admins', groups_dn) +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Unset targetfilter on %r, verify memberof is gone' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermtargetfilter=None,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Set type of %r to group' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    type=u'group',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'group'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[groups_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, groups_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "%s")' % group_filter +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Set target on %r, verify targetgroup is set' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermtarget=DN('cn=editors', groups_dn),
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'group'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermtarget=[DN('cn=editors', groups_dn)],
                    ipapermlocation=[groups_dn],
                    targetgroup=[u'editors'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, groups_dn,
            '(target = "ldap:///%s")' % DN(('cn', 'editors'), groups_dn) +
            '(targetattr = "sn")' +
            '(targetfilter = "%s")' % group_filter +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Set extra targetfilter on %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    extratargetfilter=u'(cn=blabla)',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'group'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermtarget=[DN('cn=editors', groups_dn)],
                    ipapermlocation=[groups_dn],
                    targetgroup=[u'editors'],
                    extratargetfilter=[u'(cn=blabla)'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, groups_dn,
            '(target = "ldap:///%s")' % DN(('cn', 'editors'), groups_dn) +
            '(targetattr = "sn")' +
            '(targetfilter = "(&(cn=blabla)%s)")' % group_filter +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Retrieve %r with --all' % permission1,
            command=(
                'permission_show', [permission1], dict(all=True)
            ),
            expected=dict(
                value=permission1,
                summary=None,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'group'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermtarget=[DN('cn=editors', groups_dn)],
                    ipapermlocation=[groups_dn],
                    targetgroup=[u'editors'],
                    extratargetfilter=[u'(cn=blabla)'],
                    ipapermtargetfilter=[u'(cn=blabla)', group_filter],
                ),
            ),
        ),

        dict(
            desc='Set type of %r back to user' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    type=u'user', ipapermtarget=None,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    extratargetfilter=[u'(cn=blabla)'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&(cn=blabla)(objectclass=posixaccount))")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),
    ]


class test_permission_sync_nice(Declarative):
    """Test the effects of setting convenience options on permissions"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    tests = [
        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=u'write',
                    attrs=u'sn',
                    memberof=u'admins',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&(memberOf=%s)' % DN('cn=admins', groups_dn) +
                '(objectclass=posixaccount))")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Unset type on %r, verify target & filter are gone' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    type=None,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    memberof=[u'admins'],
                    ipapermlocation=[api.env.basedn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(targetattr = "sn")' +
            '(targetfilter = "(memberOf=%s)")' % DN('cn=admins', groups_dn) +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Unset memberof on %r, verify targetfilter is gone' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    memberof=None,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(targetattr = "sn")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Set type of %r to group' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    type=u'group',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'group'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[groups_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, groups_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "%s")' % group_filter +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Set targetgroup on %r, verify target is set' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    targetgroup=u'editors',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'group'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermtarget=[DN('cn=editors', groups_dn)],
                    ipapermlocation=[groups_dn],
                    targetgroup=[u'editors'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, groups_dn,
            '(target = "ldap:///%s")' % DN(('cn', 'editors'), groups_dn) +
            '(targetattr = "sn")' +
            '(targetfilter = "%s")' % group_filter +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),
    ]


@pytest.mark.tier1
class test_permission_targetfilter(Declarative):
    """Test the targetfilter options on permissions"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    _initial_aci = (
        '(targetattr = "sn")' +
        '(targetfilter = "(&' +
            '(cn=*)' +
            '(memberOf=%s)' % DN('cn=admins', groups_dn) +
            '(objectclass=posixaccount)' +
            '(sn=*)' +
        ')")' +
        '(version 3.0;acl "permission:%s";' % permission1 +
        'allow (write) groupdn = "ldap:///%s";)' % permission1_dn
    )

    tests = [
        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=u'write',
                    attrs=u'sn',
                    memberof=u'admins',
                    extratargetfilter=[u'(cn=*)', u'(sn=*)'],
                    all=True,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                    extratargetfilter=[u'(cn=*)', u'(sn=*)'],
                    ipapermtargetfilter=[
                        u'(cn=*)', u'(sn=*)',
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=posixaccount)'],
                ),
            ),
        ),

        verify_permission_aci(permission1, users_dn, _initial_aci),

        dict(
            desc='Retrieve %r' % permission1,
            command=(
                'permission_show', [permission1], dict()
            ),
            expected=dict(
                value=permission1,
                summary=None,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                    extratargetfilter=[u'(cn=*)', u'(sn=*)'],
                ),
            ),
        ),

        dict(
            desc='Retrieve %r with --all' % permission1,
            command=(
                'permission_show', [permission1], dict(all=True)
            ),
            expected=dict(
                value=permission1,
                summary=None,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                    extratargetfilter=[u'(cn=*)', u'(sn=*)'],
                    ipapermtargetfilter=[
                        u'(cn=*)', u'(sn=*)',
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=posixaccount)'],
                ),
            ),
        ),

        dict(
            desc='Retrieve %r with --raw' % permission1,
            command=(
                'permission_show', [permission1], dict(raw=True)
            ),
            expected=dict(
                value=permission1,
                summary=None,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    aci=[_initial_aci],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtargetfilter=[
                        u'(cn=*)', u'(sn=*)',
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=posixaccount)'],
                ),
            ),
        ),

        dict(
            desc='Retrieve %r with --all and --raw' % permission1,
            command=(
                'permission_show', [permission1], dict(all=True, raw=True)
            ),
            expected=dict(
                value=permission1,
                summary=None,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    aci=[_initial_aci],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    ipapermtargetfilter=[
                        u'(cn=*)', u'(sn=*)',
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=posixaccount)'],
                ),
            ),
        ),

        dict(
            desc='Modify extratargetfilter of %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    extratargetfilter=[u'(cn=*)', u'(l=*)'],
                    all=True,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                    extratargetfilter=[u'(cn=*)', u'(l=*)'],
                    ipapermtargetfilter=[
                        u'(cn=*)', u'(l=*)',
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=posixaccount)'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&' +
                '(cn=*)' +
                '(l=*)' +
                '(memberOf=%s)' % DN('cn=admins', groups_dn) +
                '(objectclass=posixaccount)' +
            ')")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn
        ),

        dict(
            desc='Remove raw targetfilter of %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    ipapermtargetfilter=None,
                    all=True,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn
        ),

        dict(
            desc='Set extra targetfilter on %r to restore' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    extratargetfilter=[
                        u'(cn=*)',
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=posixaccount)'],
                    all=True,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                    extratargetfilter=[u'(cn=*)'],
                    ipapermtargetfilter=[
                        u'(cn=*)',
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=posixaccount)'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&' +
                '(cn=*)' +
                '(memberOf=%s)' % DN('cn=admins', groups_dn) +
                '(objectclass=posixaccount)' +
            ')")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn
        ),

    ] + [
        dict(
            desc='Search for %r using %s %s' % (permission1, value_name, option_name),
            command=(
                'permission_find', [permission1],
                {option_name: value, 'all': True}
            ),
            expected=dict(
                summary=u'1 permission matched' if should_find else u'0 permissions matched',
                truncated=False,
                count=1 if should_find else 0,
                result=[dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                    extratargetfilter=[u'(cn=*)'],
                    ipapermtargetfilter=[
                        u'(cn=*)',
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=posixaccount)'],
                )] if should_find else [],
            ),
        )
        for option_name in (
            'extratargetfilter',
            'ipapermtargetfilter',
        )
        for value_name, value, should_find in (
            ('"extra"', u'(cn=*)', True),
            ('"non-extra"', u'(objectclass=posixaccount)', True),
            ('non-existing', u'(sn=insert a very improbable last name)', False),
        )
    ] + [

        dict(
            desc='Set extra objectclass filter on %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    extratargetfilter=[u'(cn=*)', u'(objectclass=top)'],
                    all=True,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    memberof=[u'admins'],
                    extratargetfilter=[u'(cn=*)', u'(objectclass=top)'],
                    ipapermtargetfilter=[
                        u'(cn=*)',
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=posixaccount)',
                        u'(objectclass=top)'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&' +
                '(cn=*)' +
                '(memberOf=%s)' % DN('cn=admins', groups_dn) +
                '(objectclass=posixaccount)' +
                '(objectclass=top)' +
            ')")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn
        ),

        dict(
            desc='Unset type on %r to verify extra objectclass filter stays' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    type=None,
                    all=True,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                    memberof=[u'admins'],
                    extratargetfilter=[u'(cn=*)', u'(objectclass=top)'],
                    ipapermtargetfilter=[
                        u'(cn=*)',
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(objectclass=top)'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&' +
                '(cn=*)' +
                '(memberOf=%s)' % DN('cn=admins', groups_dn) +
                '(objectclass=top)' +
            ')")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn
        ),

        dict(
            desc='Set wildcard memberof filter on %r' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    extratargetfilter=u'(memberof=*)',
                    all=True,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                    memberof=[u'admins'],
                    extratargetfilter=[u'(memberof=*)'],
                    ipapermtargetfilter=[
                        u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn),
                        u'(memberof=*)'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(targetattr = "sn")' +
            '(targetfilter = "(&' +
                '(memberOf=%s)' % DN('cn=admins', groups_dn) +
                '(memberof=*)' +
            ')")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn
        ),

        dict(
            desc='Remove --memberof on %r to verify wildcard is still there' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    memberof=[],
                    all=True,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    attrs=[u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                    extratargetfilter=[u'(memberof=*)'],
                    ipapermtargetfilter=[u'(memberof=*)'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(targetattr = "sn")' +
            '(targetfilter = "(memberof=*)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn
        ),

    ]


def _make_permission_flag_tests(flags, expected_message):
    return [

        dict(
            desc='Create %r with flags %s' % (permission1, flags),
            command=(
                'permission_add_noaci', [permission1], dict(
                    ipapermissiontype=flags,
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.system_permission,
                    ipapermissiontype=flags,
                ),
            ),
        ),

        dict(
            desc='Try to modify %r' % permission1,
            command=('permission_mod', [permission1], {'type': u'user'}),
            expected=errors.ACIError(info=expected_message),
        ),

        dict(
            desc='Try to delete %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=errors.ACIError(info=expected_message),
        ),

        dict(
            desc='Add %r to %r' % (permission1, privilege1),
            command=('privilege_add_permission', [privilege1],
                     {'permission': permission1}),
            expected=dict(
                completed=1,
                failed=dict(
                    member=dict(
                        permission=[],
                    ),
                ),
                result={
                    'dn': privilege1_dn,
                    'cn': [privilege1],
                    'description': [u'privilege desc. 1'],
                    'memberof_permission': [permission1],
                }
            ),
        ),

        dict(
            desc='Delete %r with --force' % permission1,
            command=('permission_del', [permission1], {'force': True}),
            expected=dict(
                result=dict(failed=[]),
                value=[permission1],
                summary=u'Deleted permission "%s"' % permission1,
            ),
        ),
    ]


@pytest.mark.tier1
class test_permission_flags(Declarative):
    """Test that permission flags are handled correctly"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
        ('privilege_del', [privilege1], {}),
    ]

    tests = [
        dict(
            desc='Create %r' % privilege1,
            command=('privilege_add', [privilege1],
                dict(description=u'privilege desc. 1')
            ),
            expected=dict(
                value=privilege1,
                summary=u'Added privilege "%s"' % privilege1,
                result=dict(
                    dn=privilege1_dn,
                    cn=[privilege1],
                    description=[u'privilege desc. 1'],
                    objectclass=objectclasses.privilege,
                ),
            ),
        ),

    ] + (
        _make_permission_flag_tests(
            [u'SYSTEM'],
            'A SYSTEM permission may not be modified or removed') +
        _make_permission_flag_tests(
            [u'??'],
            'Permission with unknown flag ?? may not be modified or removed') +
        _make_permission_flag_tests(
            [u'SYSTEM', u'??'],
            'Permission with unknown flag ?? may not be modified or removed'))


def check_legacy_results(results):
    """Check that the expected number of legacy permissions are in $SUFFIX"""
    legacy_permissions = [p for p in results
                          if not p.get('ipapermissiontype')]
    print(legacy_permissions)
    assert len(legacy_permissions) == 10, len(legacy_permissions)
    return True


@pytest.mark.tier1
class test_permission_legacy(Declarative):
    """Tests for non-upgraded permissions"""

    tests = [
        dict(
            desc='Check that some legacy permission is found in $SUFFIX',
            command=('permission_find', [],
                     {'ipapermlocation': api.env.basedn}),
            expected=dict(
                count=lambda count: count,
                truncated=False,
                summary=lambda s: True,
                result=check_legacy_results,
            ),
        ),
    ]


@pytest.mark.tier1
class test_permission_bindtype(Declarative):
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
        ('permission_del', [permission1_renamed], {'force': True}),
        ('privilege_del', [privilege1], {}),
    ]

    tests = [
        dict(
            desc='Create anonymous %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=u'write',
                    ipapermbindruletype=u'anonymous',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'anonymous'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) userdn = "ldap:///anyone";)',
        ),

        dict(
            desc='Create %r' % privilege1,
            command=('privilege_add', [privilege1],
                dict(description=u'privilege desc. 1')
            ),
            expected=dict(
                value=privilege1,
                summary=u'Added privilege "%s"' % privilege1,
                result=dict(
                    dn=privilege1_dn,
                    cn=[privilege1],
                    description=[u'privilege desc. 1'],
                    objectclass=objectclasses.privilege,
                ),
            ),
        ),

        dict(
            desc='Try to add %r to %r' % (permission1, privilege1),
            command=(
                'privilege_add_permission', [privilege1], dict(
                    permission=[permission1],
                )
            ),
            expected=errors.ValidationError(
                name='permission',
                error=u'cannot add permission "%s" with bindtype "%s" to a '
                       'privilege' % (permission1, 'anonymous')),
        ),

        dict(
            desc='Change binddn of %r to all' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    type=u'user',
                    ipapermbindruletype=u'all',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) userdn = "ldap:///all";)',
        ),

        dict(
            desc='Try to add %r to %r' % (permission1, privilege1),
            command=(
                'privilege_add_permission', [privilege1], dict(
                    permission=[permission1],
                )
            ),
            expected=errors.ValidationError(
                name='permission',
                error=u'cannot add permission "%s" with bindtype "%s" to a '
                       'privilege' % (permission1, 'all')),
        ),

        dict(
            desc='Search for %r using --bindtype' % permission1,
            command=('permission_find', [permission1],
                     {'ipapermbindruletype': u'all'}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[
                    dict(
                        dn=permission1_dn,
                        cn=[permission1],
                        type=[u'user'],
                        ipapermright=[u'write'],
                        ipapermbindruletype=[u'all'],
                        objectclass=objectclasses.permission,
                        ipapermissiontype=[u'SYSTEM', u'V2'],
                        ipapermlocation=[users_dn],
                    ),
                ],
            ),
        ),

        dict(
            desc='Search for %r using bad --bindtype' % permission1,
            command=('permission_find', [permission1],
                     {'ipapermbindruletype': u'anonymous'}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
            ),
        ),

        dict(
            desc='Add zero permissions to %r' % (privilege1),
            command=('privilege_add_permission', [privilege1], {}),
            expected=dict(
                completed=0,
                failed=dict(member=dict(permission=[])),
                result=dict(
                    dn=privilege1_dn,
                    cn=[privilege1],
                    description=[u'privilege desc. 1'],
                ),
            ),
        ),

        dict(
            desc='Rename %r to permission %r' % (permission1,
                                                 permission1_renamed),
            command=(
                'permission_mod', [permission1], dict(rename=permission1_renamed)
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_renamed_dn,
                    cn=[permission1_renamed],
                    type=[u'user'],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1_renamed, users_dn,
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1_renamed +
            'allow (write) userdn = "ldap:///all";)',
        ),

        dict(
            desc='Reset binddn of %r to permission' % permission1_renamed,
            command=(
                'permission_mod', [permission1_renamed], dict(
                    type=u'user',
                    ipapermbindruletype=u'permission',
                )
            ),
            expected=dict(
                value=permission1_renamed,
                summary=u'Modified permission "%s"' % permission1_renamed,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_renamed_dn,
                    cn=[permission1_renamed],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1_renamed, users_dn,
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1_renamed +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_renamed_dn,
        ),

        dict(
            desc='Rename %r back to %r' % (permission1_renamed, permission1),
            command=(
                'permission_mod', [permission1_renamed],
                dict(rename=permission1)
            ),
            expected=dict(
                value=permission1_renamed,
                summary=u'Modified permission "%s"' % permission1_renamed,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    type=[u'user'],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Add %r to %r' % (permission1, privilege1),
            command=(
                'privilege_add_permission', [privilege1], dict(
                    permission=[permission1],
                )
            ),
            expected=dict(
                completed=1,
                failed=dict(member=dict(permission=[])),
                result=dict(
                    dn=privilege1_dn,
                    cn=[privilege1],
                    description=[u'privilege desc. 1'],
                    memberof_permission=[permission1],
                )
            ),
        ),

        dict(
            desc='Try to change binddn of %r to anonymous' % permission1,
            command=(
                'permission_mod', [permission1], dict(
                    type=u'user',
                    ipapermbindruletype=u'anonymous',
                )
            ),
            expected=errors.ValidationError(
                name='ipapermbindruletype',
                error=u'cannot set bindtype for a permission that is '
                    'assigned to a privilege')
        ),
    ]


@pytest.mark.tier1
class test_managed_permissions(Declarative):
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
        ('permission_del', [permission2], {'force': True}),
    ]

    @pytest.fixture(autouse=True, scope="class")
    def managed_perm_setup(self, declarative_setup):
        if not have_ldap2:
            pytest.skip('server plugin not available')

    def add_managed_permission(self):
        """Add a managed permission and the corresponding ACI"""
        ldap = ldap2(api)
        ldap.connect()

        api.Command.permission_add(
            permission1, type=u'user', ipapermright=u'write', attrs=[u'cn'])

        # TODO: This hack relies on the permission internals.
        # Change as necessary.

        # Add permission DN
        entry = ldap.get_entry(permission1_dn)
        entry['ipapermdefaultattr'] = ['l', 'o', 'cn']
        ldap.update_entry(entry)

        # Update the ACI via the API
        api.Command.permission_mod(permission1, attrs=[u'l', u'o', u'cn'])

        # Set the permission type to MANAGED
        entry = ldap.get_entry(permission1_dn)
        entry['ipapermissiontype'].append('MANAGED')
        ldap.update_entry(entry)

    tests = [
        add_managed_permission,

        dict(
            desc='Show pre-created %r' % permission1,
            command=('permission_show', [permission1], {'all': True}),
            expected=dict(
                value=permission1,
                summary=None,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermlocation=[users_dn],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o', u'cn'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "cn || l || o")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

    ] + [
        # Verify that most permission attributes can't be changed
        dict(
            desc='Try to modify %s in %r' % (attr_name, permission1),
            command=('permission_mod', [permission1],
                     {attr_name: value}),
            expected=errors.ValidationError(
                name=err_attr or attr_name,
                error='not modifiable on managed permissions'),
        )
        for attr_name, err_attr, value in (
            ('ipapermlocation', None, users_dn),
            ('ipapermright', None, u'compare'),
            ('ipapermtarget', None, users_dn),
            ('ipapermtargetfilter', None, u'(ou=engineering)'),

            ('memberof', 'ipapermtargetfilter', u'admins'),
            ('targetgroup', 'ipapermtarget', u'admins'),
            ('type', 'ipapermlocation', u'group'),
            ('extratargetfilter', 'extratargetfilter', u'(cn=*)'),
        )
    ] + [

        dict(
            desc='Try to rename %r' % permission1,
            command=('permission_mod', [permission1],
                     {'rename': permission2}),
            expected=errors.ValidationError(
                name='rename',
                error='cannot rename managed permissions'),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "cn || l || o")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Modify included and excluded attrs in %r' % permission1,
            command=('permission_mod', [permission1],
                     {'ipapermincludedattr': [u'dc'],
                      'ipapermexcludedattr': [u'cn'],
                      'all': True}),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "testperm"',
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermlocation=[users_dn],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o', u'dc'],
                    ipapermincludedattr=[u'dc'],
                    ipapermexcludedattr=[u'cn'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "dc || l || o")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Modify included attrs in %r' % permission1,
            command=('permission_mod', [permission1],
                     {'ipapermincludedattr': [u'cn', u'sn'],
                      'all': True}),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "testperm"',
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermlocation=[users_dn],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o', u'sn'],
                    ipapermincludedattr=[u'cn', u'sn'],
                    ipapermexcludedattr=[u'cn'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "l || o || sn")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Add ineffective included attr to %r' % permission1,
            command=('permission_mod', [permission1],
                     {'ipapermincludedattr': [u'cn', u'sn', u'o'],
                      'all': True}),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "testperm"',
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermlocation=[users_dn],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o', u'sn'],
                    ipapermincludedattr=[u'cn', u'sn', u'o'],
                    ipapermexcludedattr=[u'cn'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "l || o || sn")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Modify excluded attrs in %r' % permission1,
            command=('permission_mod', [permission1],
                     {'ipapermexcludedattr': [u'cn', u'sn'],
                      'all': True}),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "testperm"',
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermlocation=[users_dn],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o'],
                    ipapermincludedattr=[u'cn', u'sn', u'o'],
                    ipapermexcludedattr=[u'cn', u'sn'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "l || o")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Modify bind rule in %r' % permission1,
            command=('permission_mod', [permission1],
                     {'ipapermbindruletype': u'all'}),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "testperm"',
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermlocation=[users_dn],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o'],
                    ipapermincludedattr=[u'cn', u'sn', u'o'],
                    ipapermexcludedattr=[u'cn', u'sn'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "l || o")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) userdn = "ldap:///all";)',
        ),

        dict(
            desc='Show %r with no options' % permission1,
            command=('permission_show', [permission1], {}),
            expected=dict(
                value=permission1,
                summary=None,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermlocation=[users_dn],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o'],
                    ipapermincludedattr=[u'cn', u'sn', u'o'],
                    ipapermexcludedattr=[u'cn', u'sn'],
                ),
            ),
        ),

        dict(
            desc='Show %r with --all' % permission1,
            command=('permission_show', [permission1], {'all': True}),
            expected=dict(
                value=permission1,
                summary=None,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermlocation=[users_dn],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o'],
                    ipapermincludedattr=[u'cn', u'sn', u'o'],
                    ipapermexcludedattr=[u'cn', u'sn'],
                ),
            ),
        ),

        dict(
            desc='Show %r with --raw' % permission1,
            command=('permission_show', [permission1], {'raw': True}),
            expected=dict(
                value=permission1,
                summary=None,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    aci=['(targetattr = "l || o")'
                         '(targetfilter = "(objectclass=posixaccount)")'
                         '(version 3.0;acl "permission:%(name)s";'
                         'allow (write) userdn = "ldap:///all";)' %
                         {'name': permission1}],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermlocation=[users_dn],
                    ipapermtargetfilter=[u'(objectclass=posixaccount)'],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    ipapermincludedattr=[u'cn', u'sn', u'o'],
                    ipapermexcludedattr=[u'cn', u'sn'],
                ),
            ),
        ),

        dict(
            desc='Modify attrs of %r to normalize' % permission1,
            command=('permission_mod', [permission1],
                     {'attrs': [u'l', u'o']}),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "testperm"',
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermlocation=[users_dn],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o'],
                    ipapermexcludedattr=[u'cn'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "l || o")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) userdn = "ldap:///all";)',
        ),

        dict(
            desc='Modify attrs of %r to add sn' % permission1,
            command=('permission_mod', [permission1],
                     {'attrs': [u'l', u'o', u'sn']}),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "testperm"',
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermlocation=[users_dn],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o', u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermexcludedattr=[u'cn'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "l || o || sn")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) userdn = "ldap:///all";)',
        ),

        dict(
            desc='Try to add invalid attribute to %r' % permission1,
            command=('permission_mod', [permission1],
                     {'attrs': [u'calicense',]}),
            expected=errors.InvalidSyntax(
                attr=r'targetattr "calicense" does not exist in schema. '
                     r'Please add attributeTypes "calicense" to '
                     r'schema if necessary. '
                     r'ACL Syntax Error(-5):'
                     r'(targetattr = \22calicense\22)'
                     r'(targetfilter = \22(objectclass=posixaccount)\22)'
                     r'(version 3.0;acl \22permission:%(name)s\22;'
                     r'allow (write) userdn = \22ldap:///all\22;)' %
                     dict(name=permission1),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "l || o || sn")' \
            '(targetfilter = "(objectclass=posixaccount)")' \
            '(version 3.0;acl "permission:%s";' \
            'allow (write) userdn = "ldap:///all";)' % permission1,
        ),

        dict(
            desc='Search for %r using all its --attrs' % permission1,
            command=('permission_find', [permission1],
                     {'cn': permission1, 'attrs': [u'l', u'o', u'sn']}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermlocation=[users_dn],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o', u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermexcludedattr=[u'cn'],
                )],
            ),
        ),

        dict(
            desc='Search for %r using some --attrs' % permission1,
            command=('permission_find', [permission1],
                     {'cn': permission1, 'attrs': [u'l', u'sn']}),
            expected=dict(
                count=1,
                truncated=False,
                summary=u'1 permission matched',
                result=[dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermlocation=[users_dn],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o', u'sn'],
                    ipapermincludedattr=[u'sn'],
                    ipapermexcludedattr=[u'cn'],
                )],
            ),
        ),

        dict(
            desc='Search for %r using excluded --attrs' % permission1,
            command=('permission_find', [permission1],
                     {'cn': permission1, 'attrs': [u'sn', u'cn']}),
            expected=dict(
                count=0,
                truncated=False,
                summary=u'0 permissions matched',
                result=[],
            ),
        ),

        dict(
            desc='Modify attrs of %r to allow cn again' % permission1,
            command=('permission_mod', [permission1],
                     {'attrs': [u'l', u'o', u'sn', u'cn']}),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "testperm"',
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermissiontype=[u'SYSTEM', u'V2', u'MANAGED'],
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'all'],
                    ipapermlocation=[users_dn],
                    ipapermdefaultattr=[u'l', u'o', u'cn'],
                    attrs=[u'l', u'o', u'sn', u'cn'],
                    ipapermincludedattr=[u'sn'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetattr = "cn || l || o || sn")' +
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) userdn = "ldap:///all";)',
        ),

        dict(
            desc='Try to delete %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=errors.ACIError(
                info='cannot delete managed permissions'),
        ),

        dict(
            desc='Delete %r with --force' % permission1,
            command=('permission_del', [permission1], {'force': True}),
            expected=dict(
                result=dict(failed=[]),
                value=[permission1],
                summary=u'Deleted permission "%s"' % permission1,
            ),
        ),
    ]


@pytest.mark.tier1
class test_permission_filters(Declarative):
    """Test multi-valued filters, type, memberof"""
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    tests = [
        dict(
            desc='Create %r with many filters' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    memberof=u'ipausers',
                    ipapermright=u'write',
                    ipapermtargetfilter=[
                        u'(objectclass=top)',
                        u'(memberof=%s)' % DN(('cn', 'admins'), groups_dn),
                        ]
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    memberof=[u'admins', u'ipausers'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    extratargetfilter=[
                        u'(objectclass=top)',
                    ],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetfilter = "(&'
                '(memberOf=%s)' % DN(('cn', 'ipausers'), groups_dn) +
                '(memberof=%s)' % DN(('cn', 'admins'), groups_dn) +
                '(objectclass=posixaccount)(objectclass=top)' +
            ')")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Remove type from %r while setting other filters' % permission1,
            command=(
                'permission_mod', [permission1],
                dict(
                    type=None,
                    memberof=u'ipausers',
                    ipapermtargetfilter=[
                        u'(objectclass=ipauser)',
                        u'(memberof=%s)' % DN(('cn', 'admins'), groups_dn),
                    ],
                ),
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    memberof=[u'admins', u'ipausers'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                    extratargetfilter=[
                        u'(objectclass=ipauser)',
                    ],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(targetfilter = "(&'
                '(memberOf=%s)' % DN(('cn', 'ipausers'), groups_dn) +
                '(memberof=%s)' % DN(('cn', 'admins'), groups_dn) +
                '(objectclass=ipauser)' +
            ')")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Remove memberof from %r while adding a filter' % permission1,
            command=(
                'permission_mod', [permission1],
                dict(
                    memberof=None,
                    addattr=u'ipapermtargetfilter=(cn=xyz)',
                ),
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                    extratargetfilter=[
                        u'(cn=xyz)',
                        u'(objectclass=ipauser)',
                    ],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(targetfilter = "(&'
                '(cn=xyz)' +
                '(objectclass=ipauser)' +
            ')")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Set memberof, type and filter on %r at once' % permission1,
            command=(
                'permission_mod', [permission1],
                dict(
                    type=u'user',
                    memberof=u'admins',
                    ipapermtargetfilter=u'(uid=abc)',
                ),
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    memberof=[u'admins'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                    extratargetfilter=[
                        u'(uid=abc)',
                    ],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetfilter = "(&'
                u'(memberOf=%s)' % DN(('cn', 'admins'), groups_dn) +
                '(objectclass=posixaccount)' +
                '(uid=abc)' +
            ')")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Remove memberof & type from %r at once' % permission1,
            command=(
                'permission_mod', [permission1],
                dict(
                    type=None,
                    memberof=None,
                ),
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                    extratargetfilter=[
                        u'(uid=abc)',
                    ],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(targetfilter = "(uid=abc)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Add multiple memberof to %r' % permission1,
            command=(
                'permission_mod', [permission1],
                dict(
                    memberof=[u'admins', u'editors'],
                ),
            ),
            expected=dict(
                value=permission1,
                summary=u'Modified permission "%s"' % permission1,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    ipapermright=[u'write'],
                    memberof=[u'admins', u'editors'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[api.env.basedn],
                    extratargetfilter=[u'(uid=abc)'],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, api.env.basedn,
            '(targetfilter = "(&'
                '(memberOf=%s)' % DN(('cn', 'admins'), groups_dn) +
                '(memberOf=%s)' % DN(('cn', 'editors'), groups_dn) +
                '(uid=abc)' +
            ')")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Delete %r' % permission1,
            command=('permission_del', [permission1], {}),
            expected=dict(
                result=dict(failed=[]),
                value=[permission1],
                summary=u'Deleted permission "%s"' % permission1,
            )
        ),

        verify_permission_aci_missing(permission1, api.env.basedn),

        dict(
            desc='Create %r with empty filters [#4206]' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    type=u'user',
                    ipapermright=u'write',
                    ipapermtargetfilter=u'',
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                messages=(
                    {
                        'message': ('The permission has write rights but no '
                                    'attributes are set.'),
                        'code': 13032,
                        'type': 'warning',
                        'name': 'MissingTargetAttributesinPermission',
                        'data': {
                            'right': 'write',
                        }
                    },
                ),
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    type=[u'user'],
                    ipapermright=[u'write'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[users_dn],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, users_dn,
            '(targetfilter = "(objectclass=posixaccount)")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (write) groupdn = "ldap:///%s";)' % permission1_dn,
        ),
    ]


class test_permission_in_accounts(Declarative):
    """Test managing a permission in cn=accounts"""

    tests = [
        dict(
            desc='Create %r in cn=accounts' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    ipapermlocation=DN('cn=accounts', api.env.basedn),
                    ipapermright=u'add',
                    attrs=[u'cn'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    attrs=[u'cn'],
                    ipapermright=[u'add'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[DN('cn=accounts', api.env.basedn)],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, DN('cn=accounts', api.env.basedn),
            '(targetattr = "cn")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (add) groupdn = "ldap:///%s";)' % permission1_dn,
        ),

        dict(
            desc='Delete %r' % permission1,
            command=(
                'permission_del', [permission1], {}
            ),
            expected=dict(
                result=dict(failed=[]),
                value=[permission1],
                summary=u'Deleted permission "%s"' % permission1,
            )
        ),

        verify_permission_aci_missing(permission1, api.env.basedn),
    ]


class test_autoadd_operational_attrs(Declarative):
    """Test that read access to operational attributes is automatically added
    """
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    tests = [
        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    ipapermlocation=DN('cn=accounts', api.env.basedn),
                    ipapermright=u'read',
                    attrs=[u'ObjectClass'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    attrs=[u'ObjectClass', u'entryusn', u'createtimestamp',
                           u'modifytimestamp'],
                    ipapermright=[u'read'],
                    ipapermbindruletype=[u'permission'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[DN('cn=accounts', api.env.basedn)],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, DN('cn=accounts', api.env.basedn),
            '(targetattr = "ObjectClass || createtimestamp || entryusn || ' +
                'modifytimestamp")' +
            '(version 3.0;acl "permission:%s";' % permission1 +
            'allow (read) groupdn = "ldap:///%s";)' % permission1_dn,
        ),
    ]


class test_self_bindrule(Declarative):
    """Test creation of permission with bindrule self
    """
    cleanup_commands = [
        ('permission_del', [permission1], {'force': True}),
    ]

    tests = [
        dict(
            desc='Create %r' % permission1,
            command=(
                'permission_add', [permission1], dict(
                    ipapermlocation=DN('cn=accounts', api.env.basedn),
                    ipapermright=u'read',
                    ipapermbindruletype='self',
                    attrs=[u'objectclass'],
                )
            ),
            expected=dict(
                value=permission1,
                summary=u'Added permission "%s"' % permission1,
                result=dict(
                    dn=permission1_dn,
                    cn=[permission1],
                    objectclass=objectclasses.permission,
                    attrs=[u'objectclass', u'entryusn', u'createtimestamp',
                           u'modifytimestamp'],
                    ipapermright=[u'read'],
                    ipapermbindruletype=[u'self'],
                    ipapermissiontype=[u'SYSTEM', u'V2'],
                    ipapermlocation=[DN('cn=accounts', api.env.basedn)],
                ),
            ),
        ),

        verify_permission_aci(
            permission1, DN('cn=accounts', api.env.basedn),
            '(targetattr = "createtimestamp || entryusn || modifytimestamp '
            + '|| objectclass")'
            + '(version 3.0;acl "permission:%s";' % permission1
            + 'allow (read) userdn = "ldap:///self";)',
        ),
    ]
