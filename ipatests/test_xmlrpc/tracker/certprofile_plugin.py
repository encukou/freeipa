# -*- coding: utf-8 -*-
#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import os

import six

from ipapython.dn import DN
from ipatests.test_xmlrpc.tracker.base import Tracker
from ipatests.test_xmlrpc import objectclasses
from ipatests.util import assert_deepequal

if six.PY3:
    unicode = str


class CertprofileTracker(Tracker):
    """Tracker class for certprofile plugin.
    """

    retrieve_keys = {
        'dn', 'cn', 'description', 'ipacertprofilestoreissued',
        'ipacertprofilelocal',
    }
    retrieve_all_keys = retrieve_keys | {'objectclass'}
    create_keys = retrieve_keys | {'objectclass'}
    update_keys = retrieve_keys - {'dn'}
    managedby_keys = retrieve_keys
    allowedto_keys = retrieve_keys

    def __init__(self, name, store=False, desc='dummy description',
                 profile=None, default_version=None, local=True):
        super(CertprofileTracker, self).__init__(
            default_version=default_version
        )

        self.store = store
        self.local = local
        self.description = desc
        self._profile_path = profile

        self.dn = DN(('cn', name), 'cn=certprofiles', 'cn=ca',
                     self.api.env.basedn)

    @property
    def profile(self):
        if not self._profile_path:
            return None

        if os.path.isabs(self._profile_path):
            path = self._profile_path
        else:
            path = os.path.join(os.path.dirname(__file__),
                                self._profile_path)

        with open(path, 'r') as f:
            content = f.read()
        return unicode(content)

    def make_create_command(self, extra_lines=None):
        """
        :param extra_lines: list of extra lines to append to profile config.

        """
        if extra_lines is None:
            extra_lines = []

        if not self.profile:
            raise RuntimeError('Tracker object without path to profile '
                               'cannot be used to create profile entry.')

        return self.make_command('certprofile_import', self.name,
                                 description=self.description,
                                 ipacertprofilestoreissued=self.store,
                                 file=u'\n'.join([self.profile] + extra_lines))

    def check_create(self, result):
        assert_deepequal(dict(
            value=self.name,
            summary=u'Imported profile "{}"'.format(self.name),
            result=dict(self.filter_attrs(self.create_keys))
        ), result)

    def track_create(self):
        self.attrs = dict(
            dn=unicode(self.dn),
            cn=[self.name],
            description=[self.description],
            ipacertprofilestoreissued=[self.store],
            ipacertprofilelocal=[self.local],
            objectclass=objectclasses.certprofile
        )
        self.exists = True

    def make_delete_command(self):
        return self.make_command('certprofile_del', self.name)

    def check_delete(self, result):
        assert_deepequal(dict(
            value=[self.name],  # correctly a list?
            summary=u'Deleted profile "{}"'.format(self.name),
            result=dict(failed=[]),
        ), result)

    def make_retrieve_command(self, all=False, raw=False, **options):
        return self.make_command('certprofile_show', self.name, all=all,
                                 raw=raw, **options)

    def check_retrieve(self, result, all=False, raw=False):
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            value=self.name,
            summary=None,
            result=expected,
        ), result)

    def make_find_command(self, *args, **kwargs):
        return self.make_command('certprofile_find', *args, **kwargs)

    def check_find(self, result, all=False, raw=False):
        if all:
            expected = self.filter_attrs(self.retrieve_all_keys)
        else:
            expected = self.filter_attrs(self.retrieve_keys)

        assert_deepequal(dict(
            count=1,
            truncated=False,
            summary=u'1 profile matched',
            result=[expected]
        ), result)

    def make_update_command(self, updates):
        return self.make_command('certprofile_mod', self.name, **updates)

    def check_update(self, result, extra_keys=()):
        assert_deepequal(dict(
            value=self.name,
            summary=u'Modified Certificate Profile "{}"'.format(self.name),
            result=self.filter_attrs(self.update_keys | set(extra_keys))
        ), result)
