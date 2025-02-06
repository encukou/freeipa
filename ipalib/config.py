# Authors:
#   Martin Nagy <mnagy@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008  Red Hat
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
Process-wide static configuration and environment.

The standard run-time instance of the `Env` class is initialized early in the
`ipalib` process and is then locked into a read-only state, after which no
further changes can be made to the environment throughout the remaining life
of the process.

For the per-request thread-local information, see `ipalib.request`.
"""
from __future__ import absolute_import

import os
from os import path
import sys
from urllib.parse import urlparse, urlunparse
from configparser import RawConfigParser, ParsingError

import six

from ipaplatform.tasks import tasks
from ipapython.dn import DN
from ipalib.base import check_name
from ipalib.constants import (
    CONFIG_SECTION,
    OVERRIDE_ERROR, SET_ERROR, DEL_ERROR,
    TLS_VERSIONS, TLS_VERSION_DEFAULT_MIN, TLS_VERSION_DEFAULT_MAX,
    USER_CACHE_PATH
)
from ipalib import errors

if six.PY3:
    unicode = str


class Env:
    """
    Store and retrieve environment variables.

    First an foremost, the `Env` class provides a handy container for
    environment variables.  These variables can be both set *and* retrieved
    either as attributes *or* as dictionary items.

    For example, you can set a variable as an attribute:

    >>> env = Env()
    >>> env.attr = 'I was set as an attribute.'
    >>> env.attr
    u'I was set as an attribute.'
    >>> env['attr']  # Also retrieve as a dictionary item
    u'I was set as an attribute.'

    Or you can set a variable as a dictionary item:

    >>> env['item'] = 'I was set as a dictionary item.'
    >>> env['item']
    u'I was set as a dictionary item.'
    >>> env.item  # Also retrieve as an attribute
    u'I was set as a dictionary item.'

    The variable names must be valid lower-case Python identifiers that neither
    start nor end with an underscore.  If your variable name doesn't meet these
    criteria, a ``ValueError`` will be raised when you try to set the variable
    (compliments of the `base.check_name()` function).  For example:

    >>> env.BadName = 'Wont work as an attribute'
    Traceback (most recent call last):
      ...
    ValueError: name must match '^[a-z][_a-z0-9]*[a-z0-9]$|^[a-z]$'; got 'BadName'
    >>> env['BadName'] = 'Also wont work as a dictionary item'
    Traceback (most recent call last):
      ...
    ValueError: name must match '^[a-z][_a-z0-9]*[a-z0-9]$|^[a-z]$'; got 'BadName'

    The variable values can be ``str``, ``int``, or ``float`` instances, or the
    ``True``, ``False``, or ``None`` constants.  When the value provided is an
    ``str`` instance, some limited automatic type conversion is performed, which
    allows values of specific types to be set easily from configuration files or
    command-line options.

    So in addition to their actual values, the ``True``, ``False``, and ``None``
    constants can be specified with an ``str`` equal to what ``repr()`` would
    return.  For example:

    >>> env.true = True
    >>> env.also_true = 'True'  # Equal to repr(True)
    >>> env.true
    True
    >>> env.also_true
    True

    Note that the automatic type conversion is case sensitive.  For example:

    >>> env.not_false = 'false'  # Not equal to repr(False)!
    >>> env.not_false
    u'false'

    If an ``str`` value looks like an integer, it's automatically converted to
    the ``int`` type.

    >>> env.lucky = '7'
    >>> env.lucky
    7

    Leading and trailing white-space is automatically stripped from ``str``
    values.  For example:

    >>> env.message = '  Hello!  '  # Surrounded by double spaces
    >>> env.message
    u'Hello!'
    >>> env.number = ' 42 '  # Still converted to an int
    >>> env.number
    42
    >>> env.false = ' False '  # Still equal to repr(False)
    >>> env.false
    False

    Also, empty ``str`` instances are converted to ``None``.  For example:

    >>> env.empty = ''
    >>> env.empty is None
    True

    `Env` variables are all set-once (first-one-wins).  Once a variable has been
    set, trying to override it will raise an ``AttributeError``.  For example:

    >>> env.date = 'First'
    >>> env.date = 'Second'
    Traceback (most recent call last):
      ...
    AttributeError: cannot override Env.date value u'First' with 'Second'

    An `Env` instance can be *locked*, after which no further variables can be
    set.  Trying to set variables on a locked `Env` instance will also raise
    an ``AttributeError``.  For example:

    >>> env = Env()
    >>> env.okay = 'This will work.'
    >>> env.__lock__()
    >>> env.nope = 'This wont work!'
    Traceback (most recent call last):
      ...
    AttributeError: locked: cannot set Env.nope to 'This wont work!'

    `Env` instances also provide standard container emulation for membership
    testing, counting, and iteration.  For example:

    >>> env = Env()
    >>> 'key1' in env  # Has key1 been set?
    False
    >>> env.key1 = 'value 1'
    >>> 'key1' in env
    True
    >>> env.key2 = 'value 2'
    >>> len(env)  # How many variables have been set?
    2
    >>> list(env)  # What variables have been set?
    ['key1', 'key2']

    Lastly, in addition to all the handy container functionality, the `Env`
    class provides high-level methods for bootstraping a fresh `Env` instance
    into one containing all the run-time and configuration information needed
    by the built-in freeIPA plugins.

    These are the `Env` bootstraping methods, in the order they must be called:

        1. `Env._bootstrap()` - initialize the run-time variables and then
           merge-in variables specified on the command-line.

        2. `Env._finalize_core()` - merge-in variables from the configuration
           files and then merge-in variables from the internal defaults, after
           which at least all the standard variables will be set.  After this
           method is called, the plugins will be loaded, during which
           third-party plugins can merge-in defaults for additional variables
           they use (likely using the `Env._merge()` method).

        3. `Env._finalize()` - one last chance to merge-in variables and then
           the instance is locked.  After this method is called, no more
           environment variables can be set during the remaining life of the
           process.

    However, normally none of these three bootstraping methods are called
    directly and instead only `plugable.API.bootstrap()` is called, which itself
    takes care of correctly calling the `Env` bootstrapping methods.
    """

    __locked = False

    def __init__(self, **initialize):
        object.__setattr__(self, '_Env__d', {})
        object.__setattr__(self, '_Env__done', set())
        if initialize:
            self._merge(**initialize)

    def __lock__(self):
        """
        Prevent further changes to environment.
        """
        if self.__locked is True:
            raise Exception(
                '%s.__lock__() already called' % self.__class__.__name__
            )
        object.__setattr__(self, '_Env__locked', True)

    def __islocked__(self):
        """
        Return ``True`` if locked.
        """
        return self.__locked

    def __setattr__(self, name, value):
        """
        Set the attribute named ``name`` to ``value``.

        This just calls `Env.__setitem__()`.
        """
        self[name] = value

    def __setitem__(self, key, value):
        """
        Set ``key`` to ``value``.
        """
        if self.__locked:
            raise AttributeError(
                SET_ERROR % (self.__class__.__name__, key, value)
            )
        check_name(key)
        # pylint: disable=no-member
        if key in self.__d:
            raise AttributeError(OVERRIDE_ERROR %
                (self.__class__.__name__, key, self.__d[key], value)
            )
        # pylint: enable=no-member
        assert not hasattr(self, key)
        if isinstance(value, str):
            value = value.strip()
            if isinstance(value, bytes):
                value = value.decode('utf-8')
            m = {
                'True': True,
                'False': False,
                'None': None,
                '': None,
            }
            if value in m:
                value = m[value]
            elif value.isdigit():
                value = int(value)
            elif key == 'basedn':
                value = DN(value)
        if not callable(value) and type(
                value) not in (unicode, int, float, bool, type(None), DN):
            raise TypeError(key, value)
        object.__setattr__(self, key, value)
        # pylint: disable=no-member
        self.__d[key] = value
        # pylint: enable=no-member

    def __getitem__(self, key):
        """
        Return the value corresponding to ``key``.
        """
        return self.__d[key]  # pylint: disable=no-member

    def __delattr__(self, name):
        """
        Raise an ``AttributeError`` (deletion is never allowed).

        For example:

        >>> env = Env()
        >>> env.name = 'A value'
        >>> del env.name
        Traceback (most recent call last):
          ...
        AttributeError: locked: cannot delete Env.name
        """
        raise AttributeError(
            DEL_ERROR % (self.__class__.__name__, name)
        )

    def __contains__(self, key):
        """
        Return True if instance contains ``key``; otherwise return False.
        """
        return key in self.__d  # pylint: disable=no-member

    def __len__(self):
        """
        Return number of variables currently set.
        """
        return len(self.__d)  # pylint: disable=no-member

    def __iter__(self):
        """
        Iterate through keys in ascending order.
        """
        for key in sorted(self.__d):  # pylint: disable=no-member
            yield key

    def _merge(self, **kw):
        """
        Merge variables from ``kw`` into the environment.

        Any variables in ``kw`` that have already been set will be ignored
        (meaning this method will *not* try to override them, which would raise
        an exception).

        This method returns a ``(num_set, num_total)`` tuple containing first
        the number of variables that were actually set, and second the total
        number of variables that were provided.

        For example:

        >>> env = Env()
        >>> env._merge(one=1, two=2)
        (2, 2)
        >>> env._merge(one=1, three=3)
        (1, 2)
        >>> env._merge(one=1, two=2, three=3)
        (0, 3)

        Also see `Env._merge_from_file()`.

        :param kw: Variables provides as keyword arguments.
        """
        i = 0
        for (key, value) in kw.items():
            if key not in self:
                self[key] = value
                i += 1
        return (i, len(kw))

    def _merge_from_file(self, config_file):
        """
        Merge variables from ``config_file`` into the environment.

        Any variables in ``config_file`` that have already been set will be
        ignored (meaning this method will *not* try to override them, which
        would raise an exception).

        If ``config_file`` does not exist or is not a regular file, or if there
        is an error parsing ``config_file``, ``None`` is returned.

        Otherwise this method returns a ``(num_set, num_total)`` tuple
        containing first the number of variables that were actually set, and
        second the total number of variables found in ``config_file``.

        Also see `Env._merge()`.

        :param config_file: Path of the configuration file to load.
        """
        if not path.isfile(config_file):
            return None
        parser = RawConfigParser()
        try:
            parser.read(config_file)
        except ParsingError:
            return None
        if not parser.has_section(CONFIG_SECTION):
            parser.add_section(CONFIG_SECTION)
        items = parser.items(CONFIG_SECTION)
        if len(items) == 0:
            return 0, 0
        i = 0
        for (key, value) in items:
            if key not in self:
                self[key] = value
                i += 1
        if 'config_loaded' not in self: # we loaded at least 1 file
            self['config_loaded'] = True
        return i, len(items)

    def _join(self, key, *parts):
        """
        Append path components in ``parts`` to base path ``self[key]``.

        For example:

        >>> env = Env()
        >>> env.home = '/people/joe'
        >>> env._join('home', 'Music', 'favourites')
        u'/people/joe/Music/favourites'
        """
        if key in self and self[key] is not None:
            return path.join(self[key], *parts)
        else:
            return None

    def __doing(self, name):
        # pylint: disable=no-member
        if name in self.__done:
            raise Exception(
                '%s.%s() already called' % (self.__class__.__name__, name)
            )
        self.__done.add(name)

    def __do_if_not_done(self, name):
        if name not in self.__done:  # pylint: disable=no-member
            getattr(self, name)()

    def _isdone(self, name):
        return name in self.__done  # pylint: disable=no-member

    def _bootstrap(self, **overrides):
        """
        Initialize basic environment.

        This method will perform the following steps:

            1. Initialize certain run-time variables.  These run-time variables
               are strictly determined by the external environment the process
               is running in; they cannot be specified on the command-line nor
               in the configuration files.

            2. Merge-in the variables in ``overrides`` by calling
               `Env._merge()`.  The intended use of ``overrides`` is to merge-in
               variables specified on the command-line.

            3. Intelligently fill-in the *in_tree*, *context*, *conf*, and
               *conf_default* variables if they haven't been set already.

        Also see `Env._finalize_core()`, the next method in the bootstrap
        sequence.

        :param overrides: Variables specified via command-line options.
        """
        self.__doing('_bootstrap')

        # Set run-time variables (cannot be overridden):
        self.ipalib = path.dirname(path.abspath(__file__))
        self.site_packages = path.dirname(self.ipalib)
        self.script = path.abspath(sys.argv[0])
        self.bin = path.dirname(self.script)
        home = os.path.expanduser('~')
        self.home = home if not home.startswith('~') else None
        self.fips_mode = tasks.is_fips_enabled()

        # Merge in overrides:
        self._merge(**overrides)

        # Determine if running in source tree. The root directory of
        # IPA source directory contains ipasetup.py.in.
        if 'in_tree' not in self:
            self.in_tree = os.path.isfile(
                os.path.join(self.site_packages, "ipasetup.py.in")
            )
        if self.in_tree and 'mode' not in self:
            self.mode = 'developer'

        # Set dot_ipa:
        if 'dot_ipa' not in self:
            self.dot_ipa = self._join('home', '.ipa')

        # Set context
        if 'context' not in self:
            self.context = 'default'

        # Set confdir:
        self.env_confdir = os.environ.get('IPA_CONFDIR')

        if 'confdir' in self and self.env_confdir is not None:
            raise errors.EnvironmentError(
                    "IPA_CONFDIR env cannot be set because explicit confdir "
                    "is used")

        if 'confdir' not in self:
            if self.env_confdir is not None:
                if (not path.isabs(self.env_confdir)
                        or not path.isdir(self.env_confdir)):
                    raise errors.EnvironmentError(
                        "IPA_CONFDIR env var must be an absolute path to an "
                        "existing directory, got '{}'.".format(
                            self.env_confdir))
                self.confdir = self.env_confdir
            elif self.in_tree:
                self.confdir = self.dot_ipa
            else:
                self.confdir = path.join('/', 'etc', 'ipa')

        # Set conf (config file for this context):
        if 'conf' not in self:
            self.conf = self._join('confdir', '%s.conf' % self.context)

        # Set conf_default (default base config used in all contexts):
        if 'conf_default' not in self:
            self.conf_default = self._join('confdir', 'default.conf')

        if 'nss_dir' not in self:
            self.nss_dir = self._join('confdir', 'nssdb')

        # user cache dir for IPA, defaults to '$XDG_CACHE_HOME/ipa' or
        # '~/.cache/ipa'. XDG_CACHE_HOME env var is cached at import time.
        if 'cache_dir' not in self:
            self.cache_dir = os.path.join(USER_CACHE_PATH, 'ipa')

        if 'tls_ca_cert' not in self:
            self.tls_ca_cert = self._join('confdir', 'ca.crt')

        # having tls_ca_cert an absolute path could help us extending this
        # in the future for different certificate providers simply by adding
        # a prefix to the path
        if not path.isabs(self.tls_ca_cert):
            raise errors.EnvironmentError(
                "tls_ca_cert has to be an absolute path to a CA certificate, "
                "got '{}'".format(self.tls_ca_cert))

        # Set plugins_on_demand:
        if 'plugins_on_demand' not in self:
            self.plugins_on_demand = (self.context == 'cli')

    def _finalize_core(self, **defaults):
        """
        Complete initialization of standard IPA environment.

        This method will perform the following steps:

            1. Call `Env._bootstrap()` if it hasn't already been called.

            2. Merge-in variables from the configuration file ``self.conf``
               (if it exists) by calling `Env._merge_from_file()`.

            3. Merge-in variables from the defaults configuration file
               ``self.conf_default`` (if it exists) by calling
               `Env._merge_from_file()`.

            4. Intelligently fill-in the *in_server* , *logdir*, *log*, and
               *jsonrpc_uri* variables if they haven't already been set.

            5. Merge-in the variables in ``defaults`` by calling `Env._merge()`.
               In normal circumstances ``defaults`` will simply be those
               specified in `constants.DEFAULT_CONFIG`.

        After this method is called, all the environment variables used by all
        the built-in plugins will be available.  As such, this method should be
        called *before* any plugins are loaded.

        After this method has finished, the `Env` instance is still writable
        so that 3rd-party plugins can set variables they may require as the
        plugins are registered.

        Also see `Env._finalize()`, the final method in the bootstrap sequence.

        :param defaults: Internal defaults for all built-in variables.
        """
        self.__doing('_finalize_core')
        self.__do_if_not_done('_bootstrap')

        # Merge in context config file and then default config file:
        mode = self.__d.get('mode')  # pylint: disable=no-member
        # documented public modes: production, developer
        # internal modes: dummy, unit_test
        if mode != 'dummy':
            self._merge_from_file(self.conf)
            self._merge_from_file(self.conf_default)

        # Determine if in_server:
        if 'in_server' not in self:
            self.in_server = (self.context == 'server')

        # Set logdir:
        if 'logdir' not in self:
            if self.in_tree or not self.in_server:
                self.logdir = self._join('dot_ipa', 'log')
            else:
                self.logdir = path.join('/', 'var', 'log', 'ipa')

        # Set log file:
        if 'log' not in self:
            self.log = self._join('logdir', '%s.log' % self.context)

        # Workaround for ipa-server-install --uninstall. When no config file
        # is available, we set realm, domain, and basedn to RFC 2606 reserved
        # suffix to suppress attribute errors during uninstallation.
        if (self.in_server and self.context == 'installer' and
                not getattr(self, 'config_loaded', False)):
            if 'realm' not in self:
                self.realm = 'UNCONFIGURED.INVALID'
            if 'domain' not in self:
                self.domain = self.realm.lower()

        if 'basedn' not in self and 'domain' in self:
            self.basedn = DN(*(('dc', dc) for dc in self.domain.split('.')))

        # Derive xmlrpc_uri from server
        # (Note that this is done before deriving jsonrpc_uri from xmlrpc_uri
        # and server from jsonrpc_uri so that when only server or xmlrpc_uri
        # is specified, all 3 keys have a value.)
        if 'xmlrpc_uri' not in self and 'server' in self:
            self.xmlrpc_uri = 'https://{}/ipa/xml'.format(self.server)

        # Derive ldap_uri from server
        if 'ldap_uri' not in self and 'server' in self:
            self.ldap_uri = 'ldap://{}'.format(self.server)

        # Derive jsonrpc_uri from xmlrpc_uri
        if 'jsonrpc_uri' not in self:
            if 'xmlrpc_uri' in self:
                xmlrpc_uri = self.xmlrpc_uri
            else:
                xmlrpc_uri = defaults.get('xmlrpc_uri')
            if xmlrpc_uri:
                (scheme, netloc, uripath, params, query, fragment
                        ) = urlparse(xmlrpc_uri)
                uripath = uripath.replace('/xml', '/json', 1)
                self.jsonrpc_uri = urlunparse((
                        scheme, netloc, uripath, params, query, fragment))

        if 'server' not in self:
            if 'jsonrpc_uri' in self:
                jsonrpc_uri = self.jsonrpc_uri
            else:
                jsonrpc_uri = defaults.get('jsonrpc_uri')
            if jsonrpc_uri:
                parsed = urlparse(jsonrpc_uri)
                self.server = parsed.netloc

        self._merge(**defaults)

        # set the best known TLS version if min/max versions are not set
        if 'tls_version_min' not in self:
            self.tls_version_min = TLS_VERSION_DEFAULT_MIN
        if (
                self.tls_version_min is not None and
                self.tls_version_min not in TLS_VERSIONS
        ):
            raise errors.EnvironmentError(
                "Unknown TLS version '{ver}' set in tls_version_min."
                .format(ver=self.tls_version_min))

        if 'tls_version_max' not in self:
            self.tls_version_max = TLS_VERSION_DEFAULT_MAX
        if (
                self.tls_version_max is not None and
                self.tls_version_max not in TLS_VERSIONS
        ):
            raise errors.EnvironmentError(
                "Unknown TLS version '{ver}' set in tls_version_max."
                .format(ver=self.tls_version_max))

        if (
                self.tls_version_min is not None and
                self.tls_version_max is not None and
                self.tls_version_max < self.tls_version_min
        ):
            raise errors.EnvironmentError(
                "tls_version_min is set to a higher TLS version than "
                "tls_version_max.")

    def _finalize(self, **lastchance):
        """
        Finalize and lock environment.

        This method will perform the following steps:

            1. Call `Env._finalize_core()` if it hasn't already been called.

            2. Merge-in the variables in ``lastchance`` by calling
               `Env._merge()`.

            3. Lock this `Env` instance, after which no more environment
               variables can be set on this instance.  Aside from unit-tests
               and example code, normally only one `Env` instance is created,
               which means that after this step, no more variables can be set
               during the remaining life of the process.

        This method should be called after all plugins have been loaded and
        after `plugable.API.finalize()` has been called.

        :param lastchance: Any final variables to merge-in before locking.
        """
        self.__doing('_finalize')
        self.__do_if_not_done('_finalize_core')
        self._merge(**lastchance)
        self.__lock__()
