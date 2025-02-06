# Authors:
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
Plugin framework.

The classes in this module make heavy use of Python container emulation. If
you are unfamiliar with this Python feature, see
http://docs.python.org/ref/sequence-types.html
"""

from collections.abc import Mapping
import logging
import operator
import re
import sys
import threading
import os
from os import path
import textwrap
import collections
import importlib

import six

from ipalib import errors
from ipalib.config import Env
from ipalib.text import _
from ipalib.util import classproperty
from ipalib.base import ReadOnly, lock, islocked
from ipalib.constants import DEFAULT_CONFIG
from ipapython import ipa_log_manager, ipautil
from ipapython.config import IPAOptionParser, IPAFormatter
from ipapython.ipa_log_manager import (
    LOGGING_FORMAT_FILE,
    LOGGING_FORMAT_STDERR)
from ipapython.version import VERSION, API_VERSION, DEFAULT_PLUGINS

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

# FIXME: Updated constants.TYPE_ERROR to use this clearer format from wehjit:
TYPE_ERROR = '%s: need a %r; got a %r: %r'


# FIXME: This function has no unit test
def find_modules_in_dir(src_dir):
    """
    Iterate through module names found in ``src_dir``.
    """
    if not (os.path.abspath(src_dir) == src_dir and os.path.isdir(src_dir)):
        return
    if os.path.islink(src_dir):
        return
    suffix = '.py'
    for name in sorted(os.listdir(src_dir)):
        if not name.endswith(suffix):
            continue
        pyfile = os.path.join(src_dir, name)
        if not os.path.isfile(pyfile):
            continue
        module = name[:-len(suffix)]
        if module == '__init__':
            continue
        yield module


class Registry:
    """A decorator that makes plugins available to the API

    Usage::

        register = Registry()

        @register()
        class obj_mod(...):
            ...

    For forward compatibility, make sure that the module-level instance of
    this object is named "register".
    """
    def __init__(self):
        self.__registry = collections.OrderedDict()

    def __call__(self, **kwargs):
        def register(plugin):
            """
            Register the plugin ``plugin``.

            :param plugin: A subclass of `Plugin` to attempt to register.
            """
            if not callable(plugin):
                raise TypeError('plugin must be callable; got %r' % plugin)

            # Raise DuplicateError if this exact class was already registered:
            if plugin in self.__registry:
                raise errors.PluginDuplicateError(plugin=plugin)

            # The plugin is okay, add to __registry:
            self.__registry[plugin] = dict(kwargs, plugin=plugin)

            return plugin

        return register

    def __iter__(self):
        return iter(self.__registry.values())


class Plugin(ReadOnly):
    """
    Base class for all plugins.
    """

    version = '1'

    def __init__(self, api):
        assert api is not None
        self.__api = api
        self.__finalize_called = False
        self.__finalized = False
        self.__finalize_lock = threading.RLock()

    @classmethod
    def __name_getter(cls):
        return cls.__name__

    # you know nothing, pylint
    name = classproperty(__name_getter)

    @classmethod
    def __full_name_getter(cls):
        return '{}/{}'.format(cls.name, cls.version)

    full_name = classproperty(__full_name_getter)

    @classmethod
    def __bases_getter(cls):
        return cls.__bases__

    bases = classproperty(__bases_getter)

    @classmethod
    def __doc_getter(cls):
        return cls.__doc__

    doc = classproperty(__doc_getter)

    @classmethod
    def __summary_getter(cls):
        doc = cls.doc
        if not _(doc).msg:
            return '<%s.%s>' % (cls.__module__, cls.__name__)
        else:
            return unicode(doc).split('\n\n', 1)[0].strip()

    summary = classproperty(__summary_getter)

    @property
    def api(self):
        """
        Return `API` instance passed to `__init__()`.
        """
        return self.__api

    # FIXME: for backward compatibility only
    @property
    def env(self):
        return self.__api.env

    # FIXME: for backward compatibility only
    @property
    def Backend(self):
        return self.__api.Backend

    # FIXME: for backward compatibility only
    @property
    def Command(self):
        return self.__api.Command

    def finalize(self):
        """
        Finalize plugin initialization.

        This method calls `_on_finalize()` and locks the plugin object.

        Subclasses should not override this method. Custom finalization is done
        in `_on_finalize()`.
        """
        with self.__finalize_lock:
            assert self.__finalized is False
            if self.__finalize_called:
                # No recursive calls!
                return
            self.__finalize_called = True
            self._on_finalize()
            self.__finalized = True
            if not self.__api.is_production_mode():
                lock(self)

    def _on_finalize(self):
        """
        Do custom finalization.

        This method is called from `finalize()`. Subclasses can override this
        method in order to add custom finalization.
        """

    def ensure_finalized(self):
        """
        Finalize plugin initialization if it has not yet been finalized.
        """
        with self.__finalize_lock:
            if not self.__finalized:
                self.finalize()

    class finalize_attr:
        """
        Create a stub object for plugin attribute that isn't set until the
        finalization of the plugin initialization.

        When the stub object is accessed, it calls `ensure_finalized()` to make
        sure the plugin initialization is finalized. The stub object is expected
        to be replaced with the actual attribute value during the finalization
        (preferably in `_on_finalize()`), otherwise an `AttributeError` is
        raised.

        This is used to implement on-demand finalization of plugin
        initialization.
        """
        __slots__ = ('name', 'value')

        def __init__(self, name, value=None):
            self.name = name
            self.value = value

        def __get__(self, obj, cls):
            if obj is None or obj.api is None:
                return self.value
            obj.ensure_finalized()
            try:
                return getattr(obj, self.name)
            except RuntimeError:
                # If the actual attribute value is not set in _on_finalize(),
                # getattr() calls __get__() again, which leads to infinite
                # recursion. This can happen only if the plugin is written
                # badly, so advise the developer about that instead of giving
                # them a generic "maximum recursion depth exceeded" error.
                raise AttributeError(
                    "attribute '%s' of plugin '%s' was not set in finalize()" % (self.name, obj.name)
                )

    def __repr__(self):
        """
        Return 'module_name.class_name()' representation.

        This representation could be used to instantiate this Plugin
        instance given the appropriate environment.
        """
        return '%s.%s()' % (
            self.__class__.__module__,
            self.__class__.__name__
        )


class APINameSpace(Mapping):
    def __init__(self, api, base):
        self.__api = api
        self.__base = base
        self.__plugins = None
        self.__plugins_by_key = None

    def __enumerate(self):
        if self.__plugins is not None and self.__plugins_by_key is not None:
            return

        default_map = self.__api._API__default_map
        plugins = set()
        key_dict = self.__plugins_by_key = {}

        for plugin in self.__api._API__plugins:
            if not any(issubclass(b, self.__base) for b in plugin.bases):
                continue
            plugins.add(plugin)
            key_dict[plugin] = plugin
            key_dict[plugin.name, plugin.version] = plugin
            key_dict[plugin.full_name] = plugin
            if plugin.version == default_map.get(plugin.name, '1'):
                key_dict[plugin.name] = plugin

        self.__plugins = sorted(plugins, key=operator.attrgetter('full_name'))

    def __len__(self):
        self.__enumerate()
        return len(self.__plugins)

    def __contains__(self, key):
        self.__enumerate()
        return key in self.__plugins_by_key

    def __iter__(self):
        self.__enumerate()
        return iter(self.__plugins)

    def __dir__(self):
        # include plugins for readline tab completion and in dir()
        self.__enumerate()
        names = super().__dir__()
        names.extend(p.name for p in self)
        names.sort()
        return names

    def get_plugin(self, key):
        self.__enumerate()
        return self.__plugins_by_key[key]

    def __getitem__(self, key):
        plugin = self.get_plugin(key)
        return self.__api._get(plugin)

    def __call__(self):
        return six.itervalues(self)

    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)


class API(ReadOnly):
    """
    Dynamic API object through which `Plugin` instances are accessed.
    """

    def __init__(self):
        super(API, self).__init__()
        self.__plugins = set()
        self.__plugins_by_key = {}
        self.__default_map = {}
        self.__instances = {}
        self.__next = {}
        self.__done = set()
        self.env = Env()

    @property
    def bases(self):
        raise NotImplementedError

    @property
    def packages(self):
        raise NotImplementedError

    def __len__(self):
        """
        Return the number of plugin namespaces in this API object.
        """
        return len(self.bases)

    def __iter__(self):
        """
        Iterate (in ascending order) through plugin namespace names.
        """
        return (base.__name__ for base in self.bases)

    def __contains__(self, name):
        """
        Return True if this API object contains plugin namespace ``name``.

        :param name: The plugin namespace name to test for membership.
        """
        return name in set(self)

    def __getitem__(self, name):
        """
        Return the plugin namespace corresponding to ``name``.

        :param name: The name of the plugin namespace you wish to retrieve.
        """
        if name in self:
            try:
                return getattr(self, name)
            except AttributeError:
                pass

        raise KeyError(name)

    def __call__(self):
        """
        Iterate (in ascending order by name) through plugin namespaces.
        """
        for name in self:
            try:
                yield getattr(self, name)
            except AttributeError:
                raise KeyError(name)

    def is_production_mode(self):
        """
        If the object has self.env.mode defined and that mode is
        production return True, otherwise return False.
        """
        return getattr(self.env, 'mode', None) == 'production'

    def __doing(self, name):
        if name in self.__done:
            raise Exception(
                '%s.%s() already called' % (self.__class__.__name__, name)
            )
        self.__done.add(name)

    def __do_if_not_done(self, name):
        if name not in self.__done:
            getattr(self, name)()

    def isdone(self, name):
        return name in self.__done

    def bootstrap(self, parser=None, **overrides):
        """
        Initialize environment variables and logging.
        """
        self.__doing('bootstrap')
        self.env._bootstrap(**overrides)
        self.env._finalize_core(**dict(DEFAULT_CONFIG))

        # Add the argument parser
        if not parser:
            parser = self.build_global_parser()
        self.parser = parser

        root_logger = logging.getLogger()

        # If logging has already been configured somewhere else (like in the
        # installer), don't add handlers or change levels:
        if root_logger.handlers or self.env.validate_api:
            return

        if self.env.debug:
            level = logging.DEBUG
        else:
            level = logging.INFO
        root_logger.setLevel(level)

        for attr in self.env:
            match = re.match(r'^log_logger_level_'
                             r'(debug|info|warn|warning|error|critical|\d+)$',
                             attr)
            if not match:
                continue

            level = ipa_log_manager.convert_log_level(match.group(1))

            value = getattr(self.env, attr)
            regexps = re.split(r'\s*,\s*', value)

            # Add the regexp, it maps to the configured level
            for regexp in regexps:
                root_logger.addFilter(ipa_log_manager.Filter(regexp, level))

        # Add stderr handler:
        level = logging.INFO
        if self.env.debug:
            level = logging.DEBUG
        else:
            if self.env.context == 'cli':
                if self.env.verbose > 0:
                    level = logging.INFO
                else:
                    level = logging.WARNING
        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(ipa_log_manager.Formatter(LOGGING_FORMAT_STDERR))
        root_logger.addHandler(handler)

        # check after logging is set up but before we create files.
        fse = sys.getfilesystemencoding()
        if fse.lower() not in {'utf-8', 'utf8'}:
            raise errors.SystemEncodingError(encoding=fse)

        # Add file handler:
        if self.env.mode in ('dummy', 'unit_test'):
            return  # But not if in unit-test mode
        if self.env.log is None:
            return
        log_dir = path.dirname(self.env.log)
        if not path.isdir(log_dir):
            try:
                os.makedirs(log_dir)
            except OSError:
                logger.error('Could not create log_dir %r', log_dir)
                return

        level = logging.INFO
        if self.env.debug:
            level = logging.DEBUG
        if self.env.log is not None:
            try:
                handler = logging.FileHandler(self.env.log)
            except IOError as e:
                logger.error('Cannot open log file %r: %s', self.env.log, e)
            else:
                handler.setLevel(level)
                handler.setFormatter(
                    ipa_log_manager.Formatter(LOGGING_FORMAT_FILE)
                )
                root_logger.addHandler(handler)

    def build_global_parser(self, parser=None, context=None):
        """
        Add global options to an IPAOptionParser instance.
        """
        def config_file_callback(option, opt, value, parser):
            if not os.path.isfile(value):
                parser.error(
                    _("%(filename)s: file not found") % dict(filename=value))

            parser.values.conf = value

        if parser is None:
            parser = IPAOptionParser(
                add_help_option=False,
                formatter=IPAHelpFormatter(),
                usage='%prog [global-options] COMMAND [command-options]',
                description='Manage an IPA domain',
                version=('VERSION: %s, API_VERSION: %s' %
                            (VERSION, API_VERSION)),
                epilog='\n'.join([
                    'See "ipa help topics" for available help topics.',
                    'See "ipa help <TOPIC>" for more information on '
                    + 'a specific topic.',
                    'See "ipa help commands" for the full list of commands.',
                    'See "ipa <COMMAND> --help" for more information on '
                    + 'a specific command.',
                ]))
            parser.disable_interspersed_args()
            parser.add_option("-h", "--help", action="help",
                help='Show this help message and exit')

        parser.add_option('-e', dest='env', metavar='KEY=VAL', action='append',
            help='Set environment variable KEY to VAL',
        )
        parser.add_option('-c', dest='conf', metavar='FILE', action='callback',
            callback=config_file_callback, type='string',
            help='Load configuration from FILE.',
        )
        parser.add_option('-d', '--debug', action='store_true',
            help='Produce full debuging output',
        )
        parser.add_option('--delegate', action='store_true',
            help='Delegate the TGT to the IPA server',
        )
        parser.add_option('-v', '--verbose', action='count',
            help='Produce more verbose output. A second -v displays the XML-RPC request',
        )
        if context == 'cli':
            parser.add_option('-a', '--prompt-all', action='store_true',
                help='Prompt for ALL values (even if optional)'
            )
            parser.add_option('-n', '--no-prompt', action='store_false',
                dest='interactive',
                help='Prompt for NO values (even if required)'
            )
            parser.add_option('-f', '--no-fallback', action='store_false',
                dest='fallback',
                help='Only use the server configured in /etc/ipa/default.conf'
            )

        return parser

    def bootstrap_with_global_options(self, parser=None, context=None,
                                      additional_overrides=None):
        parser = self.build_global_parser(parser, context)
        (options, args) = parser.parse_args()
        overrides = additional_overrides or {}
        if options.env is not None:
            assert type(options.env) is list
            for item in options.env:
                try:
                    values = item.split('=', 1)
                except ValueError:
                    # FIXME: this should raise an IPA exception with an
                    # error code.
                    # --Jason, 2008-10-31
                    pass
                if len(values) == 2:
                    (key, value) = values
                    overrides[str(key.strip())] = value.strip()
                else:
                    raise errors.OptionError(_('Unable to parse option {item}'
                                               .format(item=item)))
        for key in ('conf', 'debug', 'verbose', 'prompt_all', 'interactive',
            'fallback', 'delegate'):
            value = getattr(options, key, None)
            if value is not None:
                overrides[key] = value
        if hasattr(options, 'prod'):
            overrides['webui_prod'] = options.prod
        if context is not None:
            overrides['context'] = context
        self.bootstrap(parser, **overrides)
        return (options, args)

    def load_plugins(self):
        """
        Load plugins from all standard locations.

        `API.bootstrap` will automatically be called if it hasn't been
        already.
        """
        self.__doing('load_plugins')
        self.__do_if_not_done('bootstrap')
        if self.env.mode in ('dummy', 'unit_test'):
            return
        for package in self.packages:
            self.add_package(package)

    # FIXME: This method has no unit test
    def add_package(self, package):
        """
        Add plugin modules from the ``package``.

        :param package: A package from which to add modules.
        """
        package_name = package.__name__
        package_file = package.__file__
        package_dir = path.dirname(path.abspath(package_file))

        parent = sys.modules[package_name.rpartition('.')[0]]
        parent_dir = path.dirname(path.abspath(parent.__file__))
        if parent_dir == package_dir:
            raise errors.PluginsPackageError(
                name=package_name, file=package_file
            )

        logger.debug("importing all plugin modules in %s...", package_name)
        modules = getattr(package, 'modules', find_modules_in_dir(package_dir))
        modules = ['.'.join((package_name, mname)) for mname in modules]

        for name in modules:
            logger.debug("importing plugin module %s", name)
            try:
                module = importlib.import_module(name)
            except errors.SkipPluginModule as e:
                logger.debug("skipping plugin module %s: %s", name, e.reason)
                continue
            except Exception:
                tb = self.env.startup_traceback
                if tb:
                    logger.exception("could not load plugin module %s", name)
                raise

            try:
                self.add_module(module)
            except errors.PluginModuleError as e:
                logger.debug("%s", e)

    def add_module(self, module):
        """
        Add plugins from the ``module``.

        :param module: A module from which to add plugins.
        """
        try:
            register = module.register
        except AttributeError:
            pass
        else:
            if isinstance(register, Registry):
                for kwargs in register:
                    self.add_plugin(**kwargs)
                return

        raise errors.PluginModuleError(name=module.__name__)

    def add_plugin(self, plugin, override=False, no_fail=False):
        """
        Add the plugin ``plugin``.

        :param plugin: A subclass of `Plugin` to attempt to add.
        :param override: If true, override an already added plugin.
        """
        if not callable(plugin):
            raise TypeError('plugin must be callable; got %r' % plugin)

        # Find the base class or raise SubclassError:
        for base in plugin.bases:
            if issubclass(base, self.bases):
                break
        else:
            raise errors.PluginSubclassError(
                plugin=plugin,
                bases=self.bases,
            )

        # Check override:
        prev = self.__plugins_by_key.get(plugin.full_name)
        if prev:
            if not override:
                if no_fail:
                    return
                else:
                    # Must use override=True to override:
                    raise errors.PluginOverrideError(
                        base=base.__name__,
                        name=plugin.name,
                        plugin=plugin,
                    )

            self.__plugins.remove(prev)
            self.__next[plugin] = prev
        else:
            if override:
                if no_fail:
                    return
                else:
                    # There was nothing already registered to override:
                    raise errors.PluginMissingOverrideError(
                        base=base.__name__,
                        name=plugin.name,
                        plugin=plugin,
                    )

        # The plugin is okay, add to sub_d:
        self.__plugins.add(plugin)
        self.__plugins_by_key[plugin.full_name] = plugin

    def finalize(self):
        """
        Finalize the registration, instantiate the plugins.

        `API.bootstrap` will automatically be called if it hasn't been
        already.
        """
        self.__doing('finalize')
        self.__do_if_not_done('load_plugins')

        if self.env.env_confdir is not None:
            if self.env.env_confdir == self.env.confdir:
                logger.info(
                    "IPA_CONFDIR env sets confdir to '%s'.", self.env.confdir)

        for plugin in self.__plugins:
            if not self.env.validate_api:
                if plugin.full_name not in DEFAULT_PLUGINS:
                    continue
            else:
                try:
                    default_version = self.__default_map[plugin.name]
                except KeyError:
                    pass
                else:
                    # Technicall plugin.version is not an API version. The
                    # APIVersion class can handle plugin versions. It's more
                    # lean than pkg_resource.parse_version().
                    version = ipautil.APIVersion(plugin.version)
                    default_version = ipautil.APIVersion(default_version)
                    if version < default_version:
                        continue
            self.__default_map[plugin.name] = plugin.version

        production_mode = self.is_production_mode()

        for base in self.bases:
            for plugin in self.__plugins:
                if not any(issubclass(b, base) for b in plugin.bases):
                    continue
                if not self.env.plugins_on_demand:
                    self._get(plugin)

            name = base.__name__
            if not production_mode:
                assert not hasattr(self, name)
            setattr(self, name, APINameSpace(self, base))

        for instance in six.itervalues(self.__instances):
            if not production_mode:
                assert instance.api is self
            if not self.env.plugins_on_demand:
                instance.ensure_finalized()
                if not production_mode:
                    assert islocked(instance)

        if not production_mode:
            lock(self)

    def _get(self, plugin):
        if not callable(plugin):
            raise TypeError('plugin must be callable; got %r' % plugin)
        if plugin not in self.__plugins:
            raise KeyError(plugin)

        try:
            instance = self.__instances[plugin]
        except KeyError:
            instance = self.__instances[plugin] = plugin(self)

        return instance

    def get_plugin_next(self, plugin):
        if not callable(plugin):
            raise TypeError('plugin must be callable; got %r' % plugin)

        return self.__next[plugin]


class IPAHelpFormatter(IPAFormatter):
    def format_epilog(self, epilog):
        text_width = self.width - self.current_indent
        indent = " " * self.current_indent
        lines = epilog.splitlines()
        result = '\n'.join(
            textwrap.fill(line, text_width, initial_indent=indent,
                subsequent_indent=indent)
            for line in lines)
        return '\n%s\n' % result
