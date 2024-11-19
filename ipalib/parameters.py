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
Parameter system for command plugins.

A `Param` instance can be used to describe an argument or option that a command
takes, or an attribute that a command returns.  The `Param` base class is not
used directly, but there are many subclasses for specific Python data types
(like `Str` or `Int`) and specific properties (like `Password`).

To create a `Param` instance, you must always provide the parameter *name*,
which should be the LDAP attribute name if the parameter describes the attribute
of an LDAP entry.  For example, we could create an `Str` instance describing the user's last-name attribute like this:

>>> from ipalib import Str
>>> sn = Str('sn')
>>> sn.name
'sn'

When creating a `Param`, there are also a number of optional kwargs which
which can provide additional meta-data and functionality.  For example, every
parameter has a *cli_name*, the name used on the command-line-interface.  By
default the *cli_name* is the same as the *name*:

>>> sn.cli_name
'sn'

But often the LDAP attribute name isn't user friendly for the command-line, so
you can override this with the *cli_name* kwarg:

>>> sn = Str('sn', cli_name='last')
>>> sn.name
'sn'
>>> sn.cli_name
'last'

Note that the RPC interfaces (and the internal processing pipeline) always use
the parameter *name*, regardless of what the *cli_name* might be.

A `Param` also has two translatable kwargs: *label* and *doc*.  These must both
be `Gettext` instances.  They both default to a place-holder `FixMe` instance,
a subclass of `Gettext` used to mark a missing translatable string:

>>> sn.label
FixMe('sn')
>>> sn.doc
FixMe('sn')

The *label* is a short phrase describing the parameter.  It's used on the CLI
when interactively prompting for values, and as a label for form inputs in the
web-UI.  The *label* should start with an initial capital.  For example:

>>> from ipalib import _
>>> sn = Str('sn',
...     cli_name='last',
...     label=_('Last name'),
... )
>>> sn.label
Gettext('Last name', domain='ipa', localedir=None)

The *doc* is a longer description of the parameter.  It's used on the CLI when
displaying the help information for a command, and as extra instruction for a
form input on the web-UI.  By default the *doc* is the same as the *label*:

>>> sn.doc
Gettext('Last name', domain='ipa', localedir=None)

But you can override this with the *doc* kwarg.  Like the *label*, the *doc*
should also start with an initial capital and should not end with any
punctuation.  For example:

>>> sn = Str('sn',
...     cli_name='last',
...     label=_('Last name'),
...     doc=_("The user's last name"),
... )
>>> sn.doc
Gettext("The user's last name", domain='ipa', localedir=None)

Demonstration aside, you should always provide at least the *label* so the
various UIs are translatable.  Only provide the *doc* if the parameter needs
a more detailed description for clarity.
"""

import re
import decimal
import base64
import binascii
import datetime
import inspect
import typing
from xmlrpc.client import MAXINT, MININT

import six
from cryptography import x509 as crypto_x509
import dns.name

from ipalib.text import _ as ugettext
from ipalib.base import check_name
from ipalib.plugable import ReadOnly, lock
from ipalib.errors import ConversionError, RequirementError, ValidationError
from ipalib.errors import (
    PasswordMismatch, Base64DecodeError, CertificateFormatError,
    CertificateOperationError
)
from ipalib.constants import TYPE_ERROR, CALLABLE_ERROR, LDAP_GENERALIZED_TIME_FORMAT
from ipalib.text import Gettext, FixMe
from ipalib.util import json_serialize, validate_idna_domain
from ipalib.x509 import (
    load_der_x509_certificate, IPACertificate, default_backend)
from ipalib.util import strip_csr_header, apirepr
from ipapython import kerberos
from ipapython.dn import DN
from ipapython.dnsutil import DNSName


MAX_UINT32 = (1 << 32) - 1
# JavaScript Number.MAX_SAFE_INTEGER / Number.MIN_SAFE_INTEGER
# JSON cannot safely encode values outside this range as regular number
MAX_SAFE_INTEGER = (2**53) - 1
MIN_SAFE_INTEGER = -MAX_SAFE_INTEGER


def _is_null(value):
    if value:
        return False
    elif isinstance(value, (int, float, decimal.Decimal)):
        # 0 is not NULL
        return False
    else:
        return True

if six.PY3:
    unicode = str


class DefaultFrom(ReadOnly):
    """
    Derive a default value from other supplied values.

    For example, say you wanted to create a default for the user's login from
    the user's first and last names. It could be implemented like this:

    >>> login = DefaultFrom(lambda first, last: first[0] + last)
    >>> login(first='John', last='Doe')
    'JDoe'

    If you do not explicitly provide keys when you create a `DefaultFrom`
    instance, the keys are implicitly derived from your callback by
    inspecting ``callback.func_code.co_varnames``. The keys are available
    through the ``DefaultFrom.keys`` instance attribute, like this:

    >>> login.keys
    ('first', 'last')

    The callback is available through the ``DefaultFrom.callback`` instance
    attribute, like this:

    >>> login.callback  # doctest:+ELLIPSIS
    <function <lambda> at 0x...>
    >>> login.callback.func_code.co_varnames  # The keys
    ('first', 'last')

    The keys can be explicitly provided as optional positional arguments after
    the callback. For example, this is equivalent to the ``login`` instance
    above:

    >>> login2 = DefaultFrom(lambda a, b: a[0] + b, 'first', 'last')
    >>> login2.keys
    ('first', 'last')
    >>> login2.callback.func_code.co_varnames  # Not the keys
    ('a', 'b')
    >>> login2(first='John', last='Doe')
    'JDoe'

    If any keys are missing when calling your `DefaultFrom` instance, your
    callback is not called and ``None`` is returned.  For example:

    >>> login(first='John', lastname='Doe') is None
    True
    >>> login() is None
    True

    Any additional keys are simply ignored, like this:

    >>> login(last='Doe', first='John', middle='Whatever')
    'JDoe'

    As above, because `DefaultFrom.__call__` takes only pure keyword
    arguments, they can be supplied in any order.

    Of course, the callback need not be a ``lambda`` expression. This third
    example is equivalent to both the ``login`` and ``login2`` instances
    above:

    >>> def get_login(first, last):
    ...     return first[0] + last
    ...
    >>> login3 = DefaultFrom(get_login)
    >>> login3.keys
    ('first', 'last')
    >>> login3.callback.func_code.co_varnames
    ('first', 'last')
    >>> login3(first='John', last='Doe')
    'JDoe'
    """

    def __init__(self, callback, *keys):
        """
        :param callback: The callable to call when all keys are present.
        :param keys: Optional keys used for source values.
        """
        if not callable(callback):
            raise TypeError(
                CALLABLE_ERROR % ('callback', callback, type(callback))
            )
        self.callback = callback
        if len(keys) == 0:
            fc = callback.__code__
            if fc.co_flags & 0x0c:
                raise ValueError("callback: variable-length argument list not allowed")
            self.keys = fc.co_varnames[:fc.co_argcount]
        else:
            self.keys = keys
        for key in self.keys:
            if type(key) is not str:
                raise TypeError(
                    TYPE_ERROR % ('keys', str, key, type(key))
                )
        lock(self)

    def __repr__(self):
        args = tuple(repr(k) for k in self.keys)
        return '%s(%s)' % (
            self.__class__.__name__,
            ', '.join(args)
        )

    def __call__(self, **kw):
        """
        Call the callback if all keys are present.

        If all keys are present, the callback is called and its return value is
        returned.  If any keys are missing, ``None`` is returned.

        :param kw: The keyword arguments.
        """
        vals = tuple(kw.get(k, None) for k in self.keys)
        if None in vals:
            return None
        try:
            return self.callback(*vals)
        except Exception:
            pass
        return None

    def __json__(self):
        return self.keys


def parse_param_spec(spec):
    """
    Parse shorthand ``spec`` into to ``(name, kw)``.

    The ``spec`` string determines the parameter name, whether the parameter is
    required, and whether the parameter is multivalue according the following
    syntax:

    ======  =====  ========  ==========
    Spec    Name   Required  Multivalue
    ======  =====  ========  ==========
    'var'   'var'  True      False
    'var?'  'var'  False     False
    'var*'  'var'  False     True
    'var+'  'var'  True      True
    ======  =====  ========  ==========

    For example,

    >>> parse_param_spec('login')
    ('login', {'required': True, 'multivalue': False})
    >>> parse_param_spec('gecos?')
    ('gecos', {'required': False, 'multivalue': False})
    >>> parse_param_spec('telephone_numbers*')
    ('telephone_numbers', {'required': False, 'multivalue': True})
    >>> parse_param_spec('group+')
    ('group', {'required': True, 'multivalue': True})

    :param spec: A spec string.
    """
    if type(spec) is not str:
        raise TypeError(
            TYPE_ERROR % ('spec', str, spec, type(spec))
        )
    _map = {
        '?': dict(required=False, multivalue=False),
        '*': dict(required=False, multivalue=True),
        '+': dict(required=True, multivalue=True),
    }
    end = spec[-1]
    if end in _map:
        return (spec[:-1], _map[end])
    return (spec, dict(required=True, multivalue=False))


__messages = set()

def _(message):
    __messages.add(message)
    return message


class Param(ReadOnly):
    """
    Base class for all parameters.

    Param attributes:
    =================
    The behavior of Param class and subclasses can be controlled using the
    following set of attributes:

      - cli_name: option name in CLI
      - cli_short_name: one character version of cli_name
      - deprecated_cli_aliases: deprecated CLI aliases
      - label: very short description of the parameter. This value is used in
        when the Command output is printed to CLI or in a Command help
      - doc: parameter long description used in help
      - required: the parameter is marked as required for given Command
      - multivalue: indicates if the attribute is multivalued
      - primary_key: Command's parameter primary key is used for unique
        identification of an LDAP object and for sorting
      - normalizer: a custom function for Param value normalization
      - default_from: a custom function for generating default values of
        parameter instance
      - autofill: by default, only `required` parameters get a default value
        from the default_from function. When autofill is enabled, optional
        attributes get the default value filled too
      - query: this attribute is controlled by framework. When the `query`
        is enabled, framework assumes that the value is only queried and not
        inserted in the LDAP. Validation is then relaxed - custom
        parameter validators are skipped and only basic class validators are
        executed to check the parameter value
      - attribute: this attribute is controlled by framework and enabled for
        all LDAP objects parameters (unless parameter has "virtual_attribute"
        flag). All parameters with enabled `attribute` are being encoded and
        placed to an entry passed to LDAP Create/Update calls
      - include: a list of contexts where this parameter should be included.
        `Param.use_in_context()` provides further information.
      - exclude: a list of contexts where this parameter should be excluded.
        `Param.use_in_context()` provides further information.
      - flags: there are several flags that can be used to further tune the
        parameter behavior:
            * no_display (Output parameters only): do not display the parameter
            * no_create: do not include the parameter for crud.Create based
              commands
            * no_update: do not include the parameter for crud.Update based
              commands
            * no_search: do not include the parameter for crud.Search based
              commands
            * no_option: this attribute is not displayed in the CLI, usually
              because there's a better way of setting it (for example, a
              separate command)
            * virtual_attribute: the parameter is not stored physically in the
              LDAP and thus attribute `attribute` is not enabled
            * suppress_empty (Output parameters only): do not display parameter
              value when empty
            * ask_create: CLI asks for parameter value even when the parameter
              is not `required`. Applied for all crud.Create based commands
            * ask_update: CLI asks for parameter value even when the parameter
              is not `required`. Applied for all crud.Update based commands
            * req_update: The parameter is `required` in all crud.Update based
              commands
            * nonempty: This is an internal flag; a required attribute should
              be used instead of it.
              The value of this parameter must not be empty, but it may
              not be given at all. All crud.Update commands automatically
              convert required parameters to `nonempty` ones, so the value
              can be unspecified (unchanged) but cannot be deleted.
            * optional_create: do not require the parameter for crud.Create
              based commands
            * allow_mod_for_managed_permission: permission-mod allows changing
              the parameter for managed permissions
      - hint: this attribute is currently not used
      - alwaysask: when enabled, CLI asks for parameter value even when the
        parameter is not `required`
      - sortorder: used to sort a list of parameters for Command. See
        `Command.finalize()` for further information
      - confirm: if password, ask for confirmation
    """

    # This is a dummy type so that most of the functionality of Param can be
    # unit tested directly without always creating a subclass; however, a real
    # (direct) subclass must *always* override this class attribute.
    # If multiple types are permitted, set `type` to the canonical type and
    # `allowed_types` to a tuple of all allowed types.
    type = type(None) # Ouch, this wont be very useful in the real world!

    # Subclasses should override this with something more specific:
    type_error = _('incorrect type')

    # _convert_scalar operates only on scalar values
    scalar_error = _('Only one value is allowed')

    password = False

    kwargs = (
        ('cli_name', str, None),
        ('cli_short_name', str, None),
        ('deprecated_cli_aliases', frozenset, frozenset()),
        ('label', (str, Gettext), None),
        ('doc', (str, Gettext), None),
        ('required', bool, True),
        ('multivalue', bool, False),
        ('primary_key', bool, False),
        ('normalizer', callable, None),
        ('default_from', DefaultFrom, None),
        ('autofill', bool, False),
        ('query', bool, False),
        ('attribute', bool, False),
        ('include', frozenset, None),
        ('exclude', frozenset, None),
        ('flags', frozenset, frozenset()),
        ('hint', (str, Gettext), None),
        ('alwaysask', bool, False),
        ('sortorder', int, 2), # see finalize()
        ('option_group', unicode, None),
        ('cli_metavar', str, None),
        ('no_convert', bool, False),
        ('deprecated', bool, False),
        ('confirm', bool, True),

        # The 'default' kwarg gets appended in Param.__init__():
        # ('default', self.type, None),
    )

    @property
    def allowed_types(self):
        """The allowed datatypes for this Param"""
        return (self.type,)

    def __init__(self, name, *rules, **kw):
        # Merge in kw from parse_param_spec():
        (name, kw_from_spec) = parse_param_spec(name)
        check_name(name)
        if 'required' not in kw:
            kw['required'] = kw_from_spec['required']
        if 'multivalue' not in kw:
            kw['multivalue'] = kw_from_spec['multivalue']

        # Add 'default' to self.kwargs
        if kw.get('multivalue', True):
            self.kwargs += (('default', tuple, None),)
        else:
            self.kwargs += (('default', self.type, None),)

        # Wrap 'default_from' in a DefaultFrom if not already:
        df = kw.get('default_from')
        if callable(df) and not isinstance(df, DefaultFrom):
            kw['default_from'] = DefaultFrom(df)

        # Perform type validation on kw:
        for (key, kind, default) in self.kwargs:
            value = kw.get(key)
            if value is not None:
                if kind in (tuple, frozenset):
                    if type(value) in (list, tuple, set, frozenset):
                        value = kind(value)
                    elif type(value) is str:
                        value = kind([value])
                if kind is callable and not callable(value):
                    raise TypeError(
                        CALLABLE_ERROR % (key, value, type(value))
                    )
                elif (isinstance(kind, (type, tuple)) and
                      not isinstance(value, kind)):
                    raise TypeError(
                        TYPE_ERROR % (key, kind, value, type(value))
                    )
                kw[key] = value
            elif key not in ('required', 'multivalue'):
                kw.pop(key, None)

        # We keep these values to use in __repr__():
        if kw['required']:
            if kw['multivalue']:
                self.param_spec = name + '+'
            else:
                self.param_spec = name
        else:
            if kw['multivalue']:
                self.param_spec = name + '*'
            else:
                self.param_spec = name + '?'
        self.__kw = dict(kw)
        del self.__kw['required']
        del self.__kw['multivalue']

        self.name = name
        self.nice = '%s(%r)' % (self.__class__.__name__, self.param_spec)

        # Make sure no unknown kw were given:
        assert all(isinstance(t, type) for t in self.allowed_types)
        if not set(t[0] for t in self.kwargs).issuperset(self.__kw):
            extra = set(kw) - set(t[0] for t in self.kwargs)
            raise TypeError(
                '%s: takes no such kwargs: %s' % (self.nice,
                    ', '.join(repr(k) for k in sorted(extra))
                )
            )

        # We keep this copy with merged values also to use when cloning:
        self.__clonekw = dict(kw)

        # Merge in default for 'cli_name', label, doc if not given:
        if kw.get('cli_name') is None:
            kw['cli_name'] = self.name

        if kw.get('cli_metavar') is None:
            kw['cli_metavar'] = self.__class__.__name__.upper()

        if kw.get('label') is None:
            kw['label'] = FixMe(self.name)

        if kw.get('doc') is None:
            kw['doc'] = kw['label']

        # Add in class rules:
        class_rules = []
        for (key, kind, default) in self.kwargs:
            value = kw.get(key, default)
            if hasattr(self, key):
                raise ValueError('kwarg %r conflicts with attribute on %s' % (
                    key, self.__class__.__name__)
                )
            setattr(self, key, value)
            rule_name = '_rule_%s' % key
            if value is not None and hasattr(self, rule_name):
                class_rules.append(getattr(self, rule_name))
        check_name(self.cli_name)

        # Check that only 'include' or 'exclude' was provided:
        if None not in (self.include, self.exclude):
            raise ValueError(
                '%s: cannot have both %s=%r and %s=%r' % (
                    self.nice,
                    'include', self.include,
                    'exclude', self.exclude,
                )
            )

        # Check that all the rules are callable
        self.class_rules = tuple(class_rules)
        self.rules = rules
        if self.query:  # pylint: disable=using-constant-test
            # by definition a query enforces no class or parameter rules
            self.all_rules = ()
        else:
            self.all_rules = self.class_rules + self.rules
        for rule in self.all_rules:
            if not callable(rule):
                raise TypeError(
                    '%s: rules must be callable; got %r' % (self.nice, rule)
                )

        # Check that cli_short_name is only 1 character long:
        if not (self.cli_short_name is None or len(self.cli_short_name) == 1):
            raise ValueError(
                '%s: cli_short_name can only be a single character: %s' % (
                    self.nice, self.cli_short_name)
            )

        # And we're done.
        lock(self)

    def __repr__(self):
        """
        Return an expresion that could construct this `Param` instance.
        """
        return '%s(%s)' % (
            self.__class__.__name__,
            ', '.join(self.__repr_iter())
        )

    def __repr_iter(self):
        yield repr(self.param_spec)
        for rule in self.rules:
            yield rule.__name__
        for key in sorted(self.__kw):
            value = self.__kw[key]
            if callable(value) and hasattr(value, '__name__'):
                value = value.__name__
            elif isinstance(value, int):
                value = str(value)
            elif isinstance(value, (tuple, set, frozenset)):
                value = apirepr(list(value))
            elif key == 'cli_name':
                # always represented as native string
                value = repr(value)
            else:
                value = apirepr(value)
            yield '%s=%s' % (key, value)

    def __call__(self, value, **kw):
        """
        One stop shopping.
        """
        if _is_null(value):
            value = self.get_default(**kw)
        else:
            value = self.convert(self.normalize(value))
        return value

    def get_param_name(self):
        """
        Return the right name of an attribute depending on usage.

        Normally errors should use cli_name, our "friendly" name. When
        using the API directly or *attr return the real name.
        """
        name = self.cli_name
        if not name:
            name = self.name
        return name

    def kw(self):
        """
        Iterate through ``(key,value)`` for all kwargs passed to constructor.
        """
        for key in sorted(self.__kw):
            value = self.__kw[key]
            if callable(value) and hasattr(value, '__name__'):
                value = value.__name__
            yield (key, value)

    def use_in_context(self, env):
        """
        Return ``True`` if this parameter should be used in ``env.context``.

        If a parameter is created with niether the ``include`` nor the
        ``exclude`` kwarg, this method will always return ``True``.  For
        example:

        >>> from ipalib.config import Env
        >>> param = Param('my_param')
        >>> param.use_in_context(Env(context='foo'))
        True
        >>> param.use_in_context(Env(context='bar'))
        True

        If a parameter is created with an ``include`` kwarg, this method will
        only return ``True`` if ``env.context`` is in ``include``.  For example:

        >>> param = Param('my_param', include=['foo', 'whatever'])
        >>> param.include
        frozenset(['foo', 'whatever'])
        >>> param.use_in_context(Env(context='foo'))
        True
        >>> param.use_in_context(Env(context='bar'))
        False

        If a paremeter is created with an ``exclude`` kwarg, this method will
        only return ``True`` if ``env.context`` is not in ``exclude``.  For
        example:

        >>> param = Param('my_param', exclude=['foo', 'whatever'])
        >>> param.exclude
        frozenset(['foo', 'whatever'])
        >>> param.use_in_context(Env(context='foo'))
        False
        >>> param.use_in_context(Env(context='bar'))
        True

        Note that the ``include`` and ``exclude`` kwargs are mutually exclusive
        and that at most one can be suppelied to `Param.__init__()`.  For
        example:

        >>> param = Param('nope', include=['foo'], exclude=['bar'])
        Traceback (most recent call last):
          ...
        ValueError: Param('nope'): cannot have both include=frozenset(['foo']) and exclude=frozenset(['bar'])

        So that subclasses can add additional logic based on other environment
        variables, the entire `config.Env` instance is passed in rather than
        just the value of ``env.context``.
        """
        if self.include is not None:
            return (env.context in self.include)
        if self.exclude is not None:
            return (env.context not in self.exclude)
        return True

    def safe_value(self, value):
        """
        Return a value safe for logging.

        This is used so that sensitive values like passwords don't get logged.
        For example:

        >>> p = Password('my_password')
        >>> p.safe_value(u'This is my password')
        u'********'
        >>> p.safe_value(None) is None
        True

        >>> s = Str('my_str')
        >>> s.safe_value(u'Some arbitrary value')
        u'Some arbitrary value'
        """
        if self.password and value is not None:
            return u'********'
        return value

    def clone(self, **overrides):
        """
        Return a new `Param` instance similar to this one.
        """
        return self.clone_rename(self.name, **overrides)

    def clone_rename(self, name, **overrides):
        """
        Return a new `Param` instance similar to this one, but named differently
        """
        return self.clone_retype(name, self.__class__, **overrides)

    def clone_retype(self, name, klass, **overrides):
        """
        Return a new `Param` instance similar to this one, but of a different type
        """
        kw = dict(self.__clonekw)
        kw.update(overrides)
        return klass(name, *self.rules, **kw)

    def normalize(self, value):
        """
        Normalize ``value`` using normalizer callback.

        For example:

        >>> param = Param('telephone',
        ...     normalizer=lambda value: value.replace('.', '-')
        ... )
        >>> param.normalize(u'800.123.4567')
        u'800-123-4567'

        If this `Param` instance was created with a normalizer callback and
        ``value`` is a unicode instance, the normalizer callback is called and
        *its* return value is returned.

        On the other hand, if this `Param` instance was *not* created with a
        normalizer callback, if ``value`` is *not* a unicode instance, or if an
        exception is caught when calling the normalizer callback, ``value`` is
        returned unchanged.

        :param value: A proposed value for this parameter.
        """
        if self.multivalue:  # pylint: disable=using-constant-test
            if type(value) not in (tuple, list):
                value = (value,)
        if self.multivalue:  # pylint: disable=using-constant-test
            return tuple(
                self._normalize_scalar(v) for v in value
            )
        else:
            return self._normalize_scalar(value)

    def _normalize_scalar(self, value):
        """
        Normalize a scalar value.

        This method is called once for each value in a multivalue.
        """
        if self.normalizer is None:
            return value
        try:
            return self.normalizer(value)
        except Exception:
            return value

    def convert(self, value):
        """
        Convert ``value`` to the Python type required by this parameter.

        For example:

        >>> scalar = Str('my_scalar')
        >>> scalar.type
        <type 'unicode'>
        >>> scalar.convert(43.2)
        u'43.2'

        (Note that `Str` is a subclass of `Param`.)

        All non-numeric, non-boolean values which evaluate to False will be
        converted to None.  For example:

        >>> scalar.convert(u'') is None  # An empty string
        True
        >>> scalar.convert([]) is None  # An empty list
        True

        Likewise, they will be filtered out of a multivalue parameter.
        For example:

        >>> multi = Str('my_multi', multivalue=True)
        >>> multi.convert([1.5, '', 17, None, u'Hello'])
        (u'1.5', u'17', u'Hello')
        >>> multi.convert([None, u'']) is None  # Filters to an empty list
        True

        Lastly, multivalue parameters will always return a ``tuple`` (assuming
        they don't return ``None`` as in the last example above).  For example:

        >>> multi.convert(42)  # Called with a scalar value
        (u'42',)
        >>> multi.convert([0, 1])  # Called with a list value
        (u'0', u'1')

        Note that how values are converted (and from what types they will be
        converted) completely depends upon how a subclass implements its
        `Param._convert_scalar()` method.  For example, see
        `Str._convert_scalar()`.

        :param value: A proposed value for this parameter.
        """
        if not self.no_convert:
            convert = self._convert_scalar
        else:
            def convert(value):
                if isinstance(value, unicode):
                    return value
                return self._convert_scalar(value)

        if _is_null(value):
            return
        if self.multivalue:  # pylint: disable=using-constant-test
            if type(value) not in (tuple, list):
                value = (value,)
            values = tuple(
                convert(v) for v in value if not _is_null(v)
            )
            if len(values) == 0:
                return
            return values
        return convert(value)

    def _convert_scalar(self, value, index=None):
        """
        Convert a single scalar value.
        """
        for t in self.allowed_types:
            if isinstance(value, t):
                return value

        raise ConversionError(name=self.name, error=ugettext(self.type_error))

    def validate(self, value, supplied=None):
        """
        Check validity of ``value``.

        :param value: A proposed value for this parameter.
        :param supplied: True if this parameter was supplied explicitly.
        """
        if value is None:
            if self.required or (supplied and 'nonempty' in self.flags):
                raise RequirementError(name=self.name)
            return
        if self.deprecated:  # pylint: disable=using-constant-test
            raise ValidationError(name=self.get_param_name(),
                                  error=_('this option is deprecated'))
        if self.multivalue:  # pylint: disable=using-constant-test
            if type(value) is not tuple:
                raise TypeError(
                    TYPE_ERROR % ('value', tuple, value, type(value))
                )
            if len(value) < 1:
                raise ValueError('value: empty tuple must be converted to None')
            for v in value:
                self._validate_scalar(v)
        else:
            self._validate_scalar(value)

    def _validate_scalar(self, value, index=None):
        for t in self.allowed_types:
            if isinstance(value, t):
                break
        else:
            raise TypeError(
                TYPE_ERROR % (self.name, self.type, value, type(value))
            )
        for rule in self.all_rules:
            error = rule(ugettext, value)
            if error is not None:
                raise ValidationError(name=self.get_param_name(), error=error)

    def get_default(self, **kw):
        """
        Return the static default or construct and return a dynamic default.

        (In these examples, we will use the `Str` and `Bytes` classes, which
        both subclass from `Param`.)

        The *default* static default is ``None``.  For example:

        >>> s = Str('my_str')
        >>> s.default is None
        True
        >>> s.get_default() is None
        True

        However, you can provide your own static default via the ``default``
        keyword argument when you create your `Param` instance.  For example:

        >>> s = Str('my_str', default=u'My Static Default')
        >>> s.default
        u'My Static Default'
        >>> s.get_default()
        u'My Static Default'

        If you need to generate a dynamic default from other supplied parameter
        values, provide a callback via the ``default_from`` keyword argument.
        This callback will be automatically wrapped in a `DefaultFrom` instance
        if it isn't one already (see the `DefaultFrom` class for all the gory
        details).  For example:

        >>> login = Str('login', default=u'my-static-login-default',
        ...     default_from=lambda first, last: (first[0] + last).lower(),
        ... )
        >>> isinstance(login.default_from, DefaultFrom)
        True
        >>> login.default_from.keys
        ('first', 'last')

        Then when all the keys needed by the `DefaultFrom` instance are present,
        the dynamic default is constructed and returned.  For example:

        >>> kw = dict(last=u'Doe', first=u'John')
        >>> login.get_default(**kw)
        u'jdoe'

        Or if any keys are missing, your *static* default is returned.
        For example:

        >>> kw = dict(first=u'John', department=u'Engineering')
        >>> login.get_default(**kw)
        u'my-static-login-default'
        """
        if self.default_from is not None:
            default = self.default_from(**kw)
            if default is not None:
                try:
                    return self.convert(self.normalize(default))
                except Exception:
                    pass
        return self.default

    def sort_key(self, value):
        return value

    def __json__(self):
        json_dict = {}
        for a, k, _d in self.kwargs:
            if k in (callable, DefaultFrom):
                continue
            if isinstance(getattr(self, a), frozenset):
                json_dict[a] = list(getattr(self, a, []))
            else:
                val = getattr(self, a, '')
                if val is None:
                    # ignore 'not set' because lack of their presence is
                    # the information itself
                    continue
                json_dict[a] = json_serialize(val)

        json_dict['class'] = self.__class__.__name__
        json_dict['name'] = self.name
        json_dict['type'] = self.type.__name__

        return json_dict


class Bool(Param):
    """
    A parameter for boolean values (stored in the ``bool`` type).
    """

    type = bool
    type_error = _('must be True or False')

    # FIXME: This my quick hack to get some UI stuff working, change these defaults
    #   --jderose 2009-08-28
    kwargs = Param.kwargs + (
        ('truths', frozenset, frozenset([1, u'1', True, u'true', u'TRUE'])),
        ('falsehoods', frozenset, frozenset([0, u'0', False, u'false', u'FALSE'])),
    )

    def _convert_scalar(self, value, index=None):
        """
        Convert a single scalar value.
        """
        if type(value) in self.allowed_types:
            return value
        if isinstance(value, str):
            value = value.lower()
        if value in self.truths:
            return True
        if value in self.falsehoods:
            return False
        if type(value) in (tuple, list):
            raise ConversionError(name=self.name,
                                  error=ugettext(self.scalar_error))
        raise ConversionError(name=self.name, error=ugettext(self.type_error))


class Flag(Bool):
    """
    A boolean parameter that always gets filled in with a default value.

    This `Bool` subclass forces ``autofill=True`` in `Flag.__init__()`.  If no
    default is provided, it also fills in a default value of ``False``.
    Lastly, unlike the `Bool` class, the default must be either ``True`` or
    ``False`` and cannot be ``None``.

    For example:

    >>> flag = Flag('my_flag')
    >>> (flag.autofill, flag.default)
    (True, False)

    To have a default value of ``True``, create your `Flag` intance with
    ``default=True``.  For example:

    >>> flag = Flag('my_flag', default=True)
    >>> (flag.autofill, flag.default)
    (True, True)

    Also note that creating a `Flag` instance with ``autofill=False`` will have
    no effect.  For example:

    >>> flag = Flag('my_flag', autofill=False)
    >>> flag.autofill
    True
    """

    def __init__(self, name, *rules, **kw):
        kw['autofill'] = True
        if 'default' not in kw:
            kw['default'] = False
        if type(kw['default']) is not bool:
            default = kw['default']
            raise TypeError(
                TYPE_ERROR % ('default', bool, default, type(default))
            )
        super(Flag, self).__init__(name, *rules, **kw)


class Number(Param):
    """
    Base class for the `Int` and `Decimal` parameters.
    """

    def _convert_scalar(self, value, index=None):
        """
        Convert a single scalar value.
        """
        if type(value) in self.allowed_types:
            return value
        if type(value) in (unicode, float, int):
            try:
                return self.type(value)
            except ValueError:
                pass
        if type(value) in (tuple, list):
            raise ConversionError(name=self.name,
                                  error=ugettext(self.scalar_error))
        raise ConversionError(name=self.name, error=ugettext(self.type_error))


class Int(Number):
    """
    A parameter for integer values (stored in the ``int`` type).
    """

    type = int
    allowed_types = (int,)
    type_error = _('must be an integer')

    MININT = MININT
    MAXINT = MAXINT
    MAX_UINT32 = MAX_UINT32
    MAX_SAFE_INTEGER = MAX_SAFE_INTEGER
    MIN_SAFE_INTEGER = MIN_SAFE_INTEGER

    kwargs = Param.kwargs + (
        ('minvalue', int, int(MININT)),
        ('maxvalue', int, int(MAXINT)),
    )

    @staticmethod
    def convert_int(value):
        if type(value) in Int.allowed_types:
            return value

        if type(value) is float:
            return int(value)

        if type(value) is unicode:
            if u'.' in value:
                return int(float(value))
            if six.PY3 and re.match('0[0-9]+', value):
                # 0-prefixed octal format
                return int(value, 8)
            return int(value, 0)

        raise ValueError(value)

    def __init__(self, name, *rules, **kw):
        super(Int, self).__init__(name, *rules, **kw)

        if (self.minvalue > self.maxvalue) and (self.minvalue is not None and self.maxvalue is not None):
            raise ValueError(
                '%s: minvalue > maxvalue (minvalue=%r, maxvalue=%r)' % (
                    self.nice, self.minvalue, self.maxvalue)
            )
        if self.minvalue < self.MIN_SAFE_INTEGER:
            raise ValueError(
                f"minvalue {self.minvalue} outside range of safe JSON "
                f"integer limit {self.MIN_SAFE_INTEGER}"
            )
        if self.maxvalue > self.MAX_SAFE_INTEGER:
            raise ValueError(
                f"maxvalue {self.maxvalue} outside range of safe JSON "
                f"integer limit {self.MAX_SAFE_INTEGER}"
            )

    def _convert_scalar(self, value, index=None):
        """
        Convert a single scalar value.
        """
        try:
            return Int.convert_int(value)
        except ValueError:
            raise ConversionError(name=self.get_param_name(),
                                  error=ugettext(self.type_error))

    def _rule_minvalue(self, _, value):
        """
        Check min constraint.
        """
        assert isinstance(value, int)
        if value < self.minvalue:
            return _('must be at least %(minvalue)d') % dict(
                minvalue=self.minvalue,
            )
        else:
            return None

    def _rule_maxvalue(self, _, value):
        """
        Check max constraint.
        """
        assert isinstance(value, int)
        if value > self.maxvalue:
            return _('can be at most %(maxvalue)d') % dict(
                maxvalue=self.maxvalue,
            )
        else:
            return None


class Decimal(Number):
    """
    A parameter for floating-point values (stored in the ``Decimal`` type).

    Python Decimal type helps overcome problems tied to plain "float" type,
    e.g. problem with representation or value comparison. In order to safely
    transfer the value over RPC libraries, it is being converted to string
    which is then converted back to Decimal number.
    """

    type = decimal.Decimal
    type_error = _('must be a decimal number')

    kwargs = Param.kwargs + (
        ('minvalue', decimal.Decimal, None),
        ('maxvalue', decimal.Decimal, None),
        # round Decimal to given precision
        ('precision', int, None),
        # when False, number is normalized to non-exponential form
        ('exponential', bool, False),
        # set of allowed decimal number classes
        ('numberclass', tuple, ('-Normal', '+Zero', '+Normal')),
    )

    def __init__(self, name, *rules, **kw):
        for kwparam in ('minvalue', 'maxvalue', 'default'):
            value = kw.get(kwparam)
            if value is None:
                continue
            if isinstance(value, (str, float)):
                try:
                    value = decimal.Decimal(value)
                except Exception as e:
                    raise ValueError(
                       '%s: cannot parse kwarg %s: %s' % (
                        name, kwparam, str(e)))
                kw[kwparam] = value

        super(Decimal, self).__init__(name, *rules, **kw)

        if (self.minvalue is not None and
                self.maxvalue is not None and
                self.minvalue > self.maxvalue):
            raise ValueError(
                '%s: minvalue > maxvalue (minvalue=%s, maxvalue=%s)' % (
                    self.nice, self.minvalue, self.maxvalue)
            )

        if self.precision is not None and self.precision < 0:
            raise ValueError('%s: precision must be at least 0' % self.nice)

    def _rule_minvalue(self, _, value):
        """
        Check min constraint.
        """
        assert type(value) is decimal.Decimal
        if value < self.minvalue:
            return _('must be at least %(minvalue)s') % dict(
                minvalue=self.minvalue,
            )
        else:
            return None

    def _rule_maxvalue(self, _, value):
        """
        Check max constraint.
        """
        assert type(value) is decimal.Decimal
        if value > self.maxvalue:
            return _('can be at most %(maxvalue)s') % dict(
                maxvalue=self.maxvalue,
            )
        else:
            return None

    def _enforce_numberclass(self, value):
        numberclass = value.number_class()
        if numberclass not in self.numberclass:
            raise ValidationError(name=self.get_param_name(),
                    error=_("number class '%(cls)s' is not included in a list "
                            "of allowed number classes: %(allowed)s") \
                            % dict(cls=numberclass,
                                   allowed=u', '.join(self.numberclass))
                )

    def _enforce_precision(self, value):
        assert type(value) is decimal.Decimal
        if self.precision is not None:
            quantize_exp = decimal.Decimal(10) ** -int(self.precision)
            try:
                value = value.quantize(quantize_exp)
            except decimal.DecimalException as e:
                raise ConversionError(name=self.get_param_name(),
                                      error=unicode(e))
        return value

    def _remove_exponent(self, value):
        assert type(value) is decimal.Decimal

        if not self.exponential:
            try:
                # adopted from http://docs.python.org/library/decimal.html
                value = value.quantize(decimal.Decimal(1)) \
                        if value == value.to_integral() \
                        else value.normalize()
            except decimal.DecimalException as e:
                raise ConversionError(name=self.get_param_name(),
                                      error=unicode(e))

        return value

    def _test_and_normalize(self, value):
        """
        This method is run in conversion and normalization methods to test
        that the Decimal number conforms to Parameter boundaries and then
        normalizes the value.
        """
        self._enforce_numberclass(value)
        value = self._remove_exponent(value)
        value = self._enforce_precision(value)
        return value

    def _convert_scalar(self, value, index=None):
        if isinstance(value, (str, float)):
            try:
                value = decimal.Decimal(value)
            except decimal.DecimalException as e:
                raise ConversionError(name=self.get_param_name(),
                                      error=unicode(e))

        if isinstance(value, decimal.Decimal):
            return self._test_and_normalize(value)

        return super(Decimal, self)._convert_scalar(value)

    def _normalize_scalar(self, value):
        if isinstance(value, decimal.Decimal):
            return self._test_and_normalize(value)

        return super(Decimal, self)._normalize_scalar(value)

class Data(Param):
    """
    Base class for the `Bytes` and `Str` parameters.

    Previously `Str` was as subclass of `Bytes`.  Now the common functionality
    has been split into this base class so that ``isinstance(foo, Bytes)`` wont
    be ``True`` when ``foo`` is actually an `Str` instance (which is confusing).
    """

    kwargs = Param.kwargs + (
        ('minlength', int, None),
        ('maxlength', int, None),
        ('length', int, None),
        ('pattern_errmsg', (str,), None),
    )

    re = None
    re_errmsg = None

    def __init__(self, name, *rules, **kw):
        super(Data, self).__init__(name, *rules, **kw)

        if not (
            self.length is None or
            (self.minlength is None and self.maxlength is None)
        ):
            raise ValueError(
                '%s: cannot mix length with minlength or maxlength' % self.nice
            )

        if self.minlength is not None and self.minlength < 1:
            raise ValueError(
                '%s: minlength must be >= 1; got %r' % (self.nice, self.minlength)
            )

        if self.maxlength is not None and self.maxlength < 1:
            raise ValueError(
                '%s: maxlength must be >= 1; got %r' % (self.nice, self.maxlength)
            )

        if None not in (self.minlength, self.maxlength):
            if self.minlength > self.maxlength:
                raise ValueError(
                    '%s: minlength > maxlength (minlength=%r, maxlength=%r)' % (
                        self.nice, self.minlength, self.maxlength)
                )
            elif self.minlength == self.maxlength:
                raise ValueError(
                    '%s: minlength == maxlength; use length=%d instead' % (
                        self.nice, self.minlength)
                )

    def _rule_pattern(self, _, value):
        """
        Check pattern (regex) contraint.
        """
        assert type(value) in self.allowed_types
        if self.re.match(value) is None:
            if self.re_errmsg:
                return self.re_errmsg % dict(pattern=self.pattern,)
            else:
                return _('must match pattern "%(pattern)s"') % dict(
                    pattern=self.pattern,
                )
        else:
            return None


class Bytes(Data):
    """
    A parameter for binary data (stored in the ``str`` type).

    This class is named *Bytes* instead of *Str* so it's aligned with the
    Python v3 ``(str, unicode) => (bytes, str)`` clean-up.  See:

        http://docs.python.org/3.0/whatsnew/3.0.html

    Also see the `Str` parameter.
    """

    type = bytes
    type_error = _('must be binary data')
    kwargs = Data.kwargs + (
        ('pattern', (bytes,), None),
    )

    def __init__(self, name, *rules, **kw):
        if kw.get('pattern', None) is None:
            self.re = None
        else:
            self.re = re.compile(kw['pattern'])
        self.re_errmsg = kw.get('pattern_errmsg', None)
        super(Bytes, self).__init__(name, *rules, **kw)

    def _rule_minlength(self, _, value):
        """
        Check minlength constraint.
        """
        assert type(value) is bytes
        if len(value) < self.minlength:
            return _('must be at least %(minlength)d bytes') % dict(
                minlength=self.minlength,
            )
        else:
            return None

    def _rule_maxlength(self, _, value):
        """
        Check maxlength constraint.
        """
        assert type(value) is bytes
        if len(value) > self.maxlength:
            return _('can be at most %(maxlength)d bytes') % dict(
                maxlength=self.maxlength,
            )
        else:
            return None

    def _rule_length(self, _, value):
        """
        Check length constraint.
        """
        assert type(value) is bytes
        if len(value) != self.length:
            return _('must be exactly %(length)d bytes') % dict(
                length=self.length,
            )
        else:
            return None

    def _convert_scalar(self, value, index=None):
        if isinstance(value, unicode):
            try:
                value = base64.b64decode(value)
            except (TypeError, ValueError) as e:
                raise Base64DecodeError(reason=str(e))
        return super(Bytes, self)._convert_scalar(value)


class Certificate(Param):
    type = crypto_x509.Certificate
    type_error = _('must be a certificate')
    allowed_types = (IPACertificate, bytes, unicode)

    def _convert_scalar(self, value, index=None):
        """
        :param value: either DER certificate or base64 encoded certificate
        :returns: bytes representing value converted to DER format
        """
        if isinstance(value, bytes):
            try:
                value = value.decode('ascii')
            except UnicodeDecodeError:
                # value is possibly a DER-encoded certificate
                pass

        if isinstance(value, unicode):
            # if we received unicodes right away or we got them after the
            # decoding, we will now try to receive DER-certificate
            try:
                value = base64.b64decode(value)
            except (TypeError, ValueError) as e:
                raise Base64DecodeError(reason=str(e))

        if isinstance(value, bytes):
            # we now only have either bytes or an IPACertificate object
            # if it's bytes, make it an IPACertificate object
            try:
                value = load_der_x509_certificate(value)
            except ValueError as e:
                raise CertificateFormatError(error=str(e))

        return super(Certificate, self)._convert_scalar(value)


class CertificateSigningRequest(Param):
    type = crypto_x509.CertificateSigningRequest
    type_error = _('must be a certificate signing request')
    allowed_types = (crypto_x509.CertificateSigningRequest, bytes, unicode)

    def __extract_der_from_input(self, value):
        """
        Tries to get the DER representation of whatever we receive as an input

        :param value:
            bytes instance containing something we hope is a certificate
            signing request
        :returns:
            base64-decoded representation of whatever we found in case input
            had been something else than DER or something which resembles
            DER, in which case we would just return input
        """
        try:
            value.decode('utf-8')
        except UnicodeDecodeError:
            # possibly DER-encoded CSR or something similar
            return value

        value = strip_csr_header(value)
        try:
            return base64.b64decode(value)
        except binascii.Error as e:
            raise CertificateOperationError(
                error=_('not a valid CSR: %s' % e))

    def _convert_scalar(self, value, index=None):
        """
        :param value:
            either DER csr, base64-encoded csr or an object implementing the
            cryptography.CertificateSigningRequest interface
        :returns:
            an object with the cryptography.CertificateSigningRequest interface
        """
        if isinstance(value, unicode):
            try:
                value = value.encode('ascii')
            except UnicodeDecodeError:
                raise CertificateOperationError(error=_('not a valid CSR'))

        if isinstance(value, bytes):
            # try to extract DER from whatever we got
            value = self.__extract_der_from_input(value)
            try:
                value = crypto_x509.load_der_x509_csr(
                    value, backend=default_backend())
            except ValueError as e:
                raise CertificateOperationError(
                    error=_("Failure decoding Certificate Signing Request:"
                            " %s") % e)

        return super(CertificateSigningRequest, self)._convert_scalar(value)


class Str(Data):
    """
    A parameter for Unicode text (stored in the ``unicode`` type).

    This class is named *Str* instead of *Unicode* so it's aligned with the
    Python v3 ``(str, unicode) => (bytes, str)`` clean-up.  See:

        http://docs.python.org/3.0/whatsnew/3.0.html

    Also see the `Bytes` parameter.
    """

    kwargs = Data.kwargs + (
        ('pattern', (str,), None),
        ('noextrawhitespace', bool, True),
    )

    type = unicode
    type_error = _('must be Unicode text')

    def __init__(self, name, *rules, **kw):
        if kw.get('pattern', None) is None:
            self.re = None
        else:
            self.re = re.compile(kw['pattern'], re.UNICODE)
        self.re_errmsg = kw.get('pattern_errmsg', None)
        super(Str, self).__init__(name, *rules, **kw)

    def _convert_scalar(self, value, index=None):
        """
        Convert a single scalar value.
        """
        if type(value) in self.allowed_types:
            return value
        if type(value) in (int, float, decimal.Decimal):
            return self.type(value)
        if type(value) in (tuple, list):
            raise ConversionError(name=self.name,
                                  error=ugettext(self.scalar_error))
        raise ConversionError(name=self.name, error=ugettext(self.type_error))

    def _rule_noextrawhitespace(self, _, value):
        """
        Do not allow leading/trailing spaces.
        """
        assert type(value) is unicode
        if self.noextrawhitespace is False:
            return None
        if len(value) != len(value.strip()):
            return _('Leading and trailing spaces are not allowed')
        else:
            return None

    def _rule_minlength(self, _, value):
        """
        Check minlength constraint.
        """
        assert type(value) is unicode
        if len(value) < self.minlength:
            return _('must be at least %(minlength)d characters') % dict(
                minlength=self.minlength,
            )
        else:
            return None

    def _rule_maxlength(self, _, value):
        """
        Check maxlength constraint.
        """
        assert type(value) is unicode
        if len(value) > self.maxlength:
            return _('can be at most %(maxlength)d characters') % dict(
                maxlength=self.maxlength,
            )
        else:
            return None

    def _rule_length(self, _, value):
        """
        Check length constraint.
        """
        assert type(value) is unicode
        if len(value) != self.length:
            return _('must be exactly %(length)d characters') % dict(
                length=self.length,
            )
        else:
            return None

    def sort_key(self, value):
        return value.lower()

class IA5Str(Str):
    """
    An IA5String per RFC 4517
    """

    def __init__(self, name, *rules, **kw):
        super(IA5Str, self).__init__(name, *rules, **kw)

    def _convert_scalar(self, value, index=None):
        if isinstance(value, str):
            for char in value:
                if ord(char) > 127:
                    raise ConversionError(name=self.get_param_name(),
                        error=_('The character %(char)r is not allowed.') %
                            dict(char=char,)
                    )
        return super(IA5Str, self)._convert_scalar(value)


class Password(Str):
    """
    A parameter for passwords (stored in the ``unicode`` type).
    """

    kwargs = Data.kwargs + (
        ('pattern', (str,), None),
        ('noextrawhitespace', bool, False),
    )

    password = True

    def _convert_scalar(self, value, index=None):
        if isinstance(value, (tuple, list)) and len(value) == 2:
            (p1, p2) = value
            if p1 != p2:
                raise PasswordMismatch(name=self.name)
            value = p1
        return super(Password, self)._convert_scalar(value)


class Enum(Param):
    """
    Base class for parameters with enumerable values.
    """

    kwargs = Param.kwargs + (
        ('values', tuple, tuple()),
    )

    def __init__(self, name, *rules, **kw):
        kw['cli_metavar'] = str([str(v) for v in kw.get('values', tuple())])
        super(Enum, self).__init__(name, *rules, **kw)
        for (i, v) in enumerate(self.values):
            if type(v) not in self.allowed_types:
                n = '%s values[%d]' % (self.nice, i)
                raise TypeError(
                    TYPE_ERROR % (n, self.type, v, type(v))
                )

        if len(self.values) < 1:
            raise ValueError(
                '%s: list of values must not be empty' % self.nice)

    def _rule_values(self, _, value, **kw):
        if value not in self.values:
            if len(self.values) == 1:
                return _("must be '%(value)s'") % dict(value=self.values[0])
            else:
                values = u', '.join("'%s'" % value for value in self.values)
                return _('must be one of %(values)s') % dict(values=values)
        else:
            return None

class BytesEnum(Enum):
    """
    Enumerable for binary data (stored in the ``str`` type).
    """

    type = unicode


class StrEnum(Enum):
    """
    Enumerable for Unicode text (stored in the ``unicode`` type).

    For example:

    >>> enum = StrEnum('my_enum', values=(u'One', u'Two', u'Three'))
    >>> enum.validate(u'Two', 'cli') is None
    True
    >>> enum.validate(u'Four', 'cli')
    Traceback (most recent call last):
      ...
    ValidationError: invalid 'my_enum': must be one of 'One', 'Two', 'Three'
    """

    type = unicode


class IntEnum(Enum):
    """
    Enumerable for integer data (stored in the ``int`` type).
    """

    type = int
    allowed_types = (int,)
    type_error = Int.type_error

    def _convert_scalar(self, value, index=None):
        """
        Convert a single scalar value.
        """
        try:
            return Int.convert_int(value)
        except ValueError:
            raise ConversionError(name=self.get_param_name(),
                                  error=ugettext(self.type_error))


class Any(Param):
    """
    A parameter capable of holding values of any type. For internal use only.
    """

    type = object

    def _convert_scalar(self, value, index=None):
        return value

    def _validate_scalar(self, value, index=None):
        for rule in self.all_rules:
            error = rule(ugettext, value)
            if error is not None:
                raise ValidationError(name=self.name, error=error)


class File(Str):
    """Text file parameter type.

    Accepts file names and loads their content into the parameter value.
    """
    open_mode = 'r'
    kwargs = Data.kwargs + (
        # valid for CLI, other backends (e.g. webUI) can ignore this
        ('stdin_if_missing', bool, False),
        ('noextrawhitespace', bool, False),
    )


class BinaryFile(Bytes):
    """Binary file parameter type
    """
    open_mode = 'rb'
    kwargs = Data.kwargs + (
        # valid for CLI, other backends (e.g. webUI) can ignore this
        ('stdin_if_missing', bool, False),
        ('noextrawhitespace', bool, False),
    )


class DateTime(Param):
    """
    DateTime parameter type.

    Accepts LDAP Generalized time without in the following format:
       '%Y%m%d%H%M%SZ'

    Accepts subset of values defined by ISO 8601:
        '%Y-%m-%dT%H:%M:%SZ'
        '%Y-%m-%dT%H:%MZ'
        '%Y-%m-%dZ'

    Also accepts above formats using ' ' (space) as a separator instead of 'T'.

    Refer to the `man strftime` for the explanations for the %Y,%m,%d,%H.%M,%S.
    """

    accepted_formats = [LDAP_GENERALIZED_TIME_FORMAT,  # generalized time
                        '%Y-%m-%dT%H:%M:%SZ',  # ISO 8601, second precision
                        '%Y-%m-%dT%H:%MZ',     # ISO 8601, minute precision
                        '%Y-%m-%dZ',           # ISO 8601, date only
                        '%Y-%m-%d %H:%M:%SZ',  # non-ISO 8601, second precision
                        '%Y-%m-%d %H:%MZ']     # non-ISO 8601, minute precision


    type = datetime.datetime
    type_error = _('must be datetime value')

    def _convert_scalar(self, value, index=None):
        if isinstance(value, str):
            if value == u'now':
                time = datetime.datetime.now(tz=datetime.timezone.utc)
                return time
            else:
                for date_format in self.accepted_formats:
                    try:
                        time = datetime.datetime.strptime(value, date_format)
                        return time
                    except ValueError:
                        pass

            # If we get here, the strptime call did not succeed for any
            # the accepted formats, therefore raise error

            error = (_("does not match any of accepted formats: ") +
                      (', '.join(self.accepted_formats)))

            raise ConversionError(name=self.get_param_name(),
                                  error=error)

        return super(DateTime, self)._convert_scalar(value)


class AccessTime(Str):
    """
    Access time parameter type.

    Accepts values conforming to generalizedTime as defined in RFC 4517
    section 3.3.13 without time zone information.
    """
    def _check_HHMM(self, t):
        if len(t) != 4:
            raise ValueError('HHMM must be exactly 4 characters long')
        if not t.isnumeric():
            raise ValueError('HHMM non-numeric')
        hh = int(t[0:2])
        if hh < 0 or hh > 23:
            raise ValueError('HH out of range')
        mm = int(t[2:4])
        if mm < 0 or mm > 59:
            raise ValueError('MM out of range')

    def _check_dotw(self, t):
        if t.isnumeric():
            value = int(t)
            if value < 1 or value > 7:
                raise ValueError('day of the week out of range')
        elif t not in ('Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'):
            raise ValueError('invalid day of the week')

    def _check_dotm(self, t, month_num=1, year=4):
        if not t.isnumeric():
            raise ValueError('day of the month non-numeric')
        value = int(t)
        if month_num in (1, 3, 5, 7, 8, 10, 12):
            if value < 1 or value > 31:
                raise ValueError('day of the month out of range')
        elif month_num in (4, 6, 9, 11):
            if value < 1 or value > 30:
                raise ValueError('day of the month out of range')
        elif month_num == 2:
            if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0):
                if value < 1 or value > 29:
                    raise ValueError('day of the month out of range')
            else:
                if value < 1 or value > 28:
                    raise ValueError('day of the month out of range')

    def _check_wotm(self, t):
        if not t.isnumeric():
            raise ValueError('week of the month non-numeric')
        value = int(t)
        if value < 1 or value > 6:
            raise ValueError('week of the month out of range')

    def _check_woty(self, t):
        if not t.isnumeric():
            raise ValueError('week of the year non-numeric')
        value = int(t)
        if value < 1 or value > 52:
            raise ValueError('week of the year out of range')

    def _check_doty(self, t):
        if not t.isnumeric():
            raise ValueError('day of the year non-numeric')
        value = int(t)
        if value < 1 or value > 365:
            raise ValueError('day of the year out of range')

    def _check_month_num(self, t):
        if not t.isnumeric():
            raise ValueError('month number non-numeric')
        value = int(t)
        if value < 1 or value > 12:
            raise ValueError('month number out of range')

    def _check_interval(self, t, check_func):
        intervals = t.split(',')
        for i in intervals:
            if not i:
                raise ValueError('invalid time range')
            values = i.split('-')
            if len(values) > 2:
                raise ValueError('invalid time range')
            for v in values:
                check_func(v)
            if len(values) == 2:
                if int(values[0]) > int(values[1]):
                    raise ValueError('invalid time range')

    def _check_W_spec(self, ts, index):
        if ts[index] != 'day':
            raise ValueError('invalid week specifier')
        index += 1
        self._check_interval(ts[index], self._check_dotw)
        return index

    def _check_M_spec(self, ts, index):
        if ts[index] == 'week':
            self._check_interval(ts[index + 1], self._check_wotm)
            index = self._check_W_spec(ts, index + 2)
        elif ts[index] == 'day':
            index += 1
            self._check_interval(ts[index], self._check_dotm)
        else:
            raise ValueError('invalid month specifier')
        return index

    def _check_Y_spec(self, ts, index):
        if ts[index] == 'month':
            index += 1
            self._check_interval(ts[index], self._check_month_num)
            index = self._check_M_spec(ts, index + 1)
        elif ts[index] == 'week':
            self._check_interval(ts[index + 1], self._check_woty)
            index = self._check_W_spec(ts, index + 2)
        elif ts[index] == 'day':
            index += 1
            self._check_interval(ts[index], self._check_doty)
        else:
            raise ValueError('invalid year specifier')
        return index

    def _check_generalized(self, t):
        assert type(t) is unicode
        if len(t) not in (10, 12, 14):
            raise ValueError('incomplete generalized time')
        if not t.isnumeric():
            raise ValueError('time non-numeric')
        # don't check year value, with time travel and all :)
        self._check_month_num(t[4:6])
        year_num = int(t[0:4])
        month_num = int(t[4:6])
        self._check_dotm(t[6:8], month_num, year_num)
        if len(t) >= 12:
            self._check_HHMM(t[8:12])
        else:
            self._check_HHMM('%s00' % t[8:10])
        if len(t) == 14:
            s = int(t[12:14])
            if s < 0 or s > 60:
                raise ValueError('seconds out of range')

    def _check(self, time):
        ts = time.split()
        if ts[0] == 'absolute':
            if len(ts) != 4:
                raise ValueError('invalid format, must be \'absolute generalizedTime ~ generalizedTime\'')
            self._check_generalized(ts[1])
            if ts[2] != '~':
                raise ValueError('invalid time range separator')
            self._check_generalized(ts[3])
            if int(ts[1]) >= int(ts[3]):
                raise ValueError('invalid time range')
        elif ts[0] == 'periodic':
            index = None
            if ts[1] == 'yearly':
                index = self._check_Y_spec(ts, 2)
            elif ts[1] == 'monthly':
                index = self._check_M_spec(ts, 2)
            elif ts[1] == 'weekly':
                index = self._check_W_spec(ts, 2)
            elif ts[1] == 'daily':
                index = 1
            if index is None:
                raise ValueError('period must be yearly, monthy or daily, got \'%s\'' % ts[1])
            self._check_interval(ts[index + 1], self._check_HHMM)
        else:
            raise ValueError('time neither absolute or periodic')

    def _rule_required(self, _, value):
        try:
            self._check(value)
        except ValueError as e:
            raise ValidationError(name=self.get_param_name(), error=e.args[0])
        except IndexError:
            raise ValidationError(
                name=self.get_param_name(), error=ugettext('incomplete time value')
            )


class DNParam(Param):
    type = DN

    def _convert_scalar(self, value, index=None):
        """
        Convert a single scalar value.
        """
        if type(value) in self.allowed_types:
            return value

        if type(value) in (tuple, list):
            raise ConversionError(name=self.name,
                                  error=ugettext(self.scalar_error))

        try:
            dn = DN(value)
        except Exception as e:
            raise ConversionError(name=self.get_param_name(),
                                  error=ugettext(e))
        return dn


def create_param(spec):
    """
    Create an `Str` instance from the shorthand ``spec``.

    This function allows you to create `Str` parameters (the most common) from
    a convenient shorthand that defines the parameter name, whether it is
    required, and whether it is multivalue.  (For the definition of the
    shorthand syntax, see the `parse_param_spec()` function.)

    If ``spec`` is an ``str`` instance, it will be used to create a new `Str`
    parameter, which will be returned.  For example:

    >>> s = create_param('hometown?')
    >>> s
    Str('hometown?')
    >>> (s.name, s.required, s.multivalue)
    ('hometown', False, False)

    On the other hand, if ``spec`` is already a `Param` instance, it is
    returned unchanged.  For example:

    >>> b = Bytes('cert')
    >>> create_param(b) is b
    True

    As a plugin author, you will not call this function directly (which would
    be no more convenient than simply creating the `Str` instance).  Instead,
    `frontend.Command` will call it for you when it evaluates the
    ``takes_args`` and ``takes_options`` attributes, and `frontend.Object`
    will call it for you when it evaluates the ``takes_params`` attribute.

    :param spec: A spec string or a `Param` instance.
    """
    if isinstance(spec, Param):
        return spec
    if type(spec) is not str:
        raise TypeError(
            TYPE_ERROR % ('spec', (str, Param), spec, type(spec))
        )
    return Str(spec)


class DNSNameParam(Param):
    """
    Domain name parameter type.

    :only_absolute a domain name has to be absolute
        (makes it absolute from unicode input)
    :only_relative a domain name has to be relative
    """
    type = DNSName
    type_error = _('must be DNS name')
    kwargs = Param.kwargs + (
        ('only_absolute', bool, False),
        ('only_relative', bool, False),
    )

    def __init__(self, name, *rules, **kw):
        super(DNSNameParam, self).__init__(name, *rules, **kw)
        if self.only_absolute and self.only_relative:
            raise ValueError('%s: cannot be both absolute and relative' %
                             self.nice)

    def _convert_scalar(self, value, index=None):
        if isinstance(value, unicode):
            try:
                validate_idna_domain(value)
            except ValueError as e:
                raise ConversionError(name=self.get_param_name(),
                                      error=unicode(e))
            value = DNSName(value)

            if self.only_absolute and not value.is_absolute():
                value = value.make_absolute()

        return super(DNSNameParam, self)._convert_scalar(value)

    def _rule_only_absolute(self, _, value):
        if self.only_absolute and not value.is_absolute():
            return _('must be absolute')
        else:
            return None

    def _rule_only_relative(self, _, value):
        if self.only_relative and value.is_absolute():
            return _('must be relative')
        else:
            return None


class Dict(Param):
    """
    A parameter for dictionary.
    """

    type = dict
    type_error = _("must be dictionary")


class Principal(Param):
    """
    Kerberos principal name
    """

    type = kerberos.Principal
    type_error = _('must be Kerberos principal')
    kwargs = Param.kwargs + (
        ('require_service', bool, False),
    )

    @property
    def allowed_types(self):
        return (self.type, unicode)

    def _convert_scalar(self, value, index=None):
        if isinstance(value, unicode):
            try:
                value = kerberos.Principal(value)
            except ValueError:
                raise ConversionError(
                    name=self.get_param_name(),
                    error=_("Malformed principal: '%(value)s'") % dict(
                        value=value))

        return super(Principal, self)._convert_scalar(value)

    def _rule_require_service(self, _, value):
        if self.require_service and not value.is_service:
            raise ValidationError(
                name=self.get_param_name(),
                error=_("Service principal is required")
            )


_map_types = {
    # map internal certificate subclass to generic cryptography class
    IPACertificate: crypto_x509.Certificate,
    # map internal DNS name class to generic dnspython class
    DNSName: dns.name.Name,
    # DN, Principal have their names mangled in ipaapi.__init__
}


def create_signature(command):
    """Create an inspect.Signature for a command

    :param command: ipa plugin instance (server or client)
    :return: inspect.Signature instance
    """

    signature_params = []
    seen = set()
    args_options = [
        (command.get_args(), inspect.Parameter.POSITIONAL_OR_KEYWORD),
        (command.get_options(), inspect.Parameter.KEYWORD_ONLY)
    ]
    for ipaparams, kind in args_options:
        for ipaparam in ipaparams:
            # filter out duplicates, for example user_del has a preserve flag
            # and preserve bool.
            if ipaparam.name in seen:
                continue
            seen.add(ipaparam.name)
            # ipalib.plugins.misc.env has wrong type
            if not isinstance(ipaparam, Param):
                continue

            if ipaparam.required:
                default = inspect.Parameter.empty
            else:
                default = ipaparam.default

            allowed_types = tuple(
                _map_types.get(t, t) for t in ipaparam.allowed_types
            )
            # ipalib.parameters.DNSNameParam also handles text
            if isinstance(ipaparam, DNSNameParam):
                allowed_types += (six.text_type,)
            ann = typing.Union[allowed_types]
            if ipaparam.multivalue:
                ann = typing.List[ann]

            signature_params.append(
                inspect.Parameter(
                    ipaparam.name, kind, default=default, annotation=ann
                )
            )

    # cannot describe return parameter with typing yet. TypedDict
    # is only available with mypy_extension.
    signature = inspect.Signature(
        signature_params,
        return_annotation=typing.Dict[typing.Text, typing.Any]
    )

    return signature


class SerialNumber(Str):
    """Certificate serial number parameter type
    """

    type = str
    allowed_types = (str,)

    # FIXME: currently unused, perhaps drop it
    MAX_VALUE = 340282366920938463463374607431768211456  # 2^128

    kwargs = Param.kwargs + (
        ('minlength', int, 1),
        ('maxlength', int, 40),  # Up to 128-bit values
        ('length', int, None),
    )

    def _validate_scalar(self, value, index=None):
        super(SerialNumber, self)._validate_scalar(value)
        if value.startswith('-'):
            raise ValidationError(
                name=self.name, error=_('must be at least 0')
            )
        if not value.isdigit():
            if value.lower().startswith('0x'):
                try:
                    int(value[2:], 16)
                except ValueError:
                    raise ValidationError(
                        name=self.name, error=_(
                            _('invalid valid hex'),
                        )
                    )
            else:
                raise ValidationError(
                    name=self.name, error=_(
                        _('must be an integer'),
                    )
                )
        if value == '0':
            raise ValidationError(
                name=self.name, error=_('invalid serial number 0')
            )
