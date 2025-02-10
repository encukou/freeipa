# Authors: Simo Sorce <ssorce@redhat.com>
#
# Copyright (C) 2007-2016  Red Hat, Inc.
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from __future__ import print_function

import codecs
import logging
import string
import tempfile
import subprocess
import random
import math
import os
import sys
import errno
import copy
import shutil
import socket
import re
import datetime
import netaddr
import time
import textwrap
import io
from contextlib import contextmanager
from configparser import RawConfigParser, ParsingError
import locale
import collections
import urllib

import six
from six.moves import input

try:
    import ifaddr
except ImportError:
    ifaddr = None

from ipapython.dn import DN
from ipaplatform.paths import paths
from ipaplatform.constants import User, Group


logger = logging.getLogger(__name__)

# only for OTP password that is manually retyped by user
TMP_PWD_ENTROPY_BITS = 128


PROTOCOL_NAMES = {
    socket.SOCK_STREAM: 'tcp',
    socket.SOCK_DGRAM: 'udp'
}

InterfaceDetails = collections.namedtuple(
    'InterfaceDetails', [
        'name',  # interface name
        'ifnet'  # network details of interface
    ])


class UnsafeIPAddress(netaddr.IPAddress):
    """Any valid IP address with or without netmask."""

    # Use inet_pton() rather than inet_aton() for IP address parsing. We
    # will use the same function in IPv4/IPv6 conversions + be stricter
    # and don't allow IP addresses such as '1.1.1' in the same time
    netaddr_ip_flags = netaddr.INET_PTON

    def __init__(self, addr):
        if isinstance(addr, UnsafeIPAddress):
            self._net = addr._net
            super(UnsafeIPAddress, self).__init__(addr,
                                                  flags=self.netaddr_ip_flags)
            return

        elif isinstance(addr, netaddr.IPAddress):
            self._net = None  # no information about netmask
            super(UnsafeIPAddress, self).__init__(addr,
                                                  flags=self.netaddr_ip_flags)
            return

        elif isinstance(addr, netaddr.IPNetwork):
            self._net = addr
            super(UnsafeIPAddress, self).__init__(self._net.ip,
                                                  flags=self.netaddr_ip_flags)
            return

        # option of last resort: parse it as string
        self._net = None
        addr = str(addr)
        try:
            try:
                addr = netaddr.IPAddress(addr, flags=self.netaddr_ip_flags)
            except netaddr.AddrFormatError:
                # netaddr.IPAddress doesn't handle zone indices in textual
                # IPv6 addresses. Try removing zone index and parse the
                # address again.
                addr, sep, _foo = addr.partition('%')
                if sep != '%':
                    raise
                addr = netaddr.IPAddress(addr, flags=self.netaddr_ip_flags)
                if addr.version != 6:
                    raise
        except ValueError:
            self._net = netaddr.IPNetwork(addr, flags=0)
            addr = self._net.ip
        super(UnsafeIPAddress, self).__init__(addr,
                                              flags=self.netaddr_ip_flags)

    def __getstate__(self):
        state = {
            '_net': self._net,
            'super_state': super(UnsafeIPAddress, self).__getstate__(),
        }
        return state

    def __setstate__(self, state):
        super(UnsafeIPAddress, self).__setstate__(state['super_state'])
        self._net = state['_net']


class CheckedIPAddress(UnsafeIPAddress):
    """IPv4 or IPv6 address with additional constraints.

    Reserved or link-local addresses are never accepted.
    """
    def __init__(self, addr, parse_netmask=True,
                 allow_loopback=False, allow_multicast=False):
        try:
            super(CheckedIPAddress, self).__init__(addr)
        except netaddr.core.AddrFormatError as e:
            raise ValueError(e)

        if isinstance(addr, CheckedIPAddress):
            self.prefixlen = addr.prefixlen
            return

        if not parse_netmask and self._net:
            raise ValueError(
                "netmask and prefix length not allowed here: {}".format(addr))

        if self.version not in (4, 6):
            raise ValueError("unsupported IP version {}".format(self.version))

        if not allow_loopback and self.is_loopback():
            raise ValueError("cannot use loopback IP address {}".format(addr))
        if (not self.is_loopback() and self.is_reserved()) \
                or self in netaddr.ip.IPV4_6TO4:
            raise ValueError(
                "cannot use IANA reserved IP address {}".format(addr))

        if self.is_link_local():
            raise ValueError(
                "cannot use link-local IP address {}".format(addr))
        if not allow_multicast and self.is_multicast():
            raise ValueError("cannot use multicast IP address {}".format(addr))

        if self._net is None:
            if self.version == 4:
                self._net = netaddr.IPNetwork(
                    netaddr.cidr_abbrev_to_verbose(str(self)))
            elif self.version == 6:
                self._net = netaddr.IPNetwork(str(self) + '/64')

        self.prefixlen = self._net.prefixlen

    def __getstate__(self):
        state = {
            'prefixlen': self.prefixlen,
            'super_state': super(CheckedIPAddress, self).__getstate__(),
        }
        return state

    def __setstate__(self, state):
        super(CheckedIPAddress, self).__setstate__(state['super_state'])
        self.prefixlen = state['prefixlen']

    def is_network_addr(self):
        return self == self._net.network

    def is_broadcast_addr(self):
        return self.version == 4 and self == self._net.broadcast

    def get_matching_interface(self):
        """Find matching local interface for address
        :return: InterfaceDetails named tuple or None if no interface has
        this address
        """
        if ifaddr is None:
            raise ImportError("ifaddr")
        logger.debug("Searching for an interface of IP address: %s", self)

        if self.version == 4:
            family_ips = (
                (ip.ip, ip.network_prefix, ip.nice_name)
                for ips in [a.ips for a in ifaddr.get_adapters()]
                for ip in ips if not isinstance(ip.ip, tuple)
            )
        elif self.version == 6:
            family_ips = (
                (ip.ip[0], ip.network_prefix, ip.nice_name)
                for ips in [a.ips for a in ifaddr.get_adapters()]
                for ip in ips if isinstance(ip.ip, tuple)
            )
        else:
            raise ValueError(
                "Unsupported address family ({})".format(self.version)
            )

        for ip, prefix, ifname in family_ips:
            ifaddrmask = "{ip}/{prefix}".format(ip=ip, prefix=prefix)
            logger.debug(
                "Testing local IP address: %s (interface: %s)",
                ifaddrmask, ifname)
            ifnet = netaddr.IPNetwork(ifaddrmask)

            if ifnet.ip == self:
                return InterfaceDetails(ifname, ifnet)

        return None

    def set_ip_net(self, ifnet):
        """Set IP Network details for this address. IPNetwork is valid only
        locally, so this should be set only for local IP addresses

        :param ifnet: netaddr.IPNetwork object with information about IP
        network where particula address belongs locally
        """
        assert isinstance(ifnet, netaddr.IPNetwork)
        self._net = ifnet


class CheckedIPAddressLoopback(CheckedIPAddress):
    """IPv4 or IPv6 address with additional constraints with
    possibility to use a loopback IP.
    Reserved or link-local addresses are never accepted.
    """
    def __init__(self, addr, parse_netmask=True, allow_multicast=False):

        super(CheckedIPAddressLoopback, self).__init__(
                addr, parse_netmask=parse_netmask,
                allow_multicast=allow_multicast,
                allow_loopback=True)

        if self.is_loopback():
            # print is being used instead of a logger, because at this
            # moment, in execution process, there is no logger configured
            print("WARNING: You are using a loopback IP: {}".format(addr),
                  file=sys.stderr)


class IPAddressDoTForwarder(str):
    """IPv4 or IPv6 address with added hostname as needed for DNS over TLS
    configuration. Example: 1.2.3.4#dns.hostname.test
    """
    def __init__(self, addr):
        addr_split = addr.split("#")
        if len(addr_split) != 2 or not valid_ip(addr_split[0]):
            raise ValueError(
                "DoT forwarder must be in the format "
                "of '1.2.3.4#dns.example.test'."
            )


def valid_ip(addr):
    return netaddr.valid_ipv4(addr) or netaddr.valid_ipv6(addr)

def format_netloc(host, port=None):
    """
    Format network location (host:port).

    If the host part is a literal IPv6 address, it must be enclosed in square
    brackets (RFC 2732).
    """
    host = str(host)
    try:
        socket.inet_pton(socket.AF_INET6, host)
        host = '[%s]' % host
    except socket.error:
        pass
    if port is None:
        return host
    else:
        return '%s:%s' % (host, str(port))

def realm_to_suffix(realm_name):
    'Convert a kerberos realm to a IPA suffix.'
    s = realm_name.split(".")
    suffix_dn = DN(*[('dc', x.lower()) for x in s])
    return suffix_dn

def suffix_to_realm(suffix_dn):
    'Convert a IPA suffix to a kerberos realm.'
    assert isinstance(suffix_dn, DN)
    realm = '.'.join([x.value for x in suffix_dn])
    return realm

def template_str(txt, vars):
    val = string.Template(txt).substitute(vars)

    # eval() is a special string one can insert into a template to have the
    # Python interpreter evaluate the string. This is intended to allow
    # math to be performed in templates.
    pattern = re.compile(r'(eval\s*\(([^()]*)\))')
    val = pattern.sub(lambda x: str(eval(x.group(2))), val)

    return val

def template_file(infilename, vars):
    """Read a file and perform template substitutions"""
    with open(infilename) as f:
        return template_str(f.read(), vars)

def copy_template_file(infilename, outfilename, vars):
    """Copy a file, performing template substitutions"""
    txt = template_file(infilename, vars)
    with open(outfilename, 'w') as file:
        file.write(txt)


def write_tmp_file(txt):
    fd = tempfile.NamedTemporaryFile('w+')
    fd.write(txt)
    fd.flush()

    return fd


def flush_sync(f):
    """Flush and fsync file to disk

    :param f: a file object with fileno and name
    """
    # flush file buffer to file descriptor
    f.flush()
    # flush Kernel buffer to disk
    os.fsync(f.fileno())
    # sync metadata in directory
    dirname = os.path.dirname(os.path.abspath(f.name))
    dirfd = os.open(dirname, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def shell_quote(string):
    if isinstance(string, str):
        return "'" + string.replace("'", "'\\''") + "'"
    else:
        return b"'" + string.replace(b"'", b"'\\''") + b"'"


class _RunResult(collections.namedtuple('_RunResult',
                                        'output error_output returncode')):
    """Result of ipautil.run"""


class CalledProcessError(subprocess.CalledProcessError):
    """CalledProcessError with stderr

    Hold stderr of failed call and print it in repr() to simplify debugging.
    """
    def __init__(self, returncode, cmd, output=None, stderr=None):
        super(CalledProcessError, self).__init__(returncode, cmd, output)
        self.stderr = stderr

    def __str__(self):
        args = [
            self.__class__.__name__, '('
            'Command {!s} '.format(self.cmd),
            'returned non-zero exit status {!r}'.format(self.returncode)
        ]
        if self.stderr is not None:
            args.append(': {!r}'.format(self.stderr))
        args.append(')')
        return ''.join(args)

    __repr__ = __str__


def run(args, stdin=None, raiseonerr=True, nolog=(), env=None,
        capture_output=False, skip_output=False, cwd=None,
        runas=None, suplementary_groups=(),
        capture_error=False, encoding=None, redirect_output=False,
        umask=None, nolog_output=False, nolog_error=False):
    """
    Execute an external command.

    :param args: List of arguments for the command
    :param stdin: Optional input to the command
    :param raiseonerr: If True, raises an exception if the return code is
        not zero
    :param nolog: Tuple of strings that shouldn't be logged, like passwords.
        Each tuple consists of a string to be replaced by XXXXXXXX.

        Example:
        We have a command
            ['/usr/bin/setpasswd', '--password', 'Secret123', 'someuser']
        and we don't want to log the password so nolog would be set to:
        ('Secret123',)
        The resulting log output would be:

        /usr/bin/setpasswd --password XXXXXXXX someuser

        If a value isn't found in the list it is silently ignored.
    :param env: Dictionary of environment variables passed to the command.
        When None, current environment is copied
    :param capture_output: Capture stdout
    :param skip_output: Redirect the output to /dev/null and do not log it
    :param cwd: Current working directory
    :param runas: Name or User object of a user that the command should be
        run as. The spawned process will have both real and effective UID and
        GID set.
    :param suplementary_groups: List of group names or Group object that will
        be used as suplementary groups for subporcess. The option runas must
        be specified together with this option.
    :param capture_error: Capture stderr
    :param nolog_output: do not log stdout even if it is being captured
    :param nolog_error: do not log stderr even if it is being captured
    :param encoding: For Python 3, the encoding to use for output,
        error_output, and (if it's not bytes) stdin.
        If None, the current encoding according to locale is used.
    :param redirect_output: Redirect (error) output to standard (error) output.
    :param umask: Set file-creation mask before running the command.

    :return: An object with these attributes:

        `returncode`: The process' exit status

        `output` and `error_output`: captured output, as strings. Under
        Python 3, these are encoded with the given `encoding`.
        None unless `capture_output` or `capture_error`, respectively, are
        given

        `raw_output`, `raw_error_output`: captured output, as bytes.

        `output_log` and `error_log`: The captured output, as strings, with any
        unencodable characters discarded. These should only be used
        for logging or error messages.

    If skip_output is given, all output-related attributes on the result
    (that is, all except `returncode`) are None.

    For backwards compatibility, the return value can also be used as a
    (output, error_output, returncode) triple.
    """
    assert isinstance(suplementary_groups, (tuple, list))
    p_in = None
    p_out = None
    p_err = None

    if isinstance(nolog, str):
        # We expect a tuple (or list, or other iterable) of nolog strings.
        # Passing just a single string is bad: strings are iterable, so this
        # would result in every individual character of that string being
        # replaced by XXXXXXXX.
        # This is a sanity check to prevent that.
        raise ValueError('nolog must be a tuple of strings.')

    if skip_output and (capture_output or capture_error):
        raise ValueError('skip_output is incompatible with '
                         'capture_output or capture_error')

    if redirect_output and (capture_output or capture_error):
        raise ValueError('redirect_output is incompatible with '
                         'capture_output or capture_error')

    if skip_output and redirect_output:
        raise ValueError('skip_output is incompatible with redirect_output')

    if env is None:
        # copy default env
        env = copy.deepcopy(os.environ)
        env["PATH"] = "/bin:/sbin:/usr/kerberos/bin:/usr/kerberos/sbin:/usr/bin:/usr/sbin"
    if stdin:
        p_in = subprocess.PIPE
    if skip_output:
        p_out = p_err = open(os.devnull, 'w')
    elif redirect_output:
        p_out = sys.stdout
        p_err = sys.stderr
    else:
        p_out = subprocess.PIPE
        p_err = subprocess.PIPE

    if encoding is None:
        encoding = locale.getpreferredencoding()

    if six.PY3 and isinstance(stdin, str):
        stdin = stdin.encode(encoding)

    arg_string = nolog_replace(repr(args), nolog)
    logger.debug('Starting external process')
    logger.debug('args=%s', arg_string)

    if runas is not None:
        runas = User(runas)
        suplementary_groups = [Group(group) for group in suplementary_groups]
        suplementary_gids = [group.gid for group in suplementary_groups]

        logger.debug(
            'runas=%s (UID %d, GID %s)', runas, runas.uid, runas.pgid
        )
        if suplementary_groups:
            for group in suplementary_groups:
                logger.debug(
                    'supplementary_group=%s (GID %d)', group, group.gid
                )

    if runas is not None or umask is not None:
        # preexec function is not supported in WSGI environment
        def preexec_fn():
            if runas is not None:
                os.setgroups(suplementary_gids)
                os.setregid(runas.pgid, runas.pgid)
                os.setreuid(runas.uid, runas.uid)

            if umask is not None:
                os.umask(umask)
    else:
        preexec_fn = None

    try:
        # pylint: disable=subprocess-popen-preexec-fn
        p = subprocess.Popen(args, stdin=p_in, stdout=p_out, stderr=p_err,
                             close_fds=True, env=env, cwd=cwd,
                             preexec_fn=preexec_fn)
        stdout, stderr = p.communicate(stdin)
    except KeyboardInterrupt:
        logger.debug('Process interrupted')
        p.wait()
        raise
    except BaseException:
        logger.debug('Process execution failed')
        raise
    finally:
        if skip_output:
            p_out.close()

    logger.debug('Process finished, return code=%s', p.returncode)

    # The command and its output may include passwords that we don't want
    # to log. Replace those.
    if skip_output or redirect_output:
        output_log = None
        error_log = None
    else:
        if six.PY3:
            output_log = stdout.decode(locale.getpreferredencoding(),
                                       errors='replace')
        else:
            output_log = stdout

        if six.PY3:
            error_log = stderr.decode(locale.getpreferredencoding(),
                                      errors='replace')
        else:
            error_log = stderr

        output_log = nolog_replace(output_log, nolog)
        if nolog_output:
            logger.debug('stdout=<REDACTED>')
        else:
            logger.debug('stdout=%s', output_log)

        error_log = nolog_replace(error_log, nolog)
        if nolog_error:
            logger.debug('stderr=<REDACTED>')
        else:
            logger.debug('stderr=%s', error_log)

    if capture_output:
        if six.PY2:
            output = stdout
        else:
            output = stdout.decode(encoding)
    else:
        output = None

    if capture_error:
        if six.PY2:
            error_output = stderr
        else:
            error_output = stderr.decode(encoding)
    else:
        error_output = None

    if p.returncode != 0 and raiseonerr:
        raise CalledProcessError(
            p.returncode, arg_string, output_log, error_log
        )

    result = _RunResult(output, error_output, p.returncode)
    result.raw_output = stdout
    result.raw_error_output = stderr
    result.output_log = output_log
    result.error_log = error_log
    return result


def nolog_replace(string, nolog):
    """Replace occurences of strings given in `nolog` with XXXXXXXX"""
    for value in nolog:
        if not value or not isinstance(value, str):
            continue

        quoted = urllib.parse.quote(value)
        shquoted = shell_quote(value)
        for nolog_value in (shquoted, value, quoted):
            string = string.replace(nolog_value, 'XXXXXXXX')
    return string


def install_file(fname, dest):
    # SELinux: use copy to keep the right context
    if os.path.isfile(dest):
        os.rename(dest, dest + ".orig")
    shutil.copy(fname, dest)
    os.remove(fname)


def backup_file(fname):
    if os.path.isfile(fname):
        os.rename(fname, fname + ".orig")


class CIDict(dict):
    """
    Case-insensitive but case-respecting dictionary.

    This code is derived from python-ldap's cidict.py module,
    written by stroeder: http://python-ldap.sourceforge.net/

    This version extends 'dict' so it works properly with TurboGears.
    If you extend UserDict, isinstance(foo, dict) returns false.
    """

    def __init__(self, default=None, **kwargs):
        super(CIDict, self).__init__()
        self._keys = {}  # mapping of lowercased keys to proper case
        if default:
            self.update(default)
        if kwargs:
            self.update(kwargs)

    def __getitem__(self, key):
        return super(CIDict, self).__getitem__(key.lower())

    def __setitem__(self, key, value, seen_keys=None):
        """cidict[key] = value

        The ``seen_keys`` argument is used by ``update()`` to keep track of
        duplicate keys. It should be an initially empty set that is
        passed to all calls to __setitem__ that should not set duplicate keys.
        """
        lower_key = key.lower()
        if seen_keys is not None:
            if lower_key in seen_keys:
                raise ValueError('Duplicate key in update: %s' % key)
            seen_keys.add(lower_key)
        self._keys[lower_key] = key
        return super(CIDict, self).__setitem__(lower_key, value)

    def __delitem__(self, key):
        lower_key = key.lower()
        del self._keys[lower_key]
        return super(CIDict, self).__delitem__(lower_key)

    def update(self, new=None, **kwargs):
        """Update self from dict/iterable new and kwargs

        Functions like ``dict.update()``.

        Neither ``new`` nor ``kwargs`` may contain two keys that only differ in
        case, as this situation would result in loss of data.
        """
        seen = set()
        if new:
            try:
                keys = new.keys
            except AttributeError:
                self.update(dict(new))
            else:
                for key in keys():
                    # pylint: disable=unnecessary-dunder-call
                    self.__setitem__(key, new[key], seen)
        seen = set()
        for key, value in kwargs.items():
            # pylint: disable=unnecessary-dunder-call
            self.__setitem__(key, value, seen)

    def __contains__(self, key):
        return super(CIDict, self).__contains__(key.lower())

    if six.PY2:
        def has_key(self, key):
            # pylint: disable=no-member
            return super(CIDict, self).has_key(key.lower())  # noqa
            # pylint: enable=no-member

    def get(self, key, failobj=None):
        try:
            return self[key]
        except KeyError:
            return failobj

    def __iter__(self):
        return six.itervalues(self._keys)

    def keys(self):
        if six.PY2:
            return list(self.iterkeys())
        else:
            return self.iterkeys()

    def items(self):
        if six.PY2:
            return list(self.iteritems())
        else:
            return self.iteritems()

    def values(self):
        if six.PY2:
            return list(self.itervalues())
        else:
            return self.itervalues()

    def copy(self):
        """Returns a shallow copy of this CIDict"""
        return CIDict(list(self.items()))

    def iteritems(self):
        return ((k, self[k]) for k in six.itervalues(self._keys))

    def iterkeys(self):
        return six.itervalues(self._keys)

    def itervalues(self):
        return (v for k, v in six.iteritems(self))

    def setdefault(self, key, value=None):
        try:
            return self[key]
        except KeyError:
            self[key] = value
            return value

    def pop(self, key, *args):
        try:
            value = self[key]
            del self[key]
            return value
        except KeyError:
            if len(args) == 1:
                return args[0]
            raise

    def popitem(self):
        (lower_key, value) = super(CIDict, self).popitem()
        key = self._keys[lower_key]
        del self._keys[lower_key]

        return (key, value)

    def clear(self):
        self._keys.clear()
        return super(CIDict, self).clear()

    def viewitems(self):
        raise NotImplementedError('CIDict.viewitems is not implemented')

    def viewkeys(self):
        raise NotImplementedError('CIDict.viewkeys is not implemented')

    def viewvvalues(self):
        raise NotImplementedError('CIDict.viewvvalues is not implemented')


class GeneralizedTimeZone(datetime.tzinfo):
    """This class is a basic timezone wrapper for the offset specified
       in a Generalized Time.  It is dst-ignorant."""
    def __init__(self,offsetstr="Z"):
        super(GeneralizedTimeZone, self).__init__()

        self.name = offsetstr
        self.houroffset = 0
        self.minoffset = 0

        if offsetstr == "Z":
            self.houroffset = 0
            self.minoffset = 0
        else:
            if (len(offsetstr) >= 3) and re.match(r'[-+]\d\d', offsetstr):
                self.houroffset = int(offsetstr[0:3])
                offsetstr = offsetstr[3:]
            if (len(offsetstr) >= 2) and re.match(r'\d\d', offsetstr):
                self.minoffset = int(offsetstr[0:2])
                offsetstr = offsetstr[2:]
            if len(offsetstr) > 0:
                raise ValueError()
        if self.houroffset < 0:
            self.minoffset *= -1

    def utcoffset(self, dt):
        return datetime.timedelta(hours=self.houroffset, minutes=self.minoffset)

    def dst(self):
        return datetime.timedelta(0)

    def tzname(self):
        return self.name


def parse_generalized_time(timestr):
    """Parses are Generalized Time string (as specified in X.680),
       returning a datetime object.  Generalized Times are stored inside
       the krbPasswordExpiration attribute in LDAP.

       This method doesn't attempt to be perfect wrt timezones.  If python
       can't be bothered to implement them, how can we..."""

    if len(timestr) < 8:
        return None
    try:
        date = timestr[:8]
        time = timestr[8:]

        year = int(date[:4])
        month = int(date[4:6])
        day = int(date[6:8])

        hour = min = sec = msec = 0
        tzone = None

        if (len(time) >= 2) and re.match(r'\d', time[0]):
            hour = int(time[:2])
            time = time[2:]
            if len(time) >= 2 and (time[0] == "," or time[0] == "."):
                hour_fraction = "."
                time = time[1:]
                while (len(time) > 0) and re.match(r'\d', time[0]):
                    hour_fraction += time[0]
                    time = time[1:]
                total_secs = int(float(hour_fraction) * 3600)
                min, sec = divmod(total_secs, 60)

        if (len(time) >= 2) and re.match(r'\d', time[0]):
            min = int(time[:2])
            time = time[2:]
            if len(time) >= 2 and (time[0] == "," or time[0] == "."):
                min_fraction = "."
                time = time[1:]
                while (len(time) > 0) and re.match(r'\d', time[0]):
                    min_fraction += time[0]
                    time = time[1:]
                sec = int(float(min_fraction) * 60)

        if (len(time) >= 2) and re.match(r'\d', time[0]):
            sec = int(time[:2])
            time = time[2:]
            if len(time) >= 2 and (time[0] == "," or time[0] == "."):
                sec_fraction = "."
                time = time[1:]
                while (len(time) > 0) and re.match(r'\d', time[0]):
                    sec_fraction += time[0]
                    time = time[1:]
                msec = int(float(sec_fraction) * 1000000)

        if (len(time) > 0):
            tzone = GeneralizedTimeZone(time)

        return datetime.datetime(year, month, day, hour, min, sec, msec, tzone)

    except ValueError:
        return None


def ipa_generate_password(entropy_bits=256, uppercase=1, lowercase=1, digits=1,
                          special=1, min_len=0):
    """
    Generate token containing at least `entropy_bits` bits and with the given
    character restraints.

    :param entropy_bits:
        The minimal number of entropy bits attacker has to guess:
           128 bits entropy: secure
           256 bits of entropy: secure enough if you care about quantum
                                computers

    Integer values specify minimal number of characters from given
    character class and length.
    Value None prevents given character from appearing in the token.

    Example:
    TokenGenerator(uppercase=3, lowercase=3, digits=0, special=None)

    At least 3 upper and 3 lower case ASCII chars, may contain digits,
    no special chars.
    """
    special_chars = '!$%&()*+,-./:;<>?@[]^_{|}~'
    pwd_charsets = {
        'uppercase': {
            'chars': string.ascii_uppercase,
            'entropy': math.log(len(string.ascii_uppercase), 2)
        },
        'lowercase': {
            'chars': string.ascii_lowercase,
            'entropy': math.log(len(string.ascii_lowercase), 2)
        },
        'digits': {
            'chars': string.digits,
            'entropy': math.log(len(string.digits), 2)
        },
        'special': {
            'chars': special_chars,
            'entropy': math.log(len(special_chars), 2)
        },
    }
    req_classes = dict(
        uppercase=uppercase,
        lowercase=lowercase,
        digits=digits,
        special=special
    )
    # 'all' class is used when adding entropy to too-short tokens
    # it contains characters from all allowed classes
    pwd_charsets['all'] = {
        'chars': ''.join([
            charclass['chars'] for charclass_name, charclass
            in pwd_charsets.items()
            if req_classes[charclass_name] is not None
        ])
    }
    pwd_charsets['all']['entropy'] = math.log(
            len(pwd_charsets['all']['chars']), 2)
    rnd = random.SystemRandom()

    todo_entropy = entropy_bits
    password = u''
    # Generate required character classes:
    # The order of generated characters is fixed to comply with check in
    # NSS function sftk_newPinCheck() in nss/lib/softoken/fipstokn.c.
    for charclass_name in ['digits', 'uppercase', 'lowercase', 'special']:
        charclass = pwd_charsets[charclass_name]
        todo_characters = req_classes[charclass_name]
        if todo_characters is None:
            continue
        while todo_characters > 0:
            password += rnd.choice(charclass['chars'])
            todo_entropy -= charclass['entropy']
            todo_characters -= 1

    # required character classes do not provide sufficient entropy
    # or does not fulfill minimal length constraint
    allchars = pwd_charsets['all']
    while todo_entropy > 0 or len(password) < min_len:
        password += rnd.choice(allchars['chars'])
        todo_entropy -= allchars['entropy']

    return password


def user_input(prompt, default = None, allow_empty = True):
    if default is None:
        while True:
            try:
                ret = input("%s: " % prompt)
                if allow_empty or ret.strip():
                    return ret.strip()
            except EOFError:
                if allow_empty:
                    return ''
                raise RuntimeError("Failed to get user input")

    if isinstance(default, str):
        while True:
            try:
                ret = input("%s [%s]: " % (prompt, default))
                if not ret and (allow_empty or default):
                    return default
                elif ret.strip():
                    return ret.strip()
            except EOFError:
                return default

    if isinstance(default, bool):
        choice = "yes" if default else "no"
        while True:
            try:
                ret = input("%s [%s]: " % (prompt, choice))
                ret = ret.strip()
                if not ret:
                    return default
                elif ret.lower()[0] == "y":
                    return True
                elif ret.lower()[0] == "n":
                    return False
            except EOFError:
                return default

    if isinstance(default, int):
        while True:
            try:
                ret = input("%s [%s]: " % (prompt, default))
                ret = ret.strip()
                if not ret:
                    return default
                ret = int(ret)
            except ValueError:
                pass
            except EOFError:
                return default
            else:
                return ret

    return None


def host_port_open(host, port, socket_type=socket.SOCK_STREAM,
                   socket_timeout=None, log_errors=False,
                   log_level=logging.DEBUG):
    """
    host: either hostname or IP address;
          if hostname is provided, port MUST be open on ALL resolved IPs

    returns True is port is open, False otherwise
    """
    port_open = True

    # port has to be open on ALL resolved IPs
    for res in socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket_type):
        af, socktype, proto, _canonname, sa = res
        s = None
        try:
            s = socket.socket(af, socktype, proto)

            if socket_timeout is not None:
                s.settimeout(socket_timeout)

            s.connect(sa)

            if socket_type == socket.SOCK_DGRAM:
                s.send(b'')
                s.recv(512)
        except socket.error:
            port_open = False
            if log_errors:
                msg = ('Failed to connect to port %(port)s %(proto)s on '
                       '%(addr)s' % dict(port=port,
                                         proto=PROTOCOL_NAMES[socket_type],
                                         addr=sa[0]))
                logger.log(log_level, msg)
        finally:
            if s is not None:
                s.close()

    return port_open


def check_port_bindable(port, socket_type=socket.SOCK_STREAM):
    """Check if a port is free and not bound by any other application

    :param port: port number
    :param socket_type: type (SOCK_STREAM for TCP, SOCK_DGRAM for UDP)

    Returns True if the port is free, False otherwise
    """
    if socket_type == socket.SOCK_STREAM:
        proto = 'TCP'
    elif socket_type == socket.SOCK_DGRAM:
        proto = 'UDP'
    else:
        raise ValueError(socket_type)

    # Detect dual stack or IPv4 single stack
    try:
        s = socket.socket(socket.AF_INET6, socket_type)
        anyaddr = '::'
        logger.debug(
            "check_port_bindable: Checking IPv4/IPv6 dual stack and %s",
            proto
        )
    except socket.error:
        s = socket.socket(socket.AF_INET, socket_type)
        anyaddr = ''
        logger.debug("check_port_bindable: Checking IPv4 only and %s", proto)

    # Attempt to bind
    try:
        if socket_type == socket.SOCK_STREAM:
            # reuse TCP sockets in TIME_WAIT state
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        s.bind((anyaddr, port))
    except socket.error as e:
        logger.debug(
            "check_port_bindable: failed to bind to port %i/%s: %s",
            port, proto, e
        )
        return False
    else:
        logger.debug(
            "check_port_bindable: bind success: %i/%s", port, proto
        )
        return True
    finally:
        s.close()


def config_replace_variables(filepath, replacevars=dict(), appendvars=dict(),
                             removevars=None):
    """
    Take a key=value based configuration file, and write new version
    with certain values replaced, appended, or removed.

    All (key,value) pairs from replacevars and appendvars that were not found
    in the configuration file, will be added there.

    All entries in set removevars are removed.

    It is responsibility of a caller to ensure that replacevars and
    appendvars do not overlap.

    It is responsibility of a caller to back up file.

    returns dictionary of affected keys and their previous values

    One have to run restore_context(filepath) afterwards or
    security context of the file will not be correct after modification
    """
    pattern = re.compile(r'''
(^
                        \s*
        (?P<option>     [^\#;]+?)
                        (\s*=\s*)
        (?P<value>      .+?)?
                        (\s*((\#|;).*)?)?
$)''', re.VERBOSE)
    orig_stat = os.stat(filepath)
    old_values = dict()
    temp_filename = None
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as new_config:
        temp_filename = new_config.name
        with open(filepath, 'r') as f:
            for line in f:
                new_line = line
                m = pattern.match(line)
                if m:
                    option, value = m.group('option', 'value')
                    if option is not None:
                        if replacevars and option in replacevars:
                            # replace value completely
                            new_line = u"%s=%s\n" % (option, replacevars[option])
                            old_values[option] = value
                        if appendvars and option in appendvars:
                            # append new value unless it is already existing in the original one
                            if not value:
                                new_line = u"%s=%s\n" % (option, appendvars[option])
                            elif value.find(appendvars[option]) == -1:
                                new_line = u"%s=%s %s\n" % (option, value, appendvars[option])
                            old_values[option] = value
                        if removevars and option in removevars:
                            old_values[option] = value
                            new_line = None
                if new_line is not None:
                    new_config.write(new_line)
        # Now add all options from replacevars and appendvars that were not found in the file
        new_vars = replacevars.copy()
        new_vars.update(appendvars)
        newvars_view = set(new_vars.keys()) - set(old_values.keys())
        append_view = (set(appendvars.keys()) - newvars_view)
        for item in newvars_view:
            new_config.write("%s=%s\n" % (item,new_vars[item]))
        for item in append_view:
            new_config.write("%s=%s\n" % (item,appendvars[item]))
        new_config.flush()
        # Make sure the resulting file is readable by others before installing it
        os.fchmod(new_config.fileno(), orig_stat.st_mode)
        os.fchown(new_config.fileno(), orig_stat.st_uid, orig_stat.st_gid)

    # At this point new_config is closed but not removed due to 'delete=False' above
    # Now, install the temporary file as configuration and ensure old version is available as .orig
    # While .orig file is not used during uninstall, it is left there for administrator.
    install_file(temp_filename, filepath)

    return old_values

def inifile_replace_variables(filepath, section, replacevars=dict(), appendvars=dict()):
    """
    Take a section-structured key=value based configuration file, and write new version
    with certain values replaced or appended within the section

    All (key,value) pairs from replacevars and appendvars that were not found
    in the configuration file, will be added there.

    It is responsibility of a caller to ensure that replacevars and
    appendvars do not overlap.

    It is responsibility of a caller to back up file.

    returns dictionary of affected keys and their previous values

    One have to run restore_context(filepath) afterwards or
    security context of the file will not be correct after modification
    """
    pattern = re.compile(r'''
(^
                        \[
        (?P<section>    .+) \]
                        (\s+((\#|;).*)?)?
$)|(^
                        \s*
        (?P<option>     [^\#;]+?)
                        (\s*=\s*)
        (?P<value>      .+?)?
                        (\s*((\#|;).*)?)?
$)''', re.VERBOSE)
    def add_options(config, replacevars, appendvars, oldvars):
        # add all options from replacevars and appendvars that were not found in the file
        new_vars = replacevars.copy()
        new_vars.update(appendvars)
        newvars_view = set(new_vars.keys()) - set(oldvars.keys())
        append_view = (set(appendvars.keys()) - newvars_view)
        for item in newvars_view:
            config.write("%s=%s\n" % (item,new_vars[item]))
        for item in append_view:
            config.write("%s=%s\n" % (item,appendvars[item]))

    orig_stat = os.stat(filepath)
    old_values = dict()
    temp_filename = None
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as new_config:
        temp_filename = new_config.name
        with open(filepath, 'r') as f:
            in_section = False
            finished = False
            line_idx = 1
            for line in f:
                line_idx = line_idx + 1
                new_line = line
                m = pattern.match(line)
                if m:
                    sect, option, value = m.group('section', 'option', 'value')
                    if in_section and sect is not None:
                        # End of the searched section, add remaining options
                        add_options(new_config, replacevars, appendvars, old_values)
                        finished = True
                    if sect is not None:
                        # New section is found, check whether it is the one we are looking for
                        in_section = (str(sect).lower() == str(section).lower())
                    if option is not None and in_section:
                        # Great, this is an option from the section we are loking for
                        if replacevars and option in replacevars:
                            # replace value completely
                            new_line = u"%s=%s\n" % (option, replacevars[option])
                            old_values[option] = value
                        if appendvars and option in appendvars:
                            # append a new value unless it is already existing in the original one
                            if not value:
                                new_line = u"%s=%s\n" % (option, appendvars[option])
                            elif value.find(appendvars[option]) == -1:
                                new_line = u"%s=%s %s\n" % (option, value, appendvars[option])
                            old_values[option] = value
                    new_config.write(new_line)
            # We have finished parsing the original file.
            # There are two remaining cases:
            # 1. Section we were looking for was not found, we need to add it.
            if not (in_section or finished):
                new_config.write("[%s]\n" % (section))
            # 2. The section is the last one but some options were not found, add them.
            if in_section or not finished:
                add_options(new_config, replacevars, appendvars, old_values)

        new_config.flush()
        # Make sure the resulting file is readable by others before installing it
        os.fchmod(new_config.fileno(), orig_stat.st_mode)
        os.fchown(new_config.fileno(), orig_stat.st_uid, orig_stat.st_gid)

    # At this point new_config is closed but not removed due to 'delete=False' above
    # Now, install the temporary file as configuration and ensure old version is available as .orig
    # While .orig file is not used during uninstall, it is left there for administrator.
    install_file(temp_filename, filepath)

    return old_values

def backup_config_and_replace_variables(
        fstore, filepath, replacevars=dict(), appendvars=dict()):
    """
    Take a key=value based configuration file, back up it, and
    write new version with certain values replaced or appended

    All (key,value) pairs from replacevars and appendvars that
    were not found in the configuration file, will be added there.
    The file must exist before this function is called.

    It is responsibility of a caller to ensure that replacevars and
    appendvars do not overlap.

    returns dictionary of affected keys and their previous values

    One have to run restore_context(filepath) afterwards or
    security context of the file will not be correct after modification
    """
    # Backup original filepath
    fstore.backup_file(filepath)
    old_values = config_replace_variables(filepath, replacevars, appendvars)

    return old_values


def wait_for_open_ports(host, ports, timeout=0):
    """
    Wait until the specified port(s) on the remote host are open. Timeout
    in seconds may be specified to limit the wait. If the timeout is
    exceeded, socket.timeout exception is raised.
    """
    timeout = float(timeout)
    if not isinstance(ports, (tuple, list)):
        ports = [ports]

    logger.debug('wait_for_open_ports: %s %s timeout %d', host, ports, timeout)
    op_timeout = time.time() + timeout

    for port in ports:
        logger.debug('waiting for port: %s', port)
        log_error = True
        while True:
            port_open = host_port_open(host, port, log_errors=log_error)
            log_error = False  # Log only first err so that the log is readable

            if port_open:
                logger.debug('SUCCESS: port: %s', port)
                break
            if timeout and time.time() > op_timeout: # timeout exceeded
                raise socket.timeout("Timeout exceeded")
            time.sleep(1)


def wait_for_open_socket(socket_name, timeout=0):
    """
    Wait until the specified socket on the local host is open. Timeout
    in seconds may be specified to limit the wait.
    """
    timeout = float(timeout)
    op_timeout = time.time() + timeout

    while True:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(socket_name)
            s.close()
            break
        except socket.error as e:
            if e.errno in (2,111):  # 111: Connection refused, 2: File not found
                if timeout and time.time() > op_timeout: # timeout exceeded
                    raise e
                time.sleep(1)
            else:
                raise e


def dn_attribute_property(private_name):
    '''
    Create a property for a dn attribute which assures the attribute
    is a DN or None. If the value is not None the setter converts it to
    a DN. The getter assures it's either None or a DN instance.

    The private_name parameter is the class internal attribute the property
    shadows.

    For example if a class has an attribute called base_dn, then:

        base_dn = dn_attribute_property('_base_dn')

    Thus the class with have an attriubte called base_dn which can only
    ever be None or a DN instance. The actual value is stored in _base_dn.
    '''

    def setter(self, value):
        if value is not None:
            value = DN(value)
        setattr(self, private_name, value)

    def getter(self):
        value = getattr(self, private_name)
        if value is not None:
            assert isinstance(value, DN)
        return value

    return property(getter, setter)

def posixify(string):
    """
    Convert a string to a more strict alpha-numeric representation.

    - Alpha-numeric, underscore, dot and dash characters are accepted
    - Space is converted to underscore
    - Other characters are omitted
    - Leading dash is stripped

    Note: This mapping is not one-to-one and may map different input to the
    same result. When using posixify, make sure the you do not map two different
    entities to one unintentionally.
    """

    def valid_char(char):
        return char.isalnum() or char in ('_', '.', '-')

    # First replace space characters
    replaced = string.replace(' ','_')
    omitted = ''.join(filter(valid_char, replaced))

    # Leading dash is not allowed
    return omitted.lstrip('-')

@contextmanager
def private_ccache(path=None):

    if path is None:
        dir_path = tempfile.mkdtemp(prefix='krbcc')
        path = os.path.join(dir_path, 'ccache')
    else:
        dir_path = None

    original_value = os.environ.get('KRB5CCNAME', None)

    os.environ['KRB5CCNAME'] = path

    try:
        yield path
    finally:
        if original_value is not None:
            os.environ['KRB5CCNAME'] = original_value
        else:
            os.environ.pop('KRB5CCNAME', None)

        if os.path.exists(path):
            os.remove(path)
        if dir_path is not None:
            try:
                os.rmdir(dir_path)
            except OSError:
                pass


@contextmanager
def private_krb5_config(realm, server, dir="/run/ipa"):
    """Generate override krb5 config file for a trusted domain DC access
    Provide a context where environment variable KRB5_CONFIG is set
    with the overlay on top of paths.KRB5_CONF. Overlay's file path
    is passed to the context in case it is needed for something else

    :param realm: realm of the trusted AD domain
    :param server: server to override KDC to
    :param dir: path where to create a temporary krb5.conf overlay
    """
    cfg = paths.KRB5_CONF
    tcfg = None
    if server:
        content = textwrap.dedent(u"""
            [realms]
               %s = {
                   kdc = %s
               }
            """) % (
            realm.upper(),
            server,
        )

        (fd, tcfg) = tempfile.mkstemp(dir=dir, prefix="krb5conf", text=True)

        with io.open(fd, mode='w', encoding='utf-8') as o:
            o.write(content)
        cfg = ":".join([tcfg, cfg])

    original_value = os.environ.get('KRB5_CONFIG', None)

    os.environ['KRB5_CONFIG'] = cfg

    try:
        yield tcfg
    except GeneratorExit:
        pass
    finally:
        if original_value is not None:
            os.environ['KRB5_CONFIG'] = original_value
        else:
            os.environ.pop('KRB5_CONFIG', None)

        if tcfg is not None and os.path.exists(tcfg):
            os.remove(tcfg)


if six.PY2:
    def fsdecode(value):
        """
        Decode argument using the file system encoding, as returned by
        `sys.getfilesystemencoding()`.
        """
        if isinstance(value, bytes):
            return value.decode(sys.getfilesystemencoding())
        elif isinstance(value, str):
            return value
        else:
            raise TypeError("expect {0} or {1}, not {2}".format(
                bytes.__name__,
                str.__name__,
                type(value).__name__))
else:
    fsdecode = os.fsdecode


def unescape_seq(seq, *args):
    """
    unescape (remove '\\') all occurences of sequence in input strings.

    :param seq: sequence to unescape
    :param args: input string to process

    :returns: tuple of strings with unescaped sequences
    """
    unescape_re = re.compile(r'\\{}'.format(seq))

    return tuple(re.sub(unescape_re, seq, a) for a in args)


def escape_seq(seq, *args):
    """
    escape (prepend '\\') all occurences of sequence in input strings

    :param seq: sequence to escape
    :param args: input string to process

    :returns: tuple of strings with escaped sequences
    """

    return tuple(a.replace(seq, u'\\{}'.format(seq)) for a in args)


def decode_json(data):
    """Decode JSON bytes to string with proper encoding

    Only for supporting Py 3.5

    Py 3.6 supports bytes as parameter for json.load, we can drop this when
    there is no need for python 3.5 anymore

    Code from:
        https://bugs.python.org/file43513/json_detect_encoding_3.patch

    :param data: JSON bytes
    :return: return JSON string
    """

    def detect_encoding(b):
        bstartswith = b.startswith
        if bstartswith((codecs.BOM_UTF32_BE, codecs.BOM_UTF32_LE)):
            return 'utf-32'
        if bstartswith((codecs.BOM_UTF16_BE, codecs.BOM_UTF16_LE)):
            return 'utf-16'
        if bstartswith(codecs.BOM_UTF8):
            return 'utf-8-sig'

        if len(b) >= 4:
            if not b[0]:
                # 00 00 -- -- - utf-32-be
                # 00 XX -- -- - utf-16-be
                return 'utf-16-be' if b[1] else 'utf-32-be'
            if not b[1]:
                # XX 00 00 00 - utf-32-le
                # XX 00 XX XX - utf-16-le
                return 'utf-16-le' if b[2] or b[3] else 'utf-32-le'
        elif len(b) == 2:
            if not b[0]:
                # 00 XX - utf-16-be
                return 'utf-16-be'
            if not b[1]:
                # XX 00 - utf-16-le
                return 'utf-16-le'
        # default
        return 'utf-8'

    if isinstance(data, str):
        return data

    return data.decode(detect_encoding(data), 'surrogatepass')


class APIVersion(tuple):
    """API version parser and handler

    The class is used to parse ipapython.version.API_VERSION and plugin
    versions.
    """
    __slots__ = ()

    def __new__(cls, version):
        major, dot, minor = version.partition(u'.')
        major = int(major)
        minor = int(minor) if dot else 0
        return tuple.__new__(cls, (major, minor))

    def __str__(self):
        return '{}.{}'.format(*self)

    def __repr__(self):
        return "<APIVersion('{}.{}')>".format(*self)

    def __getnewargs__(self):
        return (str(self),)

    @property
    def major(self):
        return self[0]

    @property
    def minor(self):
        return self[1]


def remove_keytab(keytab_path):
    """
    Remove Kerberos keytab and issue a warning if the procedure fails

    :param keytab_path: path to the keytab file
    """
    try:
        logger.debug("Removing service keytab: %s", keytab_path)
        os.remove(keytab_path)
    except OSError as e:
        if e.errno != errno.ENOENT:
            logger.warning("Failed to remove Kerberos keytab '%s': %s",
                           keytab_path, e)
            logger.warning("You may have to remove it manually")


def remove_ccache(ccache_path=None, run_as=None):
    """
    remove Kerberos credential cache, essentially a wrapper around kdestroy.

    :param ccache_path: path to the ccache file
    :param run_as: run kdestroy as this user
    """
    logger.debug("Removing service credentials cache")
    kdestroy_cmd = [paths.KDESTROY]
    if ccache_path is not None:
        logger.debug("Ccache path: '%s'", ccache_path)
        kdestroy_cmd.extend(['-c', ccache_path])

    try:
        run(kdestroy_cmd, runas=run_as, env={})
    except CalledProcessError as e:
        logger.warning(
            "Failed to clear Kerberos credentials cache: %s", e)


def remove_file(filename, only_if_empty=False):
    """Remove a file and log any exceptions raised.

       :only_if_empty: only remove the file if empty. Default False.
    """
    if only_if_empty and os.path.exists(filename):
        file_stat = os.stat(filename)
        if file_stat.st_size > 0:
            logger.debug('%s is not empty.', filename)
            return
    try:
        os.unlink(filename)
    except Exception as e:
        # ignore missing file
        if getattr(e, 'errno', None) != errno.ENOENT:
            logger.error('Error removing %s: %s', filename, str(e))


def remove_directory(dir):
    """Remove an empty directory."""
    try:
        os.rmdir(dir)
    except OSError as e:
        if e.errno not in {errno.ENOENT, errno.ENOTEMPTY}:
            logger.error("Failed to remove directory %s", dir)


def rmtree(path):
    """
    Remove a directory structure and log any exceptions raised.
    """
    try:
        if os.path.exists(path):
            shutil.rmtree(path)
    except Exception as e:
        logger.error('Error removing %s: %s', path, str(e))


def datetime_from_utctimestamp(t, units=1):
    """
    Convert a timestamp or a time.struct_time to a datetime.datetime
    object down to seconds, with UTC timezone

    The conversion is safe for year 2038 problem

    :param t: int or float timestamp in (milli)seconds since UNIX epoch
              or time.struct_time
    :param units: normalizing factor for the timestamp
                  (1 for seconds, 1000 for milliseconds)
                  defaults to 1
    :return: datetime.datetime object in UTC timezone
    """
    if isinstance(t, time.struct_time):
        v = int(time.mktime(t))
    elif isinstance(t, (float, int)):
        v = int(t)
    else:
        raise TypeError(t)
    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    return epoch + datetime.timedelta(seconds=v // units)


class Sleeper:
    """Helper for time.sleep() loop with timeout

    A sleeper object sleeps *sleep* seconds when it is called. Close to its
    deadline it sleeps shorter to not oversleep the *timeout* deadline. A
    sleeper object is *True* and returns *True* before it reaches *timeout*
    deadline. After its deadline a sleeper raises the exception object/class
    in *raises*. If *raises* is not given, it returns False instead.

    sleep = Sleeper(sleep=1, timeout=60, raises=TimeoutError)
    while True:
        do_something()
        sleep()

    sleep = Sleeper(sleep=0.5, timeout=60)
    while True:
        do_something
        if not sleep():
            log.info("timeout")
            break

    longsleep = Sleeper(sleep=1, timeout=sys.maxsize)
    """
    multiplier = 2

    def __init__(self, *, sleep, timeout, raises=None):
        if timeout <= 0:
            raise ValueError(f"invalid timeout {timeout}")
        if sleep < 0.01:
            raise ValueError(f"sleep duration {sleep} is too short.")

        self.timeout = timeout
        self.sleep = sleep
        self.raises = raises

        self.deadline = time.monotonic() + self.timeout

    def __bool__(self):
        return time.monotonic() < self.deadline

    def __call__(self):
        now = time.monotonic()
        if now >= self.deadline:
            if self.raises is not None:
                raise self.raises
            else:
                return False
        # don't sleep over deadline
        dur = min(self.deadline - now, self.sleep)
        time.sleep(dur)
        return True


def get_config_debug(context):
    """A simplified version of ipalib/config in order to determine if the
       API should be bootstrapped in debug mode or not.

       A number of daemons setup logging, then bootstrap the API in order
       to capture the startup. This presents a chicken-and-egg problem
       over debug output.

       Debug is rather spammy and probably shouldn't be enabled by default
       but if some problem is occuring during startup we want a way to
       see that.

       So use this limited function to pluck out the debug value out of
       the system context config file (in_tree is not supported, another
       chicken-and-egg).

       This isn't more generalized for two reasons:
           1. There is currently only a need for 'debug'
           2. Type conversion. They will all be strings.
    """
    CONFIG_SECTION = 'global'  # duplicated from ipalib.constants
    config_file = os.path.join('/', 'etc', 'ipa', '%s.conf' % context)

    parser = RawConfigParser()
    try:
        parser.read(config_file)
    except ParsingError:
        return False

    if not parser.has_section(CONFIG_SECTION):
        return False

    if not parser.has_option(CONFIG_SECTION, 'debug'):
        return False

    return parser.get(CONFIG_SECTION, 'debug').lower() == 'true'
