# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@redhat.com>
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
RPC client and shared RPC client/server functionality.

This module adds some additional functionality on top of the ``xmlrpc.client``
module in the Python standard library (``xmlrpclib`` in Python 2).
For documentation on the ``xmlrpclib`` module, see:

    http://docs.python.org/2/library/xmlrpclib.html

Also see the `ipaserver.rpcserver` module.
"""

from __future__ import absolute_import

from decimal import Decimal
import datetime
import logging
import os
import locale
import base64
import json
import re
import socket
import gzip
import urllib
from ssl import SSLError

from cryptography import x509 as crypto_x509
import gssapi
from dns.exception import DNSException
import six
import sys

from ipalib.backend import Connectible
from ipalib.constants import LDAP_GENERALIZED_TIME_FORMAT
from ipalib.errors import (errors_by_code, UnknownError, NetworkError,
                           XMLRPCMarshallError, JSONError)
from ipalib import errors, capabilities
from ipalib.request import context, Connection
from ipalib.x509 import Encoding as x509_Encoding
from ipapython import ipautil
from ipapython import session_storage
from ipapython.cookie import Cookie
from ipapython.dnsutil import DNSName, query_srv
from ipalib.text import _
from ipalib.util import create_https_connection
from ipalib.krb_utils import (
    KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN,
    KRB5KRB_AP_ERR_TKT_EXPIRED,
    KRB5_FCC_PERM,
    KRB5_FCC_NOFILE,
    KRB5_CC_FORMAT,
    KRB5_REALM_CANT_RESOLVE,
    KRB5_CC_NOTFOUND,
    get_principal,
)
from ipapython.dn import DN
from ipapython.kerberos import Principal
from ipalib.capabilities import VERSION_WITHOUT_CAPABILITIES
from ipalib import api
from ipalib.ipajson import json_encode_binary, json_decode_binary

# The XMLRPC client is in  "six.moves.xmlrpc_client", but pylint
# cannot handle that
try:
    from xmlrpclib import (
        Binary,
        Fault,
        DateTime,
        dumps,
        loads,
        ServerProxy,
        Transport,
        ProtocolError,
        MININT,
        MAXINT,
    )
except ImportError:
    from xmlrpc.client import (
        Binary,
        Fault,
        DateTime,
        dumps,
        loads,
        ServerProxy,
        Transport,
        ProtocolError,
        MININT,
        MAXINT,
    )

# pylint: disable=import-error
if six.PY3:
    from http.client import RemoteDisconnected
else:
    from httplib import BadStatusLine as RemoteDisconnected
# pylint: enable=import-error


if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

COOKIE_NAME = 'ipa_session'
CCACHE_COOKIE_KEY = 'X-IPA-Session-Cookie'


def update_persistent_client_session_data(principal, data):
    '''
    Given a principal create or update the session data for that
    principal in the persistent secure storage.

    Raises ValueError if unable to perform the action for any reason.
    '''

    try:
        session_storage.store_data(principal, CCACHE_COOKIE_KEY, data)
    except Exception as e:
        raise ValueError(str(e))


def read_persistent_client_session_data(principal):
    '''
    Given a principal return the stored session data for that
    principal from the persistent secure storage.

    Raises ValueError if unable to perform the action for any reason.
    '''

    try:
        return session_storage.get_data(principal, CCACHE_COOKIE_KEY)
    except Exception as e:
        raise ValueError(str(e))


def delete_persistent_client_session_data(principal):
    '''
    Given a principal remove the session data for that
    principal from the persistent secure storage.

    Raises ValueError if unable to perform the action for any reason.
    '''

    try:
        session_storage.remove_data(principal, CCACHE_COOKIE_KEY)
    except Exception as e:
        raise ValueError(str(e))


def xml_wrap(value, version):
    """
    Wrap all ``str`` in ``xmlrpc.client.Binary``.

    Because ``xmlrpc.client.dumps()`` will itself convert all ``unicode``
    instances into UTF-8 encoded ``str`` instances, we don't do it here.

    So in total, when encoding data for an XML-RPC packet, the following
    transformations occur:

        * All ``str`` instances are treated as binary data and are wrapped in
          an ``xmlrpc.client.Binary()`` instance.

        * Only ``unicode`` instances are treated as character data. They get
          converted to UTF-8 encoded ``str`` instances (although as mentioned,
          not by this function).

    Also see `xml_unwrap()`.

    :param value: The simple scalar or simple compound value to wrap.
    """
    if type(value) in (list, tuple):
        return tuple(xml_wrap(v, version) for v in value)
    if isinstance(value, dict):
        return dict(
            (k, xml_wrap(v, version)) for (k, v) in value.items()
        )
    if type(value) is bytes:
        return Binary(value)
    if type(value) is Decimal:
        # transfer Decimal as a string
        return unicode(value)
    if isinstance(value, int) and (value < MININT or value > MAXINT):
        return unicode(value)
    if isinstance(value, DN):
        return str(value)

    # Encode datetime.datetime objects as xmlrpc.client.DateTime objects
    if isinstance(value, datetime.datetime):
        if capabilities.client_has_capability(version, 'datetime_values'):
            return DateTime(value)
        else:
            return value.strftime(LDAP_GENERALIZED_TIME_FORMAT)

    if isinstance(value, DNSName):
        if capabilities.client_has_capability(version, 'dns_name_values'):
            return {'__dns_name__': unicode(value)}
        else:
            return unicode(value)

    if isinstance(value, Principal):
        return unicode(value)

    if isinstance(value, crypto_x509.Certificate):
        return base64.b64encode(
            value.public_bytes(x509_Encoding.DER)).decode('ascii')

    if isinstance(value, crypto_x509.CertificateSigningRequest):
        return base64.b64encode(
            value.public_bytes(x509_Encoding.DER)).decode('ascii')

    assert type(value) in (unicode, float, int, bool, type(None))
    return value


def xml_unwrap(value, encoding='UTF-8'):
    """
    Unwrap all ``xmlrpc.Binary``, decode all ``str`` into ``unicode``.

    When decoding data from an XML-RPC packet, the following transformations
    occur:

        * The binary payloads of all ``xmlrpc.client.Binary`` instances are
          returned as ``str`` instances.

        * All ``str`` instances are treated as UTF-8 encoded Unicode strings.
          They are decoded and the resulting ``unicode`` instance is returned.

    Also see `xml_wrap()`.

    :param value: The value to unwrap.
    :param encoding: The Unicode encoding to use (defaults to ``'UTF-8'``).
    """
    if isinstance(value, (unicode, int, float, bool)):
        # most common first
        return value
    elif value is None:
        return value
    elif isinstance(value, bytes):
        return value.decode(encoding)
    elif isinstance(value, (list, tuple)):
        return tuple(xml_unwrap(v, encoding) for v in value)
    elif isinstance(value, dict):
        if '__dns_name__' in value:
            return DNSName(value['__dns_name__'])
        else:
            return dict(
                (k, xml_unwrap(v, encoding)) for (k, v) in value.items()
            )
    elif isinstance(value, Binary):
        assert type(value.data) is bytes
        return value.data
    elif isinstance(value, DateTime):
        # xmlprc DateTime is converted to string of %Y%m%dT%H:%M:%S format
        return datetime.datetime.strptime(str(value), "%Y%m%dT%H:%M:%S")
    raise TypeError(value)


def xml_dumps(params, version, methodname=None, methodresponse=False,
              encoding='UTF-8'):
    """
    Encode an XML-RPC data packet, transparently wraping ``params``.

    This function will wrap ``params`` using `xml_wrap()` and will
    then encode the XML-RPC data packet using ``xmlrpc.client.dumps()``
    (from the Python standard library).

    For documentation on the ``xmlrpc.client.dumps()`` function, see:

        http://docs.python.org/library/xmlrpc.client.html#convenience-functions

    Also see `xml_loads()`.

    :param params: A ``tuple`` or an ``xmlrpc.client.Fault`` instance.
    :param methodname: The name of the method to call if this is a request.
    :param methodresponse: Set this to ``True`` if this is a response.
    :param encoding: The Unicode encoding to use (defaults to ``'UTF-8'``).
    """
    if type(params) is tuple:
        params = xml_wrap(params, version)
    else:
        assert isinstance(params, Fault)
    return dumps(
        params,
        methodname=methodname,
        methodresponse=methodresponse,
        encoding=encoding,
        allow_none=True,
    )


def decode_fault(e, encoding='UTF-8'):
    assert isinstance(e, Fault)
    if isinstance(e.faultString, bytes):
        return Fault(e.faultCode, e.faultString.decode(encoding))
    return e


def xml_loads(data, encoding='UTF-8'):
    """
    Decode the XML-RPC packet in ``data``, transparently unwrapping its params.

    This function will decode the XML-RPC packet in ``data`` using
    ``xmlrpc.client.loads()`` (from the Python standard library).  If ``data``
    contains a fault, ``xmlrpc.client.loads()`` will itself raise an
    ``xmlrpc.client.Fault`` exception.

    Assuming an exception is not raised, this function will then unwrap the
    params in ``data`` using `xml_unwrap()`.  Finally, a
    ``(params, methodname)`` tuple is returned containing the unwrapped params
    and the name of the method being called.  If the packet contains no method
    name, ``methodname`` will be ``None``.

    For documentation on the ``xmlrpc.client.loads()`` function, see:

        http://docs.python.org/2/library/xmlrpclib.html#convenience-functions

    Also see `xml_dumps()`.

    :param data: The XML-RPC packet to decode.
    """
    try:
        (params, method) = loads(data)
        return (xml_unwrap(params), method)
    except Fault as e:
        raise decode_fault(e)


class DummyParser:
    def __init__(self):
        self.data = []

    def feed(self, data):
        self.data.append(data)

    def close(self):
        return b''.join(self.data)


class MultiProtocolTransport(Transport):
    """Transport that handles both XML-RPC and JSON"""

    def __init__(self, *args, **kwargs):
        Transport.__init__(self)
        self.protocol = kwargs.get('protocol', None)
        self.api = kwargs.get('api', None)

    def getparser(self):
        if self.protocol == 'json':
            parser = DummyParser()
            return parser, parser
        else:
            return Transport.getparser(self)

    def send_content(self, connection, request_body):
        if self.protocol == 'json':
            connection.putheader("Content-Type", "application/json")
        else:
            connection.putheader("Content-Type", "text/xml")

        # gzip compression would be set up here, but we have it turned off
        # (encode_threshold is None)

        connection.putheader("Content-Length", str(len(request_body)))
        connection.endheaders(request_body)


class LanguageAwareTransport(MultiProtocolTransport):
    """Transport sending Accept-Language header"""

    def get_host_info(self, host):
        host, extra_headers, x509 = MultiProtocolTransport.get_host_info(
            self, host)

        try:
            lang = locale.setlocale(
                locale.LC_MESSAGES, ''
            ).split('.', maxsplit=1)[0].lower()
        except locale.Error:
            # fallback to default locale
            lang = 'en_us'

        if not isinstance(extra_headers, list):
            extra_headers = []

        extra_headers.append(
            ('Accept-Language', lang.replace('_', '-'))
        )
        extra_headers.append(
            ('Referer', 'https://%s/ipa/xml' % str(host))
        )

        return (host, extra_headers, x509)


class SSLTransport(LanguageAwareTransport):
    """Handles an HTTPS transaction to an XML-RPC server."""

    def make_connection(self, host):
        host, self._extra_headers, _x509 = self.get_host_info(host)

        if self._connection and host == self._connection[0]:
            logger.debug("HTTP connection keep-alive (%s)", host)
            return self._connection[1]

        conn = create_https_connection(
            host, 443,
            getattr(context, 'ca_certfile', None),
            tls_version_min=api.env.tls_version_min,
            tls_version_max=api.env.tls_version_max)

        conn.connect()
        logger.debug("New HTTP connection (%s)", host)

        self._connection = host, conn
        return self._connection[1]


class KerbTransport(SSLTransport):
    """
    Handles Kerberos Negotiation authentication to an XML-RPC server.
    """
    flags = [gssapi.RequirementFlag.mutual_authentication,
             gssapi.RequirementFlag.out_of_sequence_detection]

    def __init__(self, *args, **kwargs):
        SSLTransport.__init__(self, *args, **kwargs)
        self._sec_context = None
        self.service = kwargs.pop("service", "HTTP")
        self.ccache = kwargs.pop("ccache", None)

    def _try_acquire_cred(self, service, exc):
        if callable(self.api.env.acquire_cred):
            interactive = (self.api.env.interactive
                           and sys.stdin.isatty()) or self.api.env.prompt_all
            principal = getattr(context, 'principal', None)
            if service is None and self._connection is not None:
                # We've been through make_connection() already
                _service = self.get_service()
            else:
                _service = service
            self.api.env.acquire_cred(
                api=self.api,
                context=context,
                transport=self,
                principal=principal,
                ccache=self.ccache,
                service=_service,
                interactive=interactive,
                exc=exc)
            raise errors.NonFatalError(reason='credentials acquired')

    def _handle_exception(self, e, service=None):
        minor = e.min_code
        if minor == KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN:
            raise errors.ServiceError(service=service)
        elif minor == KRB5_FCC_NOFILE:
            raise errors.NoCCacheError()
        elif minor == KRB5KRB_AP_ERR_TKT_EXPIRED:
            self._try_acquire_cred(service, errors.TicketExpired)
            raise errors.TicketExpired()
        elif minor == KRB5_FCC_PERM:
            raise errors.BadCCachePerms()
        elif minor == KRB5_CC_FORMAT:
            raise errors.BadCCacheFormat()
        elif minor == KRB5_REALM_CANT_RESOLVE:
            raise errors.CannotResolveKDC()
        elif minor == KRB5_CC_NOTFOUND:
            self._try_acquire_cred(service, errors.CCacheError)
            raise errors.CCacheError()
        else:
            raise errors.KerberosError(message=unicode(e))

    def _get_service(self):
        return self.service + "@" + self._connection[0].split(':')[0]

    def _remove_extra_header(self, name):
        for (h, v) in self._extra_headers:
            if h == name:
                self._extra_headers.remove((h, v))
                break

    def get_auth_info(self, use_cookie=True):
        """
        Two things can happen here. If we have a session we will add
        a cookie for that. If not we will set an Authorization header.
        """
        if not isinstance(self._extra_headers, list):
            self._extra_headers = []

        # Remove any existing Cookie first
        self._remove_extra_header('Cookie')
        if use_cookie:
            session_cookie = getattr(context, 'session_cookie', None)
            if session_cookie:
                self._extra_headers.append(('Cookie', session_cookie))
                return

        # Set the remote host principal
        service = self._get_service()

        try:
            creds = None
            if self.ccache:
                creds = gssapi.Credentials(usage='initiate',
                                           store={'ccache': self.ccache})
            name = gssapi.Name(service, gssapi.NameType.hostbased_service)
            self._sec_context = gssapi.SecurityContext(creds=creds, name=name,
                                                       flags=self.flags)
            response = self._sec_context.step()
        except gssapi.exceptions.GSSError as e:
            try:
                self._handle_exception(e, service=service)
            except errors.NonFatalError:
                self.get_auth_info(use_cookie=use_cookie)
                return

        self._set_auth_header(response)

    def _set_auth_header(self, token):
        # Remove any existing authorization header first
        self._remove_extra_header('Authorization')

        if token:
            self._extra_headers.append(
                (
                    "Authorization",
                    "negotiate %s" % base64.b64encode(token).decode("ascii"),
                )
            )

    def _auth_complete(self, response):
        if self._sec_context:
            header = response.getheader('www-authenticate', '')
            token = None
            for field in header.split(','):
                k, _dummy, v = field.strip().partition(' ')
                if k.lower() == 'negotiate':
                    try:
                        token = base64.b64decode(v.encode('ascii'))
                        break
                    # b64decode raises TypeError on invalid input
                    except (TypeError, UnicodeError):
                        pass
            if not token:
                raise errors.KerberosError(
                    message=u"No valid Negotiate header in server response")
            token = self._sec_context.step(token=token)
            if self._sec_context.complete:
                self._sec_context = None
                return True
            self._set_auth_header(token)
            return False
        elif response.status == 401:
            self.get_auth_info(use_cookie=False)
            return False
        return True

    # pylint: disable=inconsistent-return-statements
    # pylint does not properly manage the _handle_exception call
    # that is always raising an exception
    def single_request(self, host, handler, request_body, verbose=0):
        # Based on Python 2.7's xmllib.Transport.single_request
        try:
            h = self.make_connection(host)

            if verbose:
                h.set_debuglevel(1)

            self.get_auth_info()

            while True:
                if six.PY2:
                    # pylint: disable=no-value-for-parameter
                    self.send_request(h, handler, request_body)
                    # pylint: enable=no-value-for-parameter
                    self.send_host(h, host)
                    self.send_user_agent(h)
                    self.send_content(h, request_body)
                    response = h.getresponse(buffering=True)
                else:
                    self.__send_request(h, host, handler,
                                        request_body, verbose)
                    response = h.getresponse()

                if response.status != 200:
                    # Must read response (even if it is empty)
                    # before sending another request.
                    #
                    # https://docs.python.org/3/library/http.client.html
                    #   #http.client.HTTPConnection.getresponse
                    #
                    # https://pagure.io/freeipa/issue/7752
                    #
                    response.read()

                    if response.status == 401:
                        if not self._auth_complete(response):
                            continue

                    raise ProtocolError(
                        host + handler,
                        response.status, response.reason,
                        response.msg)

                self.verbose = verbose
                if not self._auth_complete(response):
                    continue
                return self.parse_response(response)
        except gssapi.exceptions.GSSError as e:
            self._handle_exception(e)
        except RemoteDisconnected:
            # keep-alive connection was terminated by remote peer, close
            # connection and let transport handle reconnect for us.
            self.close()
            logger.debug("HTTP server has closed connection (%s)", host)
            raise
        except BaseException:
            # Unexpected exception may leave connections in a bad state.
            self.close()
            logger.debug("HTTP connection destroyed (%s)",
                         host, exc_info=True)
            raise
    # pylint: enable=inconsistent-return-statements

    if six.PY3:
        def __send_request(self, connection, host, handler,
                           request_body, debug):
            # Based on xmlrpc.client.Transport.send_request
            headers = self._extra_headers[:]
            if debug:
                connection.set_debuglevel(1)
            if self.accept_gzip_encoding and gzip:
                connection.putrequest("POST", handler,
                                      skip_accept_encoding=True)
                connection.putheader("Accept-Encoding", "gzip")
                headers.append(("Accept-Encoding", "gzip"))
            else:
                connection.putrequest("POST", handler)
            headers.append(("User-Agent", self.user_agent))
            self.send_headers(connection, headers)
            self.send_content(connection, request_body)
            return connection

    # Find all occurrences of the expiry component
    expiry_re = re.compile(r'.*?(&expiry=\d+).*?')

    def _slice_session_cookie(self, session_cookie):
        # Keep only the cookie value and strip away all other info.
        # This is to reduce the churn on FILE ccaches which grow every time we
        # set new data. The expiration time for the cookie is set in the
        # encrypted data anyway and will be enforced by the server
        http_cookie = session_cookie.http_cookie()
        # We also remove the "expiry" part from the data which is not required
        for exp in self.expiry_re.findall(http_cookie):
            http_cookie = http_cookie.replace(exp, '')
        return http_cookie

    def store_session_cookie(self, cookie_header):
        '''
        Given the contents of a Set-Cookie header scan the header and
        extract each cookie contained within until the session cookie
        is located. Examine the session cookie if the domain and path
        are specified, if not update the cookie with those values from
        the request URL. Then write the session cookie into the key
        store for the principal. If the cookie header is None or the
        session cookie is not present in the header no action is
        taken.

        Context Dependencies:

        The per thread context is expected to contain:
            principal
                The current pricipal the HTTP request was issued for.
            request_url
                The URL of the HTTP request.

        '''

        if cookie_header is None:
            return

        principal = getattr(context, 'principal', None)
        request_url = getattr(context, 'request_url', None)
        logger.debug("received Set-Cookie (%s)'%s'", type(cookie_header),
                     cookie_header)

        if not isinstance(cookie_header, list):
            cookie_header = [cookie_header]

        # Search for the session cookie
        session_cookie = None
        try:
            for cookie in cookie_header:
                session_cookie = (
                    Cookie.get_named_cookie_from_string(
                        cookie, COOKIE_NAME, request_url,
                        timestamp=datetime.datetime.now(
                            tz=datetime.timezone.utc))
                    )
                if session_cookie is not None:
                    break
        except Exception as e:
            logger.error("unable to parse cookie header '%s': %s",
                         cookie_header, e)
            return

        if session_cookie is None:
            return

        cookie_string = self._slice_session_cookie(session_cookie)
        logger.debug("storing cookie '%s' for principal %s",
                     cookie_string, principal)
        try:
            update_persistent_client_session_data(principal, cookie_string)
        except Exception:
            # Not fatal, we just can't use the session cookie we were sent.
            pass

    def parse_response(self, response):
        if six.PY2:
            header = response.msg.getheaders('Set-Cookie')
        else:
            header = response.msg.get_all('Set-Cookie')
        self.store_session_cookie(header)
        return SSLTransport.parse_response(self, response)


class DelegatedKerbTransport(KerbTransport):
    """
    Handles Kerberos Negotiation authentication and TGT delegation to an
    XML-RPC server.
    """
    flags = [gssapi.RequirementFlag.delegate_to_peer,
             gssapi.RequirementFlag.mutual_authentication,
             gssapi.RequirementFlag.out_of_sequence_detection]


class RPCClient(Connectible):
    """
    Forwarding backend plugin for XML-RPC client.

    Also see the `ipaserver.rpcserver.xmlserver` plugin.
    """

    # Values to set on subclasses:
    session_path = None
    server_proxy_class = ServerProxy
    protocol = None
    env_rpc_uri_key = None

    def get_url_list(self, rpc_uri):
        """
        Create a list of urls consisting of the available IPA servers.
        """
        # the configured URL defines what we use for the discovered servers
        (_scheme, _netloc, path, _params,
         _query, _fragment) = urllib.parse.urlparse(rpc_uri)
        servers = []
        name = '_ldap._tcp.%s.' % self.env.domain

        try:
            answers = query_srv(name)
        except DNSException:
            answers = []

        for answer in answers:
            server = str(answer.target).rstrip(".")
            servers.append('https://%s%s' % (
                ipautil.format_netloc(server), path))

        # make sure the configured master server is there just once and
        # it is the first one.
        if rpc_uri in servers:
            servers.remove(rpc_uri)
        servers.insert(0, rpc_uri)

        return servers

    def get_session_cookie_from_persistent_storage(self, principal):
        '''
        Retrieves the session cookie for the given principal from the
        persistent secure storage. Returns None if not found or unable
        to retrieve the session cookie for any reason, otherwise
        returns a Cookie object containing the session cookie.
        '''

        # Get the session data, it should contain a cookie string
        # (possibly with more than one cookie).
        try:
            cookie_string = read_persistent_client_session_data(principal)
            if cookie_string is None:
                return None
            cookie_string = cookie_string.decode('utf-8')
        except Exception as e:
            logger.debug('Error reading client session data: %s', e)
            return None

        # Search for the session cookie within the cookie string
        try:
            session_cookie = Cookie.get_named_cookie_from_string(
                cookie_string, COOKIE_NAME,
                timestamp=datetime.datetime.now(tz=datetime.timezone.utc))
        except Exception as e:
            logger.debug(
                'Error retrieving cookie from the persistent storage: %s',
                e)
            return None

        return session_cookie

    def apply_session_cookie(self, url):
        '''
        Attempt to load a session cookie for the current principal
        from the persistent secure storage. If the cookie is
        successfully loaded adjust the input url's to point to the
        session path and insert the session cookie into the per thread
        context for later insertion into the HTTP request. If the
        cookie is not successfully loaded then the original url is
        returned and the per thread context is not modified.

        Context Dependencies:

        The per thread context is expected to contain:
            principal
                The current pricipal the HTTP request was issued for.

        The per thread context will be updated with:
            session_cookie
                A cookie string to be inserted into the Cookie header
                of the HTPP request.

        '''

        original_url = url
        principal = getattr(context, 'principal', None)

        session_cookie = self.get_session_cookie_from_persistent_storage(
            principal)
        if session_cookie is None:
            logger.debug("failed to find session_cookie in persistent storage "
                         "for principal '%s'",
                         principal)
            return original_url
        else:
            logger.debug("found session_cookie in persistent storage for "
                         "principal '%s', cookie: '%s'",
                         principal, session_cookie)

        # Decide if we should send the cookie to the server
        try:
            session_cookie.http_return_ok(original_url)
        except Cookie.Expired as e:
            logger.debug("deleting session data for principal '%s': %s",
                         principal, e)
            try:
                delete_persistent_client_session_data(principal)
            except Exception:
                pass
            return original_url
        except Cookie.URLMismatch as e:
            logger.debug("not sending session cookie, URL mismatch: %s", e)
            return original_url
        except Exception as e:
            logger.error("not sending session cookie, unknown error: %s", e)
            return original_url

        # O.K. session_cookie is valid to be returned, stash it away where it
        # will get included in a HTTP Cookie headed sent to the server.
        logger.debug("setting session_cookie into context '%s'",
                     session_cookie.http_cookie())
        setattr(context, 'session_cookie', session_cookie.http_cookie())

        # Form the session URL by substituting the session path
        # into the original URL
        scheme, netloc, path, params, query, fragment = urllib.parse.urlparse(
            original_url)
        path = self.session_path
        session_url = urllib.parse.urlunparse((scheme, netloc, path,
                                               params, query, fragment))

        return session_url

    def create_connection(self, ccache=None, verbose=None, fallback=None,
                          delegate=None, ca_certfile=None):
        if verbose is None:
            verbose = self.api.env.verbose
        if fallback is None:
            fallback = self.api.env.fallback
        if delegate is None:
            delegate = self.api.env.delegate
        if ca_certfile is None:
            ca_certfile = self.api.env.tls_ca_cert
        context.ca_certfile = ca_certfile

        rpc_uri = self.env[self.env_rpc_uri_key]
        try:
            principal = get_principal(ccache_name=ccache)
            stored_principal = getattr(context, 'principal', None)
            if principal != stored_principal:
                try:
                    delattr(context, 'session_cookie')
                except AttributeError:
                    pass
            setattr(context, 'principal', principal)
            # We have a session cookie, try using the session URI to see if it
            # is still valid
            if not delegate:
                rpc_uri = self.apply_session_cookie(rpc_uri)
        except (errors.CCacheError, ValueError):
            # No session key, do full Kerberos auth
            pass
        urls = self.get_url_list(rpc_uri)

        proxy_kw = {
            'allow_none': True,
            'encoding': 'UTF-8',
            'verbose': verbose
        }

        for url in urls:
            # should we get ProtocolError (=> error in HTTP response) and
            # 401 (=> Unauthorized), we'll be re-trying with new session
            # cookies several times
            for _try_num in range(0, 5):
                if url.startswith('https://'):
                    if delegate:
                        transport_class = DelegatedKerbTransport
                    else:
                        transport_class = KerbTransport
                else:
                    transport_class = LanguageAwareTransport
                proxy_kw['transport'] = transport_class(
                    protocol=self.protocol, service='HTTP', ccache=ccache,
                    api=self.api)
                logger.debug('trying %s', url)
                setattr(context, 'request_url', url)
                serverproxy = self.server_proxy_class(url, **proxy_kw)
                if len(urls) == 1:
                    # if we have only 1 server and then let the
                    # main requester handle any errors. This also means it
                    # must handle a 401 but we save a ping.
                    return serverproxy
                try:
                    command = getattr(serverproxy, 'ping')
                    try:
                        command([], {})
                    except Fault as e:
                        e = decode_fault(e)
                        if e.faultCode in errors_by_code:
                            error = errors_by_code[e.faultCode]
                            raise error(message=e.faultString)
                        else:
                            raise UnknownError(
                                code=e.faultCode,
                                error=e.faultString,
                                server=url,
                            )
                    # We don't care about the response, just that we got one
                    return serverproxy
                except errors.KerberosError:
                    # kerberos error on one server is likely on all
                    raise
                except ProtocolError as e:
                    if hasattr(context, 'session_cookie') and e.errcode == 401:
                        # Unauthorized. Remove the session and try again.
                        delattr(context, 'session_cookie')
                        try:
                            delete_persistent_client_session_data(principal)
                        except Exception:
                            # This shouldn't happen if we have a session but
                            # it isn't fatal.
                            pass
                        # try the same url once more with a new session cookie
                        continue
                    if not fallback:
                        raise
                    else:
                        logger.info(
                            'Connection to %s failed with %s', url, e)
                    # try the next url
                    break
                except Exception as e:
                    if not fallback:
                        raise
                    else:
                        logger.info(
                            'Connection to %s failed with %s', url, e)
                    # try the next url
                    break
        # finished all tries but no serverproxy was found
        raise NetworkError(uri=_('any of the configured servers'),
                           error=', '.join(urls))

    def destroy_connection(self):
        conn = getattr(context, self.id, None)
        if conn is not None:
            conn = conn.conn._ServerProxy__transport
            conn.close()

    def _call_command(self, command, params):
        """Call the command with given params"""
        # For XML, this method will wrap/unwrap binary values
        # For JSON we do that in the proxy
        return command(*params)

    def forward(self, name, *args, **kw):
        """
        Forward call to command named ``name`` over XML-RPC.

        This method will encode and forward an XML-RPC request, and will then
        decode and return the corresponding XML-RPC response.

        :param command: The name of the command being forwarded.
        :param args: Positional arguments to pass to remote command.
        :param kw: Keyword arguments to pass to remote command.
        """
        server = getattr(context, 'request_url', None)
        command = getattr(self.conn, name)
        params = [args, kw]

        # we'll be trying to connect multiple times with a new session cookie
        # each time should we be getting UNAUTHORIZED error from the server
        max_tries = 5
        for try_num in range(0, max_tries):
            logger.debug("[try %d]: Forwarding '%s' to %s server '%s'",
                         try_num + 1, name, self.protocol, server)
            try:
                return self._call_command(command, params)
            except Fault as e:
                e = decode_fault(e)
                logger.debug('Caught fault %d from server %s: %s', e.faultCode,
                             server, e.faultString)
                if e.faultCode in errors_by_code:
                    error = errors_by_code[e.faultCode]
                    raise error(message=e.faultString)
                raise UnknownError(
                    code=e.faultCode,
                    error=e.faultString,
                    server=server,
                )
            except ProtocolError as e:
                # By catching a 401 here we can detect the case where we have
                # a single IPA server and the session is invalid. Otherwise
                # we always have to do a ping().
                session_cookie = getattr(context, 'session_cookie', None)
                if session_cookie and e.errcode == 401:
                    # Unauthorized. Remove the session and try again.
                    delattr(context, 'session_cookie')
                    try:
                        principal = getattr(context, 'principal', None)
                        delete_persistent_client_session_data(principal)
                    except Exception as e2:
                        # This shouldn't happen if we have a session
                        # but it isn't fatal.
                        logger.debug("Error trying to remove persisent "
                                     "session data: %s", e2)

                    # Create a new serverproxy with the non-session URI
                    serverproxy = self.create_connection(
                        os.environ.get('KRB5CCNAME'), self.env.verbose,
                        self.env.fallback, self.env.delegate)

                    setattr(context, self.id,
                            Connection(serverproxy, self.disconnect))
                    # try to connect again with the new session cookie
                    continue
                raise NetworkError(uri=server, error=e.errmsg)
            except (SSLError, socket.error) as e:
                raise NetworkError(uri=server, error=str(e))
            except (OverflowError, TypeError) as e:
                raise XMLRPCMarshallError(error=str(e))
        raise NetworkError(
            uri=server,
            error=_("Exceeded number of tries to forward a request."))


class xmlclient(RPCClient):
    session_path = '/ipa/session/xml'
    server_proxy_class = ServerProxy
    protocol = 'xml'
    env_rpc_uri_key = 'xmlrpc_uri'

    def _call_command(self, command, params):
        version = params[1].get('version', VERSION_WITHOUT_CAPABILITIES)
        params = xml_wrap(params, version)
        result = command(*params)
        return xml_unwrap(result)


class JSONServerProxy:
    def __init__(self, uri, transport, encoding, verbose, allow_none):
        split_uri = urllib.parse.urlsplit(uri)
        if split_uri.scheme not in ("http", "https"):
            raise IOError("unsupported XML-RPC protocol")
        self.__host = split_uri.netloc
        self.__handler = split_uri.path
        self.__transport = transport

        assert encoding == 'UTF-8'
        assert allow_none
        self.__verbose = verbose

        # FIXME: Some of our code requires ServerProxy internals.
        # But, xmlrpc.client.ServerProxy's _ServerProxy__transport can be
        # accessed by calling serverproxy('transport')
        self._ServerProxy__transport = transport

    def __request(self, name, args):
        print_json = self.__verbose >= 2
        payload = {'method': unicode(name), 'params': args, 'id': 0}
        version = args[1].get('version', VERSION_WITHOUT_CAPABILITIES)
        payload = json_encode_binary(
            payload, version, pretty_print=print_json)

        if print_json:
            logger.info(
                'Request: %s',
                payload
            )

        response = self.__transport.request(
            self.__host,
            self.__handler,
            payload.encode('utf-8'),
            verbose=self.__verbose >= 3,
        )

        if print_json:
            logger.info(
                'Response: %s',
                json.dumps(json.loads(response), sort_keys=True, indent=4)
            )

        try:
            response = json_decode_binary(response)
        except ValueError as e:
            raise JSONError(error=str(e))

        error = response.get('error')
        if error:
            try:
                error_class = errors_by_code[error['code']]
            except KeyError:
                raise UnknownError(
                    code=error.get('code'),
                    error=error.get('message'),
                    server=self.__host,
                )
            else:
                kw = error.get('data', {})
                kw['message'] = error['message']
                raise error_class(**kw)

        return response['result']

    def __getattr__(self, name):
        def _call(*args):
            return self.__request(name, args)
        return _call


class jsonclient(RPCClient):
    session_path = '/ipa/session/json'
    server_proxy_class = JSONServerProxy
    protocol = 'json'
    env_rpc_uri_key = 'jsonrpc_uri'
