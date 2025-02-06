# Authors:
#   Jason Gerard DeRose <jderose@redhat.com>
#
# Copyright (C) 2008-2016  Red Hat
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
RPC server.

Also see the `ipalib.rpc` module.
"""

from __future__ import absolute_import

import logging
from xml.sax.saxutils import escape
import os
import time
import traceback
from io import BytesIO
from sys import version_info
from urllib.parse import parse_qs
from xmlrpc.client import Fault

import gssapi
import requests

import ldap.controls
from pyasn1.type import univ, namedtype
from pyasn1.codec.ber import encoder
import six

from ipalib import plugable, errors
from ipalib.capabilities import VERSION_WITHOUT_CAPABILITIES
from ipalib.frontend import Local
from ipalib.install.kinit import kinit_armor, kinit_password
from ipalib.backend import Executioner
from ipalib.errors import (
    PublicError, InternalError, JSONError,
    CCacheError, RefererError, InvalidSessionPassword, NotFound, ACIError,
    ExecutionError, PasswordExpired, KrbPrincipalExpired, KrbPrincipalWrongFAST,
    UserLocked)
from ipalib.request import context, destroy_context
from ipalib.rpc import xml_dumps, xml_loads
from ipalib.ipajson import json_encode_binary, json_decode_binary
from ipapython.dn import DN
from ipaserver.plugins.ldap2 import ldap2
from ipalib.backend import Backend
from ipalib.krb_utils import (
    get_credentials_if_valid)
from ipapython import kerberos
from ipapython import ipautil
from ipaplatform.paths import paths
from ipapython.version import VERSION
from ipalib.text import _

from base64 import b64decode, b64encode
from requests.auth import AuthBase

if six.PY3:
    unicode = str

# time.perf_counter_ns appeared in Python 3.7.
if version_info < (3, 7):
    time.perf_counter_ns = lambda: int(time.perf_counter() * 10**9)

logger = logging.getLogger(__name__)

HTTP_STATUS_SUCCESS = '200 Success'
HTTP_STATUS_SERVER_ERROR = '500 Internal Server Error'
HTTP_STATUS_SERVICE_UNAVAILABLE = "503 Service Unavailable"

_not_found_template = """<html>
<head>
<title>404 Not Found</title>
</head>
<body>
<h1>Not Found</h1>
<p>
The requested URL <strong>%(url)s</strong> was not found on this server.
</p>
</body>
</html>"""

_bad_request_template = """<html>
<head>
<title>400 Bad Request</title>
</head>
<body>
<h1>Bad Request</h1>
<p>
<strong>%(message)s</strong>
</p>
</body>
</html>"""

_internal_error_template = """<html>
<head>
<title>500 Internal Server Error</title>
</head>
<body>
<h1>Internal Server Error</h1>
<p>
<strong>%(message)s</strong>
</p>
</body>
</html>"""

_unauthorized_template = """<html>
<head>
<title>401 Unauthorized</title>
</head>
<body>
<h1>Invalid Authentication</h1>
<p>
<strong>%(message)s</strong>
</p>
</body>
</html>"""

_service_unavailable_template = """<html>
<head>
<title>503 Service Unavailable</title>
</head>
<body>
<h1>Service Unavailable</h1>
<p>
<strong>%(message)s</strong>
</p>
</body>
</html>"""

_success_template = """<html>
<head>
<title>200 Success</title>
</head>
<body>
<h1>%(title)s</h1>
<p>
<strong>%(message)s</strong>
</p>
</body>
</html>"""

class HTTP_Status(plugable.Plugin):
    def check_referer(self, environ):
        if "HTTP_REFERER" not in environ:
            logger.error("Rejecting request with missing Referer")
            return False
        allowed_referers = getattr(self.api.env, 'allowed_referers', '')
        allowed_referers = allowed_referers or ''
        allowed_referers = allowed_referers.split(',')
        if (not environ["HTTP_REFERER"].startswith(
                "https://%s/ipa" % self.api.env.host)
                and all(not environ["HTTP_REFERER"].startswith(
                    "https://%s/ipa" % host) for host in allowed_referers)
                and not self.env.in_tree):
            logger.error("Rejecting request with bad Referer %s",
                         environ["HTTP_REFERER"])
            return False
        logger.debug("Valid Referer %s", environ["HTTP_REFERER"])
        return True

    def not_found(self, environ, start_response, url, message):
        """
        Return a 404 Not Found error.
        """
        status = '404 Not Found'
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]

        logger.info('%s: URL="%s", %s', status, url, message)
        start_response(status, response_headers)
        output = _not_found_template % dict(url=escape(url))
        return [output.encode('utf-8')]

    def bad_request(self, environ, start_response, message):
        """
        Return a 400 Bad Request error.
        """
        status = '400 Bad Request'
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]

        logger.info('%s: %s', status, message)

        start_response(status, response_headers)
        output = _bad_request_template % dict(message=escape(message))
        return [output.encode('utf-8')]

    def internal_error(self, environ, start_response, message):
        """
        Return a 500 Internal Server Error.
        """
        status = HTTP_STATUS_SERVER_ERROR
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]

        logger.error('%s: %s', status, message)

        start_response(status, response_headers)
        output = _internal_error_template % dict(message=escape(message))
        return [output.encode('utf-8')]

    def unauthorized(self, environ, start_response, message, reason):
        """
        Return a 401 Unauthorized error.
        """
        status = '401 Unauthorized'
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]
        if reason:
            response_headers.append(('X-IPA-Rejection-Reason', reason))

        logger.info('%s: %s', status, message)

        start_response(status, response_headers)
        output = _unauthorized_template % dict(message=escape(message))
        return [output.encode('utf-8')]

    def service_unavailable(self, environ, start_response, message):
        """
        Return a 503 Service Unavailable
        """
        status = HTTP_STATUS_SERVICE_UNAVAILABLE
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]

        logger.error('%s: %s', status, message)

        start_response(status, response_headers)
        output = _service_unavailable_template % dict(message=escape(message))
        return [output.encode('utf-8')]


def read_input(environ):
    """
    Read the request body from environ['wsgi.input'].
    """
    try:
        length = int(environ.get('CONTENT_LENGTH'))
    except (ValueError, TypeError):
        return None
    return environ['wsgi.input'].read(length).decode('utf-8')


def params_2_args_options(params):
    if len(params) == 0:
        return (tuple(), dict())
    if len(params) == 1:
        return (params[0], dict())
    return (params[0], params[1])


def nicify_query(query, encoding='utf-8'):
    if not query:
        return
    for (key, value) in query.items():
        if len(value) == 0:
            yield (key, None)
        elif len(value) == 1:
            yield (key, value[0].decode(encoding))
        else:
            yield (key, tuple(v.decode(encoding) for v in value))


def extract_query(environ):
    """
    Return the query as a ``dict``, or ``None`` if no query is presest.
    """
    qstr = None
    if environ['REQUEST_METHOD'] == 'POST':
        if environ['CONTENT_TYPE'] == 'application/x-www-form-urlencoded':
            qstr = read_input(environ)
    elif environ['REQUEST_METHOD'] == 'GET':
        qstr = environ['QUERY_STRING']
    if qstr:
        query = dict(nicify_query(parse_qs(qstr)))  # keep_blank_values=True)
    else:
        query = {}
    environ['wsgi.query'] = query
    return query


class wsgi_dispatch(Executioner, HTTP_Status):
    """
    WSGI routing middleware and entry point into IPA server.

    The `wsgi_dispatch` plugin is the entry point into the IPA server.
    It dispatchs the request to the appropriate wsgi application
    handler which is specific to the authentication and RPC mechanism.
    """

    def __init__(self, api):
        super(wsgi_dispatch, self).__init__(api)
        self.__apps = {}

    def __iter__(self):
        for key in sorted(self.__apps):
            yield key

    def __getitem__(self, key):
        return self.__apps[key]

    def __contains__(self, key):
        return key in self.__apps

    def __call__(self, environ, start_response):
        logger.debug('WSGI wsgi_dispatch.__call__:')
        try:
            return self.route(environ, start_response)
        finally:
            destroy_context()

    def _on_finalize(self):
        self.url = self.env['mount_ipa']
        super(wsgi_dispatch, self)._on_finalize()

    def route(self, environ, start_response):
        key = environ.get('PATH_INFO')
        if key in self.__apps:
            app = self.__apps[key]
            return app(environ, start_response)
        url = environ['SCRIPT_NAME'] + environ['PATH_INFO']
        return self.not_found(environ, start_response, url,
                              'URL fragment "%s" does not have a handler' % (key))

    def mount(self, app, key):
        """
        Mount the WSGI application *app* at *key*.
        """
#        if self.__islocked__():
#            raise Exception('%s.mount(): locked, cannot mount %r at %r' % (
#                self.name, app, key)
#            )
        if key in self.__apps:
            raise Exception('%s.mount(): cannot replace %r with %r at %r' % (
                self.name, self.__apps[key], app, key)
            )
        logger.debug('Mounting %r at %r', app, key)
        self.__apps[key] = app


class WSGIExecutioner(Executioner):
    """
    Base class for execution backends with a WSGI application interface.
    """

    headers = None
    content_type = None
    key = ''

    _system_commands = {}

    def _on_finalize(self):
        self.url = self.env.mount_ipa + self.key
        super(WSGIExecutioner, self)._on_finalize()
        if 'wsgi_dispatch' in self.api.Backend:
            self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def _get_command(self, name):
        try:
            # assume version 1 for unversioned command calls
            command = self.api.Command[name, '1']
        except KeyError:
            try:
                command = self.api.Command[name]
            except KeyError:
                command = None

        if command is None or isinstance(command, Local):
            raise errors.CommandError(name=name)

        return command

    def wsgi_execute(self, environ):
        result = None
        error = None
        _id = None
        name = None
        args = ()
        options = {}
        command = None

        e = None
        if 'HTTP_REFERER' not in environ:
            return self.marshal(result, RefererError(referer='missing'), _id)
        allowed_referers = getattr(self.api.env, 'allowed_referers', '')
        allowed_referers = allowed_referers or ''
        allowed_referers = allowed_referers.split(',')
        if (not environ["HTTP_REFERER"].startswith(
                "https://%s/ipa" % self.api.env.host)
                and all(not environ["HTTP_REFERER"].startswith(
                    "https://%s/ipa" % host) for host in allowed_referers)
                and not self.env.in_tree):
            return self.marshal(result, RefererError(referer=environ['HTTP_REFERER']), _id)
        if self.api.env.debug:
            time_start = time.perf_counter_ns()
        try:
            if 'KRB5CCNAME' in environ:
                setattr(context, "ccache_name", environ['KRB5CCNAME'])
            if ('HTTP_ACCEPT_LANGUAGE' in environ):
                lang_reg_w_q = environ['HTTP_ACCEPT_LANGUAGE'].split(',')[0]
                lang_reg = lang_reg_w_q.split(';')[0]
                lang = lang_reg.split('-')[0]
                setattr(context, "languages", [lang])

            if (
                environ.get('CONTENT_TYPE', '').startswith(self.content_type)
                and environ['REQUEST_METHOD'] == 'POST'
            ):
                data = read_input(environ)
                (name, args, options, _id) = self.unmarshal(data)
            else:
                (name, args, options, _id) = self.simple_unmarshal(environ)

            if name in self._system_commands:
                result = self._system_commands[name](self, *args, **options)
            else:
                command = self._get_command(name)
                result = command(*args, **options)
        except PublicError as e:
            if self.api.env.debug:
                logger.debug('WSGI wsgi_execute PublicError: %s',
                             traceback.format_exc())
            error = e
        except Exception as e:
            logger.exception(
                'non-public: %s: %s', e.__class__.__name__, str(e)
            )
            error = InternalError()
        finally:
            if hasattr(context, "languages"):
                delattr(context, "languages")

        principal = getattr(context, 'principal', 'UNKNOWN')
        if command is not None:
            try:
                params = command.args_options_2_params(*args, **options)
            except Exception as e:
                if self.api.env.debug:
                    time_end = time.perf_counter_ns()
                logger.info(
                   'exception %s caught when converting options: %s',
                   e.__class__.__name__, str(e)
                )
                # get at least some context of what is going on
                params = options
                error = e
            else:
                if self.api.env.debug:
                    time_end = time.perf_counter_ns()
            if error:
                result_string = type(error).__name__
            else:
                result_string = 'SUCCESS'
            logger.info('[%s] %s: %s(%s): %s',
                        type(self).__name__,
                        principal,
                        name,
                        ', '.join(command._repr_iter(**params)),
                        result_string)
            if self.api.env.debug:
                logger.debug('[%s] %s: %s(%s): %s %s',
                             type(self).__name__,
                             principal,
                             name,
                             ', '.join(command._repr_iter(**params)),
                             result_string,
                             'etime=' + str(time_end - time_start))
        else:
            logger.info('[%s] %s: %s: %s',
                        type(self).__name__,
                        principal,
                        name,
                        type(error).__name__)

        version = options.get('version', VERSION_WITHOUT_CAPABILITIES)
        return self.marshal(result, error, _id, version)

    def simple_unmarshal(self, environ):
        name = environ['PATH_INFO'].strip('/')
        options = extract_query(environ)
        return (name, tuple(), options, None)

    def __call__(self, environ, start_response):
        """
        WSGI application for execution.
        """

        logger.debug('WSGI WSGIExecutioner.__call__:')
        try:
            status = HTTP_STATUS_SUCCESS
            response = self.wsgi_execute(environ)
            if self.headers:
                headers = self.headers
            else:
                headers = [('Content-Type',
                            self.content_type + '; charset=utf-8')]
        except Exception:
            logger.exception('WSGI %s.__call__():', self.name)
            status = HTTP_STATUS_SERVER_ERROR
            response = status.encode('utf-8')
            headers = [('Content-Type', 'text/plain; charset=utf-8')]

        logout_cookie = getattr(context, 'logout_cookie', None)
        if logout_cookie is not None:
            headers.append(('IPASESSION', logout_cookie))

        start_response(status, headers)
        return [response]

    def unmarshal(self, data):
        raise NotImplementedError('%s.unmarshal()' % type(self).__name__)

    def marshal(self, result, error, _id=None,
                version=VERSION_WITHOUT_CAPABILITIES):
        raise NotImplementedError('%s.marshal()' % type(self).__name__)


class jsonserver(WSGIExecutioner, HTTP_Status):
    """
    JSON RPC server.

    For information on the JSON-RPC spec, see:

        http://json-rpc.org/wiki/specification
    """

    content_type = 'application/json'

    def __call__(self, environ, start_response):
        '''
        '''

        logger.debug('WSGI jsonserver.__call__:')

        response = super(jsonserver, self).__call__(environ, start_response)
        return response

    def marshal(self, result, error, _id=None,
                version=VERSION_WITHOUT_CAPABILITIES):
        if error:
            assert isinstance(error, PublicError)
            error = dict(
                code=error.errno,
                message=error.strerror,
                data=error.kw,
                name=unicode(error.__class__.__name__),
            )
        principal = getattr(context, 'principal', 'UNKNOWN')
        response = dict(
            result=result,
            error=error,
            id=_id,
            principal=unicode(principal),
            version=unicode(VERSION),
        )
        dump = json_encode_binary(
            response, version, pretty_print=self.api.env.debug
        )
        return dump.encode('utf-8')

    def unmarshal(self, data):
        try:
            d = json_decode_binary(data)
        except ValueError as e:
            raise JSONError(error=e)
        if not isinstance(d, dict):
            raise JSONError(error=_('Request must be a dict'))
        if 'method' not in d:
            raise JSONError(error=_('Request is missing "method"'))
        if 'params' not in d:
            raise JSONError(error=_('Request is missing "params"'))
        method = d['method']
        params = d['params']
        _id = d.get('id')
        if not isinstance(params, (list, tuple)):
            raise JSONError(error=_('params must be a list'))
        if len(params) != 2:
            raise JSONError(error=_('params must contain [args, options]'))
        args = params[0]
        if not isinstance(args, (list, tuple)):
            raise JSONError(error=_('params[0] (aka args) must be a list'))
        options = params[1]
        if not isinstance(options, dict):
            raise JSONError(error=_('params[1] (aka options) must be a dict'))
        options = dict((str(k), v) for (k, v) in options.items())
        return (method, args, options, _id)


class NegotiateAuth(AuthBase):
    """Negotiate Augh using python GSSAPI"""
    def __init__(self, target_host, ccache_name=None):
        self.context = None
        self.target_host = target_host
        self.ccache_name = ccache_name

    def __call__(self, request):
        self.initial_step(request)
        request.register_hook('response', self.handle_response)
        return request

    def deregister(self, response):
        response.request.deregister_hook('response', self.handle_response)

    def _get_negotiate_token(self, response):
        token = None
        if response is not None:
            h = response.headers.get('www-authenticate', '')
            if h.startswith('Negotiate'):
                val = h[h.find('Negotiate') + len('Negotiate'):].strip()
                if len(val) > 0:
                    token = b64decode(val)
        return token

    def _set_authz_header(self, request, token):
        request.headers['Authorization'] = (
            'Negotiate {}'.format(b64encode(token).decode('utf-8')))

    def initial_step(self, request, response=None):
        if self.context is None:
            store = {'ccache': self.ccache_name}
            creds = gssapi.Credentials(usage='initiate', store=store)
            name = gssapi.Name('HTTP@{0}'.format(self.target_host),
                               name_type=gssapi.NameType.hostbased_service)
            self.context = gssapi.SecurityContext(creds=creds, name=name,
                                                  usage='initiate')

        in_token = self._get_negotiate_token(response)
        out_token = self.context.step(in_token)
        self._set_authz_header(request, out_token)

    def handle_response(self, response, **kwargs):
        status = response.status_code
        if status >= 400 and status != 401:
            return response

        in_token = self._get_negotiate_token(response)
        if in_token is not None:
            out_token = self.context.step(in_token)
            if self.context.complete:
                return response
            elif not out_token:
                return response

            self._set_authz_header(response.request, out_token)
            # use response so we can make another request
            _ = response.content  # pylint: disable=unused-variable
            response.raw.release_conn()
            newresp = response.connection.send(response.request, **kwargs)
            newresp.history.append(response)
            return self.handle_response(newresp, **kwargs)

        return response


class KerberosSession(HTTP_Status):
    '''
    Functionally shared by all RPC handlers using both sessions and
    Kerberos.  This class must be implemented as a mixin class rather
    than the more obvious technique of subclassing because the classes
    needing this do not share a common base class.
    '''

    def need_login(self, start_response):
        status = '401 Unauthorized'
        headers = []
        response = b''

        logout_cookie = getattr(context, 'logout_cookie', None)
        if logout_cookie is not None:
            headers.append(('IPASESSION', logout_cookie))

        logger.debug('%s need login', status)

        start_response(status, headers)
        return [response]

    def get_environ_creds(self, environ):
        # If we have a ccache ...
        ccache_name = environ.get('KRB5CCNAME')
        if ccache_name is None:
            logger.debug('no ccache, need login')
            return None

        # ... make sure we have a name ...
        principal = environ.get('GSS_NAME')
        if principal is None:
            logger.debug('no Principal Name, need login')
            return None

        # ... and use it to resolve the ccache name (Issue: 6972 )
        gss_name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)

        # Fail if Kerberos credentials are expired or missing
        creds = get_credentials_if_valid(name=gss_name,
                                         ccache_name=ccache_name)
        if not creds:
            setattr(context, 'logout_cookie', 'MagBearerToken=')
            logger.debug(
                'ccache expired or invalid, deleting session, need login')
            return None

        return ccache_name


    def finalize_kerberos_acquisition(self, who, ccache_name, environ, start_response, headers=None):
        if headers is None:
            headers = []

        # Connect back to ourselves to get mod_auth_gssapi to
        # generate a cookie for us.
        try:
            target = self.api.env.host
            # pylint: disable-next=missing-timeout
            r = requests.get('http://{0}/ipa/session/cookie'.format(target),
                             auth=NegotiateAuth(target, ccache_name),
                             verify=paths.IPA_CA_CRT)
            session_cookie = r.cookies.get("ipa_session")
            if not session_cookie:
                raise ValueError('No session cookie found')
        except Exception as e:
            return self.unauthorized(environ, start_response,
                                     str(e),
                                     'Authentication failed')

        headers.append(('IPASESSION', session_cookie))

        start_response(HTTP_STATUS_SUCCESS, headers)
        return [b'']


class KerberosWSGIExecutioner(WSGIExecutioner, KerberosSession):
    """Base class for xmlserver and jsonserver_kerb
    """

    def _on_finalize(self):
        super(KerberosWSGIExecutioner, self)._on_finalize()

    def __call__(self, environ, start_response):
        logger.debug('KerberosWSGIExecutioner.__call__:')
        user_ccache=environ.get('KRB5CCNAME')

        object.__setattr__(
            self, 'headers',
            [('Content-Type', '%s; charset=utf-8' % self.content_type)]
        )

        if user_ccache is None:

            status = HTTP_STATUS_SERVER_ERROR

            logger.error(
                '%s: %s', status,
                'KerberosWSGIExecutioner.__call__: '
                'KRB5CCNAME not defined in HTTP request environment')

            return self.marshal(None, CCacheError())

        try:
            self.create_context(ccache=user_ccache)
            response = super(KerberosWSGIExecutioner, self).__call__(
                environ, start_response)
        except PublicError as e:
            status = HTTP_STATUS_SUCCESS
            response = status.encode('utf-8')
            start_response(status, self.headers)
            return [self.marshal(None, e)]
        finally:
            destroy_context()
        return response


class xmlserver(KerberosWSGIExecutioner):
    """
    Execution backend plugin for XML-RPC server.

    Also see the `ipalib.rpc.xmlclient` plugin.
    """

    content_type = 'text/xml'
    key = '/xml'

    def listMethods(self, *params):
        """list methods for XML-RPC introspection"""
        if params:
            raise errors.ZeroArgumentError(name='system.listMethods')
        return (tuple(unicode(cmd.name) for cmd in self.api.Command) +
                tuple(unicode(name) for name in self._system_commands))

    def _get_method_name(self, name, *params):
        """Get a method name for XML-RPC introspection commands"""
        if not params:
            raise errors.RequirementError(name='method name')
        elif len(params) > 1:
            raise errors.MaxArgumentError(name=name, count=1)
        [method_name] = params
        return method_name

    def methodSignature(self, *params):
        """get method signature for XML-RPC introspection"""
        method_name = self._get_method_name('system.methodSignature', *params)
        if method_name in self._system_commands:
            # TODO
            # for now let's not go out of our way to document standard XML-RPC
            return u'undef'
        else:
            self._get_command(method_name)

            # All IPA commands return a dict (struct),
            # and take a params, options - list and dict (array, struct)
            return [[u'struct', u'array', u'struct']]

    def methodHelp(self, *params):
        """get method docstring for XML-RPC introspection"""
        method_name = self._get_method_name('system.methodHelp', *params)
        if method_name in self._system_commands:
            return u''
        else:
            command = self._get_command(method_name)
            return unicode(command.doc or '')

    _system_commands = {
        'system.listMethods': listMethods,
        'system.methodSignature': methodSignature,
        'system.methodHelp': methodHelp,
    }

    def unmarshal(self, data):
        (params, name) = xml_loads(data)
        if name in self._system_commands:
            # For XML-RPC introspection, return params directly
            return (name, params, {}, None)
        (args, options) = params_2_args_options(params)
        if 'version' not in options:
            # Keep backwards compatibility with client containing
            # bug https://fedorahosted.org/freeipa/ticket/3294:
            # If `version` is not given in XML-RPC, assume an old version
            options['version'] = VERSION_WITHOUT_CAPABILITIES
        return (name, args, options, None)

    def marshal(self, result, error, _id=None,
                version=VERSION_WITHOUT_CAPABILITIES):
        if error:
            logger.debug('response: %s: %s',
                         error.__class__.__name__, str(error))
            response = Fault(error.errno, error.strerror)
        else:
            if isinstance(result, dict):
                logger.debug('response: entries returned %d',
                             result.get('count', 1))
            response = (result,)
        dump = xml_dumps(response, version, methodresponse=True)
        return dump.encode('utf-8')


class jsonserver_i18n_messages(jsonserver):
    """
    JSON RPC server for i18n messages only.
    """

    key = '/i18n_messages'

    def not_allowed(self, start_response):
        status = '405 Method Not Allowed'
        headers = [('Allow', 'POST')]
        response = b''

        logger.debug('jsonserver_i18n_messages: %s', status)
        start_response(status, headers)
        return [response]

    def forbidden(self, start_response):
        status = '403 Forbidden'
        headers = []
        response = b'Invalid RPC command'

        logger.debug('jsonserver_i18n_messages: %s', status)
        start_response(status, headers)
        return [response]

    def __call__(self, environ, start_response):
        logger.debug('WSGI jsonserver_i18n_messages.__call__:')
        if environ['REQUEST_METHOD'] != 'POST':
            return self.not_allowed(start_response)

        data = read_input(environ)
        unmarshal_data = super(jsonserver_i18n_messages, self
                               ).unmarshal(data)
        name = unmarshal_data[0] if unmarshal_data else ''
        if name != 'i18n_messages':
            return self.forbidden(start_response)

        environ['wsgi.input'] = BytesIO(data.encode('utf-8'))
        response = super(jsonserver_i18n_messages, self
                         ).__call__(environ, start_response)
        return response


class jsonserver_session(jsonserver, KerberosSession):
    """
    JSON RPC server protected with session auth.
    """

    key = '/session/json'

    def __init__(self, api):
        super(jsonserver_session, self).__init__(api)

    def _on_finalize(self):
        super(jsonserver_session, self)._on_finalize()

    def __call__(self, environ, start_response):
        '''
        '''

        logger.debug('WSGI jsonserver_session.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        # Redirect to login if no Kerberos credentials
        ccache_name = self.get_environ_creds(environ)
        if ccache_name is None:
            return self.need_login(start_response)

        # Store the ccache name in the per-thread context
        setattr(context, 'ccache_name', ccache_name)

        # This may fail if a ticket from wrong realm was handled via browser
        try:
            self.create_context(ccache=ccache_name)
        except ACIError as e:
            return self.unauthorized(environ, start_response, str(e), 'denied')
        except errors.DatabaseError as e:
            # account is disable but user has a valid ticket
            msg = str(e)
            if "account inactivated" in msg.lower():
                return self.unauthorized(
                    environ, start_response, str(e), "account disabled"
                )
            else:
                return self.service_unavailable(environ, start_response, msg)

        except CCacheError:
            return self.need_login(start_response)

        try:
            response = super(jsonserver_session, self).__call__(environ, start_response)
        finally:
            destroy_context()

        return response


class jsonserver_kerb(jsonserver, KerberosWSGIExecutioner):
    """
    JSON RPC server protected with kerberos auth.
    """

    key = '/json'


class KerberosLogin(Backend, KerberosSession):
    key = None

    def _on_finalize(self):
        super(KerberosLogin, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def __call__(self, environ, start_response):
        logger.debug('WSGI KerberosLogin.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        # Redirect to login if no Kerberos credentials
        user_ccache_name = self.get_environ_creds(environ)
        if user_ccache_name is None:
            return self.need_login(start_response)

        return self.finalize_kerberos_acquisition('login_kerberos', user_ccache_name, environ, start_response)


class login_kerberos(KerberosLogin):
    key = '/session/login_kerberos'


class login_x509(KerberosLogin):
    key = '/session/login_x509'

    def __call__(self, environ, start_response):
        logger.debug('WSGI login_x509.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        if 'KRB5CCNAME' not in environ:
            return self.unauthorized(
                environ, start_response, 'KRB5CCNAME not set',
                'Authentication failed')

        return super(login_x509, self).__call__(environ, start_response)


class login_password(Backend, KerberosSession):

    content_type = 'text/plain'
    key = '/session/login_password'

    def _on_finalize(self):
        super(login_password, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def __call__(self, environ, start_response):
        def attempt_kinit(user_principal, password,
                          ipa_ccache_name, use_armor=True):
            try:
                # try to remove in case an old file was there
                os.unlink(ipa_ccache_name)
            except OSError:
                pass
            try:
                self.kinit(user_principal, password,
                           ipa_ccache_name, use_armor=use_armor)
            except PasswordExpired as e:
                return self.unauthorized(environ, start_response,
                                         str(e), 'password-expired')
            except InvalidSessionPassword as e:
                return self.unauthorized(environ, start_response,
                                         str(e), 'invalid-password')
            except KrbPrincipalExpired as e:
                return self.unauthorized(environ,
                                         start_response,
                                         str(e),
                                         'krbprincipal-expired')
            except UserLocked as e:
                return self.unauthorized(environ,
                                         start_response,
                                         str(e),
                                         'user-locked')
            return None

        logger.debug('WSGI login_password.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        # Get the user and password parameters from the request
        content_type = environ.get('CONTENT_TYPE', '').lower()
        if not content_type.startswith('application/x-www-form-urlencoded'):
            return self.bad_request(environ, start_response, "Content-Type must be application/x-www-form-urlencoded")

        method = environ.get('REQUEST_METHOD', '').upper()
        if method == 'POST':
            query_string = read_input(environ)
        else:
            return self.bad_request(environ, start_response, "HTTP request method must be POST")

        try:
            query_dict = parse_qs(query_string)
        except Exception:
            return self.bad_request(environ, start_response, "cannot parse query data")

        user = query_dict.get('user', None)
        if user is not None:
            if len(user) == 1:
                user = user[0]
            else:
                return self.bad_request(environ, start_response, "more than one user parameter")
        else:
            return self.bad_request(environ, start_response, "no user specified")

        # allows login in the form user@SERVER_REALM or user@server_realm
        # we kinit as enterprise principal so we can assume that unknown realms
        # are UPN
        try:
            user_principal = kerberos.Principal(user)
        except Exception:
            # the principal is malformed in some way (e.g. user@REALM1@REALM2)
            # netbios names (NetBIOS1\user) are also not accepted (yet)
            return self.unauthorized(environ, start_response, '', 'denied')

        password = query_dict.get('password', None)
        if password is not None:
            if len(password) == 1:
                password = password[0]
            else:
                return self.bad_request(environ, start_response, "more than one password parameter")
        else:
            return self.bad_request(environ, start_response, "no password specified")

        # Get the ccache we'll use and attempt to get credentials in it with user,password
        ipa_ccache_name = os.path.join(paths.IPA_CCACHES,
                                       'kinit_{}'.format(os.getpid()))
        try:
            result = attempt_kinit(user_principal, password,
                                   ipa_ccache_name, use_armor=True)
        except KrbPrincipalWrongFAST:
            result = attempt_kinit(user_principal, password,
                                   ipa_ccache_name, use_armor=False)

        if result is not None:
            return result

        result = self.finalize_kerberos_acquisition('login_password',
                                                    ipa_ccache_name, environ,
                                                    start_response)
        try:
            # Try not to litter the filesystem with unused TGTs
            os.unlink(ipa_ccache_name)
        except OSError:
            pass
        return result

    def kinit(self, principal, password, ccache_name, use_armor=True):
        if use_armor:
            # get anonymous ccache as an armor for FAST to enable OTP auth
            armor_path = os.path.join(paths.IPA_CCACHES,
                                      "armor_{}".format(os.getpid()))

            logger.debug('Obtaining armor in ccache %s', armor_path)

            try:
                kinit_armor(
                    armor_path,
                    pkinit_anchors=[paths.KDC_CERT, paths.KDC_CA_BUNDLE_PEM],
                )
            except RuntimeError:
                logger.error("Failed to obtain armor cache")
                # We try to continue w/o armor, 2FA will be impacted
                armor_path = None
        else:
            armor_path = None

        try:
            kinit_password(
                unicode(principal),
                password,
                ccache_name,
                armor_ccache_name=armor_path,
                enterprise=True,
                canonicalize=True,
                lifetime=self.api.env.kinit_lifetime)

        except RuntimeError as e:
            if ('kinit: Cannot read password while '
                    'getting initial credentials') in str(e):
                raise PasswordExpired(principal=principal, message=unicode(e))
            elif ('kinit: Client\'s entry in database'
                  ' has expired while getting initial credentials') in str(e):
                raise KrbPrincipalExpired(principal=principal,
                                          message=unicode(e))
            elif ('kinit: Clients credentials have been revoked '
                  'while getting initial credentials') in str(e):
                raise UserLocked(principal=principal,
                                 message=unicode(e))
            elif ('kinit: Error constructing AP-REQ armor: '
                  'Matching credential not found') in str(e):
                raise KrbPrincipalWrongFAST(principal=principal)
            raise InvalidSessionPassword(principal=principal,
                                         message=unicode(e))
        finally:
            if armor_path:
                logger.debug('Cleanup the armor ccache')
                ipautil.run([paths.KDESTROY, '-A', '-c', armor_path],
                            env={'KRB5CCNAME': armor_path}, raiseonerr=False)


class change_password(Backend, HTTP_Status):

    content_type = 'text/plain'
    key = '/session/change_password'

    def _on_finalize(self):
        super(change_password, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def __call__(self, environ, start_response):
        logger.info('WSGI change_password.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        # Get the user and password parameters from the request
        content_type = environ.get('CONTENT_TYPE', '').lower()
        if not content_type.startswith('application/x-www-form-urlencoded'):
            return self.bad_request(environ, start_response, "Content-Type must be application/x-www-form-urlencoded")

        method = environ.get('REQUEST_METHOD', '').upper()
        if method == 'POST':
            query_string = read_input(environ)
        else:
            return self.bad_request(environ, start_response, "HTTP request method must be POST")

        try:
            query_dict = parse_qs(query_string)
        except Exception:
            return self.bad_request(
                environ, start_response, "cannot parse query data"
            )

        data = {}
        for field in ('user', 'old_password', 'new_password', 'otp'):
            value = query_dict.get(field, None)
            if value is not None:
                if len(value) == 1:
                    data[field] = value[0]
                else:
                    return self.bad_request(environ, start_response, "more than one %s parameter"
                                            % field)
            elif field != 'otp':  # otp is optional
                return self.bad_request(environ, start_response, "no %s specified" % field)

        # start building the response
        logger.info("WSGI change_password: start password change of user '%s'",
                    data['user'])
        status = HTTP_STATUS_SUCCESS
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]
        title = 'Password change rejected'
        result = 'error'
        policy_error = None

        bind_dn = DN((self.api.Object.user.primary_key.name, data['user']),
                     self.api.env.container_user, self.api.env.basedn)

        try:
            pw = data['old_password']
            if data.get('otp'):
                pw = data['old_password'] + data['otp']
            conn = ldap2(self.api)
            conn.connect(bind_dn=bind_dn, bind_pw=pw)
        except (NotFound, ACIError):
            result = 'invalid-password'
            message = 'The old password or username is not correct.'
        except Exception as e:
            message = "Could not connect to LDAP server."
            logger.error("change_password: cannot authenticate '%s' to LDAP "
                         "server: %s",
                         data['user'], str(e))
        else:
            try:
                conn.modify_password(bind_dn, data['new_password'], data['old_password'], skip_bind=True)
            except ExecutionError as e:
                result = 'policy-error'
                policy_error = escape(str(e))
                message = "Password change was rejected: %s" % escape(str(e))
            except Exception as e:
                message = "Could not change the password"
                logger.error("change_password: cannot change password of "
                             "'%s': %s",
                             data['user'], str(e))
            else:
                result = 'ok'
                title = "Password change successful"
                message = "Password was changed."
            finally:
                if conn.isconnected():
                    conn.disconnect()

        logger.info('%s: %s', status, message)

        response_headers.append(('X-IPA-Pwchange-Result', result))
        if policy_error:
            response_headers.append(('X-IPA-Pwchange-Policy-Error', policy_error))

        start_response(status, response_headers)
        output = _success_template % dict(title=str(title),
                                          message=str(message))
        return [output.encode('utf-8')]

class sync_token(Backend, HTTP_Status):
    content_type = 'text/plain'
    key = '/session/sync_token'

    class OTPSyncRequest(univ.Sequence):
        OID = "2.16.840.1.113730.3.8.10.6"

        componentType = namedtype.NamedTypes(
            namedtype.NamedType('firstCode', univ.OctetString()),
            namedtype.NamedType('secondCode', univ.OctetString()),
            namedtype.OptionalNamedType('tokenDN', univ.OctetString())
        )

    def _on_finalize(self):
        super(sync_token, self)._on_finalize()
        self.api.Backend.wsgi_dispatch.mount(self, self.key)

    def __call__(self, environ, start_response):
        # Make sure this is a form request.
        content_type = environ.get('CONTENT_TYPE', '').lower()
        if not content_type.startswith('application/x-www-form-urlencoded'):
            return self.bad_request(environ, start_response, "Content-Type must be application/x-www-form-urlencoded")

        # Make sure this is a POST request.
        method = environ.get('REQUEST_METHOD', '').upper()
        if method == 'POST':
            query_string = read_input(environ)
        else:
            return self.bad_request(environ, start_response, "HTTP request method must be POST")

        # Parse the query string to a dictionary.
        try:
            query_dict = parse_qs(query_string)
        except Exception:
            return self.bad_request(
                environ, start_response, "cannot parse query data"
            )
        data = {}
        for field in ('user', 'password', 'first_code', 'second_code', 'token'):
            value = query_dict.get(field, None)
            if value is not None:
                if len(value) == 1:
                    data[field] = value[0]
                else:
                    return self.bad_request(environ, start_response, "more than one %s parameter"
                                            % field)
            elif field != 'token':
                return self.bad_request(environ, start_response, "no %s specified" % field)

        # Create the request control.
        sr = self.OTPSyncRequest()
        sr.setComponentByName('firstCode', data['first_code'])
        sr.setComponentByName('secondCode', data['second_code'])
        if 'token' in data:
            try:
                token_dn = DN(data['token'])
            except ValueError:
                token_dn = DN((self.api.Object.otptoken.primary_key.name, data['token']),
                              self.api.env.container_otp, self.api.env.basedn)

            sr.setComponentByName('tokenDN', str(token_dn))
        rc = ldap.controls.RequestControl(sr.OID, True, encoder.encode(sr))

        # Resolve the user DN
        bind_dn = DN((self.api.Object.user.primary_key.name, data['user']),
                     self.api.env.container_user, self.api.env.basedn)

        # Start building the response.
        status = HTTP_STATUS_SUCCESS
        response_headers = [('Content-Type', 'text/html; charset=utf-8')]
        title = 'Token sync rejected'

        # Perform the synchronization.
        conn = ldap2(self.api)
        try:
            conn.connect(bind_dn=bind_dn,
                         bind_pw=data['password'],
                         serverctrls=[rc,])
            result = 'ok'
            title = "Token sync successful"
            message = "Token was synchronized."
        except (NotFound, ACIError):
            result = 'invalid-credentials'
            message = 'The username, password or token codes are not correct.'
        except Exception as e:
            result = 'error'
            message = "Could not connect to LDAP server."
            logger.error("token_sync: cannot authenticate '%s' to LDAP "
                         "server: %s",
                         data['user'], str(e))
        finally:
            if conn.isconnected():
                conn.disconnect()

        # Report status and return.
        response_headers.append(('X-IPA-TokenSync-Result', result))
        start_response(status, response_headers)
        output = _success_template % dict(title=str(title),
                                          message=str(message))
        return [output.encode('utf-8')]

class xmlserver_session(xmlserver, KerberosSession):
    """
    XML RPC server protected with session auth.
    """

    key = '/session/xml'

    def __init__(self, api):
        super(xmlserver_session, self).__init__(api)

    def _on_finalize(self):
        super(xmlserver_session, self)._on_finalize()

    def need_login(self, start_response):
        status = '401 Unauthorized'
        headers = []
        response = b''

        logger.debug('xmlserver_session: %s need login', status)

        start_response(status, headers)
        return [response]

    def __call__(self, environ, start_response):
        '''
        '''

        logger.debug('WSGI xmlserver_session.__call__:')

        if not self.check_referer(environ):
            return self.bad_request(environ, start_response, 'denied')

        ccache_name = environ.get('KRB5CCNAME')

        # Redirect to /ipa/xml if no Kerberos credentials
        if ccache_name is None:
            logger.debug('xmlserver_session.__call_: no ccache, need TGT')
            return self.need_login(start_response)

        # Redirect to /ipa/xml if Kerberos credentials are expired
        creds = get_credentials_if_valid(ccache_name=ccache_name)
        if not creds:
            logger.debug('xmlserver_session.__call_: ccache expired, deleting '
                         'session, need login')
            # The request is finished with the ccache, destroy it.
            return self.need_login(start_response)

        # Store the session data in the per-thread context
        setattr(context, 'ccache_name', ccache_name)

        try:
            response = super(xmlserver_session, self).__call__(environ, start_response)
        finally:
            destroy_context()

        return response
