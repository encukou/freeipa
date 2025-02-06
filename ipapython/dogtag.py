# Authors: Rob Crittenden <rcritten@redhat.com>
#
# Copyright (C) 2009    Red Hat
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

import collections
import gzip
import io
import json
import logging
from urllib.parse import urlencode
import xml.dom.minidom
import zlib

import six

# pylint: disable=ipa-forbidden-import
from ipalib import api, errors
from ipalib.util import create_https_connection
from ipalib.errors import NetworkError
from ipalib.text import _
# pylint: enable=ipa-forbidden-import
from ipapython import ipautil

# Python 3 rename. The package is available in "six.moves.http_client", but
# pylint cannot handle classes from that alias
try:
    import httplib
except ImportError:
    import http.client as httplib

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

Profile = collections.namedtuple('Profile', ['profile_id', 'description', 'store_issued'])

INCLUDED_PROFILES = {
    Profile(u'caIPAserviceCert', u'Standard profile for network services', True),
    Profile(u'IECUserRoles', u'User profile that includes IECUserRoles extension from request', True),
    Profile(u'KDCs_PKINIT_Certs',
            u'Profile for PKINIT support by KDCs',
            False),
    Profile(u'acmeIPAServerCert',
            u'ACME IPA service certificate profile',
            False),
    }

DEFAULT_PROFILE = u'caIPAserviceCert'
KDC_PROFILE = u'KDCs_PKINIT_Certs'
OCSP_PROFILE = 'caOCSPCert'
SUBSYSTEM_PROFILE = 'caSubsystemCert'
AUDIT_PROFILE = 'caSignedLogCert'
CACERT_PROFILE = 'caCACert'
CASERVER_PROFILE = 'caServerCert'
KRA_AUDIT_PROFILE = 'caAuditSigningCert'
KRA_STORAGE_PROFILE = 'caStorageCert'
KRA_TRANSPORT_PROFILE = 'caTransportCert'


if six.PY3:
    gzip_decompress = gzip.decompress
else:
    # note: gzip.decompress available in Python >= 3.2
    def gzip_decompress(data):
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
            return f.read()


def error_from_xml(doc, message_template):
    try:
        item_node = doc.getElementsByTagName("Error")
        reason = item_node[0].childNodes[0].data
        return errors.RemoteRetrieveError(reason=reason)
    except Exception as e:
        return errors.RemoteRetrieveError(reason=message_template % e)


def get_ca_certchain(ca_host=None):
    """
    Retrieve the CA Certificate chain from the configured Dogtag server.
    """
    if ca_host is None:
        ca_host = api.env.ca_host
    chain = None
    conn = httplib.HTTPConnection(
        ca_host,
        api.env.ca_install_port or 8080)
    conn.request("GET", "/ca/ee/ca/getCertChain")
    res = conn.getresponse()
    doc = None
    if res.status == 200:
        data = res.read()
        conn.close()
        try:
            doc = json.loads(data)
            chain = doc['Response']['ChainBase64']
        except (json.JSONDecodeError, KeyError):
            logger.debug("Response is not valid JSON, try XML")
            doc = xml.dom.minidom.parseString(data)
            try:
                item_node = doc.getElementsByTagName("ChainBase64")
                chain = item_node[0].childNodes[0].data
            except IndexError:
                raise error_from_xml(
                    doc, _("Retrieving CA cert chain failed: %s"))
            finally:
                if doc:
                    doc.unlink()
    else:
        raise errors.RemoteRetrieveError(
            reason=_("request failed with HTTP status %d") % res.status)

    return chain


def _parse_ca_status(body):
    try:
        doc = json.loads(body)
        return doc['Response']['Status']
    except (json.JSONDecodeError, KeyError):
        logger.debug("Response is not valid JSON, try XML")
        doc = xml.dom.minidom.parseString(body)
        try:
            item_node = doc.getElementsByTagName("XMLResponse")[0]
            item_node = item_node.getElementsByTagName("Status")[0]
            return item_node.childNodes[0].data
        except IndexError:
            raise error_from_xml(doc, _("Retrieving CA status failed: %s"))


def ca_status(ca_host=None):
    """Return the status of the CA, and the httpd proxy in front of it

    The returned status can be:
    - running
    - starting
    - Service Temporarily Unavailable
    """
    if ca_host is None:
        ca_host = api.env.ca_host
    status, _headers, body = http_request(
        ca_host, 8080, '/ca/admin/ca/getStatus',
        # timeout: CA sometimes forgot to answer, we have to try again
        timeout=api.env.http_timeout)
    if status == 503:
        # Service temporarily unavailable
        return status
    elif status != 200:
        raise errors.RemoteRetrieveError(
            reason=_("Retrieving CA status failed with status %d") % status)
    return _parse_ca_status(body)


def acme_status(ca_host=None):
    """Return the status of ACME

    Returns a boolean.

    If the proxy is not working or the CA is not running then this could
    return a false negative.
    """
    if ca_host is None:
        ca_host = api.env.ca_host
    status, _headers, _body = https_request(
        ca_host, 443,
        url='/acme/directory',
        cafile=api.env.tls_ca_cert,
        client_certfile=None,
        client_keyfile=None,
        method='GET',
        timeout=api.env.http_timeout)
    if status == 200:
        return True
    elif status == 503:
        # This is what it should return when disabled
        return False
    else:
        # Unexpected status code, log and return False
        logger.error('ACME status request returned %d', status)
        return False


def https_request(
        host, port, url, cafile, client_certfile, client_keyfile,
        method='POST', headers=None, body=None, **kw):
    """
    :param method: HTTP request method (defalut: 'POST')
    :param url: The path (not complete URL!) to post to.
    :param body: The request body (encodes kw if None)
    :param kw:  Keyword arguments to encode into POST body.
    :return:   (http_status, http_headers, http_body)
               as (integer, dict, str)

    Perform a client authenticated HTTPS request
    """

    def connection_factory(host, port):
        return create_https_connection(
            host, port,
            cafile=cafile,
            client_certfile=client_certfile,
            client_keyfile=client_keyfile,
            tls_version_min=api.env.tls_version_min,
            tls_version_max=api.env.tls_version_max)

    if body is None:
        body = urlencode(kw)
    return _httplib_request(
        'https', host, port, url, connection_factory, body,
        method=method, headers=headers)


def http_request(host, port, url, timeout=None, **kw):
    """
    :param url: The path (not complete URL!) to post to.
    :param timeout: Timeout in seconds for waiting for reply.
    :param kw: Keyword arguments to encode into POST body.
    :return:   (http_status, http_headers, http_body)
                as (integer, dict, str)

    Perform an HTTP request.
    """
    body = urlencode(kw)
    if timeout is None:
        conn_opt = {}
    else:
        conn_opt = {"timeout": timeout}

    return _httplib_request(
        'http', host, port, url, httplib.HTTPConnection, body,
        connection_options=conn_opt)


def _httplib_request(
        protocol, host, port, path, connection_factory, request_body,
        method='POST', headers=None, connection_options=None):
    """
    :param request_body: Request body
    :param connection_factory: Connection class to use. Will be called
        with the host and port arguments.
    :param method: HTTP request method (default: 'POST')
    :param connection_options: a dictionary that will be passed to
        connection_factory as keyword arguments.

    Perform a HTTP(s) request.
    """
    if connection_options is None:
        connection_options = {}

    uri = u'%s://%s%s' % (protocol, ipautil.format_netloc(host, port), path)
    logger.debug('request %s %s', method, uri)
    logger.debug('request body %r', request_body)

    headers = headers or {}
    if (
        method == 'POST'
        and 'content-type' not in (str(k).lower() for k in headers)
    ):
        headers['content-type'] = 'application/x-www-form-urlencoded'

    try:
        conn = connection_factory(host, port, **connection_options)
        conn.request(method, path, body=request_body, headers=headers)
        res = conn.getresponse()

        http_status = res.status
        http_headers = res.msg
        http_body = res.read()
        conn.close()
    except Exception as e:
        logger.debug("httplib request failed:", exc_info=True)
        raise NetworkError(uri=uri, error=str(e))

    encoding = res.getheader('Content-Encoding')
    if encoding == 'gzip':
        http_body = gzip_decompress(http_body)
    elif encoding == 'deflate':
        http_body = zlib.decompress(http_body)

    logger.debug('response status %d',    http_status)
    logger.debug('response headers %s',   http_headers)
    logger.debug('response body (decoded): %r', http_body)

    return http_status, http_headers, http_body
