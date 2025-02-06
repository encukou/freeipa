# Authors:
#   Ade Lee <alee@redhat.com>
#   Andrew Wnuk <awnuk@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#   Rob Crittenden <rcritten@@redhat.com>
#   John Dennis <jdennis@redhat.com>
#   Fraser Tweedale <ftweedal@redhat.com>
#   Abhijeet Kasurde <akasurde@redhat.com>
#
# Copyright (C) 2014-2016  Red Hat, Inc.
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

r'''

==============================================
Backend plugin for RA using Dogtag (e.g. CMS)
==============================================

Overview of interacting with CMS:
---------------------------------

CMS stands for "Certificate Management System". It has been released under a
variety of names, the open source version is called "dogtag".

IPA now uses the REST API provided by dogtag, as documented at
https://github.com/dogtagpki/pki/wiki/REST-API

The below is still relevant in places, particularly with data handling.
This history of Javascript parsing and using the optional XML is left
for historical purposes and for the last-used xml-based call that
IPA makes (updateCRL).

CMS consists of a number of servlets which in rough terms can be thought of as
RPC commands. A servlet is invoked by making an HTTP request to a specific URL
and passing URL arguments. Normally CMS responds with an HTTP response consisting
of HTML to be rendered by a web browser. This HTTP HTML response has both
Javascript SCRIPT components and HTML rendering code. One of the Javascript
SCRIPT blocks holds the data for the result. The rest of the response is derived
from templates associated with the servlet which may be customized. The
templates pull the result data from Javascript variables.

One way to get the result data is to parse the HTML looking for the Javascript
variable initializations. Simple string searches are not a robust method. First of
all one must be sure the string is only found in a Javascript SCRIPT block and
not somewhere else in the HTML document. Some of the Javascript variable
initializations are rather complex (e.g. lists of structures). It would be hard
to correctly parse such complex and diverse Javascript. Existing Javascript
parsers are not generally available. Finally, it's important to know the
character encoding for strings. There is a somewhat complex set of precedent
rules for determining the current character encoding from the HTTP header,
meta-equiv tags, mime Content-Type and charset attributes on HTML elements. All
of this means trying to read the result data from a CMS HTML response is
difficult to do robustly.

However, CMS also supports returning the result data as a XML document
(distinct from an XHTML document which would be essentially the same as
described above). There are a wide variety of tools to robustly parse
XML. Because XML is so well defined things like escapes, character encodings,
etc. are automatically handled by the tools.

Thus we never try to parse Javascript, instead we always ask CMS to return us an
XML document by passing the URL argument xml="true". The body of the HTTP
response is an XML document rather than HTML with embedded Javascript.

To parse the XML documents we use the Python lxml package which is a Python
binding around the libxml2 implementation. libxml2 is a very fast, standard
compliant, feature full XML implementation. libxml2 is the XML library of choice
for many projects. One of the features in lxml and libxml2 that is particularly
valuable to us is the XPath implementation. We make heavy use of XPath to find
data in the XML documents we're parsing.

Parse Results vs. IPA command results:
--------------------------------------

CMS results can be parsed from either HTML or XML. CMS unfortunately is not
consistent with how it names items or how it utilizes data types. IPA has strict
rules about data types. Also IPA would like to see a more consistent view CMS
data. Therefore we split the task of parsing CMS results out from the IPA
command code. The parse functions normalize the result data by using a
consistent set of names and data types. The IPA command only deals with the
normalized parse results. This also allow us to use different parsers if need be
(i.e. if we had to parse Javascript for some reason). The parse functions
attempt to parse as must information from the CMS result as is possible. It puts
the parse result into a dict whose normalized key/value pairs are easy to
access. IPA commands do not need to return all the parsed results, it can pick
and choose what it wants to return in the IPA command result from the parse
result. It also rest assured the values in the parse result will be the correct
data type. Thus the general sequence of steps for an IPA command talking to CMS
are:

#. Receive IPA arguments from IPA command
#. Formulate URL with arguments for CMS
#. Make request to CMS server
#. Extract XML document from HTML body returned by CMS
#. Parse XML document using matching parse routine which returns response dict
#. Extract relevant items from parse result and insert into command result
#. Return command result

Serial Numbers:
---------------

Serial numbers are integral values of any magnitude because they are based on
ASN.1 integers. CMS uses the Java BigInteger to represent these. Fortunately
Python also has support for big integers via the Python long() object. Any
BigIntegers we receive from CMS as a string can be parsed into a Python long
without loss of information.

However Python has a neat trick. It normally represents integers via the int
object which internally uses the native C long type. If you create an int
object by passing the int constructor a string it will check the magnitude of
the value. If it would fit in a C long then it returns you an int
object. However if the value is too big for a C long type then it returns you
a Python long object instead. This is a very nice property because it's much
more efficient to use C long types when possible (e.g. Python int), but when
necessary you'll get a Python long() object to handle large magnitude
values. Python also nicely handles type promotion transparently between int
and long objects. For example if you multiply two int objects you may get back
a long object if necessary. In general Python int and long objects may be
freely mixed without the programmer needing to be aware of which type of
integral object is being operated on.

The leads to the following rule, always parse a string representing an
integral value using the int() constructor even if it might have large
magnitude because Python will return either an int or a long automatically. By
the same token don't test for type of an object being int exclusively because
it could either be an int or a long object.

Internally we should always being using int or long object to hold integral
values. This is because we should be able to compare them correctly, be free
from concerns about having the know the radix of the string, perform
arithmetic operations, and convert to string representation (with correct
radix) when necessary. In other words internally we should never handle
integral values as strings.

However, the XMLRPC transport cannot properly handle a Python long object. The
XMLRPC encoder upon seeing a Python long will test to see if the value fits
within the range of an 32-bit integer, if so it passes the integer parameter
otherwise it raises an Overflow exception. The XMLRPC specification does
permit 64-bit integers (e.g. i8) and the Python XMLRPC module could allow long
values within the 64-bit range to be passed if it were patched, however this
only moves the problem, it does not solve passing big integers through
XMLRPC. Thus we must always pass big integers as a strings through the XMLRPC
interface. But upon receiving that value from XMLRPC we should convert it back
into an int or long object. Recall also that Python will automatically perform
a conversion to string if you output the int or long object in a string context.

Radix Issues:
-------------

CMS uses the following conventions: Serial numbers are always returned as
hexadecimal strings without a radix prefix. When CMS takes a serial number as
input it accepts the value in either decimal or hexadecimal utilizing the radix
prefix (e.g. 0x) to determine how to parse the value.

IPA has adopted the convention that all integral values in the user interface
will use base 10 decimal radix.

Basic rules on handling these values

1. Reading a serial number from CMS requires conversion from hexadecimal
   by converting it into a Python int or long object, use the int constructor:

        serial_number = int(serial_number, 16)

2. Big integers passed to XMLRPC must be decimal unicode strings

       unicode(serial_number)

3. Big integers received from XMLRPC must be converted back to int or long
   objects from the decimal string representation.

       serial_number = int(serial_number)

Xpath pattern matching on node names:
-------------------------------------

There are many excellent tutorial on how to use xpath to find items in an XML
document, as such there is no need to repeat this information here. However,
most xpath tutorials make the assumption the node names you're searching for are
fixed. For example:

    doc.xpath('//book/chapter[*]/section[2]')

Selects the second section of every chapter of the book. In this example the
node names 'book', 'chapter', 'section' are fixed. But what if the XML document
embedded the chapter number in the node name, for example 'chapter1',
'chapter2', etc.? (If you're thinking this would be incredibly lame, you're
right, but sadly people do things like this). Thus in this case you can't use
the node name 'chapter' in the xpath location step because it's not fixed and
hence won't match 'chapter1', 'chapter2', etc. The solution to this seems
obvious, use some type of pattern matching on the node name. Unfortunately this
advanced use of xpath is seldom discussed in tutorials and it's not obvious how
to do it. Here are some hints.

Use the built-in xpath string functions. Most of the examples illustrate the
string function being passed the text *contents* of the node via '.' or
string(.). However we don't want to pass the contents of the node, instead we
want to pass the node name. To do this use the name() function. One way we could
solve the chapter problem above is by using a predicate which says if the node
name begins with 'chapter' it's a match. Here is how you can do that.

        doc.xpath("//book/*[starts-with(name(), 'chapter')]/section[2]")

The built-in starts-with() returns true if its first argument starts with its
second argument. Thus the example above says if the node name of the second
location step begins with 'chapter' consider it a match and the search
proceeds to the next location step, which in this example is any node named
'section'.

But what if we would like to utilize the power of regular expressions to perform
the test against the node name? In this case we can use the EXSLT regular
expression extension. EXSLT extensions are accessed by using XML
namespaces. The regular expression name space identifier is 're:' In lxml we
need to pass a set of namespaces to XPath object constructor in order to allow
it to bind to those namespaces during its evaluation. Then we just use the
EXSLT regular expression match() function on the node name. Here is how this is
done:

        regexpNS = "http://exslt.org/regular-expressions"
        find = etree.XPath("//book/*[re:match(name(), '^chapter(_\d+)$')]/section[2]",
                           namespaces={'re':regexpNS}
        find(doc)

What is happening here is that etree.XPath() has returned us an evaluator
function which we bind to the name 'find'. We've passed it a set of namespaces
as a dict via the 'namespaces' keyword parameter of etree.XPath(). The predicate
for the second location step uses the 're:' namespace to find the function name
'match'. The re:match() takes a string to search as its first argument and a
regular expression pattern as its second argument. In this example the string
to search is the node name of the location step because we called the built-in
node() function of XPath. The regular expression pattern we've passed says it's
a match if the string begins with 'chapter' is followed by any number of
digits and nothing else follows.

'''

from __future__ import absolute_import

import json
import logging

from lxml import etree
import time
import contextlib

import six

from ipalib import Backend, api, x509
from ipapython.dn import DN
import ipapython.cookie
from ipapython import dogtag, ipautil
from ipaserver.masters import find_providing_server

import pki
from pki.client import PKIConnection
import pki.crypto as cryptoutil
from pki.kra import KRAClient

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

# These are general status return values used when
# CMSServlet.outputError() is invoked.
CMS_SUCCESS      = 0
CMS_FAILURE      = 1
CMS_AUTH_FAILURE = 2

# CMS (Certificate Management System) status return values
# These are requestStatus return values used with templates
CMS_STATUS_UNAUTHORIZED = 1
CMS_STATUS_SUCCESS      = 2
CMS_STATUS_PENDING      = 3
CMS_STATUS_SVC_PENDING  = 4
CMS_STATUS_REJECTED     = 5
CMS_STATUS_ERROR        = 6
CMS_STATUS_EXCEPTION    = 7

MAX_INT32 = 2147483647


def cms_request_status_to_string(request_status):
    '''
    :param request_status: The integral request status value
    :return:               String name of request status
    '''
    return {
    1 : 'UNAUTHORIZED',
    2 : 'SUCCESS',
    3 : 'PENDING',
    4 : 'SVC_PENDING',
    5 : 'REJECTED',
    6 : 'ERROR',
    7 : 'EXCEPTION',
    }.get(request_status, "unknown(%d)" % request_status)

def get_request_status_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   request status as an integer

    Returns the request status from a CMS operation. May be one of:

    - CMS_STATUS_UNAUTHORIZED = 1
    - CMS_STATUS_SUCCESS      = 2
    - CMS_STATUS_PENDING      = 3
    - CMS_STATUS_SVC_PENDING  = 4
    - CMS_STATUS_REJECTED     = 5
    - CMS_STATUS_ERROR        = 6
    - CMS_STATUS_EXCEPTION    = 7

    CMS will often fail to return requestStatus when the status is
    SUCCESS. Therefore if we fail to find a requestStatus field we default the
    result to CMS_STATUS_SUCCESS.
    '''

    request_status = doc.xpath('//xml/fixed/requestStatus[1]')
    if len(request_status) == 1:
        request_status = int(request_status[0].text)
    else:
        # When a request is successful CMS often omits the requestStatus
        request_status = CMS_STATUS_SUCCESS

    # However, if an error string was returned it's an error no
    # matter what CMS returned as requestStatus.
    # Just to make life interesting CMS sometimes returns an empty error string
    # when nothing wrong occurred.
    error_detail = doc.xpath('//xml/fixed/errorDetails[1]')
    if len(error_detail) == 1 and len(error_detail[0].text.strip()) > 0:
        # There was a non-empty error string, if the status was something
        # other than error or exception then force it to be an error.
        if not (request_status in (CMS_STATUS_ERROR, CMS_STATUS_EXCEPTION)):
            request_status = CMS_STATUS_ERROR

    return request_status


def parse_error_template_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict

    CMS currently returns errors via XML as either a "template" document
    (generated by CMSServlet.outputXML() or a "response" document (generated by
    CMSServlet.outputError()).

    This routine is used to parse a "template" style error or exception
    document.

    This routine should be use when the CMS requestStatus is ERROR or
    EXCEPTION. It is capable of parsing both. A CMS ERROR occurs when a known
    anticipated error condition occurs (e.g. asking for an item which does not
    exist). A CMS EXCEPTION occurs when an exception is thrown in the CMS server
    and it's not caught and converted into an ERROR. Think of EXCEPTIONS as the
    "catch all" error situation.

    ERROR's and EXCEPTIONS's both have error message strings associated with
    them. For an ERROR it's errorDetails, for an EXCEPTION it's
    unexpectedError. In addition an EXCEPTION may include an array of additional
    error strings in it's errorDescription field.

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found in
    the result dict. If a CMS data item is absent it will also be absent in the
    result dict.

    +----------------+---------------+------------------+---------------+
    |cms name        |cms type       |result name       |result type    |
    +================+===============+==================+===============+
    |requestStatus   |int            |request_status    |int            |
    +----------------+---------------+------------------+---------------+
    |errorDetails    |string         |error_string [1]_ |unicode        |
    +----------------+---------------+------------------+---------------+
    |unexpectedError |string         |error_string [1]_ |unicode        |
    +----------------+---------------+------------------+---------------+
    |errorDescription|[string]       |error_descriptions|[unicode]      |
    +----------------+---------------+------------------+---------------+
    |authority       |string         |authority         |unicode        |
    +----------------+---------------+------------------+---------------+

    .. [1] errorDetails is the error message string when the requestStatus
           is ERROR. unexpectedError is the error message string when
           the requestStatus is EXCEPTION. This routine recognizes both
           ERROR's and EXCEPTION's and depending on which is found folds
           the error message into the error_string result value.
    '''

    response = {}
    response['request_status'] = CMS_STATUS_ERROR # assume error


    request_status = doc.xpath('//xml/fixed/requestStatus[1]')
    if len(request_status) == 1:
        request_status = int(request_status[0].text)
        response['request_status'] = request_status

    error_descriptions = []
    for description in doc.xpath('//xml/records[*]/record/errorDescription'):
        error_descriptions.append(etree.tostring(description, method='text',
                                                 encoding=unicode).strip())
    if len(error_descriptions) > 0:
        response['error_descriptions'] = error_descriptions

    authority = doc.xpath('//xml/fixed/authorityName[1]')
    if len(authority) == 1:
        authority = etree.tostring(authority[0], method='text',
                                   encoding=unicode).strip()
        response['authority'] = authority

    # Should never get both errorDetail and unexpectedError
    error_detail = doc.xpath('//xml/fixed/errorDetails[1]')
    if len(error_detail) == 1:
        error_detail = etree.tostring(error_detail[0], method='text',
                                      encoding=unicode).strip()
        response['error_string'] = error_detail

    unexpected_error = doc.xpath('//xml/fixed/unexpectedError[1]')
    if len(unexpected_error) == 1:
        unexpected_error = etree.tostring(unexpected_error[0], method='text',
                                          encoding=unicode).strip()
        response['error_string'] = unexpected_error

    return response


def parse_updateCRL_xml(doc):
    '''
    :param doc: The root node of the xml document to parse
    :returns:   result dict
    :except ValueError:

    After parsing the results are returned in a result dict. The following
    table illustrates the mapping from the CMS data item to what may be found
    in the result dict. If a CMS data item is absent it will also be absent in
    the result dict.

    If the requestStatus is not SUCCESS then the response dict will have the
    contents described in `parse_error_template_xml`.

    +-----------------+-------------+-----------------------+---------------+
    |cms name         |cms type     |result name            |result type    |
    +=================+=============+=======================+===============+
    |crlIssuingPoint  |string       |crl_issuing_point      |unicode        |
    +-----------------+-------------+-----------------------+---------------+
    |crlUpdate        |string       |crl_update [1]         |unicode        |
    +-----------------+-------------+-----------------------+---------------+

    .. [1] crlUpdate may be one of:

           - "Success"
           - "Failure"
           - "missingParameters"
           - "testingNotEnabled"
           - "testingInProgress"
           - "Scheduled"
           - "inProgress"
           - "disabled"
           - "notInitialized"

    '''

    request_status = get_request_status_xml(doc)

    if request_status != CMS_STATUS_SUCCESS:
        response = parse_error_template_xml(doc)
        return response

    response = {}
    response['request_status'] = request_status

    crl_issuing_point = doc.xpath('//xml/header/crlIssuingPoint[1]')
    if len(crl_issuing_point) == 1:
        crl_issuing_point = etree.tostring(
            crl_issuing_point[0], method='text',
            encoding=unicode).strip()
        response['crl_issuing_point'] = crl_issuing_point

    crl_update = doc.xpath('//xml/header/crlUpdate[1]')
    if len(crl_update) == 1:
        crl_update = etree.tostring(crl_update[0], method='text',
                                    encoding=unicode).strip()
        response['crl_update'] = crl_update

    return response


#-------------------------------------------------------------------------------

from ipalib import Registry, errors, SkipPluginModule

# We only load the dogtag RA plugin if it is necessary to do so.
# This is legacy code from when multiple RA backends were supported.
#
# If the plugins are loaded by the server then load the RA backend.
#
if api.isdone("finalize") and not (
    api.env.ra_plugin == 'dogtag' or api.env.context == 'installer'
):
    # In this case, abort loading this plugin module...
    raise SkipPluginModule(reason='Not loading dogtag RA plugin')
import os
from ipaserver.plugins import rabase
from ipalib.constants import TYPE_ERROR
from ipalib import _
from ipaplatform.paths import paths

register = Registry()


class RestClient(Backend):
    """Simple Dogtag REST client to be subclassed by other backends.

    This class is a context manager.  Authenticated calls must be
    executed in a ``with`` suite::

        @register()
        class ra_certprofile(RestClient):
            path = 'profile'
            ...

        with api.Backend.ra_certprofile as profile_api:
            # REST client is now logged in
            profile_api.create_profile(...)

    """
    DEFAULT_PROFILE = dogtag.DEFAULT_PROFILE
    KDC_PROFILE = dogtag.KDC_PROFILE
    OCSP_PROFILE = dogtag.OCSP_PROFILE
    SUBSYSTEM_PROFILE = dogtag.SUBSYSTEM_PROFILE
    AUDIT_PROFILE = dogtag.AUDIT_PROFILE
    CACERT_PROFILE = dogtag.CACERT_PROFILE
    CASERVER_PROFILE = dogtag.CASERVER_PROFILE
    KRA_AUDIT_PROFILE = dogtag.KRA_AUDIT_PROFILE
    KRA_STORAGE_PROFILE = dogtag.KRA_STORAGE_PROFILE
    KRA_TRANSPORT_PROFILE = dogtag.KRA_TRANSPORT_PROFILE


    path = None

    @staticmethod
    def _parse_dogtag_error(body):
        try:
            return pki.PKIException.from_json(
                json.loads(ipautil.decode_json(body)))
        except Exception:
            return None

    def __init__(self, api):
        self.ca_cert = api.env.tls_ca_cert
        if api.env.in_tree:
            self.client_certfile = os.path.join(
                api.env.dot_ipa, 'ra-agent.pem')

            self.client_keyfile = os.path.join(
                api.env.dot_ipa, 'ra-agent.key')
        else:
            self.client_certfile = paths.RA_AGENT_PEM
            self.client_keyfile = paths.RA_AGENT_KEY
        super(RestClient, self).__init__(api)

        self._ca_host = None
        # session cookie
        self.override_port = None
        self.cookie = None

    @property
    def ca_host(self):
        """
        :returns: FQDN of a host hopefully providing a CA service

        Select our CA host, cache it for the first time.
        """
        if self._ca_host is not None:
            return self._ca_host

        preferred = [api.env.ca_host]
        if api.env.host != api.env.ca_host:
            preferred.append(api.env.host)
        ca_host = find_providing_server(
            'CA', conn=self.api.Backend.ldap2, preferred_hosts=preferred,
            api=self.api
        )
        if ca_host is None:
            # TODO: need during installation, CA is not yet set as enabled
            ca_host = api.env.ca_host
        # object is locked, need to use __setattr__()
        object.__setattr__(self, '_ca_host', ca_host)
        return ca_host

    def __enter__(self):
        """Log into the REST API"""
        if self.cookie is not None:
            return None

        # Refresh the ca_host property
        object.__setattr__(self, '_ca_host', None)

        status, resp_headers, _resp_body = dogtag.https_request(
            self.ca_host, self.override_port or self.env.ca_agent_port,
            url='/ca/rest/account/login',
            cafile=self.ca_cert,
            client_certfile=self.client_certfile,
            client_keyfile=self.client_keyfile,
            method='GET'
        )
        cookies = ipapython.cookie.Cookie.parse(resp_headers.get('set-cookie', ''))
        if status != 200 or len(cookies) == 0:
            raise errors.RemoteRetrieveError(reason=_('Failed to authenticate to CA REST API'))
        object.__setattr__(self, 'cookie', str(cookies[0]))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        """Log out of the REST API"""
        dogtag.https_request(
            self.ca_host, self.override_port or self.env.ca_agent_port,
            url='/ca/rest/account/logout',
            cafile=self.ca_cert,
            client_certfile=self.client_certfile,
            client_keyfile=self.client_keyfile,
            method='GET'
        )
        object.__setattr__(self, 'cookie', None)

    def _ssldo(self, method, path, headers=None, body=None, use_session=True):
        """
        Perform an HTTPS request.

        :param method: HTTP method to use
        :param path: Path component. This will *extend* the path defined for
            the class (if any).
        :param headers: Additional headers to include in the request.
        :param body: Request body.
        :param use_session: If ``True``, session cookie is added to request
            (client must be logged in).

        :return:   (http_status, http_headers, http_body)
                   as (integer, dict, str)

        :raises: ``RemoteRetrieveError`` if ``use_session`` is not ``False``
            and client is not logged in.

        """
        headers = headers or {}

        if use_session:
            if self.cookie is None:
                raise errors.RemoteRetrieveError(
                    reason=_("REST API is not logged in."))
            headers['Cookie'] = self.cookie

        resource = '/ca/rest'
        if self.path is not None:
            resource = os.path.join(resource, self.path)
        if path is not None:
            resource = os.path.join(resource, path)

        # perform main request
        status, resp_headers, resp_body = dogtag.https_request(
            self.ca_host, self.override_port or self.env.ca_agent_port,
            url=resource,
            cafile=self.ca_cert,
            client_certfile=self.client_certfile,
            client_keyfile=self.client_keyfile,
            method=method, headers=headers, body=body
        )
        if status < 200 or status >= 300:
            explanation = self._parse_dogtag_error(resp_body) or ''
            raise errors.HTTPRequestError(
                status=status,
                reason=_('Non-2xx response from CA REST API: %(status)d. %(explanation)s')
                % {'status': status, 'explanation': explanation}
            )
        return (status, resp_headers, resp_body)


@register()
class ra(rabase.rabase, RestClient):
    """
    Request Authority backend plugin.
    """
    DEFAULT_PROFILE = dogtag.DEFAULT_PROFILE

    def raise_certificate_operation_error(self, func_name, err_msg=None, detail=None):
        """
        :param func_name: function name where error occurred

        :param err_msg:   diagnostic error message, if not supplied it will be
                          'Unable to communicate with CMS'
        :param detail:    extra information that will be appended to err_msg
                          inside a parenthesis. This may be an HTTP status msg

        Raise a CertificateOperationError and log the error message.
        """

        if err_msg is None:
            err_msg = _('Unable to communicate with CMS')

        if detail is not None:
            err_msg = u'%s (%s)' % (err_msg, detail)

        logger.error('%s.%s(): %s', type(self).__name__, func_name, err_msg)
        if detail == 404:
            raise errors.NotFound(reason=err_msg)
        raise errors.CertificateOperationError(error=err_msg)

    def _request(self, url, port, **kw):
        """
        :param url: The URL to post to.
        :param kw: Keyword arguments to encode into POST body.
        :return:   (http_status, http_headers, http_body)
                   as (integer, dict, str)

        Perform an HTTP request.
        """
        return dogtag.http_request(self.ca_host, port, url, **kw)

    def _sslget(self, url, port, **kw):
        """
        :param url: The URL to post to.
        :param kw:  Keyword arguments to encode into POST body.
        :return:   (http_status, http_headers, http_body)
                   as (integer, dict, str)

        Perform an HTTPS request
        """
        return dogtag.https_request(
            self.ca_host, port, url,
            cafile=self.ca_cert,
            client_certfile=self.client_certfile,
            client_keyfile=self.client_keyfile,
            **kw)

    def get_parse_result_xml(self, xml_text, parse_func):
        '''
        :param xml_text:   The XML text to parse
        :param parse_func: The XML parsing function to apply to the parsed DOM tree.
        :return:           parsed result dict

        Utility routine which parses the input text into an XML DOM tree
        and then invokes the parsing function on the DOM tree in order
        to get the parsing result as a dict of key/value pairs.
        '''
        parser = etree.XMLParser()
        try:
            doc = etree.fromstring(xml_text, parser)
        except etree.XMLSyntaxError as e:
            self.raise_certificate_operation_error('get_parse_result_xml',
                                                   detail=str(e))
        result = parse_func(doc)
        logger.debug(
            "%s() xml_text:\n%r\nparse_result:\n%r",
            parse_func.__name__, xml_text, result)
        return result

    def check_request_status(self, request_id):
        """
        :param request_id: request ID

        Check status of a certificate signing request.

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +-------------------+---------------+---------------+
        |result name        |result type    |comments       |
        +===================+===============+===============+
        |serial_number      |unicode [1]_   |               |
        +-------------------+---------------+---------------+
        |request_id         |unicode [1]_   |               |
        +-------------------+---------------+---------------+
        |cert_request_status|unicode [2]_   |               |
        +-------------------+---------------+---------------+

        .. [1] The certID and requestId values are returned in
               JSON as hex regardless of what the request contains.
               They are converted to decimal in the return value.

        .. [2] cert_request_status, requestStatus, may be one of:

               - "begin"
               - "pending"
               - "approved"
               - "svc_pending"
               - "canceled"
               - "rejected"
               - "complete"

        The REST API responds with JSON in the form of:

        {
          "requestID": "0x3",
          "requestType": "enrollment",
          "requestStatus": "complete",
          "requestURL": "https://ipa.example.test:8443/ca/rest/certrequests/3",
          "certId": "0x3",
          "certURL": "https://ipa.example.test:8443/ca/rest/certs/3",
          "certRequestType": "pkcs10",
          "operationResult": "success",
          "requestId": "0x3"
        }

        """
        logger.debug('%s.check_request_status()', type(self).__name__)

        # Call CMS
        path = 'certrequests/{}'.format(request_id)
        try:
            http_status, _http_headers, http_body = self._ssldo(
                'GET', path, use_session=False,
                headers={
                    'Accept': 'application/json',
                },
            )
        except errors.HTTPRequestError as e:
            self.raise_certificate_operation_error(
                'check_request_status',
                err_msg=e.msg,
                detail=e.status  # pylint: disable=no-member
            )

        # Parse and handle errors
        if http_status != 200:
            # Note: this is a bit of an API change in that the error
            #       returned contains the hex value of the certificate
            #       but it's embedded in the 404. I doubt anything relies
            #       on it.
            self.raise_certificate_operation_error('check_request_status',
                                                   detail=http_status)

        try:
            parse_result = json.loads(ipautil.decode_json(http_body))
        except ValueError:
            logger.debug("Response from CA was not valid JSON: %s", e)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON")
            )
        operation_result = parse_result['operationResult']
        if operation_result != "success":
            self.raise_certificate_operation_error(
                'check_request_status',
                cms_request_status_to_string(operation_result),
                parse_result.get('errorMessage'))

        # Return command result
        cmd_result = {}
        if 'certId' in parse_result:
            cmd_result['serial_number'] = str(int(parse_result['certId'], 16))

        if 'requestID' in parse_result:
            cmd_result['request_id'] = str(int(parse_result['requestID'], 16))

        if 'requestStatus' in parse_result:
            cmd_result['cert_request_status'] = parse_result['requestStatus']

        return cmd_result

    def get_certificate_request(self, request_id):
        """
        Retrieve the full certificate request
        """
        path = 'agent/certrequests/{}'.format(request_id)
        try:
            http_status, _http_headers, http_body = self._ssldo(
                'GET', path,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                use_session=False,
            )
        except errors.HTTPRequestError as e:
            self.raise_certificate_operation_error(
                'approve_request',
                err_msg=e.msg,
                detail=e.status  # pylint: disable=no-member
            )

        if http_status != 200:
            self.raise_certificate_operation_error('get_certificate_request',
                                                   detail=http_status)

        try:
            request = json.loads(ipautil.decode_json(http_body))
        except ValueError:
            logger.debug("Response from CA was not valid JSON: %s", e)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON")
            )
        return request

    def get_certificate(self, serial_number):
        """
        Retrieve an existing certificate.

        :param serial_number: Certificate serial number.  May be int,
                              decimal string, or hex string with "0x"
                              prefix.


        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +-----------------+---------------+---------------+
        |result name      |result type    |comments       |
        +=================+===============+===============+
        |certificate      |unicode [1]_   |               |
        +-----------------+---------------+---------------+
        |serial_number    |unicode [2]_   |               |
        +-----------------+---------------+---------------+
        |revocation_reason|int [3]_       |               |
        +-----------------+---------------+---------------+

        .. [1] Base64 encoded

        .. [2] Passed through RPC as decimal string. Can convert to
               optimal integer type (int or long) via int(serial_number)

        .. [3] revocation reason may be one of:

               - 0 = UNSPECIFIED
               - 1 = KEY_COMPROMISE
               - 2 = CA_COMPROMISE
               - 3 = AFFILIATION_CHANGED
               - 4 = SUPERSEDED
               - 5 = CESSATION_OF_OPERATION
               - 6 = CERTIFICATE_HOLD
               - 8 = REMOVE_FROM_CRL
               - 9 = PRIVILEGE_WITHDRAWN
               - 10 = AA_COMPROMISE


        """
        logger.debug('%s.get_certificate()', type(self).__name__)

        # Call CMS
        path = 'certs/{}'.format(serial_number)
        try:
            _http_status, _http_headers, http_body = self._ssldo(
                'GET', path, use_session=False,
                headers={
                    'Accept': 'application/json',
                },
            )
        except errors.HTTPRequestError as e:
            self.raise_certificate_operation_error(
                'get_certificate',
                err_msg=e.msg,
                detail=e.status  # pylint: disable=no-member
            )

        try:
            resp = json.loads(ipautil.decode_json(http_body))
        except ValueError:
            logger.debug("Response from CA was not valid JSON: %s", e)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON")
            )

        # Return command result
        cmd_result = {}

        if 'Encoded' in resp:
            s = resp['Encoded']
            # The 'cert' plugin expects the result to be base64-encoded
            # X.509 DER.  We expect the result to be PEM.  We have to
            # strip the PEM headers and we use PEM_CERT_REGEX to do it.
            match = x509.PEM_CERT_REGEX.search(s.encode('utf-8'))
            if match:
                s = match.group(2).decode('utf-8')
            cmd_result['certificate'] = s.strip()

        if 'id' in resp:
            serial = int(resp['id'], 0)
            cmd_result['serial_number'] = unicode(serial)
            cmd_result['serial_number_hex'] = u'0x%X' % serial

        if 'RevocationReason' in resp and resp['RevocationReason'] is not None:
            cmd_result['revocation_reason'] = resp['RevocationReason']

        return cmd_result

    def request_certificate(
            self, csr, profile_id, ca_id, request_type='pkcs10'):
        """
        :param csr: The certificate signing request.
        :param profile_id: The profile to use for the request.
        :param ca_id: The Authority ID to send request to. ``None`` is allowed.
        :param request_type: The request type (defaults to ``'pkcs10'``).

        Submit certificate signing request.

        The command returns a dict with these key/value pairs:

        ``serial_number``
            ``unicode``, decimal representation
        ``serial_number_hex``
            ``unicode``, hex representation with ``'0x'`` leader
        ``certificate``
            ``unicode``, base64-encoded DER
        ``request_id``
            ``unicode``, decimal representation

        """
        logger.debug('%s.request_certificate()', type(self).__name__)

        # Call CMS
        template = '''
            {{
              "ProfileID" : "{profile}",
              "Renewal" : false,
              "RemoteHost" : "",
              "RemoteAddress" : "",
              "Input" : [ {{
                "id" : "i1",
                "ClassID" : "certReqInputImpl",
                "Name" : "Certificate Request Input",
                "ConfigAttribute" : [ ],
                "Attribute" : [ {{
                  "name" : "cert_request_type",
                  "Value" : "{req_type}",
                  "Descriptor" : {{
                    "Syntax" : "cert_request_type",
                    "Description" : "Certificate Request Type"
                  }}
                }}, {{
                  "name" : "cert_request",
                  "Value" : "{req}",
                  "Descriptor" : {{
                    "Syntax" : "cert_request",
                    "Description" : "Certificate Request"
                  }}
                }} ]
              }} ],
              "Output" : [ ],
              "Attributes" : {{
                "Attribute" : [ ]
              }}
            }}
        '''
        data = template.format(
            profile=profile_id,
            req_type=request_type,
            req=csr,
        )
        data = data.replace('\n', '')

        path = 'certrequests'
        if ca_id:
            path += '?issuer-id={}'.format(ca_id)

        _http_status, _http_headers, http_body = self._ssldo(
            'POST', path,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body=data,
            use_session=False,
        )

        try:
            resp_obj = json.loads(ipautil.decode_json(http_body))
        except ValueError as e:
            logger.debug("Response from CA was not valid JSON: %s", e)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON")
            )

        # Return command result
        cmd_result = {}

        entries = resp_obj.get('entries', [])

        # ipa cert-request only handles a single PKCS #10 request so
        # there's only one certinfo in the result.
        if len(entries) < 1:
            return cmd_result
        certinfo = entries[0]

        if certinfo['requestStatus'] not in ('complete', 'pending'):
            raise errors.CertificateOperationError(
                    error=certinfo.get('errorMessage'))

        if 'certId' in certinfo:
            cmd_result = self.get_certificate(certinfo['certId'])
            cert = ''.join(cmd_result['certificate'].splitlines())
            cmd_result['certificate'] = cert

        if 'requestURL' in certinfo:
            cmd_result['request_id'] = certinfo['requestURL'].split('/')[-1]
        elif 'requestId' in certinfo:
            cmd_result['request_id'] = str(int(certinfo['requestId'], 16))
        cmd_result['cert_request_status'] = certinfo['requestStatus']

        return cmd_result

    def get_pki_version(self):
        """
        Retrieve the version of a remote PKI server.

        The REST API request is a GET to the info URI:
            GET /pki/rest/info HTTP/1.1

        The response is: {"Version":"11.5.0","Attributes":{"Attribute":[]}}
        """
        path = "/pki/rest/info"
        logger.debug('%s.get_pki_version()', type(self).__name__)
        http_status, _http_headers, http_body = self._ssldo(
            'GET', path,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            use_session=False,
        )
        if http_status != 200:
            self.raise_certificate_operation_error('get_pki_version',
                                                   detail=http_status)

        try:
            response = json.loads(ipautil.decode_json(http_body))
        except ValueError as e:
            logger.debug("Response from CA was not valid JSON: %s", e)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON")
            )

        return response.get('Version')


    def revoke_certificate(self, serial_number, revocation_reason=0):
        """
        :param serial_number: Certificate serial number. Must be a string value
                              because serial numbers may be of any magnitude and
                              XMLRPC cannot handle integers larger than 64-bit.
                              The string value should be decimal, but may
                              optionally be prefixed with a hex radix prefix
                              if the integral value is represented as
                              hexadecimal. If no radix prefix is supplied
                              the string will be interpreted as decimal.
        :param revocation_reason: Integer code of revocation reason.

        Revoke a certificate.

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +---------------+---------------+---------------+
        |result name    |result type    |comments       |
        +===============+===============+===============+
        |revoked        |bool           |               |
        +---------------+---------------+---------------+

        The REST API responds with JSON in the form of:

        {
          "requestID": "0x17",
          "requestType": "revocation",
          "requestStatus": "complete",
          "requestURL": "https://ipa.example.test:8443/ca/rest/certrequests/23",
          "certId": "0x12",
          "certURL": "https://ipa.example.test:8443/ca/rest/certs/18",
          "operationResult": "success",
          "requestId": "0x17"
        }

        requestID appears to be deprecated in favor of requestId.

        The Ids are in hex. IPA has traditionally returned these as
        decimal. The REST API raises exceptions using hex which
        will be a departure from previous behavior but unless we
        scrape it out of the message there isn't much we can do.
        """
        reasons = ["Unspecified",
                   "Key_Compromise",
                   "CA_Compromise",
                   "Affiliation_Changed",
                   "Superseded",
                   "Cessation_of_Operation",
                   "Certificate_Hold",
                   "NOTUSED",  # value 7 is not used
                   "Remove_from_CRL",
                   "Privilege_Withdrawn",
                   "AA_Compromise"]

        logger.debug('%s.revoke_certificate()', type(self).__name__)
        if type(revocation_reason) is not int:
            raise TypeError(TYPE_ERROR % ('revocation_reason', int, revocation_reason, type(revocation_reason)))

        if revocation_reason == 7:
            self.raise_certificate_operation_error(
                'revoke_certificate',
                detail='7 is not a valid revocation reason'
            )

        # dogtag changed the argument case for revocation from
        # "reason" to "Reason" in PKI 11.4.0. Detect that change
        # based on the remote version and pass the expected value
        # in.
        pki_version = pki.util.Version(self.get_pki_version())
        if pki_version is None:
            self.raise_certificate_operation_error('revoke_certificate',
                                                   detail="Remove version not "
                                                          "detected")
        if pki_version < pki.util.Version("11.4.0"):
            reason = "reason"
        else:
            reason = "Reason"

        # Convert serial number to integral type from string to properly handle
        # radix issues. Note: the int object constructor will properly handle
        # large magnitude integral values by returning a Python long type
        # when necessary.
        serial_number = int(serial_number, 0)

        path = 'agent/certs/{}/revoke'.format(serial_number)
        data = '{{"{}":"{}"}}'.format(reason, reasons[revocation_reason])

        http_status, _http_headers, http_body = self._ssldo(
            'POST', path,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body=data,
            use_session=False,
        )
        if http_status != 200:
            self.raise_certificate_operation_error('revoke_certificate',
                                                   detail=http_status)

        try:
            response = json.loads(ipautil.decode_json(http_body))
        except ValueError as e:
            logger.debug("Response from CA was not valid JSON: %s", e)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON")
            )

        request_status = response['operationResult']
        if request_status != 'success':
            self.raise_certificate_operation_error(
                'revoke_certificate',
                request_status,
                response.get('errorMessage')
            )

        # Return command result
        cmd_result = {}

        # We can assume the revocation was successful because if it failed
        # then REST will return a non-200 or operationalResult will not
        # be 'success'.
        cmd_result['revoked'] = True

        return cmd_result

    def take_certificate_off_hold(self, serial_number):
        """
        :param serial_number: Certificate serial number. Must be a string value
                              because serial numbers may be of any magnitude
                              and XMLRPC cannot handle integers larger than
                              64-bit. The string value should be decimal, but
                              may optionally be prefixed with a hex radix
                              prefix if the integral value is represented as
                              hexadecimal. If no radix prefix is supplied
                              the string will be interpreted as decimal.

        Take revoked certificate off hold.

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +---------------+---------------+---------------+
        |result name    |result type    |comments       |
        +===============+===============+===============+
        |requestStatus  |unicode        |               |
        |errorMessage   |unicode        |               |
        +---------------+---------------+---------------+

        The REST API responds with JSON in the form of:

        {
          "requestID":"0x19",
          "requestType":"unrevocation",
          "requestStatus":"complete",
          "requestURL":"https://ipa.example.test:8443/ca/rest/certrequests/25",
          "operationResult":"success",
          "requestId":"0x19"
        }

        Being REST, some errors are returned as HTTP codes. Like
        not being authenticated (401) or un-revoking a non-revoked
        certificate (404).

        For removing hold, unrevoking a non-revoked certificate will
        return errorMessage.

        requestID appears to be deprecated in favor of requestId.

        The Ids are in hex. IPA has traditionally returned these as
        decimal. The REST API raises exceptions using hex which
        will be a departure from previous behavior but unless we
        scrape it out of the message there isn't much we can do.
        """

        logger.debug('%s.take_certificate_off_hold()', type(self).__name__)

        # Convert serial number to integral type from string to properly handle
        # radix issues. Note: the int object constructor will properly handle
        # large magnitude integral values by returning a Python long type when
        # necessary.
        serial_number = int(serial_number, 0)

        path = 'agent/certs/{}/unrevoke'.format(serial_number)

        http_status, _http_headers, http_body = self._ssldo(
            'POST', path,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            use_session=False,
        )
        if http_status != 200:
            self.raise_certificate_operation_error(
                'take_certificate_off_hold',
                detail=http_status)

        try:
            response = json.loads(ipautil.decode_json(http_body))
        except ValueError as e:
            logger.debug("Response from CA was not valid JSON: %s", e)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON")
            )

        request_status = response['operationResult']
        if request_status != 'success':
            self.raise_certificate_operation_error(
                'take_certificate_off_hold',
                request_status,
                response.get('errorMessage'))

        # Return command result
        cmd_result = {}

        if 'errorMessage' in response:
            cmd_result['error_string'] = response['errorMessage']

        # We can assume the un-revocation was successful because if it failed
        # then REST will return a non-200 or operationalResult will not
        # be 'success'.
        cmd_result['unrevoked'] = True

        return cmd_result

    def find(self, options):
        """
        Search for certificates

        :param options: dictionary of search options
        """

        def convert_time(value):
            """
            Convert time to milliseconds to pass to dogtag
            """
            ts = time.strptime(value, '%Y-%m-%d')
            return int(time.mktime(ts) * 1000)

        logger.debug('%s.find()', type(self).__name__)

        cert_search_request = dict()

        # This matches the default configuration of the pki tool.
        booloptions = {'serialNumberRangeInUse': True,
                       'subjectInUse': False,
                       'matchExactly': False,
                       'revokedByInUse': False,
                       'revokedOnInUse': False,
                       'revocationReasonInUse': False,
                       'issuedByInUse': False,
                       'issuedOnInUse': False,
                       'validNotBeforeInUse': False,
                       'validNotAfterInUse': False,
                       'validityLengthInUse': False,
                       'certTypeInUse': False}

        if options.get('exactly', False):
            booloptions['matchExactly'] = True

        if 'subject' in options:
            cert_search_request['commonName'] = options['subject']
            booloptions['subjectInUse'] = True

        if 'issuer' in options:
            cert_search_request['issuerDN'] = options['issuer']

        if 'revocation_reason' in options:
            cert_search_request['revocationReason'] = unicode(
                options['revocation_reason'])
            booloptions['revocationReasonInUse'] = True

        if 'min_serial_number' in options:
            cert_search_request['serialFrom'] = unicode(
                options['min_serial_number'])

        if 'max_serial_number' in options:
            cert_search_request['serialTo'] = unicode(
                options['max_serial_number'])

        if 'status' in options:
            cert_search_request['status'] = options['status']

        # date_types is a tuple that consists of:
        #   1. attribute name passed from IPA API
        #   2. attribute name used by REST API
        #   3. boolean to set in the REST API

        date_types = (
          ('validnotbefore_from', 'validNotBeforeFrom', 'validNotBeforeInUse'),
          ('validnotbefore_to', 'validNotBeforeTo', 'validNotBeforeInUse'),
          ('validnotafter_from', 'validNotAfterFrom', 'validNotAfterInUse'),
          ('validnotafter_to', 'validNotAfterTo', 'validNotAfterInUse'),
          ('issuedon_from', 'issuedOnFrom','issuedOnInUse'),
          ('issuedon_to', 'issuedOnTo','issuedOnInUse'),
          ('revokedon_from', 'revokedOnFrom','revokedOnInUse'),
          ('revokedon_to', 'revokedOnTo','revokedOnInUse'),
        )

        for (attr, dattr, battr) in date_types:
            if attr in options:
                epoch = convert_time(options[attr])
                cert_search_request[dattr] = unicode(epoch)
                booloptions[battr] = True

        # Add the boolean options to our XML document
        for opt, value in booloptions.items():
            cert_search_request[opt] = str(value).lower()

        payload = json.dumps(cert_search_request, sort_keys=True)
        logger.debug('%s.find(): request: %s', type(self).__name__, payload)

        url = '/ca/rest/certs/search?size=%d' % (
            options.get('sizelimit', 0x7fffffff))
        # pylint: disable=unused-variable
        status, _, data = dogtag.https_request(
            self.ca_host, 443,
            url=url,
            client_certfile=None,
            client_keyfile=None,
            cafile=self.ca_cert,
            method='POST',
            headers={'Accept-Encoding': 'gzip, deflate',
                     'User-Agent': 'IPA',
                     'Content-Type': 'application/json',
                     'Accept': 'application/json'},
            body=payload
        )

        if status != 200:
            try:
                response = json.loads(ipautil.decode_json(data))
            except ValueError as e:
                logger.debug("Response from CA was not valid JSON: %s", e)
                self.raise_certificate_operation_error(
                    'find',
                    detail='Failed to parse error response')

            # Try to parse out the returned error. If this fails then
            # raise the generic certificate operations error.
            try:
                msg = response.get('Message')
                msg = msg.split(':', 1)[0]
            except etree.XMLSyntaxError as e:
                self.raise_certificate_operation_error('find',
                                                       detail=status)

            # Message, at least in the case of search failing, consists
            # of "<message>: <java stack trace>". Use just the first
            # bit.
            self.raise_certificate_operation_error('find',
                                                   err_msg=msg,
                                                   detail=status)

        logger.debug('%s.find(): response: %s', type(self).__name__, data)
        try:
            data = json.loads(data)
        except TypeError as e:
            self.raise_certificate_operation_error('find',
                                                   detail=str(e))

        # Grab all the certificates
        certs = data['entries']

        results = []

        for cert in certs:
            response_request = {}
            response_request['serial_number'] = int(
                cert.get('id'), 16)  # parse as hex
            response_request["serial_number_hex"] = (
                "0x%X" % response_request["serial_number"]
            )

            dn = cert.get('SubjectDN')
            if dn:
                response_request['subject'] = dn

            issuer_dn = cert.get('IssuerDN')
            if issuer_dn:
                response_request['issuer'] = issuer_dn

            not_valid_before_utc = cert.get('NotValidBefore')
            if not_valid_before_utc:
                response_request['valid_not_before'] = (
                    not_valid_before_utc)

            not_valid_after_utc = cert.get('NotValidAfter')
            if not_valid_after_utc:
                response_request['valid_not_after'] = (not_valid_after_utc)

            status = cert.get('Status')
            if status:
                response_request['status'] = status
            results.append(response_request)

        return results

    def updateCRL(self, wait='false'):
        """
        Force update of the CRL

        :param wait: if true, the call will be synchronous and return only
                     when the CRL has been generated
        """
        logger.debug('%s.updateCRL()', type(self).__name__)
        # Call CMS
        http_status, _http_headers, http_body = (
            self._sslget('/ca/agent/ca/updateCRL',
                         self.override_port or self.env.ca_agent_port,
                         crlIssuingPoint='MasterCRL',
                         waitForUpdate=wait,
                         xml='true')
        )

        # Parse and handle errors
        if http_status != 200:
            self.raise_certificate_operation_error('updateCRL',
                                                   detail=http_status)

        parse_result = self.get_parse_result_xml(http_body,
                                                 parse_updateCRL_xml)
        request_status = parse_result['request_status']
        if request_status != CMS_STATUS_SUCCESS:
            self.raise_certificate_operation_error(
                'updateCRL',
                cms_request_status_to_string(request_status),
                parse_result.get('error_string'))

        # Return command result
        cmd_result = {}

        if 'crl_issuing_point' in parse_result:
            cmd_result['crlIssuingPoint'] = parse_result['crl_issuing_point']
        if 'crl_update' in parse_result:
            cmd_result['crlUpdate'] = parse_result['crl_update']

        return cmd_result

    def approve_request(self, request_id):
        """
        :param request_id: request ID

        Approve a certificate signing request.

        The command returns a dict with these possible key/value pairs.
        Some key/value pairs may be absent.

        +-------------------+---------------+---------------+
        |result name        |result type    |comments       |
        +===================+===============+===============+
        |serial_number      |unicode [1]_   |               |
        +-------------------+---------------+---------------+
        |request_id         |unicode [1]_   |               |
        +-------------------+---------------+---------------+
        |cert_request_status|unicode [2]_   |               |
        +-------------------+---------------+---------------+

        .. [1] The request_id and serial_number values are as
               decimal regardless of what the request contains.

        .. [2] cert_request_status, requestStatus, may be one of:

               - "begin"
               - "pending"
               - "approved"
               - "svc_pending"
               - "canceled"
               - "rejected"
               - "complete"

        The result component of IPA API responds with JSON in the form of:

        "result": {
            "cert_request_status": "complete",
            "request_id": "214708171545060652318544694826586802577",
            "serial_number": "140329369075043613975209265839482570077"
        },
        "summary": null,
        "value": "214708171545060652318544694826586802577"


        """
        logger.debug('%s.approve_request()', type(self).__name__)

        # Retrieve and verify the request
        request = self.get_certificate_request(request_id)

        if request['requestStatus'] != 'pending':
            self.raise_certificate_operation_error(
                'approve_request',
                err_msg='Not in pending state',
                detail=400
            )

        profile = request['ProfileID']
        if profile not in (
            self.OCSP_PROFILE,
            self.SUBSYSTEM_PROFILE,
            self.AUDIT_PROFILE,
            self.CACERT_PROFILE,
            self.CASERVER_PROFILE,
            self.KRA_AUDIT_PROFILE,
            self.KRA_STORAGE_PROFILE,
            self.KRA_TRANSPORT_PROFILE
        ):
            self.raise_certificate_operation_error(
                'approve_request',
                err_msg="Profile '%s' not on the approved list." % profile,
                detail=400
            )

        # Approve the request
        path = 'agent/certrequests/{}/approve'.format(request_id)
        try:
            http_status, _http_headers, _http_body = self._ssldo(
                'POST', path,
                headers={
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                },
                body=json.dumps(request),
                use_session=False,
            )
        except errors.HTTPRequestError as e:
            self.raise_certificate_operation_error(
                'approve_request',
                err_msg=e.msg,
                detail=e.status  # pylint: disable=no-member
            )

        if http_status != 204:
            self.raise_certificate_operation_error('approve_request',
                                                   detail=http_status)

        return self.check_request_status(request_id)


# ----------------------------------------------------------------------------
@register()
class kra(Backend):
    """
    KRA backend plugin (for Vault)
    """

    def __init__(self, api, kra_port=443):
        self.kra_port = kra_port
        super(kra, self).__init__(api)

    @property
    def kra_host(self):
        """
        :return:   host
                   as str

        Select our KRA host.
        """
        preferred = [api.env.ca_host]
        if api.env.host != api.env.ca_host:
            preferred.append(api.env.host)

        kra_host = find_providing_server(
            'KRA', self.api.Backend.ldap2, preferred_hosts=preferred,
            api=self.api
        )
        if kra_host is None:
            # TODO: need during installation, KRA is not yet set as enabled
            kra_host = api.env.ca_host
        return kra_host

    @contextlib.contextmanager
    def get_client(self):
        """
        Returns an authenticated KRA client to access KRA services.

        Raises a generic exception if KRA is not enabled.
        """

        if not self.api.Command.kra_is_enabled()['result']:
            # TODO: replace this with a more specific exception
            raise RuntimeError('KRA service is not enabled')

        crypto = cryptoutil.CryptographyCryptoProvider(
            transport_cert_nick="ra_agent",
            transport_cert=x509.load_certificate_from_file(
                paths.RA_AGENT_PEM).cert
        )

        # TODO: obtain KRA host & port from IPA service list or point to KRA load balancer
        # https://fedorahosted.org/freeipa/ticket/4557
        connection = PKIConnection(
            'https',
            self.kra_host,
            str(self.kra_port),
            'kra',
            cert_paths=paths.IPA_CA_CRT
        )

        connection.set_authentication_cert(paths.RA_AGENT_PEM,
                                           paths.RA_AGENT_KEY)

        yield KRAClient(connection, crypto)


@register()
class ra_certprofile(RestClient):
    """
    Profile management backend plugin.
    """
    path = 'profiles'

    def create_profile(self, profile_data):
        """
        Import the profile into Dogtag
        """
        self._ssldo('POST', 'raw',
            headers={
                'Content-type': 'application/xml',
                'Accept': 'application/json',
            },
            body=profile_data
        )

    def read_profile(self, profile_id):
        """
        Read the profile configuration from Dogtag
        """
        _status, _resp_headers, resp_body = self._ssldo(
            'GET', profile_id + '/raw')
        return resp_body

    def update_profile(self, profile_id, profile_data):
        """
        Update the profile configuration in Dogtag
        """
        self._ssldo('PUT', profile_id + '/raw',
            headers={
                'Content-type': 'application/xml',
                'Accept': 'application/json',
            },
            body=profile_data
        )

    def enable_profile(self, profile_id):
        """
        Enable the profile in Dogtag
        """
        self._ssldo('POST', profile_id + '?action=enable')

    def disable_profile(self, profile_id):
        """
        Enable the profile in Dogtag
        """
        self._ssldo('POST', profile_id + '?action=disable')

    def delete_profile(self, profile_id):
        """
        Delete the profile from Dogtag
        """
        self._ssldo('DELETE', profile_id, headers={'Accept': 'application/json'})

    def list_profiles(self):
        savepath = self.path
        self.path = None
        path = 'profiles?visible=true&enable=true&size={}'.format(MAX_INT32)

        try:
            _http_status, _http_headers, http_body = self._ssldo(
                'GET', path, headers={'Accept': 'application/json',})
        finally:
            self.path = savepath

        data = json.loads(http_body)

        profiles = data['entries']

        results = []

        for profile in profiles:
            response = {}
            response['profile_id'] = profile.get('profileId')
            response['profile_name'] = profile.get('profileName')
            response['profile_enabled'] = profile.get('profileEnable')
            results.append(response)

        return results


@register()
class ra_lightweight_ca(RestClient):
    """
    Lightweight CA management backend plugin.
    """
    path = 'authorities'

    def create_ca(self, dn):
        """Create CA with the given DN.

        New CA is issued by IPA CA.  Nested sub-CAs and unrelated
        root CAs are not yet supported.

        Return the (parsed) JSON response from server.

        """

        assert isinstance(dn, DN)
        _status, _resp_headers, resp_body = self._ssldo(
            'POST', None,
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json',
            },
            body=json.dumps({"parentID": "host-authority", "dn": unicode(dn)}),
        )
        try:
            return json.loads(ipautil.decode_json(resp_body))
        except Exception as e:
            logger.debug('%s', e, exc_info=True)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON")
            )

    def read_ca(self, ca_id):
        _status, _resp_headers, resp_body = self._ssldo(
            'GET', ca_id, headers={'Accept': 'application/json'})
        try:
            return json.loads(ipautil.decode_json(resp_body))
        except Exception as e:
            logger.debug('%s', e, exc_info=True)
            raise errors.RemoteRetrieveError(
                reason=_("Response from CA was not valid JSON"))

    def read_ca_cert(self, ca_id):
        _status, _resp_headers, resp_body = self._ssldo(
            'GET', '{}/cert'.format(ca_id),
            headers={'Accept': 'application/pkix-cert'})
        return resp_body

    def read_ca_chain(self, ca_id):
        _status, _resp_headers, resp_body = self._ssldo(
            'GET', '{}/chain'.format(ca_id),
            headers={'Accept': 'application/pkcs7-mime'})
        return resp_body

    def disable_ca(self, ca_id):
        self._ssldo(
            'POST', ca_id + '/disable',
            headers={'Accept': 'application/json'},
        )

    def enable_ca(self, ca_id):
        self._ssldo(
            'POST', ca_id + '/enable',
            headers={'Accept': 'application/json'},
        )

    def delete_ca(self, ca_id):
        self._ssldo('DELETE', ca_id)


@register()
class ra_securitydomain(RestClient):
    """
    Security domain management backend plugin.

    Dogtag handles the creation of securitydomain entries
    we need to clean them up when an IPA server is removed.
    """
    path = 'securityDomain/hosts'

    def delete_domain(self, hostname, type):
        """
        Delete a security domain
        """
        self._ssldo(
            'DELETE', f'{type}%20{hostname}%20443',
            headers={'Accept': 'application/json'}
        )
