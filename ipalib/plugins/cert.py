# Authors:
#   Andrew Wnuk <awnuk@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
IPA certificate operations

Implements a set of commands for managing server SSL certificates.

Certificate request come in the form of a Certificate Signing Request (CSR)
in PEM format.

If using the selfsign backend then the subject in the CSR needs to match
the subject configured in the server. The dogtag CA uses just the CN
value of the CSR and forces the rest of the subject.

A certificate is stored with a service principal and a service principal
needs a host. So in order to request a certificate the following conditions
must be met:

* The host exists
* The service exists (or you use the --add option to automatically add it)

EXAMPLES:

 Request a new certificate, add the principal:
   ipa cert-request --add --principal=HTTP/lion.example.com example.csr

 Retrieve an existing certificate:
   ipa cert-show 1032

 Revoke a certificate (see RFC 5280 for reason details):
   ipa cert-revoke --revocation-reason=6 1032

 Remove a certificate from revocation hold status:
   ipa cert-remove-hold 1032

 Check the status of a signing request:
   ipa cert-status 10

IPA currently immediately issues (or declines) all certificate requests.
"""

from ipalib import api, SkipPluginModule
if api.env.enable_ra is not True:
    # In this case, abort loading this plugin module...
    raise SkipPluginModule(reason='env.enable_ra is not True')
from ipalib import Command, Str, Int, Bytes, Flag, File
from ipalib import errors
from ipalib import pkcs10
from ipalib import x509
from ipalib.plugins.virtual import *
from ipalib.plugins.service import split_principal
import base64
from pyasn1.error import PyAsn1Error
import logging
import traceback
from ipalib.text import _
from ipalib.request import context
from ipalib.output import Output
from ipalib.plugins.service import validate_principal
import nss.nss as nss

def get_csr_hostname(csr):
    """
    Return the value of CN in the subject of the request
    """
    try:
        request = pkcs10.load_certificate_request(csr)
        sub = request.get_subject().get_components()
        for s in sub:
            if s[0].lower() == "cn":
                return s[1]
    except PyAsn1Error:
        # The ASN.1 decoding errors tend to be long and involved and the
        # last bit is generally not interesting. We need the whole traceback.
        logging.error('Unable to decode CSR\n%s', traceback.format_exc())
        raise errors.CertificateOperationError(error=_('Failure decoding Certificate Signing Request'))

    return None

def get_subjectaltname(csr):
    """
    Return the value of the subject alt name, if any
    """
    try:
        request = pkcs10.load_certificate_request(csr)
    except PyAsn1Error:
        # The ASN.1 decoding errors tend to be long and involved and the
        # last bit is generally not interesting. We need the whole traceback.
        logging.error('Unable to decode CSR\n%s', traceback.format_exc())
        raise errors.CertificateOperationError(error=_('Failure decoding Certificate Signing Request'))
    return request.get_subjectaltname()

def validate_csr(ugettext, csr):
    """
    Ensure the CSR is base64-encoded and can be decoded by our PKCS#10
    parser.
    """
    try:
        request = pkcs10.load_certificate_request(csr)

        # Explicitly request the attributes. This fires off additional
        # decoding to get things like the subjectAltName.
        attrs = request.get_attributes()
    except TypeError, e:
        raise errors.Base64DecodeError(reason=str(e))
    except PyAsn1Error:
        raise errors.CertificateOperationError(error=_('Failure decoding Certificate Signing Request'))
    except Exception, e:
        raise errors.CertificateOperationError(error=_('Failure decoding Certificate Signing Request: %s') % str(e))

def normalize_csr(csr):
    """
    Strip any leading and trailing cruft around the BEGIN/END block
    """
    end_len = 37
    s = csr.find('-----BEGIN NEW CERTIFICATE REQUEST-----')
    if s == -1:
        s = csr.find('-----BEGIN CERTIFICATE REQUEST-----')
    e = csr.find('-----END NEW CERTIFICATE REQUEST-----')
    if e == -1:
        e = csr.find('-----END CERTIFICATE REQUEST-----')
        if e != -1:
            end_len = 33

    if s > -1 and e > -1:
        # We're normalizing here, not validating
        csr = csr[s:e+end_len]

    return csr

def get_host_from_principal(principal):
    """
    Given a principal with or without a realm return the
    host portion.
    """
    validate_principal(None, principal)
    realm = principal.find('@')
    slash = principal.find('/')
    if realm == -1:
        realm = len(principal)
    hostname = principal[slash+1:realm]

    return hostname

class cert_request(VirtualCommand):
    """
    Submit a certificate signing request.
    """

    takes_args = (
        File('csr', validate_csr,
            cli_name='csr_file',
            normalizer=normalize_csr,
        ),
    )
    operation="request certificate"

    takes_options = (
        Str('principal',
            label=_('Principal'),
            doc=_('Service principal for this certificate (e.g. HTTP/test.example.com)'),
        ),
        Str('request_type',
            default=u'pkcs10',
            autofill=True,
        ),
        Flag('add',
            doc=_("automatically add the principal if it doesn't exist"),
            default=False,
            autofill=True
        ),
    )

    has_output_params = (
        Str('certificate?',
            label=_('Certificate'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('subject?',
            label=_('Subject'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('issuer?',
            label=_('Issuer'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('valid_not_before?',
            label=_('Not Before'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('valid_not_after?',
            label=_('Not After'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('md5_fingerprint?',
            label=_('Fingerprint (MD5)'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('sha1_fingerprint?',
            label=_('Fingerprint (SHA1)'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
        Str('serial_number?',
            label=_('Serial number'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )

    has_output = (
        Output('result',
            type=dict,
            doc=_('Dictionary mapping variable name to value'),
        ),
    )

    def execute(self, csr, **kw):
        ldap = self.api.Backend.ldap2
        principal = kw.get('principal')
        add = kw.get('add')
        del kw['principal']
        del kw['add']
        service = None

        """
        Access control is partially handled by the ACI titled
        'Hosts can modify service userCertificate'. This is for the case
        where a machine binds using a host/ prinicpal. It can only do the
        request if the target hostname is in the managedBy attribute which
        is managed using the add/del member commands.

        Binding with a user principal one needs to be in the request_certs
        taskgroup (directly or indirectly via role membership).
        """

        bind_principal = getattr(context, 'principal')
        # Can this user request certs?
        if not bind_principal.startswith('host/'):
            self.check_access()

        # FIXME: add support for subject alt name

        # Ensure that the hostname in the CSR matches the principal
        subject_host = get_csr_hostname(csr)
        (servicename, hostname, realm) = split_principal(principal)
        if subject_host.lower() != hostname.lower():
            raise errors.ACIError(info="hostname in subject of request '%s' does not match principal hostname '%s'" % (subject_host, hostname))

        dn = None
        service = None
        # See if the service exists and punt if it doesn't and we aren't
        # going to add it
        try:
            if not principal.startswith('host/'):
                service = api.Command['service_show'](principal, all=True, raw=True)['result']
                dn = service['dn']
            else:
                hostname = get_host_from_principal(principal)
                service = api.Command['host_show'](hostname, all=True, raw=True)['result']
                dn = service['dn']
        except errors.NotFound, e:
            if not add:
                raise errors.NotFound(reason="The service principal for this request doesn't exist.")
            try:
                service = api.Command['service_add'](principal, **{})['result']
                dn = service['dn']
            except errors.ACIError:
                raise errors.ACIError(info='You need to be a member of the serviceadmin role to add services')

        # We got this far so the service entry exists, can we write it?
        if not ldap.can_write(dn, "usercertificate"):
            raise errors.ACIError(info="Insufficient 'write' privilege to the 'userCertificate' attribute of entry '%s'." % dn)

        # Validate the subject alt name, if any
        subjectaltname = get_subjectaltname(csr)
        if subjectaltname is not None:
            for name in subjectaltname:
                try:
                    hostentry = api.Command['host_show'](name, all=True, raw=True)['result']
                    hostdn = hostentry['dn']
                except errors.NotFound:
                    # We don't want to issue any certificates referencing
                    # machines we don't know about. Nothing is stored in this
                    # host record related to this certificate.
                    raise errors.NotFound(reason='no host record for subject alt name %s in certificate request' % name)
                authprincipal = getattr(context, 'principal')
                if authprincipal.startswith("host/"):
                    if not hostdn in service.get('managedby', []):
                        raise errors.ACIError(info="Insufficient privilege to create a certificate with subject alt name '%s'." % name)

        if 'usercertificate' in service:
            serial = x509.get_serial_number(service['usercertificate'][0], datatype=x509.DER)
            # revoke the certificate and remove it from the service
            # entry before proceeding. First we retrieve the certificate to
            # see if it is already revoked, if not then we revoke it.
            try:
                result = api.Command['cert_show'](unicode(serial))['result']
                if 'revocation_reason' not in result:
                    try:
                        api.Command['cert_revoke'](unicode(serial), revocation_reason=4)
                    except errors.NotImplementedError:
                        # some CA's might not implement revoke
                        pass
            except errors.NotImplementedError:
                # some CA's might not implement get
                pass
            if not principal.startswith('host/'):
                api.Command['service_mod'](principal, usercertificate=None)
            else:
                hostname = get_host_from_principal(principal)
                api.Command['host_mod'](hostname, usercertificate=None)

        # Request the certificate
        result = self.Backend.ra.request_certificate(csr, **kw)
        cert = x509.load_certificate(result['certificate'])
        result['issuer'] = unicode(cert.issuer)
        result['valid_not_before'] = unicode(cert.valid_not_before_str)
        result['valid_not_after'] = unicode(cert.valid_not_after_str)
        result['md5_fingerprint'] = unicode(nss.data_to_hex(nss.md5_digest(cert.der_data), 64)[0])
        result['sha1_fingerprint'] = unicode(nss.data_to_hex(nss.sha1_digest(cert.der_data), 64)[0])

        # Success? Then add it to the service entry.
        if 'certificate' in result:
            if not principal.startswith('host/'):
                skw = {"usercertificate": str(result.get('certificate'))}
                api.Command['service_mod'](principal, **skw)
            else:
                hostname = get_host_from_principal(principal)
                skw = {"usercertificate": str(result.get('certificate'))}
                api.Command['host_mod'](hostname, **skw)

        return dict(
            result=result
        )

api.register(cert_request)


class cert_status(VirtualCommand):
    """
    Check status of a certificate signing request.
    """

    takes_args = (
        Str('request_id',
            label=_('Request id'),
            flags=['no_create', 'no_update', 'no_search'],
        ),
    )
    has_output_params = (
        Str('cert_request_status',
            label=_('Request status'),
        ),
    )
    operation = "certificate status"


    def execute(self, request_id, **kw):
        self.check_access()
        return dict(
            result=self.Backend.ra.check_request_status(request_id)
        )

api.register(cert_status)


_serial_number = Str('serial_number',
    label=_('Serial number'),
    doc=_('Serial number in decimal or if prefixed with 0x in hexadecimal'),
)

class cert_show(VirtualCommand):
    """
    Retrieve an existing certificate.
    """

    takes_args = _serial_number

    has_output_params = (
        Str('certificate',
            label=_('Certificate'),
        ),
        Str('subject',
            label=_('Subject'),
        ),
        Str('issuer',
            label=_('Issuer'),
        ),
        Str('valid_not_before',
            label=_('Not Before'),
        ),
        Str('valid_not_after',
            label=_('Not After'),
        ),
        Str('md5_fingerprint',
            label=_('Fingerprint (MD5)'),
        ),
        Str('sha1_fingerprint',
            label=_('Fingerprint (SHA1)'),
        ),
        Str('revocation_reason?',
            label=_('Revocation reason'),
        ),
    )

    operation="retrieve certificate"

    def execute(self, serial_number):
        self.check_access()
        result=self.Backend.ra.get_certificate(serial_number)
        cert = x509.load_certificate(result['certificate'])
        result['subject'] = unicode(cert.subject)
        result['issuer'] = unicode(cert.issuer)
        result['valid_not_before'] = unicode(cert.valid_not_before_str)
        result['valid_not_after'] = unicode(cert.valid_not_after_str)
        result['md5_fingerprint'] = unicode(nss.data_to_hex(nss.md5_digest(cert.der_data), 64)[0])
        result['sha1_fingerprint'] = unicode(nss.data_to_hex(nss.sha1_digest(cert.der_data), 64)[0])
        return dict(result=result)

api.register(cert_show)


class cert_revoke(VirtualCommand):
    """
    Revoke a certificate.
    """

    takes_args = _serial_number

    has_output_params = (
        Flag('revoked',
            label=_('Revoked'),
        ),
    )
    operation = "revoke certificate"

    # FIXME: The default is 0.  Is this really an Int param?
    takes_options = (
        Int('revocation_reason?',
            label=_('Reason'),
            doc=_('Reason for revoking the certificate (0-10)'),
            minvalue=0,
            maxvalue=10,
            default=0,
        ),
    )

    def execute(self, serial_number, **kw):
        self.check_access()
        return dict(
            result=self.Backend.ra.revoke_certificate(serial_number, **kw)
        )

api.register(cert_revoke)


class cert_remove_hold(VirtualCommand):
    """
    Take a revoked certificate off hold.
    """

    takes_args = _serial_number

    has_output_params = (
        Flag('unrevoked?',
            label=_('Unrevoked'),
        ),
        Str('error_string?',
            label=_('Error'),
        ),
    )
    operation = "certificate remove hold"

    def execute(self, serial_number, **kw):
        self.check_access()
        return dict(
            result=self.Backend.ra.take_certificate_off_hold(serial_number)
        )

api.register(cert_remove_hold)
