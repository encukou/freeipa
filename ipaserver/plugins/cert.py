# Authors:
#   Andrew Wnuk <awnuk@redhat.com>
#   Jason Gerard DeRose <jderose@redhat.com>
#   John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2009  Red Hat
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

import base64
import collections
import datetime
import os

import cryptography.x509
from nss import nss
from nss.error import NSPRError
import six

from ipalib import Command, Str, Int, Flag
from ipalib import api
from ipalib import errors, messages
from ipalib import pkcs10
from ipalib import x509
from ipalib import ngettext
from ipalib.constants import IPA_CA_CN
from ipalib.crud import Create, PKQuery, Retrieve, Search
from ipalib.frontend import Method, Object
from ipalib.parameters import Bytes, DateTime, DNParam, DNSNameParam, Principal
from ipalib.plugable import Registry
from .virtual import VirtualCommand
from .baseldap import pkey_to_value
from .certprofile import validate_profile_id
from .caacl import acl_evaluate
from ipalib.text import _
from ipalib.request import context
from ipalib import output
from ipapython import kerberos
from ipapython.dn import DN
from ipapython.ipa_log_manager import root_logger
from ipaserver.plugins.service import normalize_principal, validate_realm

if six.PY3:
    unicode = str

__doc__ = _("""
IPA certificate operations
""") + _("""
Implements a set of commands for managing server SSL certificates.
""") + _("""
Certificate requests exist in the form of a Certificate Signing Request (CSR)
in PEM format.
""") + _("""
The dogtag CA uses just the CN value of the CSR and forces the rest of the
subject to values configured in the server.
""") + _("""
A certificate is stored with a service principal and a service principal
needs a host.
""") + _("""
In order to request a certificate:
""") + _("""
* The host must exist
* The service must exist (or you use the --add option to automatically add it)
""") + _("""
SEARCHING:
""") + _("""
Certificates may be searched on by certificate subject, serial number,
revocation reason, validity dates and the issued date.
""") + _("""
When searching on dates the _from date does a >= search and the _to date
does a <= search. When combined these are done as an AND.
""") + _("""
Dates are treated as GMT to match the dates in the certificates.
""") + _("""
The date format is YYYY-mm-dd.
""") + _("""
EXAMPLES:
""") + _("""
 Request a new certificate and add the principal:
   ipa cert-request --add --principal=HTTP/lion.example.com example.csr
""") + _("""
 Retrieve an existing certificate:
   ipa cert-show 1032
""") + _("""
 Revoke a certificate (see RFC 5280 for reason details):
   ipa cert-revoke --revocation-reason=6 1032
""") + _("""
 Remove a certificate from revocation hold status:
   ipa cert-remove-hold 1032
""") + _("""
 Check the status of a signing request:
   ipa cert-status 10
""") + _("""
 Search for certificates by hostname:
   ipa cert-find --subject=ipaserver.example.com
""") + _("""
 Search for revoked certificates by reason:
   ipa cert-find --revocation-reason=5
""") + _("""
 Search for certificates based on issuance date
   ipa cert-find --issuedon-from=2013-02-01 --issuedon-to=2013-02-07
""") + _("""
 Search for certificates owned by a specific user:
   ipa cert-find --user=user
""") + _("""
 Examine a certificate:
   ipa cert-find --file=cert.pem --all
""") + _("""
 Verify that a certificate is owned by a specific user:
   ipa cert-find --file=cert.pem --user=user
""") + _("""
IPA currently immediately issues (or declines) all certificate requests so
the status of a request is not normally useful. This is for future use
or the case where a CA does not immediately issue a certificate.
""") + _("""
The following revocation reasons are supported:

""") + _("""    * 0 - unspecified
""") + _("""    * 1 - keyCompromise
""") + _("""    * 2 - cACompromise
""") + _("""    * 3 - affiliationChanged
""") + _("""    * 4 - superseded
""") + _("""    * 5 - cessationOfOperation
""") + _("""    * 6 - certificateHold
""") + _("""    * 8 - removeFromCRL
""") + _("""    * 9 - privilegeWithdrawn
""") + _("""    * 10 - aACompromise
""") + _("""
Note that reason code 7 is not used.  See RFC 5280 for more details:
""") + _("""
http://www.ietf.org/rfc/rfc5280.txt

""")

USER, HOST, SERVICE = range(3)

PRINCIPAL_TYPE_STRING_MAP = {
    USER: _('user'),
    HOST: _('host'),
    SERVICE: _('service'),
}

register = Registry()

PKIDATE_FORMAT = '%Y-%m-%d'


def normalize_pkidate(value):
    return datetime.datetime.strptime(value, PKIDATE_FORMAT)


def validate_csr(ugettext, csr):
    """
    Ensure the CSR is base64-encoded and can be decoded by our PKCS#10
    parser.
    """
    if api.env.context == 'cli':
        # If we are passed in a pointer to a valid file on the client side
        # escape and let the load_files() handle things
        if csr and os.path.exists(csr):
            return
    try:
        pkcs10.load_certificate_request(csr)
    except (TypeError, ValueError) as e:
        raise errors.CertificateOperationError(error=_('Failure decoding Certificate Signing Request: %s') % e)


def normalize_serial_number(num):
    """
    Convert a SN given in decimal or hexadecimal.
    Returns the number or None if conversion fails.
    """
    # plain decimal or hexa with radix prefix
    try:
        num = int(num, 0)
    except ValueError:
        try:
            # hexa without prefix
            num = int(num, 16)
        except ValueError:
            pass

    return unicode(num)


def ca_enabled_check():
    if not api.Command.ca_is_enabled()['result']:
        raise errors.NotFound(reason=_('CA is not configured'))

def caacl_check(principal_type, principal, ca, profile_id):
    principal_type_map = {USER: 'user', HOST: 'host', SERVICE: 'service'}
    if not acl_evaluate(
            principal_type_map[principal_type],
            principal, ca, profile_id):
        raise errors.ACIError(info=_(
                "Principal '%(principal)s' "
                "is not permitted to use CA '%(ca)s' "
                "with profile '%(profile_id)s' for certificate issuance."
            ) % dict(
                principal=unicode(principal),
                ca=ca,
                profile_id=profile_id
            )
        )


def validate_certificate(value):
    return x509.validate_certificate(value, x509.DER)


def bind_principal_can_manage_cert(cert):
    """Check that the bind principal can manage the given cert.

    ``cert``
        An NSS certificate object.

    """
    bind_principal = kerberos.Principal(getattr(context, 'principal'))
    if not bind_principal.is_host:
        return False

    hostname = bind_principal.hostname

    # If we have a hostname we want to verify that the subject
    # of the certificate matches it.
    return hostname == cert.subject.common_name  #pylint: disable=E1101


class BaseCertObject(Object):
    takes_params = (
        Str(
            'cacn?',
            cli_name='ca',
            default=IPA_CA_CN,
            autofill=True,
            label=_('Issuing CA'),
            doc=_('Name of issuing CA'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Bytes(
            'certificate', validate_certificate,
            label=_("Certificate"),
            doc=_("Base-64 encoded certificate."),
            normalizer=x509.normalize_certificate,
            flags={'no_create', 'no_update', 'no_search'},
        ),
        DNParam(
            'subject',
            label=_('Subject'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'san_rfc822name*',
            label=_('Subject email address'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        DNSNameParam(
            'san_dnsname*',
            label=_('Subject DNS name'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'san_x400address*',
            label=_('Subject X.400 address'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        DNParam(
            'san_directoryname*',
            label=_('Subject directory name'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'san_edipartyname*',
            label=_('Subject EDI Party name'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'san_uri*',
            label=_('Subject URI'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'san_ipaddress*',
            label=_('Subject IP Address'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'san_oid*',
            label=_('Subject OID'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Principal(
            'san_other_upn*',
            label=_('Subject UPN'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Principal(
            'san_other_kpn*',
            label=_('Subject Kerberos principal name'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'san_other*',
            label=_('Subject Other Name'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        DNParam(
            'issuer',
            label=_('Issuer'),
            doc=_('Issuer DN'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        DateTime(
            'valid_not_before',
            label=_('Not Before'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        DateTime(
            'valid_not_after',
            label=_('Not After'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'md5_fingerprint',
            label=_('Fingerprint (MD5)'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'sha1_fingerprint',
            label=_('Fingerprint (SHA1)'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Int(
            'serial_number',
            label=_('Serial number'),
            doc=_('Serial number in decimal or if prefixed with 0x in hexadecimal'),
            normalizer=normalize_serial_number,
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'serial_number_hex',
            label=_('Serial number (hex)'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
    )

    def _parse(self, obj, full=True):
        """Extract certificate-specific data into a result object.

        ``obj``
            Result object containing certificate, into which extracted
            data will be inserted.
        ``full``
            Whether to include all fields, or only the ones we guess
            people want to see most of the time.  Also add
            recognised otherNames to the generic ``san_other``
            attribute when ``True`` in addition to the specialised
            attribute.

        """
        cert = obj.get('certificate')
        if cert is not None:
            cert = x509.load_certificate(cert)
            obj['subject'] = DN(unicode(cert.subject))
            obj['issuer'] = DN(unicode(cert.issuer))
            obj['serial_number'] = cert.serial_number
            obj['valid_not_before'] = unicode(cert.valid_not_before_str)
            obj['valid_not_after'] = unicode(cert.valid_not_after_str)
            if full:
                obj['md5_fingerprint'] = unicode(
                    nss.data_to_hex(nss.md5_digest(cert.der_data), 64)[0])
                obj['sha1_fingerprint'] = unicode(
                    nss.data_to_hex(nss.sha1_digest(cert.der_data), 64)[0])

            try:
                ext_san = cert.get_extension(nss.SEC_OID_X509_SUBJECT_ALT_NAME)
                general_names = x509.decode_generalnames(ext_san.value)
            except KeyError:
                general_names = []

            for name_type, _desc, name, der_name in general_names:
                try:
                    self._add_san_attribute(
                        obj, full, name_type, name, der_name)
                except Exception:
                    # Invalid GeneralName (i.e. not a valid X.509 cert);
                    # don't fail but log something about it
                    root_logger.warning(
                        "Encountered bad GeneralName; skipping", exc_info=True)

        serial_number = obj.get('serial_number')
        if serial_number is not None:
            obj['serial_number_hex'] = u'0x%X' % serial_number


    def _add_san_attribute(
            self, obj, full, name_type, name, der_name):
        name_type_map = {
            nss.certRFC822Name: 'san_rfc822name',
            nss.certDNSName: 'san_dnsname',
            nss.certX400Address: 'san_x400address',
            nss.certDirectoryName: 'san_directoryname',
            nss.certEDIPartyName: 'san_edipartyname',
            nss.certURI: 'san_uri',
            nss.certIPAddress: 'san_ipaddress',
            nss.certRegisterID: 'san_oid',
            (nss.certOtherName, x509.SAN_UPN): 'san_other_upn',
            (nss.certOtherName, x509.SAN_KRB5PRINCIPALNAME): 'san_other_kpn',
        }
        default_attrs = {
            'san_rfc822name', 'san_dnsname', 'san_other_upn', 'san_other_kpn',
        }

        attr_name = name_type_map.get(name_type, 'san_other')

        if full or attr_name in default_attrs:
            if attr_name != 'san_other':
                name_formatted = name
            else:
                # display as "OID : b64(DER)"
                name_formatted = u'{}:{}'.format(
                    name_type[1], base64.b64encode(der_name))
            attr_value = self.params[attr_name].type(name_formatted)
            obj.setdefault(attr_name, []).append(attr_value)

        if full and attr_name.startswith('san_other_'):
            # also include known otherName in generic otherName attribute
            name_formatted = u'{}:{}'.format(
                name_type[1], base64.b64encode(der_name))
            attr_value = self.params['san_other'].type(name_formatted)
            obj.setdefault('san_other', []).append(attr_value)


class BaseCertMethod(Method):
    def get_options(self):
        yield self.obj.params['cacn'].clone(query=True)

        for option in super(BaseCertMethod, self).get_options():
            yield option


@register()
class certreq(BaseCertObject):
    takes_params = BaseCertObject.takes_params + (
        Str(
            'request_type',
            default=u'pkcs10',
            autofill=True,
            flags={'no_update', 'no_update', 'no_search'},
        ),
        Str(
            'profile_id?', validate_profile_id,
            label=_("Profile ID"),
            doc=_("Certificate Profile to use"),
            flags={'no_update', 'no_update', 'no_search'},
        ),
        Str(
            'cert_request_status',
            label=_('Request status'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Int(
            'request_id',
            label=_('Request id'),
            primary_key=True,
            flags={'no_create', 'no_update', 'no_search', 'no_output'},
        ),
    )


@register()
class cert_request(Create, BaseCertMethod, VirtualCommand):
    __doc__ = _('Submit a certificate signing request.')

    obj_name = 'certreq'
    attr_name = 'request'

    takes_args = (
        Str(
            'csr', validate_csr,
            label=_('CSR'),
            cli_name='csr_file',
            noextrawhitespace=False,
        ),
    )
    operation="request certificate"

    takes_options = (
        Principal(
            'principal',
            validate_realm,
            label=_('Principal'),
            doc=_('Principal for this certificate (e.g. HTTP/test.example.com)'),
            normalizer=normalize_principal
        ),
        Flag(
            'add',
            doc=_(
                "automatically add the principal if it doesn't exist "
                "(service principals only)"),
        ),
    )

    def get_args(self):
        # FIXME: the 'no_create' flag is ignored for positional arguments
        for arg in super(cert_request, self).get_args():
            if arg.name == 'request_id':
                continue
            yield arg

    def execute(self, csr, all=False, raw=False, **kw):
        ca_enabled_check()

        ldap = self.api.Backend.ldap2
        add = kw.get('add')
        request_type = kw.get('request_type')
        profile_id = kw.get('profile_id', self.Backend.ra.DEFAULT_PROFILE)

        # Check that requested authority exists (done before CA ACL
        # enforcement so that user gets better error message if
        # referencing nonexistant CA) and look up authority ID.
        #
        ca = kw['cacn']
        ca_obj = api.Command.ca_show(ca)['result']
        ca_id = ca_obj['ipacaid'][0]

        """
        Access control is partially handled by the ACI titled
        'Hosts can modify service userCertificate'. This is for the case
        where a machine binds using a host/ prinicpal. It can only do the
        request if the target hostname is in the managedBy attribute which
        is managed using the add/del member commands.

        Binding with a user principal one needs to be in the request_certs
        taskgroup (directly or indirectly via role membership).
        """

        principal = kw.get('principal')
        principal_string = unicode(principal)

        if principal.is_user:
            principal_type = USER
        elif principal.is_host:
            principal_type = HOST
        else:
            principal_type = SERVICE

        bind_principal = kerberos.Principal(
            getattr(context, 'principal'))
        bind_principal_string = unicode(bind_principal)

        if bind_principal.is_user:
            bind_principal_type = USER
        elif bind_principal.is_host:
            bind_principal_type = HOST
        else:
            bind_principal_type = SERVICE

        if (bind_principal_string != principal_string and
                bind_principal_type != HOST):
            # Can the bound principal request certs for another principal?
            self.check_access()

        try:
            self.check_access("request certificate ignore caacl")
            bypass_caacl = True
        except errors.ACIError:
            bypass_caacl = False

        if not bypass_caacl:
            caacl_check(principal_type, principal, ca, profile_id)

        try:
            csr_obj = pkcs10.load_certificate_request(csr)
        except ValueError as e:
            raise errors.CertificateOperationError(
                error=_("Failure decoding Certificate Signing Request: %s") % e)

        try:
            ext_san = csr_obj.extensions.get_extension_for_oid(
                cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except cryptography.x509.extensions.ExtensionNotFound:
            ext_san = None

        # self-service and host principals may bypass SAN permission check
        if (bind_principal_string != principal_string
                and bind_principal_type != HOST):
            if ext_san is not None:
                self.check_access('request certificate with subjectaltname')

        dn = None
        principal_obj = None
        # See if the service exists and punt if it doesn't and we aren't
        # going to add it
        try:
            if principal_type == SERVICE:
                principal_obj = api.Command['service_show'](principal_string, all=True)
            elif principal_type == HOST:
                principal_obj = api.Command['host_show'](
                    principal.hostname, all=True)
            elif principal_type == USER:
                principal_obj = api.Command['user_show'](
                    principal.username, all=True)
        except errors.NotFound as e:
            if add:
                if principal_type == SERVICE:
                    principal_obj = api.Command['service_add'](
                        principal_string, force=True)
                else:
                    princtype_str = PRINCIPAL_TYPE_STRING_MAP[principal_type]
                    raise errors.OperationNotSupportedForPrincipalType(
                        operation=_("'add' option"),
                        principal_type=princtype_str)
            else:
                raise errors.NotFound(
                    reason=_("The principal for this request doesn't exist."))
        principal_obj = principal_obj['result']
        dn = principal_obj['dn']

        # Ensure that the DN in the CSR matches the principal
        #
        # We only look at the "most specific" CN value
        cns = csr_obj.subject.get_attributes_for_oid(
                cryptography.x509.oid.NameOID.COMMON_NAME)
        if len(cns) == 0:
            raise errors.ValidationError(name='csr',
                error=_("No Common Name was found in subject of request."))
        cn = cns[-1].value  # "most specific" is end of list

        if principal_type in (SERVICE, HOST):
            if cn.lower() != principal.hostname.lower():
                raise errors.ACIError(
                    info=_("hostname in subject of request '%(cn)s' "
                        "does not match principal hostname '%(hostname)s'")
                        % dict(cn=cn, hostname=principal.hostname))
        elif principal_type == USER:
            # check user name
            if cn != principal.username:
                raise errors.ValidationError(
                    name='csr',
                    error=_("DN commonName does not match user's login")
                )

            # check email address
            #
            # fail if any email addr from DN does not appear in ldap entry
            email_addrs = csr_obj.subject.get_attributes_for_oid(
                    cryptography.x509.oid.NameOID.EMAIL_ADDRESS)
            if len(set(email_addrs) - set(principal_obj.get('mail', []))) > 0:
                raise errors.ValidationError(
                    name='csr',
                    error=_(
                        "DN emailAddress does not match "
                        "any of user's email addresses")
                )

        # We got this far so the principal entry exists, can we write it?
        if not ldap.can_write(dn, "usercertificate"):
            raise errors.ACIError(info=_("Insufficient 'write' privilege "
                "to the 'userCertificate' attribute of entry '%s'.") % dn)

        # Validate the subject alt name, if any
        generalnames = []
        if ext_san is not None:
            generalnames = x509.process_othernames(ext_san.value)
        for gn in generalnames:
            if isinstance(gn, cryptography.x509.general_name.DNSName):
                name = gn.value
                alt_principal = None
                alt_principal_obj = None
                try:
                    if principal_type == HOST:
                        alt_principal = kerberos.Principal(
                            (u'host', name), principal.realm)
                        alt_principal_obj = api.Command['host_show'](name, all=True)
                    elif principal_type == SERVICE:
                        alt_principal = kerberos.Principal(
                            (principal.service_name, name), principal.realm)
                        alt_principal_obj = api.Command['service_show'](
                            alt_principal, all=True)
                    elif principal_type == USER:
                        raise errors.ValidationError(
                            name='csr',
                            error=_(
                                "subject alt name type %s is forbidden "
                                "for user principals") % "DNSName"
                        )
                except errors.NotFound:
                    # We don't want to issue any certificates referencing
                    # machines we don't know about. Nothing is stored in this
                    # host record related to this certificate.
                    raise errors.NotFound(reason=_('The service principal for '
                        'subject alt name %s in certificate request does not '
                        'exist') % name)
                if alt_principal_obj is not None:
                    altdn = alt_principal_obj['result']['dn']
                    if not ldap.can_write(altdn, "usercertificate"):
                        raise errors.ACIError(info=_(
                            "Insufficient privilege to create a certificate "
                            "with subject alt name '%s'.") % name)
                if alt_principal is not None and not bypass_caacl:
                    caacl_check(principal_type, alt_principal, ca, profile_id)
            elif isinstance(gn, (x509.KRB5PrincipalName, x509.UPN)):
                if gn.name != principal_string:
                    raise errors.ACIError(
                        info=_(
                            "Principal '%s' in subject alt name does not "
                            "match requested principal") % gn.name)
            elif isinstance(gn, cryptography.x509.general_name.RFC822Name):
                if principal_type == USER:
                    if gn.value not in principal_obj.get('mail', []):
                        raise errors.ValidationError(
                            name='csr',
                            error=_(
                                "RFC822Name does not match "
                                "any of user's email addresses")
                        )
                else:
                    raise errors.ValidationError(
                        name='csr',
                        error=_(
                            "subject alt name type %s is forbidden "
                            "for non-user principals") % "RFC822Name"
                    )
            else:
                raise errors.ACIError(
                    info=_("Subject alt name type %s is forbidden")
                    % type(gn).__name__)

        # Request the certificate
        try:
            result = self.Backend.ra.request_certificate(
                csr, profile_id, ca_id, request_type=request_type)
        except errors.HTTPRequestError as e:
            if e.status == 409:  # pylint: disable=no-member
                raise errors.CertificateOperationError(
                    error=_("CA '%s' is disabled") % ca)
            else:
                raise e

        if not raw:
            self.obj._parse(result, all)
            result['request_id'] = int(result['request_id'])
            result['cacn'] = ca_obj['cn'][0]

        # Success? Then add it to the principal's entry
        # (unless the profile tells us not to)
        profile = api.Command['certprofile_show'](profile_id)
        store = profile['result']['ipacertprofilestoreissued'][0] == 'TRUE'
        if store and 'certificate' in result:
            cert = str(result.get('certificate'))
            kwargs = dict(addattr=u'usercertificate={}'.format(cert))
            if principal_type == SERVICE:
                api.Command['service_mod'](principal_string, **kwargs)
            elif principal_type == HOST:
                api.Command['host_mod'](principal.hostname, **kwargs)
            elif principal_type == USER:
                api.Command['user_mod'](principal.username, **kwargs)

        return dict(
            result=result,
            value=pkey_to_value(int(result['request_id']), kw),
        )


@register()
class cert_status(Retrieve, BaseCertMethod, VirtualCommand):
    __doc__ = _('Check the status of a certificate signing request.')

    obj_name = 'certreq'
    attr_name = 'status'

    operation = "certificate status"

    def execute(self, request_id, **kw):
        ca_enabled_check()
        self.check_access()

        # Dogtag requests are uniquely identified by their number;
        # furthermore, Dogtag (as at v10.3.4) does not report the
        # target CA in request data, so we cannot check.  So for
        # now, there is nothing we can do with the 'cacn' option
        # but check if the specified CA exists.
        self.api.Command.ca_show(kw['cacn'])

        return dict(
            result=self.Backend.ra.check_request_status(str(request_id)),
            value=pkey_to_value(request_id, kw),
        )


@register()
class cert(BaseCertObject):
    takes_params = BaseCertObject.takes_params + (
        Str(
            'status',
            label=_('Status'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Flag(
            'revoked',
            label=_('Revoked'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Int(
            'revocation_reason',
            label=_('Revocation reason'),
            doc=_('Reason for revoking the certificate (0-10). Type '
                  '"ipa help cert" for revocation reason details. '),
            minvalue=0,
            maxvalue=10,
            flags={'no_create', 'no_update'},
        ),
    )

    def get_params(self):
        for param in super(cert, self).get_params():
            if param.name == 'serial_number':
                param = param.clone(primary_key=True)
            elif param.name in ('certificate', 'issuer'):
                param = param.clone(flags=param.flags - {'no_search'})
            yield param

        for owner in self._owners():
            yield owner.primary_key.clone_rename(
                'owner_{0}'.format(owner.name),
                required=False,
                multivalue=True,
                primary_key=False,
                label=_("Owner %s") % owner.object_name,
                flags={'no_create', 'no_update', 'no_search'},
            )

    def _owners(self):
        for name in ('user', 'host', 'service'):
            yield self.api.Object[name]

    def _fill_owners(self, obj):
        dns = obj.pop('owner', None)
        if dns is None:
            return

        for owner in self._owners():
            container_dn = DN(owner.container_dn, self.api.env.basedn)
            name = 'owner_' + owner.name
            for dn in dns:
                if dn.endswith(container_dn, 1):
                    value = owner.get_primary_key_from_dn(dn)
                    obj.setdefault(name, []).append(value)


class CertMethod(BaseCertMethod):
    def get_options(self):
        for option in super(CertMethod, self).get_options():
            yield option

        for o in self.has_output:
            if isinstance(o, (output.Entry, output.ListOfEntries)):
                yield Flag(
                    'no_members',
                    doc=_("Suppress processing of membership attributes."),
                    exclude='webui',
                    flags={'no_output'},
                )
                break


@register()
class cert_show(Retrieve, CertMethod, VirtualCommand):
    __doc__ = _('Retrieve an existing certificate.')

    takes_options = (
        Str('out?',
            label=_('Output filename'),
            doc=_('File to store the certificate in.'),
            exclude='webui',
        ),
    )

    operation="retrieve certificate"

    def execute(self, serial_number, all=False, raw=False, no_members=False,
                **options):
        ca_enabled_check()

        # Dogtag lightweight CAs have shared serial number domain, so
        # we don't tell Dogtag the issuer (but we check the cert after).
        #
        result = self.Backend.ra.get_certificate(str(serial_number))
        cert = x509.load_certificate(result['certificate'])

        try:
            self.check_access()
        except errors.ACIError as acierr:
            self.debug("Not granted by ACI to retrieve certificate, looking at principal")
            if not bind_principal_can_manage_cert(cert):
                raise acierr  # pylint: disable=E0702

        ca_obj = api.Command.ca_show(options['cacn'])['result']
        if DN(unicode(cert.issuer)) != DN(ca_obj['ipacasubjectdn'][0]):
            # DN of cert differs from what we requested
            raise errors.NotFound(
                reason=_("Certificate with serial number %(serial)s "
                    "issued by CA '%(ca)s' not found")
                    % dict(serial=serial_number, ca=options['cacn']))

        if all or not no_members:
            ldap = self.api.Backend.ldap2
            filter = ldap.make_filter_from_attr(
                'usercertificate', base64.b64decode(result['certificate']))
            try:
                entries = ldap.get_entries(base_dn=self.api.env.basedn,
                                           filter=filter,
                                           attrs_list=[''])
            except errors.EmptyResult:
                entries = []
            for entry in entries:
                result.setdefault('owner', []).append(entry.dn)

        if not raw:
            result['certificate'] = result['certificate'].replace('\r\n', '')
            self.obj._parse(result, all)
            result['revoked'] = ('revocation_reason' in result)
            self.obj._fill_owners(result)
            result['cacn'] = ca_obj['cn'][0]

        return dict(result=result, value=pkey_to_value(serial_number, options))


@register()
class cert_revoke(PKQuery, CertMethod, VirtualCommand):
    __doc__ = _('Revoke a certificate.')

    operation = "revoke certificate"

    def get_options(self):
        # FIXME: The default is 0.  Is this really an Int param?
        yield self.obj.params['revocation_reason'].clone(
            default=0,
            autofill=True,
        )

        for option in super(cert_revoke, self).get_options():
            yield option

    def execute(self, serial_number, **kw):
        ca_enabled_check()

        # Make sure that the cert specified by issuer+serial exists.
        # Will raise NotFound if it does not.
        resp = api.Command.cert_show(unicode(serial_number), cacn=kw['cacn'])

        try:
            self.check_access()
        except errors.ACIError as acierr:
            self.debug("Not granted by ACI to revoke certificate, looking at principal")
            try:
                cert = x509.load_certificate(resp['result']['certificate'])
                if not bind_principal_can_manage_cert(cert):
                    raise acierr
            except errors.NotImplementedError:
                raise acierr
        revocation_reason = kw['revocation_reason']
        if revocation_reason == 7:
            raise errors.CertificateOperationError(error=_('7 is not a valid revocation reason'))
        return dict(
            # Dogtag lightweight CAs have shared serial number domain, so
            # we don't tell Dogtag the issuer (but we already checked that
            # the given serial was issued by the named ca).
            result=self.Backend.ra.revoke_certificate(
                str(serial_number), revocation_reason=revocation_reason)
        )



@register()
class cert_remove_hold(PKQuery, CertMethod, VirtualCommand):
    __doc__ = _('Take a revoked certificate off hold.')

    operation = "certificate remove hold"

    def execute(self, serial_number, **kw):
        ca_enabled_check()

        # Make sure that the cert specified by issuer+serial exists.
        # Will raise NotFound if it does not.
        api.Command.cert_show(serial_number, cacn=kw['cacn'])

        self.check_access()
        return dict(
            # Dogtag lightweight CAs have shared serial number domain, so
            # we don't tell Dogtag the issuer (but we already checked that
            # the given serial was issued by the named ca).
            result=self.Backend.ra.take_certificate_off_hold(
                str(serial_number))
        )


@register()
class cert_find(Search, CertMethod):
    __doc__ = _('Search for existing certificates.')

    takes_options = (
        Str('subject?',
            label=_('Subject'),
            doc=_('Subject'),
            autofill=False,
        ),
        Int('min_serial_number?',
            doc=_("minimum serial number"),
            autofill=False,
            minvalue=0,
            maxvalue=2147483647,
        ),
        Int('max_serial_number?',
            doc=_("maximum serial number"),
            autofill=False,
            minvalue=0,
            maxvalue=2147483647,
        ),
        Flag('exactly?',
            doc=_('match the common name exactly'),
            autofill=False,
        ),
        DateTime('validnotafter_from?',
            doc=_('Valid not after from this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('validnotafter_to?',
            doc=_('Valid not after to this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('validnotbefore_from?',
            doc=_('Valid not before from this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('validnotbefore_to?',
            doc=_('Valid not before to this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('issuedon_from?',
            doc=_('Issued on from this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('issuedon_to?',
            doc=_('Issued on to this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('revokedon_from?',
            doc=_('Revoked on from this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        DateTime('revokedon_to?',
            doc=_('Revoked on to this date (YYYY-mm-dd)'),
            normalizer=normalize_pkidate,
            autofill=False,
        ),
        Flag('pkey_only?',
            label=_("Primary key only"),
            doc=_("Results should contain primary key attribute only "
                  "(\"certificate\")"),
        ),
        Int('timelimit?',
            label=_('Time Limit'),
            doc=_('Time limit of search in seconds (0 is unlimited)'),
            minvalue=0,
        ),
        Int('sizelimit?',
            label=_("Size Limit"),
            doc=_("Maximum number of entries returned (0 is unlimited)"),
            minvalue=0,
        ),
    )

    msg_summary = ngettext(
        '%(count)d certificate matched', '%(count)d certificates matched', 0
    )

    def get_options(self):
        for option in super(cert_find, self).get_options():
            if option.name == 'no_members':
                option = option.clone(default=True,
                                      flags=set(option.flags) | {'no_option'})
            elif option.name == 'cacn':
                # make CA optional, so that user may directly
                # specify Issuer DN instead
                option = option.clone(default=None, autofill=None)
            yield option

        for owner in self.obj._owners():
            yield owner.primary_key.clone_rename(
                '{0}'.format(owner.name),
                required=False,
                multivalue=True,
                primary_key=False,
                query=True,
                cli_name='{0}s'.format(owner.name),
                doc=(_("Search for certificates with these owner %s.") %
                     owner.object_name_plural),
                label=owner.object_name,
            )
            yield owner.primary_key.clone_rename(
                'no_{0}'.format(owner.name),
                required=False,
                multivalue=True,
                primary_key=False,
                query=True,
                cli_name='no_{0}s'.format(owner.name),
                doc=(_("Search for certificates without these owner %s.") %
                     owner.object_name_plural),
                label=owner.object_name,
            )

    def _get_cert_key(self, cert):
        try:
            nss_cert = x509.load_certificate(cert, x509.DER)
        except NSPRError as e:
            message = messages.SearchResultTruncated(
                reason=_("failed to load certificate: %s") % e,
            )
            self.add_message(message)

            raise ValueError("failed to load certificate")

        return (DN(unicode(nss_cert.issuer)), nss_cert.serial_number)

    def _get_cert_obj(self, cert, all, raw, pkey_only):
        obj = {'certificate': unicode(base64.b64encode(cert))}

        full = not pkey_only and all
        if not raw:
            self.obj._parse(obj, full)
        if not full:
            del obj['certificate']

        return obj

    def _cert_search(self, all, raw, pkey_only, **options):
        result = collections.OrderedDict()

        try:
            cert = options['certificate']
        except KeyError:
            return result, False, False

        try:
            key = self._get_cert_key(cert)
        except ValueError:
            return result, True, True

        result[key] = self._get_cert_obj(cert, all, raw, pkey_only)

        return result, False, True

    def _ca_search(self, all, raw, pkey_only, sizelimit, exactly, **options):
        ra_options = {}
        for name in ('revocation_reason',
                     'issuer',
                     'subject',
                     'min_serial_number', 'max_serial_number',
                     'validnotafter_from', 'validnotafter_to',
                     'validnotbefore_from', 'validnotbefore_to',
                     'issuedon_from', 'issuedon_to',
                     'revokedon_from', 'revokedon_to'):
            try:
                value = options[name]
            except KeyError:
                continue
            if isinstance(value, datetime.datetime):
                value = value.strftime(PKIDATE_FORMAT)
            elif isinstance(value, DN):
                value = unicode(value)
            ra_options[name] = value
        if sizelimit:
            ra_options['sizelimit'] = sizelimit
        if exactly:
            ra_options['exactly'] = True

        result = collections.OrderedDict()
        complete = bool(ra_options)

        try:
            ca_enabled_check()
        except errors.NotFound:
            if ra_options:
                raise
            return result, False, complete

        ca_objs = self.api.Command.ca_find()['result']
        ca_objs = {DN(ca['ipacasubjectdn'][0]): ca for ca in ca_objs}

        ra = self.api.Backend.ra
        for ra_obj in ra.find(ra_options):
            issuer = DN(ra_obj['issuer'])
            serial_number = ra_obj['serial_number']

            try:
                ca_obj = ca_objs[issuer]
            except KeyError:
                continue

            if pkey_only:
                obj = {'serial_number': serial_number}
            else:
                obj = ra_obj
                if all:
                    obj.update(ra.get_certificate(str(serial_number)))

                if not raw:
                    obj['issuer'] = issuer
                    obj['subject'] = DN(ra_obj['subject'])
                    obj['revoked'] = (
                        ra_obj['status'] in (u'REVOKED', u'REVOKED_EXPIRED'))
                    if all:
                        obj['certificate'] = (
                            obj['certificate'].replace('\r\n', ''))
                        self.obj._parse(obj)

            obj['cacn'] = ca_obj['cn'][0]

            result[issuer, serial_number] = obj

        return result, False, complete

    def _ldap_search(self, all, raw, pkey_only, no_members, timelimit,
                     sizelimit, **options):
        ldap = self.api.Backend.ldap2

        filters = []
        for owner in self.obj._owners():
            for prefix, rule in (('', ldap.MATCH_ALL),
                                 ('no_', ldap.MATCH_NONE)):
                try:
                    value = options[prefix + owner.name]
                except KeyError:
                    continue

                filter = ldap.make_filter_from_attr(
                    'objectclass',
                    owner.object_class,
                    ldap.MATCH_ALL)
                if filter not in filters:
                    filters.append(filter)

                filter = ldap.make_filter_from_attr(
                    owner.primary_key.name,
                    value,
                    rule)
                filters.append(filter)

        result = collections.OrderedDict()
        complete = bool(filters)

        cert = options.get('certificate')
        if cert is not None:
            filter = ldap.make_filter_from_attr('usercertificate', cert)
        else:
            filter = '(usercertificate=*)'
        filters.append(filter)

        filter = ldap.combine_filters(filters, ldap.MATCH_ALL)
        try:
            entries, truncated = ldap.find_entries(
                base_dn=self.api.env.basedn,
                filter=filter,
                attrs_list=['usercertificate'],
                time_limit=timelimit,
                size_limit=sizelimit,
            )
        except errors.EmptyResult:
            entries = []
            truncated = False
        else:
            try:
                ldap.handle_truncated_result(truncated)
            except errors.LimitsExceeded as e:
                self.add_message(messages.SearchResultTruncated(reason=e))

            truncated = bool(truncated)

        for entry in entries:
            for attr in ('usercertificate', 'usercertificate;binary'):
                for cert in entry.get(attr, []):
                    try:
                        key = self._get_cert_key(cert)
                    except ValueError:
                        truncated = True
                        continue

                    try:
                        obj = result[key]
                    except KeyError:
                        obj = self._get_cert_obj(cert, all, raw, pkey_only)
                        result[key] = obj

                    if not pkey_only and (all or not no_members):
                        owners = obj.setdefault('owner', [])
                        if entry.dn not in owners:
                            owners.append(entry.dn)

        if not raw:
            for obj in six.itervalues(result):
                self.obj._fill_owners(obj)

        return result, truncated, complete

    def execute(self, criteria=None, all=False, raw=False, pkey_only=False,
                no_members=True, timelimit=None, sizelimit=None, **options):
        if 'cacn' in options:
            ca_obj = api.Command.ca_show(options['cacn'])['result']
            ca_sdn = unicode(ca_obj['ipacasubjectdn'][0])
            if 'issuer' in options:
                if DN(ca_sdn) != DN(options['issuer']):
                    # client has provided both 'ca' and 'issuer' but
                    # issuer DNs don't match; result must be empty
                    return dict(result=[], count=0, truncated=False)
            else:
                options['issuer'] = ca_sdn

        if criteria is not None:
            return dict(result=[], count=0, truncated=False)

        result = collections.OrderedDict()
        truncated = False
        complete = False

        for sub_search in (self._cert_search,
                           self._ca_search,
                           self._ldap_search):
            sub_result, sub_truncated, sub_complete = sub_search(
                all=all,
                raw=raw,
                pkey_only=pkey_only,
                no_members=no_members,
                timelimit=timelimit,
                sizelimit=sizelimit,
                **options)

            if sub_complete:
                sizelimit = None

                for key in tuple(result):
                    if key not in sub_result:
                        del result[key]

            for key, sub_obj in six.iteritems(sub_result):
                try:
                    obj = result[key]
                except KeyError:
                    if complete:
                        continue
                    result[key] = sub_obj
                else:
                    obj.update(sub_obj)

            truncated = truncated or sub_truncated
            complete = complete or sub_complete

        result = list(six.itervalues(result))

        ret = dict(
            result=result
        )
        ret['count'] = len(ret['result'])
        ret['truncated'] = bool(truncated)
        return ret


@register()
class ca_is_enabled(Command):
    """
    Checks if any of the servers has the CA service enabled.
    """
    NO_CLI = True
    has_output = output.standard_value

    def execute(self, *args, **options):
        base_dn = DN(('cn', 'masters'), ('cn', 'ipa'), ('cn', 'etc'),
                     self.api.env.basedn)
        filter = '(&(objectClass=ipaConfigObject)(cn=CA))'
        try:
            self.api.Backend.ldap2.find_entries(
                base_dn=base_dn, filter=filter, attrs_list=[])
        except errors.NotFound:
            result = False
        else:
            result = True
        return dict(result=result, value=pkey_to_value(None, options))
