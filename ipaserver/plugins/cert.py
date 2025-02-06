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
import itertools
import logging
from operator import attrgetter

import cryptography.x509
from cryptography.hazmat.primitives import hashes, serialization
from dns import resolver, reversename
import six

from ipalib import Command, Str, Int, Flag, StrEnum, SerialNumber
from ipalib import api
from ipalib import errors, messages
from ipalib import x509
from ipalib import ngettext
from ipalib.constants import IPA_CA_CN, IPA_CA_RECORD
from ipalib.crud import Create, PKQuery, Retrieve, Search
from ipalib.frontend import Method, Object
from ipalib.parameters import (
    Bytes, Certificate, CertificateSigningRequest, DateTime, DNParam,
    DNSNameParam, Principal
)
from ipalib.plugable import Registry
from .virtual import VirtualCommand
from .baseldap import pkey_to_value
from .certprofile import validate_profile_id
from ipalib.text import _
from ipalib.request import context
from ipalib import output
from ipapython import dnsutil, kerberos
from ipapython.dn import DN
from ipapython.ipautil import datetime_from_utctimestamp
from ipaserver.plugins.service import normalize_principal, validate_realm
from ipaserver.masters import (
    ENABLED_SERVICE, CONFIGURED_SERVICE, HIDDEN_SERVICE, is_service_enabled
)

try:
    import pyhbac
except ImportError:
    raise errors.SkipPluginModule(reason=_('pyhbac is not installed.'))

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

logger = logging.getLogger(__name__)

USER, HOST, KRBTGT, SERVICE = range(4)

register = Registry()

PKIDATE_FORMAT = '%Y-%m-%d'


def _acl_make_request(principal_type, principal, ca_id, profile_id):
    """Construct HBAC request for the given principal, CA and profile"""

    req = pyhbac.HbacRequest()
    req.targethost.name = ca_id
    req.service.name = profile_id
    if principal_type == 'user':
        req.user.name = principal.username
    elif principal_type == 'host':
        req.user.name = principal.hostname
    elif principal_type == 'service':
        req.user.name = unicode(principal)
    groups = []
    if principal_type == 'user':
        user_obj = api.Command.user_show(
            str(principal.username))['result']
        groups = user_obj.get('memberof_group', [])
        groups += user_obj.get('memberofindirect_group', [])
    elif principal_type == 'host':
        host_obj = api.Command.host_show(
            str(principal.hostname))['result']
        groups = host_obj.get('memberof_hostgroup', [])
        groups += host_obj.get('memberofindirect_hostgroup', [])
    req.user.groups = sorted(set(groups))
    return req


def _acl_make_rule(principal_type, obj):
    """Turn CA ACL object into HBAC rule.

    ``principal_type``
        String in {'user', 'host', 'service'}
    """
    rule = pyhbac.HbacRule(obj['cn'][0])
    rule.enabled = obj['ipaenabledflag'][0]
    rule.srchosts.category = {pyhbac.HBAC_CATEGORY_ALL}

    # add CA(s)
    if 'ipacacategory' in obj and obj['ipacacategory'][0].lower() == 'all':
        rule.targethosts.category = {pyhbac.HBAC_CATEGORY_ALL}
    else:
        # For compatibility with pre-lightweight-CAs CA ACLs,
        # no CA members implies the host authority (only)
        rule.targethosts.names = obj.get('ipamemberca_ca', [IPA_CA_CN])

    # add profiles
    if ('ipacertprofilecategory' in obj
            and obj['ipacertprofilecategory'][0].lower() == 'all'):
        rule.services.category = {pyhbac.HBAC_CATEGORY_ALL}
    else:
        attr = 'ipamembercertprofile_certprofile'
        rule.services.names = obj.get(attr, [])

    # add principals and principal's groups
    category_attr = '{}category'.format(principal_type)
    if category_attr in obj and obj[category_attr][0].lower() == 'all':
        rule.users.category = {pyhbac.HBAC_CATEGORY_ALL}
    else:
        if principal_type == 'user':
            rule.users.names = obj.get('memberuser_user', [])
            rule.users.groups = obj.get('memberuser_group', [])
        elif principal_type == 'host':
            rule.users.names = obj.get('memberhost_host', [])
            rule.users.groups = obj.get('memberhost_hostgroup', [])
        elif principal_type == 'service':
            rule.users.names = [
                unicode(principal)
                for principal in obj.get('memberservice_service', [])
            ]

    return rule


def acl_evaluate(principal, ca_id, profile_id):
    if principal.is_user:
        principal_type = 'user'
    elif principal.is_host:
        principal_type = 'host'
    else:
        principal_type = 'service'
    req = _acl_make_request(principal_type, principal, ca_id, profile_id)
    acls = api.Command.caacl_find(no_members=False)['result']
    rules = [_acl_make_rule(principal_type, obj) for obj in acls]
    return req.evaluate(rules) == pyhbac.HBAC_EVAL_ALLOW


def normalize_pkidate(value):
    return datetime.datetime.strptime(value, PKIDATE_FORMAT)


def convert_pkidatetime(value):
    if isinstance(value, str):
        value = int(value)
    return x509.format_datetime(datetime_from_utctimestamp(value, units=1000))


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


def ca_enabled_check(_api):
    if not _api.Command.ca_is_enabled()['result']:
        raise errors.NotFound(reason=_('CA is not configured'))


def caacl_check(principal, ca, profile_id):
    if not acl_evaluate(principal, ca, profile_id):
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


def ca_kdc_check(api_instance, hostname):
    master_dn = api_instance.Object.server.get_dn(unicode(hostname))
    kdc_dn = DN(('cn', 'KDC'), master_dn)
    wanted = {ENABLED_SERVICE, CONFIGURED_SERVICE, HIDDEN_SERVICE}
    try:
        kdc_entry = api_instance.Backend.ldap2.get_entry(
            kdc_dn, ['ipaConfigString'])
        if not wanted.intersection(kdc_entry['ipaConfigString']):
            raise errors.NotFound(
                reason=_("enabledService/configuredService not in "
                         "ipaConfigString kdc entry"))
    except errors.NotFound:
        raise errors.ACIError(
            info=_("Host '%(hostname)s' is not an active KDC")
            % dict(hostname=hostname))


def bind_principal_can_manage_cert(cert):
    """Check that the bind principal can manage the given cert.

    ``cert``
        A python-cryptography ``Certificate`` object.

    """
    op_account = getattr(context, 'principal', None)
    if op_account is None:
        return False
    bind_principal = kerberos.Principal(op_account)
    if not bind_principal.is_host:
        return False

    hostname = bind_principal.hostname

    # Verify that hostname matches subject of cert.
    # We check the "most-specific" CN value.
    cns = cert.subject.get_attributes_for_oid(
            cryptography.x509.oid.NameOID.COMMON_NAME)
    if len(cns) == 0:
        return False  # no CN in subject
    else:
        return hostname == cns[-1].value


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
        Certificate(
            'certificate',
            label=_("Certificate"),
            doc=_("Base-64 encoded certificate."),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Bytes(
            'certificate_chain*',
            label=_("Certificate chain"),
            doc=_("X.509 certificate chain"),
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
            'sha1_fingerprint',
            label=_('Fingerprint (SHA1)'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'sha256_fingerprint',
            label=_('Fingerprint (SHA256)'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        SerialNumber(
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

        Raise ``ValueError`` if the certificate is malformed.
        (Note: only the main certificate structure and Subject Alt
        Name extension are examined.)

        """
        if 'certificate' in obj:
            cert = x509.load_der_x509_certificate(
                base64.b64decode(obj['certificate']))
            obj['subject'] = DN(cert.subject)
            obj['issuer'] = DN(cert.issuer)
            obj['serial_number'] = str(cert.serial_number)
            obj['serial_number_hex'] = '0x%X' % cert.serial_number
            obj['valid_not_before'] = x509.format_datetime(
                cert.not_valid_before_utc)
            obj['valid_not_after'] = x509.format_datetime(
                cert.not_valid_after_utc)
            if full:
                obj['sha1_fingerprint'] = x509.to_hex_with_colons(
                    cert.fingerprint(hashes.SHA1()))
                obj['sha256_fingerprint'] = x509.to_hex_with_colons(
                    cert.fingerprint(hashes.SHA256()))

            general_names = x509.process_othernames(
                    cert.san_general_names)

            for gn in general_names:
                try:
                    self._add_san_attribute(obj, full, gn)
                except Exception:
                    # Invalid GeneralName (i.e. not a valid X.509 cert);
                    # don't fail but log something about it
                    logger.warning(
                        "Encountered bad GeneralName; skipping", exc_info=True)

    def _add_san_attribute(self, obj, full, gn):
        name_type_map = {
            cryptography.x509.RFC822Name:
                ('san_rfc822name', attrgetter('value')),
            cryptography.x509.DNSName: ('san_dnsname', attrgetter('value')),
            # cryptography.x509.???: 'san_x400address',
            cryptography.x509.DirectoryName:
                ('san_directoryname', lambda x: DN(x.value)),
            # cryptography.x509.???: 'san_edipartyname',
            cryptography.x509.UniformResourceIdentifier:
                ('san_uri', attrgetter('value')),
            cryptography.x509.IPAddress:
                ('san_ipaddress', attrgetter('value')),
            cryptography.x509.RegisteredID:
                ('san_oid', attrgetter('value.dotted_string')),
            cryptography.x509.OtherName: ('san_other', _format_othername),
            x509.UPN: ('san_other_upn', attrgetter('name')),
            x509.KRB5PrincipalName: ('san_other_kpn', attrgetter('name')),
        }
        default_attrs = {
            'san_rfc822name', 'san_dnsname', 'san_other_upn', 'san_other_kpn',
        }

        if type(gn) not in name_type_map:
            return

        attr_name, format_name = name_type_map[type(gn)]

        if full or attr_name in default_attrs:
            attr_value = self.params[attr_name].type(format_name(gn))
            obj.setdefault(attr_name, []).append(attr_value)

        if full and attr_name.startswith('san_other_'):
            # also include known otherName in generic otherName attribute
            attr_value = self.params['san_other'].type(_format_othername(gn))
            obj.setdefault('san_other', []).append(attr_value)


def _format_othername(on):
    """Format a python-cryptography OtherName for display."""
    return u'{}:{}'.format(
        on.type_id.dotted_string,
        base64.b64encode(on.value).decode('ascii')
    )


class BaseCertMethod(Method):
    def get_options(self):
        yield self.obj.params['cacn'].clone(query=True)

        yield from super(BaseCertMethod, self).get_options()


@register()
class certreq(BaseCertObject):
    takes_params = BaseCertObject.takes_params + (
        Str(
            'request_type',
            default=u'pkcs10',
            autofill=True,
            flags={'no_option', 'no_update', 'no_search'},
        ),
        Str(
            'profile_id?', validate_profile_id,
            label=_("Profile ID"),
            doc=_("Certificate Profile to use"),
            flags={'no_update', 'no_search'},
        ),
        Str(
            'cert_request_status',
            label=_('Request status'),
            flags={'no_create', 'no_update', 'no_search'},
        ),
        Str(
            'request_id',
            label=_('Request id'),
            primary_key=True,
            flags={'no_create', 'no_update', 'no_search'},
        ),
    )


_chain_flag = Flag(
    'chain',
    default=False,
    doc=_('Include certificate chain in output'),
)


@register()
class cert_request(Create, BaseCertMethod, VirtualCommand):
    __doc__ = _('Submit a certificate signing request.')

    obj_name = 'certreq'
    attr_name = 'request'

    takes_args = (
        CertificateSigningRequest(
            'csr',
            label=_('CSR'),
            cli_name='csr_file',
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
        _chain_flag,
    )

    def get_args(self):
        # FIXME: the 'no_create' flag is ignored for positional arguments
        for arg in super(cert_request, self).get_args():
            if arg.name == 'request_id':
                continue
            yield arg

    def execute(self, csr, all=False, raw=False, chain=False, **kw):
        # deferred import to avoid issues building documentation
        from ipaserver.install import cainstance, dsinstance, krainstance
        from ipaserver.install.ca import lookup_ca_subject

        ca_enabled_check(self.api)

        ldap = self.api.Backend.ldap2
        realm = unicode(self.api.env.realm)
        add = kw.get('add')
        request_type = kw.get('request_type')
        profile_id = kw.get('profile_id', self.Backend.ra.DEFAULT_PROFILE)

        # Check that requested authority exists (done before CA ACL
        # enforcement so that user gets better error message if
        # referencing nonexistant CA) and look up authority ID.
        #
        ca = kw['cacn']
        ca_obj = api.Command.ca_show(ca, all=all, chain=chain)['result']
        ca_id = ca_obj['ipacaid'][0]

        """
        Access control is partially handled by the ACI titled
        'Hosts can modify service userCertificate'. This is for the case
        where a machine binds using a host/ prinicpal. It can only do the
        request if the target hostname is in the managedBy attribute which
        is managed using the add/del member commands.

        Binding with a user principal one needs to be in the request_certs
        taskgroup (directly or indirectly via role membership).

        When requesting certificates for the CA/KRA subsytem profiles
        the principal argument is going to be the host itself. We will
        ignore it.
        """
        principal_arg = kw.get('principal')
        op_account = getattr(context, 'principal', None)
        logger.debug(
            "Requesting cert for principal %s from principal %s with "
            "profile %s", principal_arg, op_account, profile_id
        )
        if (
            op_account
            and profile_id in (
                self.Backend.ra.OCSP_PROFILE,
                self.Backend.ra.SUBSYSTEM_PROFILE,
                self.Backend.ra.AUDIT_PROFILE,
                self.Backend.ra.CACERT_PROFILE,
                self.Backend.ra.CASERVER_PROFILE,
                self.Backend.ra.KRA_AUDIT_PROFILE,
                self.Backend.ra.KRA_STORAGE_PROFILE,
                self.Backend.ra.KRA_TRANSPORT_PROFILE
            )
        ):
            # Here we validate for these CA/KRA profiles:
            #  1. the requesting principal is a host
            #  2. the requesting principal is an IPA server
            #  3. the subject of the CSR matches the expected
            #     subject for this profile type
            host_principal = kerberos.Principal(op_account)
            if principal_to_principal_type(host_principal) != HOST:
                raise errors.NotFound(
                    reason=_("Certificate not requested from a host")
                )
            try:
                self.api.Command.server_show(host_principal.hostname)
            except errors.NotFound:
                raise errors.NotFound(
                    reason=_("Certificate not requested from an IPA server")
                )

            ca = cainstance.CAInstance(api.env.realm)
            reqs = ca.tracking_reqs.items()
            kra = krainstance.KRAInstance(api.env.realm)
            if kra.is_installed():
                reqs = itertools.chain(reqs,
                                       kra.tracking_reqs.items())
            nickname = None
            for nick, prof in reqs:
                if prof == profile_id:
                    nickname = nick
                    break
            subject_dn = None
            if nickname:
                logger.debug("Found CA/KRA nickname %s", nickname)
                subject_base = dsinstance.DsInstance().find_subject_base()
                ca_subject_dn = lookup_ca_subject(api, subject_base)
                nickname_by_subject_dn = cainstance.get_nickname_by_subject_dn(
                    subject_base, ca_subject_dn
                )
                for sub_dn, nick in nickname_by_subject_dn.items():
                    logger.debug("Looking for %s in %s", nickname, nick)
                    if nick == nickname:
                        subject_dn = sub_dn
                        break
                if subject_dn:
                    if subject_dn != DN(csr.subject):
                        raise errors.NotFound(
                            reason=_(
                                "CSR subject mismatch, {expected} vs "
                                "{csr}".format(
                                    expected=subject_dn, csr=csr.subject
                                )
                            )
                        )
                    else:
                        logger.debug("Found subject %s", subject_dn)
            else:
                raise errors.NotFound(
                    reason=_("Unable to matcht the request to a nickname")
                )

            try:
                csr.extensions.get_extension_for_oid(
                    cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            except cryptography.x509.extensions.ExtensionNotFound:
                pass
            else:
                if profile_id != 'caServerCert':
                    raise errors.ACIError(
                        info=_("SAN are not allowed with the %s profile") %
                        (profile_id)
                    )
        else:
            if principal_to_principal_type(principal_arg) == KRBTGT:
                principal_obj = None
                principal = principal_arg

                # Allow krbtgt to use only the KDC certprofile
                if profile_id != self.Backend.ra.KDC_PROFILE:
                    raise errors.ACIError(
                        info=_("krbtgt certs can use only the %s profile") %
                        (self.Backend.ra.KDC_PROFILE))

                # Allow only our own realm krbtgt for now; no trusted realms.
                if principal != kerberos.Principal((u'krbtgt', realm),
                                                   realm=realm):
                    raise errors.NotFound("Not our realm's krbtgt")

            else:
                principal_obj = self.lookup_or_add_principal(principal_arg, add)
                if 'krbcanonicalname' in principal_obj:
                    principal = principal_obj['krbcanonicalname'][0]
                else:
                    principal = principal_obj['krbprincipalname'][0]

            principal_string = unicode(principal)
            principal_type = principal_to_principal_type(principal)

            op_account = getattr(context, 'principal', None)
            if op_account is None:
                # Can the bound principal request certs for another principal?
                # the virtual operation check will rely on LDAP ACIs, no need
                # for the Kerberos principal here.
                # Force the principal that cannot be matched in normal
                # deployments
                op_account = '<unknown>@<UNKNOWN>'

            bind_principal = kerberos.Principal(op_account)
            bind_principal_string = unicode(bind_principal)
            bind_principal_type = principal_to_principal_type(bind_principal)

            if (bind_principal_string != principal_string
                    and bind_principal_type != HOST):
                # Can the bound principal request certs for another principal?
                self.check_access()

            try:
                self.check_access("request certificate ignore caacl")
                bypass_caacl = True
            except errors.ACIError:
                bypass_caacl = False

            if not bypass_caacl:
                if principal_type == KRBTGT:
                    ca_kdc_check(self.api, bind_principal.hostname)
                else:
                    caacl_check(principal, ca, profile_id)

            try:
                ext_san = csr.extensions.get_extension_for_oid(
                    cryptography.x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            except cryptography.x509.extensions.ExtensionNotFound:
                ext_san = None

            # Ensure that the DN in the CSR matches the principal
            #
            # We only look at the "most specific" CN value
            cns = csr.subject.get_attributes_for_oid(
                cryptography.x509.oid.NameOID.COMMON_NAME
            )
            if len(cns) == 0:
                raise errors.ValidationError(
                    name='csr',
                    error=_("No Common Name was found in subject of request.")
                )
            cn = cns[-1].value  # "most specific" is end of list

            if principal_type in (SERVICE, HOST):
                if not _dns_name_matches_principal(cn, principal,
                                                   principal_obj):
                    raise errors.ValidationError(
                        name='csr',
                        error=_(
                            "hostname in subject of request '%(cn)s' does not "
                            "match name or aliases of principal '%(principal)s'"
                        ) % dict(cn=cn, principal=principal)
                    )
            elif principal_type == KRBTGT and not bypass_caacl:
                if cn.lower() != bind_principal.hostname.lower():
                    raise errors.ACIError(
                        info=_("hostname in subject of request '%(cn)s' "
                               "does not match principal hostname "
                               "'%(hostname)s'") % dict(
                                   cn=cn, hostname=bind_principal.hostname)
                    )
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
                email_addrs = csr.subject.get_attributes_for_oid(
                    cryptography.x509.oid.NameOID.EMAIL_ADDRESS
                )
                csr_emails = [attr.value for attr in email_addrs]
                if not _emails_are_valid(csr_emails,
                                         principal_obj.get('mail', [])):
                    raise errors.ValidationError(
                        name='csr',
                        error=_(
                            "DN emailAddress does not match "
                            "any of user's email addresses")
                    )

            if principal_type != KRBTGT:
                # We got this far so the principal entry exists,
                # can we write it?
                dn = principal_obj.dn
                if not ldap.can_write(dn, "usercertificate"):
                    raise errors.ACIError(
                        info=_("Insufficient 'write' privilege to the "
                               "'userCertificate' attribute of entry "
                               "'%s'.") % dn)

            # During SAN validation, we collect IPAddressName values,
            # and *qualified* DNS names, and then ensure that all
            # IPAddressName values correspond to one of the DNS names.
            #
            san_ipaddrs = set()
            san_dnsnames = set()

            # Validate the subject alt name, if any
            if ext_san is not None:
                generalnames = x509.process_othernames(ext_san.value)
            else:
                generalnames = []
            for gn in generalnames:
                if isinstance(gn, cryptography.x509.general_name.DNSName):
                    if principal.is_user:
                        raise errors.ValidationError(
                            name='csr',
                            error=_(
                                "subject alt name type %s is forbidden "
                                "for user principals") % "DNSName"
                        )

                    name = gn.value

                    # Special case: if the DNS name is ipa-ca.$DOMAIN and if the
                    # subject principal is the HTTP service for an IPA server
                    # then allow the name.
                    if name == f'{IPA_CA_RECORD}.{self.api.env.domain}' \
                            and principal.is_service \
                            and principal.service_name == 'HTTP':
                        try:
                            self.api.Command.server_show(principal.hostname)
                        except errors.NotFound:
                            pass  # not an IPA server; proceed as usual
                        else:
                            # subject principal is an IPA server, so the
                            # ipa-ca.$DOMAIN name is allowed
                            continue

                    if _dns_name_matches_principal(name,
                                                   principal, principal_obj):
                        san_dnsnames.add(name)
                        continue  # nothing more to check for this alt name

                    # no match yet; check for an alternative principal with
                    # same realm and service type as subject principal.
                    components = list(principal.components)
                    components[-1] = name
                    alt_principal = kerberos.Principal(
                        components, principal.realm
                    )
                    alt_principal_obj = None
                    try:
                        if principal_type == HOST:
                            alt_principal_obj = api.Command['host_show'](
                                name, all=True)['result']
                        elif principal_type == KRBTGT:
                            alt_principal = kerberos.Principal(
                                (u'host', name), principal.realm)
                        elif principal_type == SERVICE:
                            alt_principal_obj = api.Command['service_show'](
                                alt_principal, all=True)['result']
                    except errors.NotFound:
                        # We don't want to issue any certificates referencing
                        # machines we don't know about. Nothing is stored in
                        # this host record related to this certificate.
                        raise errors.NotFound(reason=_(
                            'The service principal for subject alt name %s '
                            'in certificate request does not '
                            'exist') % name
                        )

                    if alt_principal_obj is not None:
                        # We found an alternative principal.

                        # First check that the DNS name does in fact match this
                        # principal.  Because we used the DNSName value as the
                        # basis for the search, this may seem redundant.
                        # Actually, we only perform this check to distinguish
                        # between qualified and unqualified DNS names.
                        #
                        # We collect only fully qualified names for the
                        # purposes of IPAddressName validation, because it
                        # is undecidable whether 'ninja' refers to
                        # 'ninja.my.domain.' or 'ninja.'.
                        # Remember that even a TLD can have an A record!
                        #
                        if _dns_name_matches_principal(
                                name, alt_principal, alt_principal_obj):
                            san_dnsnames.add(name)
                        else:
                            # Unqualified SAN DNS names are a valid use case.
                            # We don't add them to san_dnsnames for IPAddress
                            # validation, but we don't reject the request
                            # either.
                            pass

                        # Now check write access and caacl
                        altdn = alt_principal_obj['dn']
                        if not ldap.can_write(altdn, "usercertificate"):
                            raise errors.ACIError(info=_(
                                "Insufficient privilege to create a "
                                "certificate with subject alt name "
                                "'%s'.") % name)
                    if not bypass_caacl:
                        if principal_type == KRBTGT:
                            ca_kdc_check(self.api, alt_principal.hostname)
                        else:
                            caacl_check(alt_principal, ca, profile_id)

                elif isinstance(gn, (x509.KRB5PrincipalName, x509.UPN)):
                    if principal_type == KRBTGT:
                        principal_obj = dict()
                        principal_obj['krbprincipalname'] = [
                            kerberos.Principal((u'krbtgt', realm), realm)]
                    if not _principal_name_matches_principal(
                            gn.name, principal_obj):
                        raise errors.ValidationError(
                            name='csr',
                            error=_(
                                "Principal '%s' in subject alt name does not "
                                "match requested principal") % gn.name)
                elif isinstance(gn, cryptography.x509.general_name.RFC822Name):
                    if principal_type == USER:
                        if not _emails_are_valid([gn.value],
                                                 principal_obj.get('mail', [])):
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
                elif isinstance(gn, cryptography.x509.general_name.IPAddress):
                    if principal.is_user:
                        raise errors.ValidationError(
                            name='csr',
                            error=_(
                                "subject alt name type %s is forbidden "
                                "for user principals") % "IPAddress"
                        )

                    # collect the value; we will validate it after we
                    # finish iterating all the SAN values
                    san_ipaddrs.add(gn.value)
                else:
                    raise errors.ACIError(
                        info=_("Subject alt name type %s is forbidden")
                        % type(gn).__name__)

            if san_ipaddrs:
                _validate_san_ips(san_ipaddrs, san_dnsnames)

        # Request the certificate
        try:
            # re-serialise to PEM, in case the user-supplied data has
            # extraneous material that will cause Dogtag to freak out
            # keep it as string not bytes, it is required later
            csr_pem = csr.public_bytes(
                serialization.Encoding.PEM).decode('utf-8')
            result = self.Backend.ra.request_certificate(
                csr_pem, profile_id, ca_id, request_type=request_type)
        except errors.HTTPRequestError as e:
            if e.status == 409:  # pylint: disable=no-member
                raise errors.CertificateOperationError(
                    error=_("CA '%s' is disabled") % ca)
            else:
                raise e

        if not raw:
            try:
                self.obj._parse(result, all)
            except ValueError as e:
                self.add_message(
                    messages.CertificateInvalid(
                        subject=principal,
                        reason=e,
                    )
                )
            result['request_id'] = result['request_id']
            result['cacn'] = ca_obj['cn'][0]

        # Success? Then add it to the principal's entry
        # (unless the profile tells us not to)
        try:
            profile = api.Command['certprofile_show'](profile_id)
        except Exception as e:
            logger.debug("certprofile-show failed with %s", e)
        else:
            store = profile['result']['ipacertprofilestoreissued'][0]
            if store and 'certificate' in result:
                cert = result.get('certificate')
                kwargs = dict(addattr=u'usercertificate={}'.format(cert))
                # note: we call different commands for the different
                # principal types because handling of 'userCertificate'
                # vs. 'userCertificate;binary' varies by plugin.
                if principal_type == SERVICE:
                    api.Command['service_mod'](principal_string, **kwargs)
                elif principal_type == HOST:
                    api.Command['host_mod'](principal.hostname, **kwargs)
                elif principal_type == USER:
                    api.Command['user_mod'](principal.username, **kwargs)
                elif principal_type == KRBTGT:
                    logger.error("Profiles used to store cert should't be "
                                 "used for krbtgt certificates")

        if 'certificate_chain' in ca_obj:
            cert = x509.load_der_x509_certificate(
                base64.b64decode(result['certificate']))
            cert = cert.public_bytes(serialization.Encoding.DER)
            result['certificate_chain'] = [cert] + ca_obj['certificate_chain']

        return dict(
            result=result,
            value=pkey_to_value(result['request_id'], kw),
        )

    def lookup_principal(self, principal):
        """
        Look up a principal's account.  Only works for users, hosts, services.
        """
        return self.api.Backend.ldap2.find_entry_by_attr(
            'krbprincipalname', principal, 'krbprincipalaux',
            base_dn=DN(self.api.env.container_accounts, self.api.env.basedn)
        )

    def lookup_or_add_principal(self, principal, add):
        """
        Look up a principal or add it if it does not exist.

        Only works for users, hosts, services.  krbtgt must be
        handled separately.

        Only service principals get added, and only when ``add`` is
        ``True``.  If ``add`` is requested for a nonexistant user or
        host, raise ``OperationNotSupportedForPrincipalTypes``.

        :param principal: ``kerberos.Principal`` to look up
        :param add: whether to add the principal if not found; bool
        :return: an ``LDAPEntry``

        """
        try:
            return self.lookup_principal(principal)
        except errors.NotFound:
            if add:
                if principal.is_service and not principal.is_host:
                    self.api.Command.service_add(
                        str(principal), all=True, force=True)
                    return self.lookup_principal(principal)  # we want an LDAPEntry
                else:
                    if principal.is_user:
                        princtype_str = _('user')
                    else:
                        princtype_str = _('host')
                    raise errors.OperationNotSupportedForPrincipalType(
                        operation=_("'add' option"),
                        principal_type=princtype_str)
            else:
                raise errors.NotFound(
                    reason=_("The principal for this request doesn't exist."))


def _emails_are_valid(csr_emails, principal_emails):
    """
    Checks if any email address from certificate request does not
    appear in ldap entry, comparing the domain part case-insensitively.
    """

    def lower_domain(email):
        email_splitted = email.split('@', 1)
        if len(email_splitted) > 1:
            email_splitted[1] = email_splitted[1].lower()

        return '@'.join(email_splitted)

    principal_emails_lower = set(map(lower_domain, principal_emails))
    csr_emails_lower = set(map(lower_domain, csr_emails))

    return csr_emails_lower.issubset(principal_emails_lower)


def principal_to_principal_type(principal):
    if principal.is_user:
        return USER
    elif principal.is_host:
        return HOST
    elif principal.service_name == 'krbtgt':
        return KRBTGT
    else:
        return SERVICE


def _dns_name_matches_principal(name, principal, principal_obj):
    """
    Ensure that a DNS name matches the given principal.

    :param name: The DNS name to match
    :param principal: The subject ``Principal``
    :param principal_obj: The subject principal's LDAP object
    :return: True if name matches, otherwise False

    """
    if principal_obj is None:
        return False

    for alias in principal_obj.get('krbprincipalname', []):
        # we can only compare them if both subject principal and
        # the alias are service or host principals
        if not (alias.is_service and principal.is_service):
            continue

        # ignore aliases with different realm or service name from
        # subject principal
        if alias.realm != principal.realm:
            continue
        if alias.service_name != principal.service_name:
            continue

        # now compare DNS name to alias hostname
        if name.lower() == alias.hostname.lower():
            return True  # we have a match

    return False


def _principal_name_matches_principal(name, principal_obj):
    """
    Ensure that a stringy principal name (e.g. from UPN
    or KRB5PrincipalName OtherName) matches the given principal.

    """
    try:
        principal = kerberos.Principal(name)
    except ValueError:
        return False

    return principal in principal_obj.get('krbprincipalname', [])


def _validate_san_ips(san_ipaddrs, san_dnsnames):
    """
    Check the IP addresses in a CSR subjectAltName.

    Raise a ValidationError if the subjectAltName in a CSR includes
    any IP addresses that do not match a DNS name in the SAN.  Matching means
    the following:

    * One of the DNS names in the SAN resolves (possibly via a single CNAME -
      no CNAME chains allowed) to an A or AAAA record containing that
      IP address.
    * The IP address has a reverse DNS record pointing to that A or AAAA
      record.
    * All of the DNS records (A, AAAA, CNAME, and PTR) are managed by this IPA
      instance.

    :param san_ipaddrs: The IP addresses in the subjectAltName
    :param san_dnsnames: The DNS names in the subjectAltName

    :raises: errors.ValidationError if the SAN containes a non-matching IP
        address.

    """
    san_ip_set = frozenset(unicode(ip) for ip in san_ipaddrs)

    # Build a dict of IPs that are reachable from the SAN dNSNames
    reachable = {}
    for name in san_dnsnames:
        _san_ip_update_reachable(reachable, name, cname_depth=1)

    # Each iPAddressName must be reachable from a dNSName
    unreachable_ips = san_ip_set - six.viewkeys(reachable)
    if len(unreachable_ips) > 0:
        raise errors.ValidationError(
            name='csr',
            error=_(
                "IP address in subjectAltName (%s) unreachable from DNS names"
            ) % ', '.join(unreachable_ips)
        )

    # Collect PTR records for each IP address
    ptrs_by_ip = {}
    for ip in san_ipaddrs:
        ptrs = _ip_ptr_records(unicode(ip))
        if len(ptrs) > 0:
            ptrs_by_ip[unicode(ip)] = set(s.rstrip('.') for s in ptrs)

    # Each iPAddressName must have a corresponding PTR record.
    missing_ptrs = san_ip_set - six.viewkeys(ptrs_by_ip)
    if len(missing_ptrs) > 0:
        raise errors.ValidationError(
            name='csr',
            error=_(
                "IP address in subjectAltName (%s) does not have PTR record"
            ) % ', '.join(missing_ptrs)
        )

    # PTRs and forward records must form a loop
    for ip, ptrs in ptrs_by_ip.items():
        # PTR value must appear in the set of names that resolve to
        # this IP address (via A/AAAA records)
        if len(ptrs - reachable.get(ip, set())) > 0:
            raise errors.ValidationError(
                name='csr',
                error=_(
                    "PTR record for SAN IP (%s) does not match A/AAAA records"
                ) % ip
            )


def _san_ip_update_reachable(reachable, dnsname, cname_depth):
    """
    Update dict of reachable IPs and the names that reach them.

    :param reachable: the dict to update. Keys are IP addresses,
                      values are sets of DNS names.
    :param dnsname: the DNS name to resolve
    :param cname_depth: How many levels of CNAME indirection are permitted.

    """
    fqdn = dnsutil.DNSName(dnsname).make_absolute()
    try:
        zone = dnsutil.DNSName(dnsutil.zone_for_name(fqdn))
    except resolver.NoNameservers:
        return  # if there's no zone, there are no records
    name = fqdn.relativize(zone)

    try:
        result = api.Command['dnsrecord_show'](zone, name)['result']
    except errors.NotFound as nf:
        logger.debug("Skipping IPs for %s: %s", dnsname, nf)
        return  # nothing to do

    for ip in itertools.chain(result.get('arecord', ()),
                              result.get('aaaarecord', ())):
        # add this forward relationship to the 'reachable' dict
        names = reachable.get(ip, set())
        names.add(dnsname.rstrip('.'))
        reachable[ip] = names

    if cname_depth > 0:
        for cname in result.get('cnamerecord', []):
            if not cname.endswith('.'):
                cname = u'%s.%s' % (cname, zone)
            _san_ip_update_reachable(reachable, cname, cname_depth - 1)


def _ip_ptr_records(ip):
    """
    Look up PTR record(s) for IP address.

    :return: a ``set`` of IP addresses, possibly empty.

    """
    rname = dnsutil.DNSName(reversename.from_address(ip))
    try:
        zone = dnsutil.DNSName(dnsutil.zone_for_name(rname))
        name = rname.relativize(zone)
        result = api.Command['dnsrecord_show'](zone, name)['result']
    except resolver.NoNameservers:
        ptrs = set()  # if there's no zone, there are no records
    except errors.NotFound:
        ptrs = set()
    else:
        ptrs = set(result.get('ptrrecord', []))
    return ptrs


@register()
class cert_status(Retrieve, BaseCertMethod, VirtualCommand):
    __doc__ = _('Check the status of a certificate signing request.')

    obj_name = 'certreq'
    attr_name = 'status'

    operation = "certificate status"

    def execute(self, request_id, **kw):
        ca_enabled_check(self.api)
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
class cert_approve(Retrieve, BaseCertMethod, VirtualCommand):
    __doc__ = _('Approve a certificate signing request.')

    operation = "certificate approve"

    def execute(self, request_id, **kw):
        ca_enabled_check(self.api)

        self.check_access()

        return dict(
            result=self.Backend.ra.approve_request(str(request_id)),
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

        for owner, search_key in self._owners():
            yield search_key.clone_rename(
                'owner_{0}'.format(owner.name),
                required=False,
                multivalue=True,
                primary_key=False,
                label=_("Owner %s") % owner.object_name,
                flags={'no_create', 'no_update', 'no_search'},
            )

    def _owners(self):
        for obj_name, search_key in [('user', None),
                                     ('host', None),
                                     ('service', 'krbprincipalname')]:
            obj = self.api.Object[obj_name]
            if search_key is None:
                pkey = obj.primary_key
            else:
                pkey = obj.params[search_key]
            yield obj, pkey

    def _fill_owners(self, obj):
        dns = obj.pop('owner', None)
        if dns is None:
            return

        for owner, _search_key in self._owners():
            container_dn = DN(owner.container_dn, self.api.env.basedn)
            name = 'owner_' + owner.name
            for dn in dns:
                if dn.endswith(container_dn, 1):
                    value = owner.get_primary_key_from_dn(dn)
                    obj.setdefault(name, []).append(value)


class CertMethod(BaseCertMethod):
    def get_options(self):
        yield from super(CertMethod, self).get_options()

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
        _chain_flag,
    )

    operation="retrieve certificate"

    def execute(self, serial_number, all=False, raw=False, no_members=False,
                chain=False, **options):
        ca_enabled_check(self.api)

        # Dogtag lightweight CAs have shared serial number domain, so
        # we don't tell Dogtag the issuer (but we check the cert after).
        #
        result = self.Backend.ra.get_certificate(serial_number)
        cert = x509.load_der_x509_certificate(
                    base64.b64decode(result['certificate']))

        try:
            self.check_access()
        except errors.ACIError as acierr:
            logger.debug("Not granted by ACI to retrieve certificate, "
                         "looking at principal")
            if not bind_principal_can_manage_cert(cert):
                raise acierr

        ca_obj = api.Command.ca_show(
            options['cacn'],
            all=all,
            chain=chain,
        )['result']
        if DN(cert.issuer) != DN(ca_obj['ipacasubjectdn'][0]):
            # DN of cert differs from what we requested
            raise errors.NotFound(
                reason=_("Certificate with serial number %(serial)s "
                    "issued by CA '%(ca)s' not found")
                    % dict(serial=serial_number, ca=options['cacn']))

        der_cert = base64.b64decode(result['certificate'])

        if all or not no_members:
            ldap = self.api.Backend.ldap2
            filter = ldap.make_filter_from_attr('usercertificate', der_cert)
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

        if 'certificate_chain' in ca_obj:
            result['certificate_chain'] = (
                [der_cert] + ca_obj['certificate_chain'])

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

        yield from super(cert_revoke, self).get_options()

    def execute(self, serial_number, **kw):
        ca_enabled_check(self.api)

        # Make sure that the cert specified by issuer+serial exists.
        # Will raise NotFound if it does not.
        resp = api.Command.cert_show(serial_number, cacn=kw['cacn'])

        try:
            self.check_access()
        except errors.ACIError as acierr:
            logger.debug("Not granted by ACI to revoke certificate, "
                         "looking at principal")
            try:
                cert = x509.load_der_x509_certificate(
                    base64.b64decode(resp['result']['certificate']))
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
                serial_number,
                revocation_reason=revocation_reason)
        )



@register()
class cert_remove_hold(PKQuery, CertMethod, VirtualCommand):
    __doc__ = _('Take a revoked certificate off hold.')

    operation = "certificate remove hold"

    def execute(self, serial_number, **kw):
        ca_enabled_check(self.api)

        # Make sure that the cert specified by issuer+serial exists.
        # Will raise NotFound if it does not.
        api.Command.cert_show(serial_number, cacn=kw['cacn'])

        self.check_access()
        return dict(
            # Dogtag lightweight CAs have shared serial number domain, so
            # we don't tell Dogtag the issuer (but we already checked that
            # the given serial was issued by the named ca).
            result=self.Backend.ra.take_certificate_off_hold(
                serial_number
            )
        )


@register()
class cert_find(Search, CertMethod):
    __doc__ = _('Search for existing certificates.')

    takes_options = (
        Str('subject?',
            label=_('Subject'),
            doc=_('Match cn attribute in subject'),
            autofill=False,
        ),
        SerialNumber('min_serial_number?',
            doc=_("minimum serial number"),
            autofill=False,
        ),
        SerialNumber('max_serial_number?',
            doc=_("maximum serial number"),
            autofill=False,
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
        StrEnum(
            'status?',
            doc=_("Status of the certificate"),
            values=(u'VALID', u'INVALID', u'REVOKED', u'EXPIRED',
                    u'REVOKED_EXPIRED'),
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

        for owner, search_key in self.obj._owners():
            yield search_key.clone_rename(
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
            yield search_key.clone_rename(
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
        return (DN(cert.issuer), cert.serial_number)

    def _cert_search(self, pkey_only, **options):
        result = collections.OrderedDict()

        try:
            cert = options['certificate']
        except KeyError:
            return result, False, False

        obj = {'serial_number': cert.serial_number}
        if not pkey_only:
            obj['certificate'] = base64.b64encode(
                cert.public_bytes(x509.Encoding.DER)).decode('ascii')

        result[self._get_cert_key(cert)] = obj

        return result, False, True

    def _ca_search(self, raw, pkey_only, exactly, **options):
        ra_options = {}
        for name in ('revocation_reason',
                     'issuer',
                     'subject',
                     'min_serial_number', 'max_serial_number',
                     'validnotafter_from', 'validnotafter_to',
                     'validnotbefore_from', 'validnotbefore_to',
                     'issuedon_from', 'issuedon_to',
                     'revokedon_from', 'revokedon_to',
                     'status'):
            try:
                value = options[name]
            except KeyError:
                continue
            if isinstance(value, datetime.datetime):
                value = value.strftime(PKIDATE_FORMAT)
            elif isinstance(value, DN):
                value = unicode(value)
            ra_options[name] = value
        if exactly:
            ra_options['exactly'] = True
        if 'sizelimit' in options:
            # sizelimit = 0 means return everything, drop it and let
            # ra_find() handle the value.
            if options['sizelimit'] > 0:
                ra_options['sizelimit'] = options['sizelimit']
        else:
            ra_options['sizelimit'] = self.api.Backend.ldap2.size_limit

        result = collections.OrderedDict()
        complete = bool(ra_options)

        # workaround for RHBZ#1669012 and RHBZ#1695685
        # Improve performance for service, host and user case by also
        # searching for subject. This limits the amount of certificate
        # retrieved from Dogtag. The special case is only used, when
        # no ra_options are set and exactly one service, host, or user is
        # supplied.
        # IPA enforces that subject CN is either a hostname or a username.
        # The complete flag is left to False to catch overrides.
        if not ra_options:
            services = options.get('service', ())
            hosts = options.get('host', ())
            users = options.get('user', ())
            if len(services) == 1 and not hosts and not users:
                principal = kerberos.Principal(services[0])
                if principal.is_service:
                    ra_options['subject'] = principal.hostname
            elif len(hosts) == 1 and not services and not users:
                ra_options['subject'] = hosts[0]
            elif len(users) == 1 and not services and not hosts:
                ra_options['subject'] = users[0]
        if 'status' in options:
            ra_options['status'] = options.get('status')

        try:
            ca_enabled_check(self.api)
        except errors.NotFound:
            if ra_options:
                raise
            return result, False, complete

        ca_objs = self.api.Command.ca_find(
            timelimit=0,
            sizelimit=0,
        )['result']
        ca_objs = {DN(ca['ipacasubjectdn'][0]): ca for ca in ca_objs}

        ra = self.api.Backend.ra
        for ra_obj in ra.find(ra_options):
            issuer = DN(ra_obj['issuer'])
            serial_number = ra_obj['serial_number']

            try:
                ca_obj = ca_objs[issuer]
            except KeyError:
                # A deleted LWCA? Return the issuer DN as a string
                ca_obj = {'cn': [str(issuer)]}

            if pkey_only:
                obj = {'serial_number': serial_number}
            else:
                obj = ra_obj

                if not raw:
                    obj['issuer'] = issuer
                    obj['subject'] = DN(ra_obj['subject'])
                    obj['valid_not_before'] = (
                        convert_pkidatetime(obj['valid_not_before']))
                    obj['valid_not_after'] = (
                        convert_pkidatetime(obj['valid_not_after']))
                    obj['revoked'] = (
                        ra_obj['status'] in (u'REVOKED', u'REVOKED_EXPIRED'))

            obj['cacn'] = ca_obj['cn'][0]

            result[issuer, serial_number] = obj

        return result, False, complete

    def _ldap_search(self, all, pkey_only, no_members, **options):
        ldap = self.api.Backend.ldap2

        filters = []
        for owner, search_key in self.obj._owners():
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
                    search_key.name,
                    value,
                    rule)
                filters.append(filter)

        result = collections.OrderedDict()
        complete = bool(filters)

        cert = options.get('certificate')
        if cert is not None:
            filter = ldap.make_filter_from_attr(
                'usercertificate', cert.public_bytes(x509.Encoding.DER))
        else:
            filter = '(usercertificate=*)'
        filters.append(filter)

        filter = ldap.combine_filters(filters, ldap.MATCH_ALL)
        try:
            entries, truncated = ldap.find_entries(
                base_dn=self.api.env.basedn,
                filter=filter,
                attrs_list=['usercertificate'],
                time_limit=0,
                size_limit=0,
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

        ca_enabled = getattr(context, 'ca_enabled')
        for entry in entries:
            for attr in ('usercertificate', 'usercertificate;binary'):
                for der in entry.raw.get(attr, []):
                    cert = cryptography.x509.load_der_x509_certificate(der)
                    cert_key = self._get_cert_key(cert)
                    try:
                        obj = result[cert_key]
                    except KeyError:
                        obj = {'serial_number': cert.serial_number}
                        if not pkey_only and (all or not ca_enabled):
                            # Retrieving certificate details is now deferred
                            # until after all certificates are collected.
                            # For the case of CA-less we need to keep
                            # the certificate because getting it again later
                            # would require unnecessary LDAP searches.
                            obj['certificate'] = (
                                base64.b64encode(
                                    cert.public_bytes(x509.Encoding.DER))
                                .decode('ascii'))

                        result[cert_key] = obj

                    if not pkey_only and (all or not no_members):
                        owners = obj.setdefault('owner', [])
                        if entry.dn not in owners:
                            owners.append(entry.dn)

        return result, truncated, complete

    def execute(self, criteria=None, all=False, raw=False, pkey_only=False,
                no_members=True, timelimit=None, sizelimit=None, **options):
        ca_enabled = self.api.Command.ca_is_enabled()['result']

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

        # respect the configured search limits
        if timelimit is None:
            timelimit = self.api.Backend.ldap2.time_limit
        if sizelimit is None:
            sizelimit = self.api.Backend.ldap2.size_limit
        options['sizelimit'] = sizelimit

        result = collections.OrderedDict()
        truncated = False
        complete = False

        # Do not execute the CA sub-search in CA-less deployment.
        # See https://pagure.io/freeipa/issue/8369.
        if ca_enabled:
            searches = [self._cert_search, self._ca_search, self._ldap_search]
        else:
            searches = [self._cert_search, self._ldap_search]

        for sub_search in searches:
            sub_result, sub_truncated, sub_complete = sub_search(
                all=all,
                raw=raw,
                pkey_only=pkey_only,
                no_members=no_members,
                **options)

            if sub_complete:
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

        if not pkey_only:
            ca_objs = {}
            if ca_enabled:
                ra = self.api.Backend.ra

            for key, obj in six.iteritems(result):
                if all and 'cacn' in obj:
                    _issuer, serial_number = key
                    cacn = obj['cacn']

                    try:
                        ca_obj = ca_objs[cacn]
                    except KeyError:
                        try:
                            ca_obj = ca_objs[cacn] = (
                                self.api.Command.ca_show(
                                    cacn, all=True)['result'])
                        except errors.NotFound:
                            # If we have inserted a CA DN because the
                            # LWCA was deleted then ca-show of it will
                            # fail as NotFound. There is no chain to
                            # retrieve.
                            ca_obj = []

                    obj.update(
                        ra.get_certificate(serial_number)
                    )
                    if not raw:
                        obj['certificate'] = (
                            obj['certificate'].replace('\r\n', ''))

                    if 'certificate_chain' in ca_obj:
                        cert_der = base64.b64decode(obj['certificate'])
                        obj['certificate_chain'] = (
                            [cert_der] + ca_obj['certificate_chain'])

                if not raw:
                    self.obj._parse(obj, all)
                    if not ca_enabled and not all:
                        # For the case of CA-less don't display the full
                        # certificate unless requested. It is kept in the
                        # entry from _ldap_search() so its attributes can
                        # be retrieved.
                        obj.pop('certificate', None)
                    self.obj._fill_owners(obj)

        result = list(six.itervalues(result))
        if (len(result) > sizelimit > 0):
            if not truncated:
                self.add_message(messages.SearchResultTruncated(
                        reason=errors.SizeLimitExceeded()))
            result = result[:sizelimit]
            truncated = True

        ret = dict(
            result=result
        )
        ret['count'] = len(ret['result'])
        ret['truncated'] = bool(truncated)
        return ret


@register()
class ca_is_enabled(Command):
    __doc__ = _('Checks if any of the servers has the CA service enabled.')
    NO_CLI = True
    has_output = output.standard_value

    def execute(self, *args, **options):
        # Store ca_enabled status in the context to save making the API
        # call multiple times.
        ca_enabled = getattr(context, 'ca_enabled', None)
        if ca_enabled is not None and api.env.context in ('lite', 'server',):
            result = ca_enabled
        else:
            result = is_service_enabled('CA', conn=self.api.Backend.ldap2)
            setattr(context, 'ca_enabled', result)
        return dict(result=result, value=pkey_to_value(None, options))
