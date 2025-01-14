# Authors: Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2014  Red Hat
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
#

from __future__ import print_function, absolute_import

import datetime
import logging
import os
import gssapi

from ipalib.constants import (
    RENEWAL_CA_NAME, RENEWAL_REUSE_CA_NAME, RENEWAL_SELFSIGNED_CA_NAME,
    IPA_CA_CN)
from ipalib.install import certmonger, certstore
from ipapython import admintool, ipautil, config
from ipapython.certdb import (EMPTY_TRUST_FLAGS,
                              EXTERNAL_CA_TRUST_FLAGS,
                              TrustFlags,
                              parse_trust_flags,
                              get_ca_nickname)
from ipapython.dn import DN
from ipaplatform.paths import paths
from ipalib import api, errors, x509
from ipaserver.install import certs, cainstance, installutils

logger = logging.getLogger(__name__)


class CACertManage(admintool.AdminTool):
    command_name = 'ipa-cacert-manage'

    usage = "%prog renew [options]\n%prog install [options] CERTFILE\n" \
            "%prog delete [options] NICKNAME\n%prog list\n%prog prune"

    description = "Manage CA certificates."

    cert_nickname = 'caSigningCert cert-pki-ca'

    @classmethod
    def add_options(cls, parser):
        super(CACertManage, cls).add_options(parser)

        parser.add_option(
            "-p", "--password", dest='password',
            help="Directory Manager password")

        renew_group = config.OptionGroup(parser, "Renew options")
        renew_group.add_option(
            "--self-signed", dest='self_signed',
            action='store_true',
            help="Sign the renewed certificate by itself")
        renew_group.add_option(
            "--external-ca", dest='self_signed',
            action='store_false',
            help="Sign the renewed certificate by external CA")
        ext_cas = tuple(x.value for x in x509.ExternalCAType)
        renew_group.add_option(
            "--external-ca-type", dest="external_ca_type",
            type="choice", choices=ext_cas,
            metavar="{{{0}}}".format(",".join(ext_cas)),
            help="Type of the external CA. Default: generic")
        renew_group.add_option(
            "--external-ca-profile", dest="external_ca_profile",
            type='constructor', constructor=x509.ExternalCAProfile,
            default=None, metavar="PROFILE-SPEC",
            help="Specify the certificate profile/template to use "
                 "at the external CA")
        renew_group.add_option(
            "--external-cert-file", dest="external_cert_files",
            action="append", metavar="FILE",
            help="File containing the IPA CA certificate and the external CA "
                 "certificate chain")
        parser.add_option_group(renew_group)

        install_group = config.OptionGroup(parser, "Install options")
        install_group.add_option(
            "-n", "--nickname", dest='nickname',
            help="Nickname for the certificate")
        install_group.add_option(
            "-t", "--trust-flags", dest='trust_flags', default='C,,',
            help="Trust flags for the certificate in certutil format")
        parser.add_option_group(install_group)

        delete_group = config.OptionGroup(parser, "Delete options")
        delete_group.add_option(
            "-f", "--force", action='store_true',
            help="Force removing the CA even if chain validation fails")
        delete_group.add_option(
            "-s", "--serial",
            help="Serial number of the certificate to delete (decimal)")
        parser.add_option_group(delete_group)

    def validate_options(self):
        super(CACertManage, self).validate_options(needs_root=True)

        installutils.check_server_configuration()

        parser = self.option_parser

        if not self.args:
            parser.error("command not provided")

        command = self.command = self.args[0]

        if command not in ('renew', 'list', 'install', 'delete', 'prune'):
            parser.error("unknown command \"%s\"" % command)
        elif command == 'install':
            if len(self.args) < 2:
                parser.error("certificate file name not provided")
        elif command == 'delete':
            if len(self.args) < 2:
                parser.error("nickname not provided")

    def run(self):
        command = self.command

        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()

        self.ldap_connect()

        try:
            if command == 'renew':
                return self.renew()
            elif command == 'install':
                return self.install()
            elif command == 'list':
                return self.list()
            elif command == 'delete':
                return self.delete()
            elif command == 'prune':
                return self.prune()
            else:
                raise NotImplementedError
        finally:
            api.Backend.ldap2.disconnect()

    def ldap_connect(self):
        password = self.options.password
        if not password:
            try:
                api.Backend.ldap2.connect(ccache=os.environ.get('KRB5CCNAME'))
            except (gssapi.exceptions.GSSError, errors.ACIError):
                pass
            else:
                return

            password = installutils.read_password(
                "Directory Manager", confirm=False, validate=False)
            if password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")

        api.Backend.ldap2.connect(bind_pw=password)

    def _get_ca_request_id(self, ca_name):
        """Lookup tracking request for IPA CA, using given ca-name."""
        criteria = {
            'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
            'cert-nickname': self.cert_nickname,
            'ca-name': ca_name,
        }
        return certmonger.get_request_id(criteria)

    def renew(self):
        ca = cainstance.CAInstance(api.env.realm)
        if not ca.is_configured():
            raise admintool.ScriptError("CA is not configured on this system")

        self.request_id = self._get_ca_request_id(RENEWAL_CA_NAME)
        if self.request_id is None:
            # if external CA renewal was interrupted, the request may have
            # been left with the "dogtag-ipa-ca-renew-agent-reuse" CA;
            # look for it too
            self.request_id = self._get_ca_request_id(RENEWAL_REUSE_CA_NAME)
            if self.request_id is None:
                raise admintool.ScriptError(
                    "CA certificate is not tracked by certmonger")
        logger.debug(
            "Found certmonger request id %r", self.request_id)

        db = certs.CertDB(api.env.realm, nssdir=paths.PKI_TOMCAT_ALIAS_DIR)
        cert = db.get_cert_from_db(self.cert_nickname)

        options = self.options
        if options.external_cert_files:
            return self.renew_external_step_2(ca, cert)

        if options.self_signed is not None:
            self_signed = options.self_signed
        else:
            self_signed = cert.is_self_signed()

        if self_signed:
            return self.renew_self_signed(ca)
        else:
            return self.renew_external_step_1(ca)

    def renew_self_signed(self, ca):
        print("Renewing CA certificate, please wait")

        msg = "You cannot specify {} when renewing a self-signed CA"
        if self.options.external_ca_type:
            raise admintool.ScriptError(msg.format("--external-ca-type"))
        if self.options.external_ca_profile:
            raise admintool.ScriptError(msg.format("--external-ca-profile"))

        try:
            ca.set_renewal_master()
        except errors.NotFound:
            raise admintool.ScriptError("CA renewal master not found")

        self.resubmit_request(RENEWAL_SELFSIGNED_CA_NAME)

        db = certs.CertDB(api.env.realm, nssdir=paths.PKI_TOMCAT_ALIAS_DIR)
        cert = db.get_cert_from_db(self.cert_nickname)
        update_ipa_ca_entry(api, cert)

        print("CA certificate successfully renewed")

    def renew_external_step_1(self, ca):
        print("Exporting CA certificate signing request, please wait")

        options = self.options

        if not options.external_ca_type:
            options.external_ca_type = x509.ExternalCAType.GENERIC.value

        if options.external_ca_type == x509.ExternalCAType.MS_CS.value \
                and options.external_ca_profile is None:
            options.external_ca_profile = x509.MSCSTemplateV1(u"SubCA")

        if options.external_ca_profile is not None:
            # check that profile is valid for the external ca type
            if options.external_ca_type \
                    not in options.external_ca_profile.valid_for:
                raise admintool.ScriptError(
                    "External CA profile specification '{}' "
                    "cannot be used with external CA type '{}'."
                    .format(
                        options.external_ca_profile.unparsed_input,
                        options.external_ca_type)
                    )

        self.resubmit_request(
            RENEWAL_REUSE_CA_NAME,
            profile=options.external_ca_profile)

        print(("The next step is to get %s signed by your CA and re-run "
              "ipa-cacert-manage as:" % paths.IPA_CA_CSR))
        print("ipa-cacert-manage renew "
              "--external-cert-file=/path/to/signed_certificate "
              "--external-cert-file=/path/to/external_ca_certificate")

    def renew_external_step_2(self, ca, old_cert):
        print("Importing the renewed CA certificate, please wait")

        options = self.options
        conn = api.Backend.ldap2

        old_spki = old_cert.public_key_info_bytes

        cert_file, ca_file = installutils.load_external_cert(
            options.external_cert_files, DN(old_cert.subject))

        with open(cert_file.name, 'rb') as f:
            new_cert_data = f.read()
        new_cert = x509.load_pem_x509_certificate(new_cert_data)
        new_spki = new_cert.public_key_info_bytes

        if new_cert.subject != old_cert.subject:
            raise admintool.ScriptError(
                "Subject name mismatch (visit "
                "http://www.freeipa.org/page/Troubleshooting for "
                "troubleshooting guide)")
        if new_cert.subject_bytes != old_cert.subject_bytes:
            raise admintool.ScriptError(
                "Subject name encoding mismatch (visit "
                "http://www.freeipa.org/page/Troubleshooting for "
                "troubleshooting guide)")
        if new_spki != old_spki:
            raise admintool.ScriptError(
                "Subject public key info mismatch (visit "
                "http://www.freeipa.org/page/Troubleshooting for "
                "troubleshooting guide)")

        with certs.NSSDatabase() as tmpdb:
            tmpdb.create_db()
            tmpdb.add_cert(old_cert, 'IPA CA', EXTERNAL_CA_TRUST_FLAGS)

            try:
                tmpdb.add_cert(new_cert, 'IPA CA', EXTERNAL_CA_TRUST_FLAGS)
            except ipautil.CalledProcessError as e:
                raise admintool.ScriptError(
                    "Not compatible with the current CA certificate: %s" % e)

            ca_certs = x509.load_certificate_list_from_file(ca_file.name)
            for ca_cert in ca_certs:
                tmpdb.add_cert(
                    ca_cert, str(DN(ca_cert.subject)), EXTERNAL_CA_TRUST_FLAGS)

            try:
                tmpdb.verify_ca_cert_validity('IPA CA')
            except ValueError as e:
                raise admintool.ScriptError(
                    "Not a valid CA certificate: %s (visit "
                    "http://www.freeipa.org/page/Troubleshooting for "
                    "troubleshooting guide)" % e)

            trust_chain = tmpdb.get_trust_chain('IPA CA')[:-1]
            for nickname in trust_chain:
                try:
                    ca_cert = tmpdb.get_cert(nickname)
                except RuntimeError:
                    break
                certstore.put_ca_cert_nss(
                    conn,
                    api.env.basedn,
                    ca_cert,
                    nickname,
                    EMPTY_TRUST_FLAGS)

        dn = DN(('cn', self.cert_nickname), ('cn', 'ca_renewal'),
                ('cn', 'ipa'), ('cn', 'etc'), api.env.basedn)

        try:
            entry = conn.get_entry(dn, ['usercertificate'])
            entry['usercertificate'] = [new_cert]
            conn.update_entry(entry)
        except errors.NotFound:
            entry = conn.make_entry(
                dn,
                objectclass=['top', 'pkiuser', 'nscontainer'],
                cn=[self.cert_nickname],
                usercertificate=[new_cert])
            conn.add_entry(entry)
        except errors.EmptyModlist:
            pass

        update_ipa_ca_entry(api, new_cert)

        try:
            ca.set_renewal_master()
        except errors.NotFound:
            raise admintool.ScriptError("CA renewal master not found")

        self.resubmit_request(RENEWAL_REUSE_CA_NAME)

        print("CA certificate successfully renewed")

    def resubmit_request(self, ca=RENEWAL_CA_NAME, profile=None):
        timeout = api.env.startup_timeout + 60

        cm_profile = None
        if isinstance(profile, x509.MSCSTemplateV1):
            cm_profile = profile.unparsed_input

        cm_template = None
        if isinstance(profile, x509.MSCSTemplateV2):
            cm_template = profile.unparsed_input

        logger.debug("resubmitting certmonger request '%s'", self.request_id)
        certmonger.resubmit_request(self.request_id, ca=ca, profile=cm_profile,
                                    template_v2=cm_template, is_ca=True)
        try:
            state = certmonger.wait_for_request(self.request_id, timeout)
        except RuntimeError:
            raise admintool.ScriptError(
                "Resubmitting certmonger request '%s' timed out, "
                "please check the request manually" % self.request_id)
        ca_error = certmonger.get_request_value(self.request_id, 'ca-error')
        if state != 'MONITORING' or ca_error:
            raise admintool.ScriptError(
                "Error resubmitting certmonger request '%s', "
                "please check the request manually" % self.request_id)

        logger.debug("modifying certmonger request '%s'", self.request_id)
        certmonger.modify(self.request_id,
                          ca=RENEWAL_CA_NAME,
                          profile='', template_v2='')

    def install(self):
        print("Installing CA certificate, please wait")

        options = self.options

        ca_certs = certstore.get_ca_certs_nss(api.Backend.ldap2,
                                              api.env.basedn,
                                              api.env.realm,
                                              False)

        with certs.NSSDatabase() as tmpdb:
            tmpdb.create_db()
            tmpdb.import_files(self.args[1:])
            imported = tmpdb.list_certs()
            logger.debug("loaded raw certs '%s'", imported)

            if len(imported) > 1 and options.nickname:
                raise admintool.ScriptError(
                    "Nickname can only be used if only a single "
                    "certificate is loaded")

            # If a nickname was provided re-import the cert
            if options.nickname:
                (nickname, trust_flags) = imported[0]
                cert = tmpdb.get_cert(nickname)
                tmpdb.delete_cert(nickname)
                tmpdb.add_cert(cert, options.nickname, EXTERNAL_CA_TRUST_FLAGS)
                imported = tmpdb.list_certs()

            for ca_cert, ca_nickname, ca_trust_flags, _serial in ca_certs:
                tmpdb.add_cert(ca_cert, ca_nickname, ca_trust_flags)

            for nickname, trust_flags in imported:
                if trust_flags.has_key:
                    continue
                tmpdb.trust_root_cert(nickname, EXTERNAL_CA_TRUST_FLAGS)

            for nickname, trust_flags in imported:
                try:
                    tmpdb.verify_ca_cert_validity(nickname)
                except ValueError as e:
                    raise admintool.ScriptError(
                        "Not a valid CA certificate: %s (visit "
                        "http://www.freeipa.org/page/Troubleshooting for "
                        "troubleshooting guide)" % e)
                else:
                    print("Verified %s" % nickname)

            trust_flags = options.trust_flags.split(',')
            if (set(options.trust_flags) - set(',CPTcgpuw') or
                    len(trust_flags) not in [3, 4]):
                raise admintool.ScriptError("Invalid trust flags")

            extra_flags = trust_flags[3:]
            extra_usages = set()
            if extra_flags:
                if 'C' in extra_flags[0]:
                    extra_usages.add(x509.EKU_PKINIT_KDC)
                if 'T' in extra_flags[0]:
                    extra_usages.add(x509.EKU_PKINIT_CLIENT_AUTH)

            trust_flags = parse_trust_flags(','.join(trust_flags[:3]))
            trust_flags = TrustFlags(trust_flags.has_key,
                                     trust_flags.trusted,
                                     trust_flags.ca,
                                     trust_flags.usages | extra_usages)

            for nickname, _trust_flags in imported:
                try:
                    cert = tmpdb.get_cert(nickname)
                    certstore.put_ca_cert_nss(
                        api.Backend.ldap2, api.env.basedn, cert, nickname,
                        trust_flags)
                except ValueError as e:
                    raise admintool.ScriptError(
                        "Failed to install the certificate: %s" % e)

        print("CA certificate successfully installed")

    def list(self):
        ca_certs = certstore.get_ca_certs_nss(api.Backend.ldap2,
                                              api.env.basedn,
                                              api.env.realm,
                                              False)
        for _ca_cert, ca_nickname, _ca_trust_flags, serial in ca_certs:
            print(f"{ca_nickname}  {serial}")

    def _delete_by_nickname(self, nicknames, options):
        conn = api.Backend.ldap2

        ca_certs = certstore.get_ca_certs_nss(api.Backend.ldap2,
                                              api.env.basedn,
                                              api.env.realm,
                                              False)

        ipa_ca_nickname = get_ca_nickname(api.env.realm)

        # Count the number of times the nickname appears in case we
        # have a duplicate. If a serial number is provided we can skip
        # this.
        cert_count = 0
        if not options.serial:
            for nickname in nicknames:
                for _ca_cert, ca_nickname, _ca_trust_flags, _serial in ca_certs:
                    if ca_nickname == nickname:
                        cert_count += 1
            if cert_count > 1:
                raise admintool.ScriptError(
                    'Multiple matching certificates found (%d). Use the '
                    '--serial option to specify which one to remove.' %
                    cert_count
                )

        for nickname in nicknames:
            found = False
            for _ca_cert, ca_nickname, _ca_trust_flags, _serial in ca_certs:
                if ca_nickname == nickname:
                    if ca_nickname == ipa_ca_nickname:
                        raise admintool.ScriptError(
                            'The IPA CA cannot be removed with this tool'
                        )
                    else:
                        found = True
                        break

            if not found:
                raise admintool.ScriptError(
                    'Unknown CA \'{}\''.format(nickname)
                )

        with certs.NSSDatabase() as tmpdb:
            tmpdb.create_db()
            for ca_cert, ca_nickname, ca_trust_flags, serial in ca_certs:
                if nickname == ca_nickname:
                    if options.serial and options.serial == serial:
                        continue
                tmpdb.add_cert(ca_cert, ca_nickname, ca_trust_flags)
            loaded = tmpdb.list_certs()
            logger.debug("loaded raw certs '%s'", loaded)

            if not options.serial:
                for nickname in nicknames:
                    tmpdb.delete_cert(nickname)

            for ca_nickname, _trust_flags in loaded:
                if ca_nickname in nicknames:
                    continue
                if ipa_ca_nickname in nicknames:
                    raise admintool.ScriptError(
                        "The IPA CA cannot be removed")
                logger.debug("Verifying %s", ca_nickname)
                try:
                    tmpdb.verify_ca_cert_validity(ca_nickname)
                except ValueError as e:
                    msg = "Verifying removal of \'%s\' failed. Removing " \
                          "part of the chain? %s" % (nickname, e)
                    if options.force:
                        print(msg)
                        continue
                    raise admintool.ScriptError(msg)
                else:
                    logger.debug("Verified %s", ca_nickname)

        for ca_cert, ca_nickname, _ca_trust_flags, serial in ca_certs:
            if ca_nickname in nicknames:
                if options.serial and options.serial != serial:
                    continue
                logger.debug("Deleting %s", ca_nickname)
                certstore.delete_ca_cert(conn, api.env.basedn, ca_cert)

                return

    def delete(self):
        nickname = self.args[1]
        self._delete_by_nickname([nickname], self.options)

    def prune(self):
        expired_certs = []
        ca_certs = certstore.get_ca_certs_nss(api.Backend.ldap2,
                                              api.env.basedn,
                                              api.env.realm,
                                              False)

        now = datetime.datetime.now(tz=datetime.timezone.utc)
        for ca_cert, ca_nickname, _ca_trust_flags, _serial in ca_certs:
            if ca_cert.not_valid_after_utc < now:
                expired_certs.append(ca_nickname)

        del_options = self.options
        del_options.force = True
        if expired_certs:
            print("Expired certificates deleted:")
            for ca_cert in expired_certs:
                self._delete_by_nickname([ca_cert], del_options)
                print(ca_cert)
            print("Run ipa-certupdate on enrolled machines to apply changes.")
        else:
            print("No certificates were deleted")


def update_ipa_ca_entry(api, cert):
    """
    The Issuer DN of the IPA CA may have changed.  Update the IPA CA entry.

    :param api: finalised API object, with *connected* LDAP backend
    :param cert: a python-cryptography Certificate object

    """
    try:
        entry = api.Backend.ldap2.get_entry(
            DN(('cn', IPA_CA_CN), api.env.container_ca, api.env.basedn),
            ['ipacaissuerdn'])
        entry['ipacaissuerdn'] = [DN(cert.issuer)]
        api.Backend.ldap2.update_entry(entry)
    except errors.EmptyModlist:
        pass
