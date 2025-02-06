# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#          Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2007-2013  Red Hat
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

import os
import os.path
import tempfile

from ipalib import x509
from ipalib.install import certmonger
from ipaplatform.paths import paths
from ipapython import admintool, dogtag, config
from ipapython.certdb import NSSDatabase, get_ca_nickname
from ipapython.dn import DN
from ipapython import ipaldap
from ipalib import api, errors
from ipaserver.install import certs, dsinstance, installutils, krbinstance
from ipaserver.install import cainstance, httpinstance


class ServerCertInstall(admintool.AdminTool):
    command_name = 'ipa-server-certinstall'

    usage = "%prog <-d|-w|-k> [options] <file> ..."

    description = "Install new SSL server certificates."

    @classmethod
    def add_options(cls, parser):
        super(ServerCertInstall, cls).add_options(parser)

        parser.add_option(
            "-d", "--dirsrv",
            dest="dirsrv", action="store_true", default=False,
            help="install certificate for the directory server")
        parser.add_option(
            "-w", "--http",
            dest="http", action="store_true", default=False,
            help="install certificate for the http server")
        parser.add_option(
            "-k", "--kdc",
            dest="kdc", action="store_true", default=False,
            help="install PKINIT certificate for the KDC")
        parser.add_option(
            "--pin",
            dest="pin", metavar="PIN", sensitive=True,
            help="The password of the PKCS#12 file")
        parser.add_option(
            "--dirsrv_pin", "--http_pin",
            dest="pin", sensitive=True,
            help=config.SUPPRESS_HELP)
        parser.add_option(
            "--cert-name",
            dest="cert_name", metavar="NAME",
            help="Name of the certificate to install")
        parser.add_option(
            "-p", "--dirman-password",
            dest="dirman_password", sensitive=True,
            help="Directory Manager password")

    def validate_options(self):
        super(ServerCertInstall, self).validate_options(needs_root=True)

        installutils.check_server_configuration()

        if not any((self.options.dirsrv, self.options.http, self.options.kdc)):
            self.option_parser.error(
                "you must specify dirsrv, http and/or kdc")

        if not self.args:
            self.option_parser.error("you must provide certificate filename")

    def ask_for_options(self):
        super(ServerCertInstall, self).ask_for_options()

        if not self.options.dirman_password:
            self.options.dirman_password = installutils.read_password(
                "Directory Manager", confirm=False, validate=False, retry=False)
            if self.options.dirman_password is None:
                raise admintool.ScriptError(
                    "Directory Manager password required")

        if self.options.pin is None:
            self.options.pin = installutils.read_password(
                "Enter private key unlock",
                confirm=False, validate=False, retry=False)
            if self.options.pin is None:
                raise admintool.ScriptError(
                    "Private key unlock password required")

    def validate_http_cert(self):
        if dogtag.acme_status():
            cert, unused, _unused = self.load_pkcs12(
                ca_chain_fname=paths.IPA_CA_CRT,
                host_name=api.env.host
            )
            cainstance.check_ipa_ca_san(cert)

    def run(self):
        api.bootstrap(in_server=True, confdir=paths.ETC_IPA)
        api.finalize()
        api.Backend.ldap2.connect(bind_pw=self.options.dirman_password)

        if self.options.http:
            self.validate_http_cert()

        if self.options.dirsrv:
            self.install_dirsrv_cert()

        if self.options.http:
            self.replace_http_cert()

        if self.options.kdc:
            self.replace_kdc_cert()

        print(
            "Please restart ipa services after installing certificate "
            "(ipactl restart)")

        api.Backend.ldap2.disconnect()

    def install_dirsrv_cert(self):
        from ipaserver.plugins.service import revoke_certs

        serverid = ipaldap.realm_to_serverid(api.env.realm)
        dirname = dsinstance.config_dirname(serverid)

        conn = api.Backend.ldap2
        entry = conn.get_entry(DN(('cn', 'RSA'), ('cn', 'encryption'),
                                  ('cn', 'config')),
                               ['nssslpersonalityssl'])
        old_cert = entry.single_value['nssslpersonalityssl']

        nickname, cert = self.import_cert(dirname, self.options.pin,
                                          old_cert, 'ldap/%s' % api.env.host,
                                          'restart_dirsrv %s' % serverid)

        entry['nssslpersonalityssl'] = [nickname]
        try:
            conn.update_entry(entry)
        except errors.EmptyModlist:
            pass

        ds = dsinstance.DsInstance()
        ds.suffix = api.env.basedn
        ds.realm = api.env.realm
        ds.fqdn = api.env.host
        ds.service_prefix = 'ldap'
        ds.cert = cert
        name = f'{ds.service_prefix}/{ds.fqdn}'
        oldcerts = api.Command.cert_find(service=name)['result']
        ds.add_cert_to_service(append=False)

        revoke_certs(oldcerts)

    def replace_http_cert(self):
        """
        Replace the current HTTP cert-key pair with another one
        from a PKCS#12 file
        """
        from ipaserver.plugins.service import revoke_certs

        # pass in `host_name` to perform
        # `NSSDatabase.verify_server_cert_validity()``
        cert, key, ca_cert = self.load_pkcs12(
            ca_chain_fname=paths.IPA_CA_CRT,
            host_name=api.env.host
        )

        key_passwd_path = paths.HTTPD_PASSWD_FILE_FMT.format(host=api.env.host)

        req_id = self.replace_key_cert_files(
            cert, key,
            cert_fname=paths.HTTPD_CERT_FILE,
            key_fname=paths.HTTPD_KEY_FILE,
            ca_cert=ca_cert,
            passwd_fname=key_passwd_path,
            cmgr_post_command='restart_httpd')

        if req_id is not None:
            certmonger.add_principal(
                req_id, 'HTTP/{host}'.format(host=api.env.host))
            certmonger.add_subject(req_id, str(DN(cert.subject)))

        http = httpinstance.HTTPInstance()
        http.suffix = api.env.basedn
        http.realm = api.env.realm
        http.fqdn = api.env.host
        http.service_prefix = 'HTTP'
        http.cert = cert
        name = f'{http.service_prefix}/{http.fqdn}'
        oldcerts = api.Command.cert_find(service=name)['result']
        http.add_cert_to_service(append=False)

        revoke_certs(oldcerts)

    def replace_kdc_cert(self):
        # pass in `realm` to perform `NSSDatabase.verify_kdc_cert_validity()`
        cert, key, ca_cert = self.load_pkcs12(
            ca_chain_fname=paths.CA_BUNDLE_PEM, realm_name=api.env.realm)

        self.replace_key_cert_files(
            cert, key, paths.KDC_CERT, paths.KDC_KEY, ca_cert,
            profile="KDCs_PKINIT_Certs"
        )

        krb = krbinstance.KrbInstance()
        krb.init_info(
            realm_name=api.env.realm,
            host_name=api.env.host,
        )
        krb.pkinit_enable()

    def load_pkcs12(self, ca_chain_fname=paths.IPA_CA_CRT, **kwargs):
        # Note that the "installutils.load_pkcs12" is quite a complex function
        # which performs some checking based on its kwargs:
        #       host_name performs NSSDatabase.verify_server_cert_validity()
        #       realm performs NSSDatabase.verify_kdc_cert_validity()
        pkcs12_file, pin, ca_cert = installutils.load_pkcs12(
            cert_files=self.args,
            key_password=self.options.pin,
            key_nickname=self.options.cert_name,
            ca_cert_files=[ca_chain_fname],
            **kwargs)

        # Check that the ca_cert is known and trusted
        with tempfile.NamedTemporaryFile() as temp:
            certs.install_pem_from_p12(pkcs12_file.name, pin, temp.name)
            cert = x509.load_certificate_from_file(temp.name)

        with tempfile.NamedTemporaryFile("rb") as temp:
            certs.install_key_from_p12(pkcs12_file.name, pin, temp.name)
            key = x509.load_pem_private_key(
                temp.read(), None, backend=x509.default_backend())

        return cert, key, ca_cert

    def replace_key_cert_files(
        self, cert, key, cert_fname, key_fname, ca_cert, passwd_fname=None,
        profile=None, cmgr_post_command=None
    ):
        try:
            ca_enabled = api.Command.ca_is_enabled()['result']
            if ca_enabled:
                certmonger.stop_tracking(certfile=cert_fname)

            pkey_passwd = None
            if passwd_fname is not None:
                with open(passwd_fname, 'rb') as f:
                    pkey_passwd = f.read()

            x509.write_certificate(cert, cert_fname)
            x509.write_pem_private_key(key, key_fname, pkey_passwd)

            if ca_enabled:
                # Start tracking only if the cert was issued by IPA CA
                # Retrieve IPA CA
                cdb = certs.CertDB(api.env.realm, nssdir=paths.IPA_NSSDB_DIR)
                ipa_ca_cert = cdb.get_cert_from_db(
                    get_ca_nickname(api.env.realm))
                # And compare with the CA which signed this certificate
                if ca_cert == ipa_ca_cert:
                    req_id = certmonger.start_tracking(
                        (cert_fname, key_fname),
                        pinfile=passwd_fname,
                        storage='FILE',
                        post_command=cmgr_post_command
                    )
                    return req_id
        except RuntimeError as e:
            raise admintool.ScriptError(str(e))
        return None

    def check_chain(self, pkcs12_filename, pkcs12_pin, nssdb):
        # create a temp nssdb
        with NSSDatabase() as tempnssdb:
            tempnssdb.create_db()

            # import the PKCS12 file, then delete all CA certificates
            # this leaves only the server certs in the temp db
            tempnssdb.import_pkcs12(pkcs12_filename, pkcs12_pin)
            for nickname, flags in tempnssdb.list_certs():
                if not flags.has_key:
                    while tempnssdb.has_nickname(nickname):
                        tempnssdb.delete_cert(nickname)

            # import all the CA certs from nssdb into the temp db
            for nickname, flags in nssdb.list_certs():
                if not flags.has_key:
                    cert = nssdb.get_cert_from_db(nickname)
                    tempnssdb.add_cert(cert, nickname, flags)

            # now get the server certs from tempnssdb and check their validity
            try:
                for nick, flags in tempnssdb.find_server_certs():
                    tempnssdb.verify_server_cert_validity(nick, api.env.host)
            except ValueError as e:
                raise admintool.ScriptError(
                    "Peer's certificate issuer is not trusted (%s). "
                    "Please run ipa-cacert-manage install and ipa-certupdate "
                    "to install the CA certificate." % str(e))

    def import_cert(self, dirname, pkcs12_passwd, old_cert, principal, command):
        pkcs12_file, pin, ca_cert = installutils.load_pkcs12(
            cert_files=self.args,
            key_password=pkcs12_passwd,
            key_nickname=self.options.cert_name,
            ca_cert_files=[paths.IPA_CA_CRT],
            host_name=api.env.host)

        dirname = os.path.normpath(dirname)
        cdb = certs.CertDB(api.env.realm, nssdir=dirname)

        # Check that the ca_cert is known and trusted
        self.check_chain(pkcs12_file.name, pin, cdb)

        try:
            ca_enabled = api.Command.ca_is_enabled()['result']
            if ca_enabled:
                cdb.untrack_server_cert(old_cert)

            cdb.delete_cert(old_cert)
            prevs = cdb.find_server_certs()
            cdb.import_pkcs12(pkcs12_file.name, pin)
            news = cdb.find_server_certs()
            server_certs = [item for item in news if item not in prevs]
            nickname = server_certs[0][0]
            cert = cdb.get_cert_from_db(nickname)

            if ca_enabled:
                # Start tracking only if the cert was issued by IPA CA
                # Retrieve IPA CA
                ipa_ca_cert = cdb.get_cert_from_db(
                    get_ca_nickname(api.env.realm))
                # And compare with the CA which signed this certificate
                if ca_cert == ipa_ca_cert:
                    cdb.track_server_cert(nickname,
                                          principal,
                                          cdb.passwd_fname,
                                          command)
        except RuntimeError as e:
            raise admintool.ScriptError(str(e))

        return nickname, cert
