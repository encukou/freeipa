# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2007  Red Hat
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

from __future__ import absolute_import

import configparser
import logging
import os
import stat
import sys
import tempfile
import shutil
import xml.dom.minidom
import grp
import pwd
import base64
import fcntl
import time
import datetime

from ipalib.install import certmonger, sysrestore
from ipapython import dogtag
from ipapython import ipautil
from ipapython.certdb import EMPTY_TRUST_FLAGS, IPA_CA_TRUST_FLAGS
from ipapython.certdb import get_ca_nickname, find_cert_from_txt, NSSDatabase
from ipapython.dn import DN
from ipalib import x509, api
from ipalib.errors import CertificateOperationError
from ipalib.install import certstore
from ipalib.util import strip_csr_header
from ipalib.text import _
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks


logger = logging.getLogger(__name__)


def get_cert_nickname(cert):
    """
    Using the subject from cert come up with a nickname suitable
    for NSS. The caller can decide whether to use just the RDN
    or the whole subject.

    Returns a tuple of (rdn, subject_dn) when rdn is the string
    representation of the first RDN in the subject and subject_dn
    is a DN object.
    """
    dn = DN(cert.subject)
    return (str(dn[0]), dn)


def install_pem_from_p12(p12_fname, p12_passwd, pem_fname):
    pwd = ipautil.write_tmp_file(p12_passwd)
    args = [paths.OPENSSL, "pkcs12", "-nokeys", "-clcerts",
            "-in", p12_fname, "-out", pem_fname,
            "-passin", "file:" + pwd.name]
    # the PKCS12 MAC requires PKCS12KDF which is not an approved FIPS
    # algorithm and cannot be supported by the FIPS provider.
    # Do not require mac verification in FIPS mode
    fips_enabled = tasks.is_fips_enabled()
    if fips_enabled:
        args.append('-nomacver')
    ipautil.run(args)


def install_key_from_p12(
        p12_fname, p12_passwd, pem_fname, out_passwd_fname=None):
    pwd = ipautil.write_tmp_file(p12_passwd)
    args = [
        paths.OPENSSL, "pkcs12", "-nocerts",
        "-in", p12_fname, "-out", pem_fname,
        "-passin", "file:" + pwd.name]
    if out_passwd_fname is not None:
        args.extend(['-passout', 'file:{}'.format(out_passwd_fname)])
    else:
        args.append('-nodes')
    # the PKCS12 MAC requires PKCS12KDF which is not an approved FIPS
    # algorithm and cannot be supported by the FIPS provider.
    # Do not require mac verification in FIPS mode
    fips_enabled = tasks.is_fips_enabled()
    if fips_enabled:
        args.append('-nomacver')

    ipautil.run(args, umask=0o077)


def pkcs12_to_certkeys(p12_fname, p12_passwd=None):
    """
    Deserializes pkcs12 file to python objects

    :param p12_fname: A PKCS#12 filename
    :param p12_passwd: Optional password for the pkcs12_fname file
    """
    args = [paths.OPENSSL, "pkcs12", "-in", p12_fname, "-nodes"]
    if p12_passwd:
        pwd = ipautil.write_tmp_file(p12_passwd)
        args.extend(["-passin", "file:{fname}".format(fname=pwd.name)])
    else:
        args.extend(["-passin", "pass:"])

    pems = ipautil.run(args).raw_output

    certs = x509.load_certificate_list(pems)
    priv_keys = x509.load_private_key_list(pems)

    return (certs, priv_keys)


def is_ipa_issued_cert(api, cert):
    """
    Return True if the certificate has been issued by IPA

    Note that this method can only be executed if the api has been
    initialized.

    :param api: The pre-initialized IPA API
    :param cert: The IPACertificate certificiate to test
    """
    cacert_subject = certstore.get_ca_subject(
        api.Backend.ldap2,
        api.env.container_ca,
        api.env.basedn)

    return DN(cert.issuer) == cacert_subject


class CertDB:
    """An IPA-server-specific wrapper around NSS

    This class knows IPA-specific details such as nssdir location, or the
    CA cert name.

    ``subject_base``
      Realm subject base DN.  This argument is required when creating
      server or object signing certs.
    ``ca_subject``
      IPA CA subject DN.  This argument is required when importing
      CA certificates into the certificate database.

    """
    # TODO: Remove all selfsign code
    def __init__(self, realm, nssdir, fstore=None,
                 host_name=None, subject_base=None, ca_subject=None,
                 user=None, group=None, mode=None, create=False,
                 dbtype='auto', pwd_file=None):
        self.nssdb = NSSDatabase(nssdir, dbtype=dbtype, pwd_file=pwd_file)

        self.realm = realm

        self.noise_fname = os.path.join(self.secdir, "noise.txt")

        self.pk12_fname = os.path.join(self.secdir, "cacert.p12")
        self.pin_fname = os.path.join(self.secdir + "pin.txt")
        self.reqdir = None
        self.certreq_fname = None
        self.certder_fname = None
        self.host_name = host_name
        self.ca_subject = ca_subject
        self.subject_base = subject_base

        self.cacert_name = get_ca_nickname(self.realm)

        self.user = user
        self.group = group
        self.mode = mode
        self.uid = 0
        self.gid = 0

        if not create:
            if os.path.isdir(self.secdir):
                # We are going to set the owner of all of the cert
                # files to the owner of the containing directory
                # instead of that of the process. This works when
                # this is called by root for a daemon that runs as
                # a normal user
                mode = os.stat(self.secdir)
                self.uid = mode[stat.ST_UID]
                self.gid = mode[stat.ST_GID]
        else:
            if user is not None:
                pu = pwd.getpwnam(user)
                self.uid = pu.pw_uid
                self.gid = pu.pw_gid
            if group is not None:
                self.gid = grp.getgrnam(group).gr_gid
            self.create_certdbs()

        if fstore:
            self.fstore = fstore
        else:
            self.fstore = sysrestore.FileStore(paths.SYSRESTORE)

    ca_subject = ipautil.dn_attribute_property('_ca_subject')
    subject_base = ipautil.dn_attribute_property('_subject_base')

    # migration changes paths, just forward attribute lookup to nssdb
    @property
    def secdir(self):
        return self.nssdb.secdir

    @property
    def dbtype(self):
        return self.nssdb.dbtype

    @property
    def certdb_fname(self):
        return self.nssdb.certdb

    @property
    def keydb_fname(self):
        return self.nssdb.keydb

    @property
    def secmod_fname(self):
        return self.nssdb.secmod

    @property
    def passwd_fname(self):
        return self.nssdb.pwd_file

    def exists(self):
        """
        Checks whether all NSS database files + our pwd_file exist
        """
        return self.nssdb.exists()

    def __del__(self):
        if self.reqdir is not None:
            shutil.rmtree(self.reqdir, ignore_errors=True)
            self.reqdir = None
        self.nssdb.close()

    def setup_cert_request(self):
        """
        Create a temporary directory to store certificate requests and
        certificates. This should be called before requesting certificates.

        This is set outside of __init__ to avoid creating a temporary
        directory every time we open a cert DB.
        """
        if self.reqdir is not None:
            return

        self.reqdir = tempfile.mkdtemp('', 'ipa-', paths.VAR_LIB_IPA)
        self.certreq_fname = self.reqdir + "/tmpcertreq"
        self.certder_fname = self.reqdir + "/tmpcert.der"

    def set_perms(self, fname, write=False):
        perms = stat.S_IRUSR
        if write:
            perms |= stat.S_IWUSR
        if hasattr(fname, 'fileno'):
            os.fchown(fname.fileno(), self.uid, self.gid)
            os.fchmod(fname.fileno(), perms)
        else:
            os.chown(fname, self.uid, self.gid)
            os.chmod(fname, perms)

    def run_certutil(self, args, stdin=None, **kwargs):
        return self.nssdb.run_certutil(args, stdin, **kwargs)

    def create_noise_file(self):
        if os.path.isfile(self.noise_fname):
            os.remove(self.noise_fname)
        with open(self.noise_fname, "w") as f:
            self.set_perms(f)
            f.write(ipautil.ipa_generate_password())

    def create_passwd_file(self, passwd=None):
        ipautil.backup_file(self.passwd_fname)
        with open(self.passwd_fname, "w") as f:
            self.set_perms(f)
            if passwd is not None:
                f.write("%s\n" % passwd)
            else:
                f.write(ipautil.ipa_generate_password())

    def create_certdbs(self):
        self.nssdb.create_db(
            user=self.user, group=self.group, mode=self.mode,
            backup=True
        )
        self.set_perms(self.passwd_fname, write=True)

    def restore(self):
        self.nssdb.restore()

    def list_certs(self):
        """
        Return a tuple of tuples containing (nickname, trust)
        """
        return self.nssdb.list_certs()

    def has_nickname(self, nickname):
        """
        Returns True if nickname exists in the certdb, False otherwise.

        This could also be done directly with:
            certutil -L -d -n <nickname> ...
        """

        certs = self.list_certs()

        for cert in certs:
            if nickname == cert[0]:
                return True

        return False

    def export_ca_cert(self, nickname, create_pkcs12=False):
        """create_pkcs12 tells us whether we should create a PKCS#12 file
           of the CA or not. If we are running on a replica then we won't
           have the private key to make a PKCS#12 file so we don't need to
           do that step."""
        cacert_fname = paths.IPA_CA_CRT
        # export the CA cert for use with other apps
        ipautil.backup_file(cacert_fname)
        root_nicknames = self.find_root_cert(nickname)[:-1]
        with open(cacert_fname, "w") as f:
            os.fchmod(f.fileno(), 0o644)
            for root in root_nicknames:
                result = self.run_certutil(["-L", "-n", root, "-a"],
                                           capture_output=True)
                f.write(result.output)

        if create_pkcs12:
            ipautil.backup_file(self.pk12_fname)
            self.nssdb.run_pk12util([
                "-o", self.pk12_fname,
                "-n", self.cacert_name,
                "-k", self.passwd_fname,
                "-w", self.passwd_fname,
            ])
            self.set_perms(self.pk12_fname)

    def load_cacert(self, cacert_fname, trust_flags):
        """
        Load all the certificates from a given file. It is assumed that
        this file creates CA certificates.
        """
        with open(cacert_fname) as f:
            certs = f.read()

        st = 0
        while True:
            try:
                (cert, st) = find_cert_from_txt(certs, st)
                _rdn, subject_dn = get_cert_nickname(cert)
                if subject_dn == self.ca_subject:
                    nick = get_ca_nickname(self.realm)
                else:
                    nick = str(subject_dn)
                self.nssdb.add_cert(cert, nick, trust_flags)
            except RuntimeError:
                break

    def get_cert_from_db(self, nickname):
        """
        Retrieve a certificate from the current NSS database for nickname.
        """
        if ':' in nickname:
            token = nickname.split(':', 1)[0]
        else:
            token = None
        try:
            args = ["-L", "-n", nickname, "-a"]
            if token:
                args.extend(['-h', token])
            result = self.run_certutil(args, capture_output=True)
            return x509.load_pem_x509_certificate(result.raw_output)
        except ipautil.CalledProcessError:
            return None

    def track_server_cert(
            self, nickname, principal,
            password_file=None, command=None, profile=None):
        """
        Tell certmonger to track the given certificate nickname.
        """
        try:
            request_id = certmonger.start_tracking(
                self.secdir, nickname=nickname, pinfile=password_file,
                post_command=command, profile=profile)
        except RuntimeError as e:
            logger.error("certmonger failed starting to track certificate: %s",
                         str(e))
            return

        cert = self.get_cert_from_db(nickname)
        subject = str(DN(cert.subject))
        certmonger.add_principal(request_id, principal)
        certmonger.add_subject(request_id, subject)

    def untrack_server_cert(self, nickname):
        """
        Tell certmonger to stop tracking the given certificate nickname.
        """
        try:
            certmonger.stop_tracking(self.secdir, nickname=nickname)
        except RuntimeError as e:
            logger.error("certmonger failed to stop tracking certificate: %s",
                         str(e))

    def create_server_cert(self, nickname, hostname, subject=None):
        """
        If we are using a dogtag CA then other_certdb contains the RA agent key
        that will issue our cert.

        You can override the certificate Subject by specifying a subject.

        Returns a certificate in DER format.
        """
        if subject is None:
            subject=DN(('CN', hostname), self.subject_base)
        self.request_cert(subject, san_dnsnames=[hostname])
        try:
            self.issue_server_cert(self.certreq_fname, self.certder_fname)
            self.import_cert(self.certder_fname, nickname)

            with open(self.certder_fname, "rb") as f:
                dercert = f.read()
                return x509.load_der_x509_certificate(dercert)
        finally:
            for fname in (self.certreq_fname, self.certder_fname):
                try:
                    os.unlink(fname)
                except OSError:
                    pass

    def request_cert(
            self, subject, certtype="rsa", keysize="2048",
            san_dnsnames=None):
        assert isinstance(subject, DN)
        self.create_noise_file()
        self.setup_cert_request()
        args = ["-R", "-s", str(subject),
                "-o", self.certreq_fname,
                "-k", certtype,
                "-g", keysize,
                "-z", self.noise_fname,
                "-f", self.passwd_fname,
                "-a"]
        if san_dnsnames is not None and len(san_dnsnames) > 0:
            args += ['-8', ','.join(san_dnsnames)]
        result = self.run_certutil(args,
                                   capture_output=True, capture_error=True)
        os.remove(self.noise_fname)
        return (result.output, result.error_output)

    def issue_server_cert(self, certreq_fname, cert_fname):
        self.setup_cert_request()

        if self.host_name is None:
            raise RuntimeError("CA Host is not set.")

        with open(certreq_fname, "rb") as f:
            csr = f.read()

        # We just want the CSR bits, make sure there is no thing else
        csr = strip_csr_header(csr).decode('utf8')

        params = {'profileId': dogtag.DEFAULT_PROFILE,
                'cert_request_type': 'pkcs10',
                'requestor_name': 'IPA Installer',
                'cert_request': csr,
                'xmlOutput': 'true'}

        # Send the request to the CA
        result = dogtag.https_request(
            self.host_name, 8443,
            url="/ca/ee/ca/profileSubmitSSLClient",
            cafile=api.env.tls_ca_cert,
            client_certfile=paths.RA_AGENT_PEM,
            client_keyfile=paths.RA_AGENT_KEY,
            **params)
        http_status, _http_headers, http_body = result
        logger.debug("CA answer: %r", http_body)

        if http_status != 200:
            raise CertificateOperationError(
                error=_('Unable to communicate with CMS (status %d)') % http_status)

        # The result is an XML blob. Pull the certificate out of that
        doc = xml.dom.minidom.parseString(http_body)
        item_node = doc.getElementsByTagName("b64")
        try:
            try:
                cert = item_node[0].childNodes[0].data
            except IndexError:
                raise RuntimeError("Certificate issuance failed")
        finally:
            doc.unlink()

        # base64-decode the result for uniformity
        cert = base64.b64decode(cert)

        # Write the certificate to a file. It will be imported in a later
        # step. This file will be read later to be imported.
        with open(cert_fname, "wb") as f:
            f.write(cert)

    def add_cert(self, cert, nick, flags):
        self.nssdb.add_cert(cert, nick, flags)

    def import_cert(self, cert_fname, nickname):
        """
        Load a certificate from a PEM file and add minimal trust.
        """
        args = ["-A", "-n", nickname,
                "-t", "u,u,u",
                "-i", cert_fname,
                "-f", self.passwd_fname]
        self.run_certutil(args)

    def delete_cert(self, nickname):
        self.nssdb.delete_cert(nickname)

    def create_pin_file(self):
        """
        This is the format of Directory Server pin files.
        """
        ipautil.backup_file(self.pin_fname)
        with open(self.pin_fname, "w") as pinfile:
            self.set_perms(pinfile)
            pinfile.write("Internal (Software) Token:")
            with open(self.passwd_fname) as pwdfile:
                pinfile.write(pwdfile.read())

    def find_root_cert(self, nickname):
        """
        Given a nickname, return a list of the certificates that make up
        the trust chain.
        """
        root_nicknames = self.nssdb.get_trust_chain(nickname)

        return root_nicknames

    def trust_root_cert(self, root_nickname, trust_flags):
        if root_nickname is None:
            logger.debug("Unable to identify root certificate to trust. "
                         "Continuing but things are likely to fail.")
            return

        try:
            self.nssdb.trust_root_cert(root_nickname, trust_flags)
        except RuntimeError:
            pass

    def find_server_certs(self):
        return self.nssdb.find_server_certs()

    def import_pkcs12(self, pkcs12_fname, pkcs12_passwd=None):
        return self.nssdb.import_pkcs12(pkcs12_fname,
                                        pkcs12_passwd=pkcs12_passwd)

    def export_pkcs12(self, pkcs12_fname, pkcs12_pwd_fname, nickname=None):
        if nickname is None:
            nickname = get_ca_nickname(api.env.realm)

        self.nssdb.run_pk12util([
            "-o", pkcs12_fname,
            "-n", nickname,
            "-k", self.passwd_fname,
            "-w", pkcs12_pwd_fname
        ])

    def create_from_cacert(self):
        """
        Ensure that a CA chain is in the NSS database.

        If an NSS database already exists ensure that the CA chain
        we want to load is in there and if not add it. If there is no
        database then create an NSS database and load the CA chain.
        """
        cacert_fname = paths.IPA_CA_CRT

        if self.nssdb.exists():
            # We already have a cert db, see if it is for the same CA.
            # If it is we leave things as they are.
            with open(cacert_fname, "r") as f:
                newca = f.read()

            newca, _st = find_cert_from_txt(newca)

            cacert = self.get_cert_from_db(self.cacert_name)

            if newca == cacert:
                return

        # The CA certificates are different or something went wrong. Start with
        # a new certificate database.
        self.create_passwd_file()
        self.create_certdbs()
        self.load_cacert(cacert_fname, IPA_CA_TRUST_FLAGS)

    def create_from_pkcs12(self, pkcs12_fname, pkcs12_passwd,
                           ca_file, trust_flags):
        """Create a new NSS database using the certificates in a PKCS#12 file.

           pkcs12_fname: the filename of the PKCS#12 file
           pkcs12_pwd_fname: the file containing the pin for the PKCS#12 file
           nickname: the nickname/friendly-name of the cert we are loading

           The global CA may be added as well in case it wasn't included in the
           PKCS#12 file. Extra certs won't hurt in any case.

           The global CA may be specified in ca_file, as a PEM filename.
        """
        self.create_noise_file()
        self.create_passwd_file()
        self.create_certdbs()
        self.init_from_pkcs12(
            pkcs12_fname,
            pkcs12_passwd,
            ca_file=ca_file,
            trust_flags=trust_flags)

    def init_from_pkcs12(self, pkcs12_fname, pkcs12_passwd,
                         ca_file, trust_flags):
        self.import_pkcs12(pkcs12_fname, pkcs12_passwd)
        server_certs = self.find_server_certs()
        if len(server_certs) == 0:
            raise RuntimeError("Could not find a suitable server cert in import in %s" % pkcs12_fname)

        if ca_file:
            try:
                with open(ca_file) as fd:
                    certs = fd.read()
            except IOError as e:
                raise RuntimeError(
                    "Failed to open %s: %s" % (ca_file, e.strerror))
            st = 0
            num = 1
            while True:
                try:
                    cert, st = find_cert_from_txt(certs, st)
                except RuntimeError:
                    break
                self.add_cert(cert, 'CA %s' % num, EMPTY_TRUST_FLAGS)
                num += 1

        # We only handle one server cert
        nickname = server_certs[0][0]

        ca_names = self.find_root_cert(nickname)[:-1]
        if len(ca_names) == 0:
            raise RuntimeError("Could not find a CA cert in %s" % pkcs12_fname)

        self.cacert_name = ca_names[-1]
        self.trust_root_cert(self.cacert_name, trust_flags)

        self.export_ca_cert(nickname, False)

    def export_pem_cert(self, nickname, location):
        return self.nssdb.export_pem_cert(nickname, location)

    def request_service_cert(self, nickname, principal, host,
                             resubmit_timeout=None):
        if resubmit_timeout is None:
            resubmit_timeout = api.env.certmonger_wait_timeout
        return certmonger.request_and_wait_for_cert(
            certpath=self.secdir,
            storage='NSSDB',
            nickname=nickname,
            principal=principal,
            subject=host,
            dns=[host],
            passwd_fname=self.passwd_fname,
            resubmit_timeout=resubmit_timeout
        )

    def is_ipa_issued_cert(self, api, nickname):
        """
        Return True if the certificate contained in the CertDB with the
        provided nickname has been issued by IPA.

        Note that this method can only be executed if the api has been
        initialized.

        This method needs to compare the cert issuer (from the NSS DB
        and the subject from the CA (from LDAP), because nicknames are not
        always aligned.

        The cert can be issued directly by IPA. In this case, the cert
        issuer is IPA CA subject.
        """
        cert = self.get_cert_from_db(nickname)
        if cert is None:
            raise RuntimeError("Could not find the cert %s in %s"
                               % (nickname, self.secdir))

        return is_ipa_issued_cert(api, cert)

    def needs_upgrade_format(self):
        """Check if NSSDB file format needs upgrade

        Only upgrade if it's an existing dbm database and default
        database type is no 'dbm'.
        """
        return (
            self.nssdb.dbtype == 'dbm' and
            self.exists()
        )

    def upgrade_format(self):
        """Upgrade NSSDB to new file format
        """
        self.nssdb.convert_db()

    def pki_issue_certificate(self, service, profile, subject,
                              keyfile, certfile, key_passwd_file=None,
                              dns_2_san='', use_admin=False):
        """Use openssl to generate a CSR and submit it using the pki
           cli tool.

           There are effective two modes for this depending on the value
           of use_admin. When use_admin is True we are issuing the RA
           certificate using the CA admin certificate. When it is False
           we are using the RA agent certificate to issue certificates for
           services during installation.

           use_admin = True
              - service and profile can be None
              - fetch the CA chain manually
              - the request needs to be manually approved
        """
        def get_string(instring, key):
            start = instring.find(key)
            if start == -1:
                raise RuntimeError(
                    "Unable to find %s in output" % key)
            return instring[start + len(key):].split()[0]

        if use_admin:
            nickname = 'ipa-ca-agent'
        else:
            ipautil.run(
                [paths.OPENSSL, 'pkcs12', '-export',
                 '-in', paths.RA_AGENT_PEM,
                 '-out', os.path.join(self.secdir, 'agent.p12'),
                 '-inkey', paths.RA_AGENT_KEY,
                 '-name', 'IPA RA',
                 '-password', 'file:{}'.format(self.passwd_fname),
                 '-keypbe', 'AES-256-CBC',
                 '-certpbe', 'AES-256-CBC',
                 '-macalg', 'sha384',]
            )

            with open(self.passwd_fname, "r") as fd:
                key_password = fd.read()
            self.import_pkcs12(
                os.path.join(self.secdir, 'agent.p12'),
                pkcs12_passwd=key_password
            )

            if service == "krbtgt":
                host = api.env.realm
            else:
                host = api.env.host

            template = os.path.join(
                paths.USR_SHARE_IPA_DIR, "openssl_cnf.template")
            sub_dict = dict(
                REALM=api.env.realm,
                FQDN=host,
                NICKNAME="Server-Cert",
                PROFILE=profile,
                SERVICE=service,
                DNS_2=dns_2_san,
            )
            conf = ipautil.template_file(template, sub_dict)
            destfile = os.path.join(self.secdir, "openssl.cnf")
            with open(destfile, 'w') as f:
                os.fchmod(f.fileno(), 0o600)
                f.write(conf)

            args = ["openssl", "req", "-new",
                    "-out", os.path.join(self.secdir, "csr"),
                    "-keyout", keyfile,
                    "-config", destfile]
            if key_passwd_file:
                args.extend(["-passout", "file:{}".format(key_passwd_file)])
            else:
                args.extend(["-nodes"])
            result = ipautil.run(args, capture_output=True)
            nickname = 'IPA RA'

        result = ipautil.run(
            ["pki", "-d", self.secdir,
             "-C", self.passwd_fname,
             "-n", nickname,
             "ca-cert-request-submit",
             "--profile", profile,
             "--subject", subject,
             "--csr", os.path.join(self.secdir, "csr")],
            capture_output=True)
        if use_admin:
            request_id = get_string(result.output, 'Request ID:')
            status = get_string(result.output, 'Request Status:')
            if status != "pending":
                raise RuntimeError(
                    "The certificate submission was not successful")
            result = ipautil.run(
                ["pki", "-C", self.passwd_fname,
                 "-d", self.secdir,
                 "-n", "ipa-ca-agent",
                 "ca-cert-request-approve",
                 "--force", request_id],
                capture_output=True)

        serial_number = get_string(result.output, 'Certificate ID:')
        status = get_string(result.output, 'Operation Result:')
        if status != "success":
            raise RuntimeError(
                "The certificate submission was not successful")

        # The profile auto-issues so no need to approve it
        result = ipautil.run(
            ["pki",
             "-d", self.secdir,
             "ca-cert-export",
             "--output-file", certfile,
             "--output-format", "pem",
             serial_number],
            capture_output=True)


class _CrossProcessLock:
    _DATETIME_FORMAT = '%Y%m%d%H%M%S%f'

    def __init__(self, filename):
        self._filename = filename

    def __enter__(self):
        self.acquire()

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()

    def acquire(self, owner=None):
        self._do(self._acquire, owner)

    def release(self, owner=None):
        self._do(self._release, owner)

    def _acquire(self, owner):
        now = datetime.datetime.now(tz=datetime.timezone.utc)

        if self._locked and now >= self._expire:
            self._locked = False

        if self._locked:
            return False

        self._locked = True
        self._owner = owner
        self._expire = now + datetime.timedelta(hours=1)

        return True

    def _release(self, owner):
        if not self._locked or self._owner != owner:
            raise RuntimeError("lock not acquired by %s" % owner)

        self._locked = False
        self._owner = None
        self._expire = None

        return True

    def _do(self, func, owner):
        if owner is None:
            owner = '%s[%s]' % (os.path.basename(sys.argv[0]), os.getpid())

        while True:
            with open(self._filename, 'a+') as f:
                fcntl.flock(f, fcntl.LOCK_EX)

                f.seek(0)
                self._read(f)

                if func(owner):
                    f.seek(0)
                    f.truncate()
                    self._write(f)
                    return

            time.sleep(10)

    def _read(self, fileobj):
        p = configparser.RawConfigParser()
        p.read_file(fileobj)

        try:
            self._locked = p.getboolean('lock', 'locked')

            if self._locked:
                self._owner = p.get('lock', 'owner')

                expire = p.get('lock', 'expire')
                try:
                    self._expire = datetime.datetime.strptime(
                        expire, self._DATETIME_FORMAT).replace(
                        tzinfo=datetime.timezone.utc)
                except ValueError:
                    raise configparser.Error
        except configparser.Error:
            self._locked = False
            self._owner = None
            self._expire = None

    def _write(self, fileobj):
        p = configparser.RawConfigParser()
        p.add_section('lock')

        locked = '1' if self._locked else '0'
        p.set('lock', 'locked', locked)

        if self._locked:
            expire = self._expire.strftime(self._DATETIME_FORMAT)
            p.set('lock', 'owner', self._owner)
            p.set('lock', 'expire', expire)

        p.write(fileobj)

renewal_lock = _CrossProcessLock(paths.IPA_RENEWAL_LOCK)
