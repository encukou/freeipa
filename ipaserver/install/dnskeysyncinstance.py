#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from __future__ import print_function, absolute_import

import errno
import logging
import os
import re
import shutil
import stat

import ldap

from ipaserver import p11helper as _ipap11helper
from ipapython.dnsutil import DNSName
from ipaserver.install import service
from ipaserver.install import installutils
from ipapython.dn import DN
from ipapython import directivesetter
from ipapython import ipautil
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipalib import errors, api
from ipalib.constants import SOFTHSM_DNSSEC_TOKEN_LABEL
from ipaserver.install.bindinstance import dns_container_exists

logger = logging.getLogger(__name__)

replica_keylabel_template = u"dnssec-replica:%s"


def dnssec_container_exists(suffix):
    """
    Test whether the dns container exists.
    """
    assert isinstance(suffix, DN)
    return api.Backend.ldap2.entry_exists(
        DN(('cn', 'sec'), ('cn', 'dns'), suffix))


def remove_replica_public_keys(hostname):
    keysyncd = DNSKeySyncInstance()
    keysyncd.remove_replica_public_keys(hostname)


class DNSKeySyncInstance(service.Service):
    def __init__(self, fstore=None, logger=logger):
        super(DNSKeySyncInstance, self).__init__(
            "ipa-dnskeysyncd",
            service_desc="DNS key synchronization service",
            fstore=fstore,
            service_prefix=u'ipa-dnskeysyncd',
            keytab=paths.IPA_DNSKEYSYNCD_KEYTAB
        )
        self.extra_config = [u'dnssecVersion 1', ]  # DNSSEC enabled

    suffix = ipautil.dn_attribute_property('_suffix')

    def set_dyndb_ldap_workdir_permissions(self):
        """
        Setting up correct permissions to allow write/read access for daemons
        """
        directories = [
            paths.BIND_LDAP_DNS_IPA_WORKDIR,
            paths.BIND_LDAP_DNS_ZONE_WORKDIR,
        ]
        for directory in directories:
            try:
                os.mkdir(directory, 0o770)
            except FileExistsError:
                pass
            else:
                os.chmod(directory, 0o770)
            # dnssec daemons require to have access into the directory
            constants.NAMED_USER.chown(directory, gid=constants.NAMED_GROUP.gid)

    def remove_replica_public_keys(self, replica_fqdn):
        ldap = api.Backend.ldap2
        dn_base = DN(('cn', 'keys'), ('cn', 'sec'), ('cn', 'dns'), api.env.basedn)
        keylabel = replica_keylabel_template % DNSName(replica_fqdn).\
            make_absolute().canonicalize().ToASCII()
        # get old keys from LDAP
        search_kw = {
            'objectclass': u"ipaPublicKeyObject",
            'ipk11Label': keylabel,
            'ipk11Wrap': True,
        }
        filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
        entries, _truncated = ldap.find_entries(filter=filter, base_dn=dn_base)
        for entry in entries:
            ldap.delete_entry(entry)

    def start_dnskeysyncd(self):
        print("Restarting ipa-dnskeysyncd")
        self.__start()

    def create_instance(self, fqdn, realm_name):
        self.fqdn = fqdn
        self.realm = realm_name
        self.suffix = ipautil.realm_to_suffix(self.realm)
        try:
            self.stop()
        except Exception:
            pass

        # checking status step must be first
        self.step("checking status", self.__check_dnssec_status)
        self.step("setting up bind-dyndb-ldap working directory",
                  self.set_dyndb_ldap_workdir_permissions)
        self.step("setting up kerberos principal", self.__setup_principal)
        self.step("setting up SoftHSM", self.__setup_softhsm)
        self.step("adding DNSSEC containers", self.__setup_dnssec_containers)
        self.step("creating replica keys", self.__setup_replica_keys)
        self.step("configuring ipa-dnskeysyncd to start on boot", self.__enable)
        # we need restart named after setting up this service
        self.start_creation()

    def __check_dnssec_status(self):
        if not dns_container_exists(self.suffix):
            raise RuntimeError("DNS container does not exist")

        # ready to be installed, storing a state is required to run uninstall
        self.backup_state("configured", True)

    def __setup_dnssec_containers(self):
        """
        Setup LDAP containers for DNSSEC
        """
        if dnssec_container_exists(self.suffix):

            logger.info("DNSSEC container exists (step skipped)")
            return

        self._ldap_mod("dnssec.ldif", {'SUFFIX': self.suffix, })

    def _are_named_options_configured(self, options):
        """Check whether the sysconfig of named is patched

        Additional command line options for named are passed
        via OPTIONS env variable. Since custom options can be
        supplied by a vendor, at least, the base parsing of such
        is required.
        Current named command line options:
        NS_MAIN_ARGS "46A:c:C:d:D:E:fFgi:lL:M:m:n:N:p:P:sS:t:T:U:u:vVx:X:"
        If there are several same options the last passed wins.
        """
        if options:
            pattern = r"[ ]*-[a-zA-Z46]*E[ ]*(.*?)(?: |$)"
            engines = re.findall(pattern, options)
            if engines and engines[-1] == constants.NAMED_OPENSSL_ENGINE:
                return True

        return False

    def setup_named_openssl_conf(self):
        opensslcnf_tmpl = None
        conf_file_dict = {
            'CRYPTO_POLICY_FILE': paths.CRYPTO_POLICY_OPENSSLCNF_FILE,
            'SOFTHSM_MODULE': paths.LIBSOFTHSM2_SO,
            'SOFTHSM_PIN': paths.DNSSEC_SOFTHSM_PIN,
        }
        if constants.NAMED_OPENSSL_ENGINE is not None:
            # Traditional configuration using OpenSSL engine API
            # requires openssl-pkcs11 engine to load PKCS#11 token
            # provided by SoftHSMv2
            conf_file_dict['OPENSSL_ENGINE'] = constants.NAMED_OPENSSL_ENGINE
            if paths.CRYPTO_POLICY_OPENSSLCNF_FILE is None:
                opensslcnf_tmpl = "bind.openssl.cnf.template"
            else:
                opensslcnf_tmpl = "bind.openssl.cryptopolicy.cnf.template"
        elif constants.NAMED_OPENSSL_PROVIDER is not None:
            # OpenSSL provider API is preferred and requires
            # pkcs11-provider to load PKCS#11 token provided by SoftHSMv2
            if paths.CRYPTO_POLICY_OPENSSLCNF_FILE is None:
                opensslcnf_tmpl = "bind.openssl.provider.cnf.template"
            else:
                opensslcnf_tmpl = "bind.openssl.provider.crp.cnf.template"
        else:
            conf_file_dict = None

        if opensslcnf_tmpl is not None and conf_file_dict is not None:
            logger.debug("Setup OpenSSL config for BIND")
            # setup OpenSSL config for BIND,
            # this one is needed because FreeIPA installation
            # disables p11-kit-proxy PKCS11 module
            named_openssl_txt = ipautil.template_file(
                os.path.join(paths.USR_SHARE_IPA_DIR, opensslcnf_tmpl),
                conf_file_dict
            )
            with open(paths.DNSSEC_OPENSSL_CONF, 'w') as f:
                os.fchmod(f.fileno(), 0o640)
                os.fchown(f.fileno(), 0, gid=constants.NAMED_GROUP.gid)
                f.write(named_openssl_txt)

    def setup_named_sysconfig(self):
        logger.debug("Setup BIND sysconfig")
        sysconfig = paths.SYSCONFIG_NAMED
        self.fstore.backup_file(sysconfig)

        directivesetter.set_directive(
            sysconfig,
            'SOFTHSM2_CONF', paths.DNSSEC_SOFTHSM2_CONF,
            quotes=False, separator='=')

        if any([constants.NAMED_OPENSSL_ENGINE is not None,
                constants.NAMED_OPENSSL_PROVIDER is not None]):
            directivesetter.set_directive(
                sysconfig,
                'OPENSSL_CONF', paths.DNSSEC_OPENSSL_CONF,
                quotes=False, separator='=')

            options = directivesetter.get_directive(
                paths.SYSCONFIG_NAMED,
                constants.NAMED_OPTIONS_VAR,
                separator="="
            ) or ''
            new_options = None
            if all([constants.NAMED_OPENSSL_ENGINE is not None,
                    not self._are_named_options_configured(options)]):
                engine_cmd = "-E {}".format(constants.NAMED_OPENSSL_ENGINE)
                new_options = ' '.join([options, engine_cmd])
            # Remove '-E pkcs11' from the options in the OpenSSL provider case
            if all([constants.NAMED_OPENSSL_ENGINE is None,
                    self._are_named_options_configured(options)]):
                lst_options = options.split()
                try:
                    idx = lst_options.index('-E')
                    lst_options.pop(idx)
                    lst_options.pop(idx)
                    new_options = ' '.join(lst_options)
                except ValueError:
                    pass
            if new_options is not None:
                directivesetter.set_directive(
                    sysconfig,
                    constants.NAMED_OPTIONS_VAR, new_options,
                    quotes=True, separator='=')

    def setup_ipa_dnskeysyncd_sysconfig(self):
        logger.debug("Setup ipa-dnskeysyncd sysconfig")
        sysconfig = paths.SYSCONFIG_IPA_DNSKEYSYNCD
        directivesetter.set_directive(
            sysconfig,
            'SOFTHSM2_CONF', paths.DNSSEC_SOFTHSM2_CONF,
            quotes=False, separator='=')

        if any([constants.NAMED_OPENSSL_ENGINE is not None,
                constants.NAMED_OPENSSL_PROVIDER is not None]):
            directivesetter.set_directive(
                sysconfig,
                'OPENSSL_CONF', paths.DNSSEC_OPENSSL_CONF,
                quotes=False, separator='=')

    def __setup_softhsm(self):
        token_dir_exists = os.path.exists(paths.DNSSEC_TOKENS_DIR)

        # create dnssec directory
        if not os.path.exists(paths.IPA_DNSSEC_DIR):
            logger.debug("Creating %s directory", paths.IPA_DNSSEC_DIR)
            os.mkdir(paths.IPA_DNSSEC_DIR)
            os.chmod(paths.IPA_DNSSEC_DIR, 0o770)
            # chown ods:named
            constants.ODS_USER.chown(paths.IPA_DNSSEC_DIR,
                                     gid=constants.NAMED_GROUP.gid)

        # setup softhsm2 config file
        softhsm_conf_txt = ("# SoftHSM v2 configuration file \n"
                            "# File generated by IPA instalation\n"
                            "directories.tokendir = %(tokens_dir)s\n"
                            "objectstore.backend = file") % {
                               'tokens_dir': paths.DNSSEC_TOKENS_DIR
                            }
        logger.debug("Creating new softhsm config file")
        with open(paths.DNSSEC_SOFTHSM2_CONF, 'w') as f:
            os.fchmod(f.fileno(), 0o644)
            f.write(softhsm_conf_txt)

        # setting up named and ipa-dnskeysyncd to use our softhsm2 and
        # openssl configs
        self.setup_named_openssl_conf()
        self.setup_named_sysconfig()
        self.setup_ipa_dnskeysyncd_sysconfig()

        if (token_dir_exists and os.path.exists(paths.DNSSEC_SOFTHSM_PIN) and
                os.path.exists(paths.DNSSEC_SOFTHSM_PIN_SO)):
            # there is initialized softhsm
            return

        # remove old tokens
        if token_dir_exists:
            logger.debug('Removing old tokens directory %s',
                         paths.DNSSEC_TOKENS_DIR)
            shutil.rmtree(paths.DNSSEC_TOKENS_DIR)

        # create tokens subdirectory
        logger.debug('Creating tokens %s directory', paths.DNSSEC_TOKENS_DIR)
        # sticky bit is required by daemon
        os.mkdir(paths.DNSSEC_TOKENS_DIR)
        os.chmod(paths.DNSSEC_TOKENS_DIR, 0o770 | stat.S_ISGID)
        # chown to ods:named
        constants.ODS_USER.chown(paths.DNSSEC_TOKENS_DIR,
                                 gid=constants.NAMED_GROUP.gid)

        # generate PINs for softhsm
        pin_length = 30  # Bind allows max 32 bytes including ending '\0'
        pin = ipautil.ipa_generate_password(
            entropy_bits=0, special=None, min_len=pin_length)
        pin_so = ipautil.ipa_generate_password(
            entropy_bits=0, special=None, min_len=pin_length)

        logger.debug("Saving user PIN to %s", paths.DNSSEC_SOFTHSM_PIN)
        with open(paths.DNSSEC_SOFTHSM_PIN, 'w') as f:
            # chown to ods:named
            constants.ODS_USER.chown(f.fileno(), gid=constants.NAMED_GROUP.gid)
            os.fchmod(f.fileno(), 0o660)
            f.write(pin)

        logger.debug("Saving SO PIN to %s", paths.DNSSEC_SOFTHSM_PIN_SO)
        with open(paths.DNSSEC_SOFTHSM_PIN_SO, 'w') as f:
            # owner must be root
            os.fchmod(f.fileno(), 0o400)
            f.write(pin_so)

        # initialize SoftHSM

        command = [
            paths.SOFTHSM2_UTIL,
            '--init-token',
            '--free',  # use random free slot
            '--label', SOFTHSM_DNSSEC_TOKEN_LABEL,
            '--pin', pin,
            '--so-pin', pin_so,
        ]
        logger.debug("Initializing tokens")
        os.environ["SOFTHSM2_CONF"] = paths.DNSSEC_SOFTHSM2_CONF
        ipautil.run(command, nolog=(pin, pin_so,))

    def __setup_replica_keys(self):
        keylabel = replica_keylabel_template % DNSName(self.fqdn).\
            make_absolute().canonicalize().ToASCII()

        ldap = api.Backend.ldap2
        dn_base = DN(('cn', 'keys'), ('cn', 'sec'), ('cn', 'dns'), api.env.basedn)

        with open(paths.DNSSEC_SOFTHSM_PIN, "r") as f:
                pin = f.read()

        os.environ["SOFTHSM2_CONF"] = paths.DNSSEC_SOFTHSM2_CONF
        p11 = _ipap11helper.P11_Helper(
            SOFTHSM_DNSSEC_TOKEN_LABEL, pin, paths.LIBSOFTHSM2_SO)

        try:
            # generate replica keypair
            logger.debug("Creating replica's key pair")
            key_id = None
            while True:
                # check if key with this ID exist in softHSM
                key_id = _ipap11helper.gen_key_id()
                replica_pubkey_dn = DN(('ipk11UniqueId', 'autogenerate'), dn_base)


                pub_keys = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                        label=keylabel,
                                        id=key_id)
                if pub_keys:
                    # key with id exists
                    continue

                priv_keys = p11.find_keys(_ipap11helper.KEY_CLASS_PRIVATE_KEY,
                                        label=keylabel,
                                        id=key_id)
                if not priv_keys:
                    break  # we found unique id

            public_key_handle, _privkey_handle = p11.generate_replica_key_pair(
                    keylabel, key_id,
                    pub_cka_verify=False,
                    pub_cka_verify_recover=False,
                    pub_cka_wrap=True,
                    priv_cka_unwrap=True,
                    priv_cka_sensitive=True,
                    priv_cka_extractable=False)

            # export public key
            public_key_blob = p11.export_public_key(public_key_handle)

            # save key to LDAP
            replica_pubkey_objectclass = [
                'ipk11Object', 'ipk11PublicKey', 'ipaPublicKeyObject', 'top'
            ]
            kw = {
                'objectclass': replica_pubkey_objectclass,
                'ipk11UniqueId': [u'autogenerate'],
                'ipk11Label': [keylabel],
                'ipaPublicKey': [public_key_blob],
                'ipk11Id': [key_id],
                'ipk11Wrap': [True],
                'ipk11Verify': [False],
                'ipk11VerifyRecover': [False],
            }

            logger.debug("Storing replica public key to LDAP, %s",
                         replica_pubkey_dn)

            entry = ldap.make_entry(replica_pubkey_dn, **kw)
            ldap.add_entry(entry)
            logger.debug("Replica public key stored")

            logger.debug("Setting CKA_WRAP=False for old replica keys")
            # first create new keys, we don't want disable keys before, we
            # have new keys in softhsm and LDAP

            # get replica pub keys with CKA_WRAP=True
            replica_pub_keys = p11.find_keys(_ipap11helper.KEY_CLASS_PUBLIC_KEY,
                                             label=keylabel,
                                             cka_wrap=True)
            # old keys in softHSM
            for handle in replica_pub_keys:
                # don't disable wrapping for new key
                # compare IDs not handle
                if key_id != p11.get_attribute(handle, _ipap11helper.CKA_ID):
                    p11.set_attribute(handle, _ipap11helper.CKA_WRAP, False)

            # get old keys from LDAP
            search_kw = {
                'objectclass': u"ipaPublicKeyObject",
                'ipk11Label': keylabel,
                'ipk11Wrap': True,
            }
            filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
            entries, _truncated = ldap.find_entries(filter=filter,
                                                   base_dn=dn_base)
            for entry in entries:
                # don't disable wrapping for new key
                if entry.single_value['ipk11Id'] != key_id:
                    entry['ipk11Wrap'] = [False]
                    ldap.update_entry(entry)

        finally:
            p11.finalize()

        # change tokens mod/owner
        logger.debug("Changing ownership of token files")
        for (root, dirs, files) in os.walk(paths.DNSSEC_TOKENS_DIR):
            for directory in dirs:
                dir_path = os.path.join(root, directory)
                os.chmod(dir_path, 0o770 | stat.S_ISGID)
                # chown to ods:named
                constants.ODS_USER.chown(dir_path,
                                         gid=constants.NAMED_GROUP.gid)
            for filename in files:
                file_path = os.path.join(root, filename)
                os.chmod(file_path, 0o660 | stat.S_ISGID)
                # chown to ods:named
                constants.ODS_USER.chown(file_path,
                                         gid=constants.NAMED_GROUP.gid)

    def __enable(self):
        try:
            self.ldap_configure('DNSKeySync', self.fqdn, None,
                                self.suffix, self.extra_config)
        except errors.DuplicateEntry:
            logger.error("DNSKeySync service already exists")

    def __setup_principal(self):
        ipautil.remove_keytab(self.keytab)
        installutils.kadmin_addprinc(self.principal)

        # Store the keytab on disk
        installutils.create_keytab(self.keytab, self.principal)
        p = self.move_service(self.principal)
        if p is None:
            # the service has already been moved, perhaps we're doing a DNS reinstall
            dnssynckey_principal_dn = DN(
                ('krbprincipalname', self.principal),
                ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        else:
            dnssynckey_principal_dn = p

        # Make sure access is strictly reserved to the named user
        os.chown(self.keytab, 0, constants.ODS_GROUP.gid)
        os.chmod(self.keytab, 0o440)

        dns_group = DN(('cn', 'DNS Servers'), ('cn', 'privileges'),
                       ('cn', 'pbac'), self.suffix)
        mod = [(ldap.MOD_ADD, 'member', dnssynckey_principal_dn)]

        try:
            api.Backend.ldap2.modify_s(dns_group, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass
        except Exception as e:
            logger.critical("Could not modify principal's %s entry: %s",
                            dnssynckey_principal_dn, str(e))
            raise

        # bind-dyndb-ldap persistent search feature requires both size and time
        # limit-free connection

        mod = [(ldap.MOD_REPLACE, 'nsTimeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsSizeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsIdleTimeout', '-1'),
               (ldap.MOD_REPLACE, 'nsLookThroughLimit', '-1')]
        try:
            api.Backend.ldap2.modify_s(dnssynckey_principal_dn, mod)
        except Exception as e:
            logger.critical("Could not set principal's %s LDAP limits: %s",
                            dnssynckey_principal_dn, str(e))
            raise

    def __start(self):
        try:
            self.restart()
        except Exception as e:
            print("Failed to start ipa-dnskeysyncd")
            logger.debug("Failed to start ipa-dnskeysyncd: %s", e)


    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        # Just eat states
        self.restore_state("running")
        self.restore_state("enabled")
        self.restore_state("configured")

        # stop and disable service (IPA service, we do not need it anymore)
        self.stop()
        self.disable()

        for f in [paths.SYSCONFIG_NAMED]:
            try:
                self.fstore.restore_file(f)
            except ValueError as error:
                logger.debug('%s', error)

        # remove softhsm pin, to make sure new installation will generate
        # new token database
        # do not delete *so pin*, user can need it to get token data
        ipautil.remove_file(paths.DNSSEC_SOFTHSM_PIN)
        ipautil.remove_file(paths.DNSSEC_SOFTHSM2_CONF)
        ipautil.remove_file(paths.DNSSEC_OPENSSL_CONF)

        ipautil.rmtree(paths.IPA_DNSSEC_DIR)

        try:
            shutil.rmtree(paths.DNSSEC_TOKENS_DIR)
        except OSError as e:
            if e.errno != errno.ENOENT:
                logger.exception(
                    "Failed to remove %s", paths.DNSSEC_TOKENS_DIR
                )

        ipautil.remove_keytab(self.keytab)
