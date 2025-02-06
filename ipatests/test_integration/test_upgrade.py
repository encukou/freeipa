#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#

"""
Module provides tests to verify that the upgrade script works.
"""
import base64
import configparser
import os
import io
import textwrap
from subprocess import CalledProcessError

from cryptography.hazmat.primitives import serialization
import pytest

from ipaplatform.paths import paths
from ipapython.dn import DN
from ipapython.ipautil import template_str
from ipaserver.install import bindinstance
from ipaserver.install.sysupgrade import STATEFILE_FILE
from ipalib.constants import DEFAULT_CONFIG
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks

# old template without comments for testing
# and "dnssec-validation no"
OLD_NAMED_TEMPLATE = """
options {
        listen-on-v6 {any;};
        directory "$NAMED_VAR_DIR"; // the default
        dump-file               "${NAMED_DATA_DIR}cache_dump.db";
        statistics-file         "${NAMED_DATA_DIR}named_stats.txt";
        memstatistics-file      "${NAMED_DATA_DIR}named_mem_stats.txt";
        tkey-gssapi-keytab "$NAMED_KEYTAB";
        pid-file "$NAMED_PID";
        dnssec-enable yes;
        dnssec-validation no;
        bindkeys-file "$BINDKEYS_FILE";
        managed-keys-directory "$MANAGED_KEYS_DIR";
        $INCLUDE_CRYPTO_POLICY
};

logging {
        channel default_debug {
                file "${NAMED_DATA_DIR}named.run";
                severity dynamic;
                print-time yes;
        };
};

include "$RFC1912_ZONES";
include "$ROOT_KEY";

/* WARNING: This part of the config file is IPA-managed.
 * Modifications may break IPA setup or upgrades.
 */
dyndb "ipa" "$BIND_LDAP_SO" {
        uri "ldapi://%2fvar%2frun%2fslapd-$SERVER_ID.socket";
        base "cn=dns,$SUFFIX";
        server_id "$FQDN";
        auth_method "sasl";
        sasl_mech "GSSAPI";
        sasl_user "DNS/$FQDN";
};
/* End of IPA-managed part. */
"""


def named_test_template(host):
    # create bind instance to get a substitution dict
    bind = bindinstance.BindInstance()
    bind.setup_templating(
        fqdn=host.hostname,
        realm_name=host.domain.realm,
        domain_name=host.domain.name,
    )
    sub_dict = bind.sub_dict.copy()
    sub_dict.update(BINDKEYS_FILE="/etc/named.iscdlv.key")
    return template_str(OLD_NAMED_TEMPLATE, sub_dict)


def clear_sysupgrade(host, *sections):
    # get state file
    statefile = os.path.join(paths.STATEFILE_DIR, STATEFILE_FILE)
    state = host.get_file_contents(statefile, encoding="utf-8")
    # parse it
    parser = configparser.ConfigParser()
    parser.optionxform = str
    parser.read_string(state)
    # remove sections
    for section in sections:
        parser.remove_section(section)
    # dump the modified config
    out = io.StringIO()
    parser.write(out)
    # upload it
    host.put_file_contents(statefile, out.getvalue())


def get_main_krb_rec_dn(domain):
    return DN(
        ('idnsname', '_kerberos'),
        ('idnsname', domain.name + '.'),
        dict(DEFAULT_CONFIG)['container_dns'],
        domain.basedn,
    )


def get_location_krb_rec_dn(domain, location):
    return DN(
        ('idnsname', '_kerberos.' + location + '._locations'),
        ('idnsname', domain.name + '.'),
        dict(DEFAULT_CONFIG)['container_dns'],
        domain.basedn,
    )


class TestUpgrade(IntegrationTest):
    """
    Test ipa-server-upgrade.

    Note that ipa-server-upgrade on a CA-less installation is tested
    in ``test_caless.TestIPACommands.test_invoke_upgrader``.

    """
    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master)
        tasks.install_dns(cls.master)

    @pytest.fixture
    def setup_locations(self):
        realm = self.master.domain.realm

        _locations = []

        def _setup_locations(locations):
            _locations = locations

            ldap = self.master.ldap_connect()

            for location in locations:
                self.master.run_command(['ipa', 'location-add', location])
            self.master.run_command([
                'ipa',
                'server-mod',
                '--location=' + locations[0],
                self.master.hostname,
            ])

            main_krb_rec = ldap.get_entry(
                get_main_krb_rec_dn(self.master.domain),
            )
            main_krb_rec['objectClass'].remove('idnsTemplateObject')
            del main_krb_rec['idnsTemplateAttribute;cnamerecord']
            ldap.update_entry(main_krb_rec)

            for location in locations:
                location_krb_rec = ldap.get_entry(
                    get_location_krb_rec_dn(self.master.domain, location),
                )
                del location_krb_rec['tXTRecord']
                ldap.update_entry(location_krb_rec)

        yield _setup_locations
        ldap = self.master.ldap_connect()

        modified = False
        main_krb_rec = ldap.get_entry(get_main_krb_rec_dn(self.master.domain))
        if 'idnsTemplateObject' not in main_krb_rec['objectClass']:
            main_krb_rec['objectClass'].append('idnsTemplateObject')
            modified = True
        if 'idnsTemplateAttribute;cnamerecord' not in main_krb_rec:
            main_krb_rec['idnsTemplateAttribute;cnamerecord'] = \
                '_kerberos.\\{substitutionvariable_ipalocation\\}._locations'
            modified = True
        if modified:
            ldap.update_entry(main_krb_rec)

        for location in _locations:
            location_krb_rec = ldap.get_entry(
                get_location_krb_rec_dn(self.master.domain, location),
            )
            if 'tXTRecord' not in location_krb_rec:
                location_krb_rec['tXTRecord'] = f'"{realm}"'
                ldap.update_entry(location_krb_rec)

        self.master.run_command([
            'ipa',
            'server-mod',
            '--location=',
            self.master.hostname,
        ])
        for location in _locations:
            self.master.run_command(['ipa', 'location-del', location])

    def test_invoke_upgrader(self):
        cmd = self.master.run_command(['ipa-server-upgrade'],
                                      raiseonerr=False)
        assert ("DN: cn=Schema Compatibility,cn=plugins,cn=config does not \
                exists or haven't been updated" not in cmd.stdout_text)
        assert cmd.returncode == 0

    def test_double_encoded_cacert(self):
        """Test for BZ 1644874

        In old IPA version, the entry cn=CAcert,cn=ipa,cn=etc,$basedn
        could contain a double-encoded cert, which leads to ipa-server-upgrade
        failure.
        Force a double-encoded value then call upgrade to check the fix.
        """
        # Read the current entry from LDAP
        ldap = self.master.ldap_connect()
        basedn = self.master.domain.basedn
        dn = DN(('cn', 'CAcert'), ('cn', 'ipa'), ('cn', 'etc'), basedn)
        entry = ldap.get_entry(dn)
        # Extract the certificate as DER then double-encode
        cacert = entry['cacertificate;binary'][0]
        cacert_der = cacert.public_bytes(serialization.Encoding.DER)
        cacert_b64 = base64.b64encode(cacert_der)
        # overwrite the value with double-encoded cert
        entry.single_value['cACertificate;binary'] = cacert_b64
        ldap.update_entry(entry)

        # try the upgrade
        self.master.run_command(['ipa-server-upgrade'])

        # reconnect to the master (upgrade stops 389-ds)
        ldap = self.master.ldap_connect()
        # read the value after upgrade, should be fixed
        entry = ldap.get_entry(dn)
        try:
            _cacert = entry['cacertificate;binary']
        except ValueError:
            raise AssertionError('%s contains a double-encoded cert'
                                 % entry.dn)

    def get_named_confs(self):
        named_conf = self.master.get_file_contents(
            paths.NAMED_CONF, encoding="utf-8"
        )
        print(named_conf)
        custom_conf = self.master.get_file_contents(
            paths.NAMED_CUSTOM_CONF, encoding="utf-8"
        )
        print(custom_conf)
        opt_conf = self.master.get_file_contents(
            paths.NAMED_CUSTOM_OPTIONS_CONF, encoding="utf-8"
        )
        print(opt_conf)

        log_conf = self.master.get_file_contents(
            paths.NAMED_LOGGING_OPTIONS_CONF, encoding="utf-8"
        )
        print(log_conf)
        return named_conf, custom_conf, opt_conf, log_conf

    @pytest.mark.skip_if_platform(
        "debian", reason="Debian does not use crypto policy"
    )
    def test_named_conf_crypto_policy(self):
        named_conf = self.master.get_file_contents(
            paths.NAMED_CONF, encoding="utf-8"
        )
        assert paths.NAMED_CRYPTO_POLICY_FILE in named_conf

    def test_current_named_conf(self):
        named_conf, custom_conf, opt_conf, log_conf = self.get_named_confs()
        # verify that all includes are present exactly one time
        inc_opt_conf = f'include "{paths.NAMED_CUSTOM_OPTIONS_CONF}";'
        assert named_conf.count(inc_opt_conf) == 1
        inc_custom_conf = f'include "{paths.NAMED_CUSTOM_CONF}";'
        assert named_conf.count(inc_custom_conf) == 1
        inc_log_conf = f'include "{paths.NAMED_LOGGING_OPTIONS_CONF}";'
        assert named_conf.count(inc_log_conf) == 1

        assert "dnssec-validation yes;" in opt_conf
        assert "dnssec-validation" not in named_conf

        assert custom_conf
        assert log_conf

    def test_update_named_conf_simple(self):
        # remove files to force a migration
        self.master.run_command(
            [
                "rm",
                "-f",
                paths.NAMED_CUSTOM_CONF,
                paths.NAMED_CUSTOM_OPTIONS_CONF,
                paths.NAMED_LOGGING_OPTIONS_CONF,
            ]
        )
        self.master.run_command(['ipa-server-upgrade'])
        named_conf, custom_conf, opt_conf, log_conf = self.get_named_confs()

        # not empty
        assert custom_conf.strip()
        assert log_conf.strip()
        # has dnssec-validation enabled in option config
        assert "dnssec-validation yes;" in opt_conf
        assert "dnssec-validation" not in named_conf

        # verify that both includes are present exactly one time
        inc_opt_conf = f'include "{paths.NAMED_CUSTOM_OPTIONS_CONF}";'
        assert named_conf.count(inc_opt_conf) == 1
        inc_custom_conf = f'include "{paths.NAMED_CUSTOM_CONF}";'
        assert named_conf.count(inc_custom_conf) == 1
        inc_log_conf = f'include "{paths.NAMED_LOGGING_OPTIONS_CONF}";'
        assert named_conf.count(inc_log_conf) == 1

    def test_update_named_conf_old(self):
        # remove files to force a migration
        self.master.run_command(
            [
                "rm",
                "-f",
                paths.NAMED_CUSTOM_CONF,
                paths.NAMED_CUSTOM_OPTIONS_CONF,
                paths.NAMED_LOGGING_OPTIONS_CONF,
            ]
        )
        # dump an old named conf to verify migration
        old_contents = named_test_template(self.master)
        self.master.put_file_contents(paths.NAMED_CONF, old_contents)
        clear_sysupgrade(self.master, "dns", "named.conf")
        # check and skip dnssec-enable-related issues in 9.18+
        # where dnssec-enable option was removed completely
        try:
            self.master.run_command(
                ["named-checkconf", paths.NAMED_CONF]
            )
        except CalledProcessError as e:
            if not('dnssec-enable' in e.output):
                raise e

        # upgrade
        self.master.run_command(['ipa-server-upgrade'])

        named_conf, custom_conf, opt_conf, log_conf = self.get_named_confs()

        # not empty
        assert custom_conf.strip()
        assert log_conf.strip()
        # dnssec-validation is migrated as "disabled" from named.conf
        assert "dnssec-validation no;" in opt_conf
        assert "dnssec-validation" not in named_conf

        # verify that both includes are present exactly one time
        inc_opt_conf = f'include "{paths.NAMED_CUSTOM_OPTIONS_CONF}";'
        assert named_conf.count(inc_opt_conf) == 1
        inc_custom_conf = f'include "{paths.NAMED_CUSTOM_CONF}";'
        assert named_conf.count(inc_custom_conf) == 1
        inc_log_conf = f'include "{paths.NAMED_LOGGING_OPTIONS_CONF}";'
        assert named_conf.count(inc_log_conf) == 1

    def test_admin_root_alias_upgrade_CVE_2020_10747(self):
        # Test upgrade for CVE-2020-10747 fix
        # https://bugzilla.redhat.com/show_bug.cgi?id=1810160
        rootprinc = "root@{}".format(self.master.domain.realm)
        self.master.run_command(
            ["ipa", "user-remove-principal", "admin", rootprinc]
        )
        result = self.master.run_command(["ipa", "user-show", "admin"])
        assert rootprinc not in result.stdout_text

        self.master.run_command(['ipa-server-upgrade'])
        result = self.master.run_command(["ipa", "user-show", "admin"])
        assert rootprinc in result.stdout_text

    def test_pwpolicy_upgrade(self):
        """Test that ipapwdpolicy objectclass is added to all policies"""
        entry_ldif = textwrap.dedent("""
            dn: cn=global_policy,cn={realm},cn=kerberos,{base_dn}
            changetype: modify
            delete: passwordGraceLimit
            -
            delete: objectclass
            objectclass: ipapwdpolicy
        """).format(
            base_dn=str(self.master.domain.basedn),
            realm=self.master.domain.realm)
        tasks.ldapmodify_dm(self.master, entry_ldif)

        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa-server-upgrade'])
        result = self.master.run_command(["ipa", "pwpolicy-find"])
        # if it is still missing the oc it won't be displayed
        assert 'global_policy' in result.stdout_text

    def test_kra_detection(self):
        """Test that ipa-server-upgrade correctly detects KRA presence

        Test for https://pagure.io/freeipa/issue/8596
        When the directory /var/lib/pki/pki-tomcat/kra/ exists, the upgrade
        wrongly assumes that KRA component is installed and crashes.
        The test creates an empty dir and calls kra.is_installed()
        to make sure that KRA detection is not based on the directory
        presence.
        Note: because of issue https://github.com/dogtagpki/pki/issues/3397
        ipa-server-upgrade fails even with the kra detection fix. That's
        why the test does not exercise the whole ipa-server-upgrade command
        but only the KRA detection part.
        """
        kra_path = os.path.join(paths.VAR_LIB_PKI_TOMCAT_DIR, "kra")
        try:
            self.master.run_command(["mkdir", "-p", kra_path])
            script = (
                "from ipalib import api; "
                "from ipaserver.install import krainstance; "
                "api.bootstrap(); "
                "api.finalize(); "
                "kra = krainstance.KRAInstance(api.env.realm); "
                "print(kra.is_installed())"
            )
            result = self.master.run_command(['python3', '-c', script])
            assert "False" in result.stdout_text
        finally:
            self.master.run_command(["rmdir", kra_path])

    def test_krb_uri_txt_to_cname(self, setup_locations):
        """Test that ipa-server-upgrade correctly updates Kerberos DNS records

        Test for https://pagure.io/freeipa/issue/9257
        Kerberos URI and TXT DNS records should be location-aware in case the
        server is part of a location, in order for DNS discovery to prioritize
        servers from the same location. This means that for such servers the
        _kerberos record should be a CNAME one pointing to the appropriate set
        of location-aware records.
        """
        realm = self.master.domain.realm
        locations = ['a', 'b']

        setup_locations(locations)

        self.master.run_command(['ipa-server-upgrade'])

        ldap = self.master.ldap_connect()

        main_krb_rec = ldap.get_entry(
            get_main_krb_rec_dn(self.master.domain),
        )
        assert 'idnsTemplateObject' in main_krb_rec['objectClass']
        assert len(main_krb_rec['idnsTemplateAttribute;cnamerecord']) == 1
        assert main_krb_rec['idnsTemplateAttribute;cnamerecord'][0] \
            == '_kerberos.\\{substitutionvariable_ipalocation\\}._locations'

        for location in locations:
            location_krb_rec = ldap.get_entry(
                get_location_krb_rec_dn(self.master.domain, location),
            )
            assert 'tXTRecord' in location_krb_rec
            assert len(location_krb_rec['tXTRecord']) == 1
            assert location_krb_rec['tXTRecord'][0] == f'"{realm}"'

    def test_pki_dropin_file(self):
        """Test that upgrade adds the drop-in file if missing

        Test for ticket 9381
        Simulate an update from a version that didn't provide
        /etc/systemd/system/pki-tomcatd@pki-tomcat.service.d/ipa.conf,
        remove one of the certificate profiles from LDAP and check that upgrade
        completes successfully and adds the missing file.
        When the drop-in file is missing, the upgrade tries to login to
        PKI in order to migrate the profile and fails because PKI failed to
        start.
        """
        self.master.run_command(["rm", "-f", paths.SYSTEMD_PKI_TOMCAT_IPA_CONF])
        ldif = textwrap.dedent("""
             dn: cn=caECServerCertWithSCT,ou=certificateProfiles,ou=ca,o=ipaca
             changetype: delete
             """)
        tasks.ldapmodify_dm(self.master, ldif)
        self.master.run_command(['ipa-server-upgrade'])
        assert self.master.transport.file_exists(
            paths.SYSTEMD_PKI_TOMCAT_IPA_CONF)

    def test_ssh_config(self):
        """Test that pkg upgrade does not create .orig files

        Test for ticket 9610
        The upgrade of ipa-client package should not create a backup file
        /etc/ssh/ssh_config.orig or /etc/ssh/ssh_config.d/04-ipa.conf if
        no change is applied.
        """
        # Ensure there is no backup file before the test
        self.master.run_command(["rm", "-f", paths.SSH_CONFIG + ".orig"])
        self.master.run_command(["rm", "-f", paths.SSH_IPA_CONFIG + ".orig"])
        # Force client package reinstallation to trigger %post scriptlet
        tasks.reinstall_packages(self.master, ['*ipa-client'])
        assert not self.master.transport.file_exists(
            paths.SSH_CONFIG + ".orig")
        assert not self.master.transport.file_exists(
            paths.SSH_IPA_CONFIG + ".orig")

    def test_mspac_attribute_set(self):
        """
        This testcase deletes the already existing attribute
        'ipaKrbAuthzData: MS-PAC'.
        The test then runs ipa-server-upgrade and checks that
        the attribute 'ipaKrbAuthzData: MS-PAC' is added again.
        """
        base_dn = str(self.master.domain.basedn)
        dn = DN(
            ("cn", "ipaConfig"),
            ("cn", "etc"),
            base_dn
        )
        ldif = textwrap.dedent("""
             dn: cn=ipaConfig,cn=etc,{}
             changetype: modify
             delete: ipaKrbAuthzData
        """).format(base_dn)
        tasks.ldapmodify_dm(self.master, ldif)
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa-server-upgrade'])
        result = tasks.ldapsearch_dm(self.master, str(dn),
                                     ["ipaKrbAuthzData"])
        assert 'ipaKrbAuthzData: MS-PAC' in result.stdout_text
