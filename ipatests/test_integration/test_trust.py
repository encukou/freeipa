# Copyright (C) 2019  FreeIPA Contributors see COPYING for license

from __future__ import absolute_import

import re
import unittest

from ipaplatform.paths import paths
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


class TestTrust(IntegrationTest):
    topology = 'line'
    num_ad_domains = 1

    upn_suffix = 'UPNsuffix.com'
    upn_username = 'upnuser'
    upn_name = 'UPN User'
    upn_principal = '{}@{}'.format(upn_username, upn_suffix)
    upn_password = 'Secret123456'

    shared_secret = 'qwertyuiopQq!1'

    @classmethod
    def install(cls, mh):
        if not cls.master.transport.file_exists('/usr/bin/rpcclient'):
            raise unittest.SkipTest("Package samba-client not available "
                                    "on {}".format(cls.master.hostname))
        super(TestTrust, cls).install(mh)
        cls.ad = cls.ads[0]  # pylint: disable=no-member
        cls.ad_domain = cls.ad.domain.name
        tasks.install_adtrust(cls.master)
        cls.check_sid_generation()

    @classmethod
    def check_sid_generation(cls):
        command = ['ipa', 'user-show', 'admin', '--all', '--raw']

        # TODO: remove duplicate definition and import from common module
        _sid_identifier_authority = '(0x[0-9a-f]{1,12}|[0-9]{1,10})'
        sid_regex = 'S-1-5-21-%(idauth)s-%(idauth)s-%(idauth)s'\
                    % dict(idauth=_sid_identifier_authority)
        stdout_re = re.escape('  ipaNTSecurityIdentifier: ') + sid_regex

        tasks.run_repeatedly(cls.master, command,
                             test=lambda x: re.search(stdout_re, x))

    def configure_dns_and_time(self, ad_host):
        tasks.configure_dns_for_trust(self.master, ad_host)
        tasks.sync_time(self.master, ad_host)

    def check_trustdomains(self, realm, expected_ad_domains):
        """Check that ipa trustdomain-find lists all expected domains"""
        result = self.master.run_command(['ipa', 'trustdomain-find', realm])
        for domain in expected_ad_domains:
            expected_text = 'Domain name: %s\n' % domain
            assert expected_text in result.stdout_text
        expected_text = ("Number of entries returned %s\n" %
                         len(expected_ad_domains))
        assert expected_text in result.stdout_text

    def check_range_properties(self, realm, expected_type, expected_size):
        """Check the properties of the created range"""
        range_name = realm.upper() + '_id_range'
        result = self.master.run_command(['ipa', 'idrange-show', range_name,
                                          '--all', '--raw'])
        expected_text = 'ipaidrangesize: %s\n' % expected_size
        assert expected_text in result.stdout_text
        expected_text = 'iparangetype: %s\n' % expected_type
        assert expected_text in result.stdout_text

    def remove_trust(self, ad):
        tasks.remove_trust_with_ad(self.master, ad.domain.name)
        tasks.unconfigure_dns_for_trust(self.master, ad)
        tasks.clear_sssd_cache(self.master)

    # Tests for non-posix AD trust

    def test_establish_nonposix_trust(self):
        self.configure_dns_and_time(self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust'])

    def test_trustdomains_found_in_nonposix_trust(self):
        self.check_trustdomains(
            self.ad_domain, [self.ad_domain])

    def test_range_properties_in_nonposix_trust(self):
        self.check_range_properties(self.ad_domain, 'ipa-ad-trust', 200000)

    def test_user_gid_uid_resolution_in_nonposix_trust(self):
        """Check that user has SID-generated UID"""
        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        # This regex checks that Test User does not have UID 10042 nor belongs
        # to the group with GID 10047
        testuser_regex = r"^testuser@%s:\*:(?!10042)(\d+):(?!10047)(\d+):"\
                         r"Test User:/home/%s/testuser:/bin/sh$"\
                         % (re.escape(self.ad_domain),
                            re.escape(self.ad_domain))

        assert re.search(
            testuser_regex, result.stdout_text), result.stdout_text

    def test_ipauser_authentication_with_nonposix_trust(self):
        ipauser = u'tuser'
        original_passwd = 'Secret123'
        new_passwd = 'userPasswd123'

        # create an ipauser for this test
        self.master.run_command(['ipa', 'user-add', ipauser, '--first=Test',
                                 '--last=User', '--password'],
                                stdin_text=original_passwd)

        # change password for the user to be able to kinit
        tasks.ldappasswd_user_change(ipauser, original_passwd, new_passwd,
                                     self.master)

        # try to kinit as ipauser
        self.master.run_command([
            'kinit', '-E', '{0}@{1}'.format(ipauser, self.master.domain.name)],
            stdin_text=new_passwd)

    # Tests for UPN suffixes

    def test_upn_in_nonposix_trust(self):
        """Check that UPN is listed as trust attribute"""
        result = self.master.run_command(['ipa', 'trust-show', self.ad_domain,
                                          '--all', '--raw'])

        assert ("ipantadditionalsuffixes: {}".format(self.upn_suffix) in
                result.stdout_text)

    def test_upn_user_resolution_in_nonposix_trust(self):
        """Check that user with UPN can be resolved"""
        result = self.master.run_command(['getent', 'passwd',
                                          self.upn_principal])

        # result will contain AD domain, not UPN
        upnuser_regex = (
            r"^{}@{}:\*:(\d+):(\d+):{}:/home/{}/{}:/bin/sh$".format(
                self.upn_username, self.ad_domain, self.upn_name,
                self.ad_domain, self.upn_username)
        )
        assert re.search(upnuser_regex, result.stdout_text), result.stdout_text

    def test_upn_user_authentication_in_nonposix_trust(self):
        """ Check that AD user with UPN can authenticate in IPA """
        self.master.run_command(['kinit', '-C', '-E', self.upn_principal],
                                stdin_text=self.upn_password)

    def test_remove_nonposix_trust(self):
        self.remove_trust(self.ad)

    # Tests for posix AD trust

    def test_establish_posix_trust(self):
        self.configure_dns_and_time(self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust-posix'])

    def test_trustdomains_found_in_posix_trust(self):
        """Tests that all trustdomains can be found."""
        self.check_trustdomains(
            self.ad_domain, [self.ad_domain])

    def test_range_properties_in_posix_trust(self):
        """Check the properties of the created range"""
        self.check_range_properties(self.ad_domain, 'ipa-ad-trust-posix',
                                    200000)

    def test_user_uid_gid_resolution_in_posix_trust(self):
        """Check that user has AD-defined UID"""

        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        testuser_stdout = "testuser@%s:*:10042:10047:"\
                          "Test User:/home/%s/testuser:/bin/sh"\
                          % (self.ad_domain, self.ad_domain)

        assert testuser_stdout in result.stdout_text

    def test_user_without_posix_attributes_not_visible(self):
        """Check that user has AD-defined UID"""

        # Using domain name since it is lowercased realm name for AD domains
        nonposixuser = 'nonposixuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', nonposixuser],
                                         raiseonerr=False)

        # Getent exits with 2 for non-existent user
        assert result.returncode == 2

    def test_override_homedir(self):
        """Check that POSIX attributes, such as shell or
        home directory should not be overwritten or missing.

        Related ticket https://pagure.io/SSSD/sssd/issue/2474
        """
        tasks.backup_file(self.master, paths.SSSD_CONF)
        testuser = 'testuser@%s' % self.ad_domain
        try:
            domain = self.master.domain
            tasks.modify_sssd_conf(
                self.master,
                domain.name,
                {
                    'subdomain_homedir': '%o'
                }
            )
            tasks.clear_sssd_cache(self.master)
            self.master.run_command(['getent', 'initgroups', '-s', 'sss', testuser])

            result = self.master.run_command(['getent', 'passwd', testuser])
            assert "/home/testuser" in result.stdout_text
            log_file = "/var/log/sssd/sssd_{0}.log" .format(self.master.domain.name)
            sssd_debug_log = self.master.get_file_contents(
                log_file, encoding='utf-8'
            )
            assert 'get_subdomain_homedir_of_user failed' not in sssd_debug_log
        finally:
            tasks.restore_files(self.master)
            tasks.clear_sssd_cache(self.master)

    def test_remove_posix_trust(self):
        self.remove_trust(self.ad)

    # Tests for handling invalid trust types

    def test_invalid_range_types(self):

        invalid_range_types = ['ipa-local',
                               'ipa-ad-winsync',
                               'ipa-ipa-trust',
                               'random-invalid',
                               're@ll%ybad12!']

        self.configure_dns_and_time(self.ad)
        try:
            for range_type in invalid_range_types:
                tasks.kinit_admin(self.master)

                result = self.master.run_command(
                    ['ipa', 'trust-add', '--type', 'ad', self.ad_domain,
                     '--admin', 'Administrator',
                     '--range-type', range_type, '--password'],
                    raiseonerr=False,
                    stdin_text=self.master.config.ad_admin_password)

                # The trust-add command is supposed to fail
                assert result.returncode == 1
                assert "ERROR: invalid 'range_type'" in result.stderr_text
        finally:
            tasks.unconfigure_dns_for_trust(self.master, self.ad)

    # Tests for external trust with AD subdomain

    # Tests for external trust with tree domain

    # Tests for external trust with root domain

    def test_establish_external_rootdomain_trust(self):
        self.configure_dns_and_time(self.ad)
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain,
            extra_args=['--range-type', 'ipa-ad-trust', '--external=True'])

    def test_trustdomains_found_in_external_rootdomain_trust(self):
        self.check_trustdomains(self.ad_domain, [self.ad_domain])

    def test_remove_external_rootdomain_trust(self):
        self.remove_trust(self.ad)

    # Test for one-way forest trust with shared secret

    # Test for one-way external trust with shared secret

    def test_establish_external_trust_with_shared_secret(self):
        self.configure_dns_and_time(self.ad)
        tasks.configure_windows_dns_for_trust(self.ad, self.master)

        # create windows side of trust using netdom.exe utility
        self.ad.run_command(
            ['netdom.exe', 'trust', self.master.domain.name,
             '/d:' + self.ad.domain.name,
             '/passwordt:' + self.shared_secret, '/add', '/oneside:TRUSTED'])

        # create ipa side of trust
        tasks.establish_trust_with_ad(
            self.master, self.ad_domain, shared_secret=self.shared_secret,
            extra_args=['--range-type', 'ipa-ad-trust', '--external=True'])

    def test_trustdomains_found_in_external_trust_with_shared_secret(self):
        result = self.master.run_command(
            ['ipa', 'trust-fetch-domains', self.ad.domain.name],
            raiseonerr=False)
        assert result.returncode == 1
        self.check_trustdomains(
            self.ad_domain, [self.ad_domain])

    def test_user_uid_resolution_in_external_trust_with_shared_secret(self):
        """Check that user has SID-generated UID"""
        # Using domain name since it is lowercased realm name for AD domains
        testuser = 'testuser@%s' % self.ad_domain
        result = self.master.run_command(['getent', 'passwd', testuser])

        # This regex checks that Test User does not have UID 10042 nor belongs
        # to the group with GID 10047
        testuser_regex = r"^testuser@%s:\*:(?!10042)(\d+):(?!10047)(\d+):"\
                         r"Test User:/home/%s/testuser:/bin/sh$"\
                         % (re.escape(self.ad_domain),
                            re.escape(self.ad_domain))

        assert re.search(
            testuser_regex, result.stdout_text), result.stdout_text

    def test_remove_external_trust_with_shared_secret(self):
        self.ad.run_command(
            ['netdom.exe', 'trust', self.master.domain.name,
             '/d:' + self.ad.domain.name, '/remove', '/oneside:TRUSTED']
        )
        self.remove_trust(self.ad)
        tasks.unconfigure_windows_dns_for_trust(self.ad, self.master)
