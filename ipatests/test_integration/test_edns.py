#
# Copyright (C) 2024  FreeIPA Contributors see COPYING for license
#
"""This covers tests for DNS over TLS related feature"""

from __future__ import absolute_import
import textwrap

from ipatests.pytest_ipa.integration import tasks
from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration.test_dns import TestDNS
from ipatests.pytest_ipa.integration.firewall import Firewall
from ipaplatform.paths import paths


class TestDNSOverTLS(IntegrationTest):
    """Tests for DNS over TLS feature."""

    topology = 'line'
    num_replicas = 1
    num_clients = 1

    @classmethod
    def install(cls, mh):
        Firewall(cls.master).enable_service("dns-over-tls")
        Firewall(cls.replicas[0]).enable_service("dns-over-tls")
        tasks.install_packages(cls.master, ['*ipa-server-encrypted-dns'])
        tasks.install_packages(cls.replicas[0], ['*ipa-server-encrypted-dns'])
        tasks.install_packages(cls.clients[0], ['*ipa-client-encrypted-dns'])

    def test_install_dnsovertls_invalid_ca(self):
        """
        This test checks that the installers throws an error
        when invalid cert is specified.
        """
        bad_ca_cnf = textwrap.dedent("""
        [ req ]
        x509_extensions = v3_ca
        [ v3_ca ]
        basicConstraints = critical,CA:false
        """)
        self.master.put_file_contents("/bad_ca.cnf", bad_ca_cnf)
        self.master.run_command(["openssl", "req", "-newkey", "rsa:2048",
                                 "-nodes", "-keyout",
                                 "/etc/pki/tls/certs/privkey-invalid.pem",
                                 "-x509", "-days", "36500", "-out",
                                 "/etc/pki/tls/certs/certificate-invalid.pem",
                                 "-subj",
                                 ("/C=ES/ST=Andalucia/L=Sevilla/O=CompanyName/"
                                  "OU=IT/CN=www.example.com/"
                                  "emailAddress=email@example.com"),
                                 "-config", "/bad_ca.cnf"])
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--dns-over-tls-cert",
            "/etc/pki/tls/certs/certificate-invalid.pem",
            "--dns-over-tls-key",
            "/etc/pki/tls/certs/privkey-invalid.pem"
        ]
        res = tasks.install_master(self.master, extra_args=args,
                                   raiseonerr=False)
        assert "Not a valid CA certificate: " in res.stderr_text
        tasks.uninstall_master(self.master)

    def test_install_dnsovertls_without_setup_dns_master(self):
        """
        This test installs an IPA server using the --dns-over-tls option
        without using setup-dns option, and captures warnings that appear.
        """
        self.master.run_command(["ipa-server-install", "--uninstall", "-U"])
        args = [
            "--dns-over-tls",
        ]
        res = tasks.install_master(
            self.master, extra_args=args, setup_dns=False)
        assert ("Warning: --dns-over-tls option specified without "
                "--setup-dns, ignoring") in res.stdout_text
        tasks.uninstall_master(self.master)

    def test_install_dnsovertls_master(self):
        """
        This tests installs IPA server with --dns-over-tls option.
        """
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
        ]
        return tasks.install_master(self.master, extra_args=args)

    def test_install_dnsovertls_client(self):
        """
        This tests installs IPA client with --dns-over-tls option.
        """
        self.clients[0].put_file_contents(
            paths.RESOLV_CONF,
            "nameserver %s" % self.master.ip
        )
        args = [
            "--dns-over-tls"
        ]
        return tasks.install_client(self.master,
                                    self.clients[0],
                                    nameservers=None,
                                    extra_args=args)

    def test_install_dnsovertls_replica(self):
        """
        This tests installs IPA replica with --dns-over-tls option.
        """
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
        ]
        return tasks.install_replica(self.master, self.replicas[0],
                                     setup_dns=True, extra_args=args)

    def test_queries_encrypted(self):
        """
        This test performs queries from each of the hosts
        and ensures they were routed to 1.1.1.1#853 (eDNS).
        """
        unbound_log_cfg = textwrap.dedent("""
        server:
            verbosity: 3
            log-queries: yes
        """)
        # Test servers first (querying to local Unbound)
        for server in [self.master, self.replicas[0]]:
            server.put_file_contents("/etc/unbound/conf.d/log.conf",
                                     unbound_log_cfg)
            server.run_command(["systemctl", "restart", "unbound"])
            server.run_command(["journalctl", "--flush", "--rotate",
                                "--vacuum-time=1s"])
            server.run_command(["dig", "freeipa.org"])
            server.run_command(["journalctl", "-u", "unbound",
                                "--grep=1.1.1.1#853"])
            server.run_command(["journalctl", "--flush", "--rotate",
                                "--vacuum-time=1s"])
        # Now, test the client (redirects query to master)
        self.clients[0].run_command(["dig", "redhat.com"])
        self.master.run_command(["journalctl", "-u", "unbound",
                                 "--grep=1.1.1.1#853"])

    def test_uninstall_all(self):
        """
        This test ensures that all hosts can be uninstalled correctly.
        """
        tasks.uninstall_client(self.clients[0])
        tasks.uninstall_replica(self.master, self.replicas[0])
        tasks.uninstall_master(self.master)

    def test_install_dnsovertls_master_external_ca(self):
        """
        This test ensures that IPA server can be installed
        with DoT using an external CA.
        """
        self.master.run_command(["openssl", "req", "-newkey", "rsa:2048",
                                 "-nodes", "-keyout",
                                 "/etc/pki/tls/certs/privkey.pem", "-x509",
                                 "-days", "36500", "-out",
                                 "/etc/pki/tls/certs/certificate.pem", "-subj",
                                 ("/C=ES/ST=Andalucia/L=Sevilla/O=CompanyName/"
                                  "OU=IT/CN={}/"
                                  "emailAddress=email@example.com")
                                 .format(self.master.hostname)])
        self.master.run_command(["chown", "named:named",
                                 "/etc/pki/tls/certs/privkey.pem",
                                 "/etc/pki/tls/certs/certificate.pem"])
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com",
            "--dns-over-tls-cert", "/etc/pki/tls/certs/certificate.pem",
            "--dns-over-tls-key", "/etc/pki/tls/certs/privkey.pem"
        ]
        return tasks.install_master(self.master, extra_args=args)

    def test_enrollments_external_ca(self):
        """
        Test that replicas and clients can be deployed when the master
        uses an external CA.
        """
        tasks.copy_files(self.master, self.clients[0],
                         ["/etc/pki/tls/certs/certificate.pem"])
        self.clients[0].run_command(["mv",
                                     "/etc/pki/tls/certs/certificate.pem",
                                     "/etc/pki/ca-trust/source/anchors/"])
        self.clients[0].run_command(["update-ca-trust", "extract"])
        self.test_install_dnsovertls_client()
        self.test_install_dnsovertls_replica()
        self.test_queries_encrypted()

    def test_install_dnsovertls_with_invalid_ipaddress_master(self):
        """
        This test installs an IPA server using the --dns-over-tls
        option with an invalid IP address.
        """
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "198.168.0.0.1#example-dns.test",
        ]
        res = tasks.install_master(self.master, extra_args=args,
                                   raiseonerr=False)
        assert ("--dot-forwarder invalid: DoT forwarder must be in "
                "the format of '1.2.3.4#dns.example.test'") in res.stderr_text
        tasks.uninstall_master(self.master)

    def test_validate_DoT_options_master(self):
        """
        Tests that DoT options are displayed correctly on master.
        """
        cmdout = self.master.run_command(
            ['ipa-server-install', '--help'])
        assert '''--dot-forwarder=DOT_FORWARDERS
                        Add a DNS over TLS forwarder. This option can be used
                        multiple times''' in cmdout.stdout_text  # noqa: E501
        assert '''--dns-over-tls-cert=DNS_OVER_TLS_CERT
                        Certificate to use for DNS over TLS. If empty, a new
                        certificate will be requested from IPA CA''' in cmdout.stdout_text  # noqa: E501
        assert '''--dns-over-tls-key=DNS_OVER_TLS_KEY
                        Key for certificate specified in --dns-over-tls-cert''' in cmdout.stdout_text  # noqa: E501
        assert '''--dns-over-tls      Configure DNS over TLS''' in cmdout.stdout_text  # noqa: E501

    def test_validate_DoT_options_replica(self):
        """
        Tests that DoT options are displayed correctly on replica.
        """
        cmdout = self.replicas[0].run_command(
            ['ipa-server-install', '--help'])
        assert '''--dot-forwarder=DOT_FORWARDERS
                        Add a DNS over TLS forwarder. This option can be used
                        multiple times''' in cmdout.stdout_text
        assert '''--dns-over-tls-cert=DNS_OVER_TLS_CERT
                        Certificate to use for DNS over TLS. If empty, a new
                        certificate will be requested from IPA CA''' in cmdout.stdout_text  # noqa: E501
        assert '''--dns-over-tls-key=DNS_OVER_TLS_KEY
                        Key for certificate specified in --dns-over-tls-cert''' in cmdout.stdout_text  # noqa: E501
        assert '''--dns-over-tls      Configure DNS over TLS''' in cmdout.stdout_text  # noqa: E501

    def test_validate_DoT_options_client(self):
        """
        Tests that DoT options are displayed correctly on client.
        """
        cmdout = self.clients[0].run_command(
            ['ipa-client-install', '--help'])
        assert '''--dns-over-tls      Configure DNS over TLS''' in cmdout.stdout_text  # noqa: E501


class TestDNS_DoT(TestDNS):
    @classmethod
    def install(cls, mh):
        tasks.install_packages(cls.master, ['*ipa-server-encrypted-dns'])
        args = [
            "--dns-over-tls",
            "--dot-forwarder", "1.1.1.1#cloudflare-dns.com"
        ]
        tasks.install_master(cls.master, extra_args=args)
