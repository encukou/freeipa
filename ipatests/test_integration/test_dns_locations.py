#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#
import time
import dns.resolver
import dns.rrset
import dns.rdatatype
import dns.rdataclass

from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_plugins.integration import tasks
from ipapython.dnsutil import DNSName

IPA_DEFAULT_MASTER_SRV_REC = (
    # srv record name, port
    (DNSName(u'_ldap._tcp'), 389),
    (DNSName(u'_kerberos._tcp'), 88),
    (DNSName(u'_kerberos._udp'), 88),
    (DNSName(u'_kerberos-master._tcp'), 88),
    (DNSName(u'_kerberos-master._udp'), 88),
    (DNSName(u'_kpasswd._tcp'), 464),
    (DNSName(u'_kpasswd._udp'), 464),
)

IPA_DEFAULT_KDC_URI_REC = (
    # URI record name, target
    (DNSName(u'_kpasswd'), u'krb5srv:M:tcp:{server}'),
    (DNSName(u'_kpasswd'), u'krb5srv:M:udp:{server}'),
    (DNSName(u'_kerberos'), u'krb5srv:M:tcp:{server}'),
    (DNSName(u'_kerberos'), u'krb5srv:M:udp:{server}'),
)

IPA_KDCPROXY_PRIORITY_PENALIZATION = 10
IPA_DEFAULT_KDCPROXY_URI_REC = (
    # URI record name, target
    (DNSName(u'_kpasswd'), u'krb5srv:M:kkdcp:https://{server}/KdcProxy'),
    (DNSName(u'_kerberos'), u'krb5srv:M:kkdcp:https://{server}/KdcProxy'),
)


def resolve_records_from_server(rname, rtype, nameserver, logger):
    res = dns.resolver.Resolver()
    res.nameservers = [nameserver]
    res.lifetime = 10
    logger.debug("Query: %s %s, nameserver %s", rname, rtype, nameserver)
    ans = res.query(rname, rtype)
    logger.debug("Answer: %s", ans.rrset)
    return ans.rrset


def _gen_expected_srv_rrset(rname, port, servers, ttl=86400):
    rdata_list = [
        "{prio} {weight} {port} {servername}".format(
            prio=prio,
            weight=weight,
            port=port,
            servername=servername.make_absolute()
        )
        for prio, weight, servername in servers
    ]
    return dns.rrset.from_text_list(
        rname, ttl, dns.rdataclass.IN, dns.rdatatype.SRV, rdata_list
    )


def _gen_expected_kdc_uri_rrset(
        rname, target, servers, ttl=86400, priority_penalization=0):
    rdata_list = [
        "{prio} {weight} {target}".format(
            prio=prio + priority_penalization,
            weight=weight,
            target=target.format(server=servername)
        )
        for prio, weight, servername in servers
    ]
    return dns.rrset.from_text_list(
        rname, ttl, dns.rdataclass.IN, dns.rdatatype.URI, rdata_list
    )


class TestDNSLocations(IntegrationTest):
    """Simple test if SRV DNS records for IPA locations are generated properly

    Topology:
        * 3 servers (replica0 --- master --- replica1)
        * 2 locations (prague, paris)
    """
    num_replicas = 2
    topology = 'star'

    LOC_PRAGUE = u'prague'
    LOC_PARIS = u'paris'

    PRIO_HIGH = 0
    PRIO_LOW = 50
    WEIGHT = 100

    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_replica(cls.master, cls.replicas[0], setup_dns=True,
                              setup_ca=False)
        tasks.install_replica(cls.master, cls.replicas[1], setup_dns=True,
                              setup_ca=False)

        for host in (cls.master, cls.replicas[0], cls.replicas[1]):
            ldap = host.ldap_connect()
            tasks.wait_for_replication(ldap)

        # give time to named to retrieve new records
        time.sleep(20)

    def _test_against_server(self, server_ip, domain, expected_servers):
        for rname, port in IPA_DEFAULT_MASTER_SRV_REC:
            name_abs = rname.derelativize(domain)
            expected = _gen_expected_srv_rrset(
                name_abs, port, expected_servers)
            query = resolve_records_from_server(
                name_abs, 'SRV', server_ip, self.log)
            assert expected == query, (
                "Expected and received DNS data do not match on server "
                "with IP: '{}' for name '{}' (expected:\n{}\ngot:\n{})".format(
                    server_ip, name_abs, expected, query))

        for records, penalization in (
            (IPA_DEFAULT_KDC_URI_REC, 0),
            (IPA_DEFAULT_KDCPROXY_URI_REC, IPA_KDCPROXY_PRIORITY_PENALIZATION)
        ):
            expected = None
            for rname, target in records:
                name_abs = rname.derelativize(domain)
                res = _gen_expected_kdc_uri_rrset(
                    name_abs, target, expected_servers,
                    priority_penalization=penalization
                )
                if expected:
                    expected.update(res)
                else:
                    expected = res
            query = resolve_records_from_server(
                name_abs, 'URI', server_ip, self.log)
            assert expected == query, (
                "Expected and received DNS data do not match on server "
                "with IP: '{}' for name '{}' (expected:\n{}\ngot:\n{}"
                ")".format(server_ip, name_abs, expected, query))

    def test_without_locations(self):
        """Servers are not in locations, this tests if basic system records
        are generated properly"""
        domain = DNSName(self.master.domain.name).make_absolute()
        expected_servers = (
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        for ip in (self.master.ip, self.replicas[0].ip, self.replicas[1].ip):
            self._test_against_server(ip, domain, expected_servers)

    def test_nsupdate_without_locations(self):
        """Test nsupdate file generated by dns-update-system-records
        Remove all records and the use nsupdate to restore state and test if
        all record are there as expected"""
        domain = DNSName(self.master.domain.name).make_absolute()
        filepath = '/tmp/ipa.nsupdate'
        self.master.run_command([
            'ipa', 'dns-update-system-records', '--dry-run', '--out', filepath
        ])

        # delete original records first
        for rname, _port in IPA_DEFAULT_MASTER_SRV_REC:
            self.master.run_command([
                'ipa', 'dnsrecord-del', str(domain), str(rname), '--del-all'
            ])

        # allow unauthenticates nsupdate (no need to testing authentication)
        self.master.run_command([
            'ipa', 'dnszone-mod', str(domain),
            '--update-policy=grant * wildcard *;'
        ])
        self.master.run_command(['nsupdate', '-g', filepath])
        time.sleep(5)  # give time to named to process everything from update
        self.test_without_locations()

    def test_one_replica_in_location(self):
        """Put one replica to location and test if records changed properly
        """

        # create location prague, replica0 --> location prague
        self.master.run_command([
            'ipa', 'location-add', self.LOC_PRAGUE
        ])
        self.master.run_command([
            'ipa', 'server-mod', self.replicas[0].hostname,
            '--location', self.LOC_PRAGUE
        ])
        tasks.restart_named(self.replicas[0])

        servers_without_loc = (
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_without_loc = DNSName(self.master.domain.name).make_absolute()

        servers_prague_loc = (
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_prague_loc = (
            DNSName('{}._locations'.format(self.LOC_PRAGUE)) +
            DNSName(self.master.domain.name).make_absolute()
        )

        self._test_against_server(
            self.replicas[0].ip, domain_prague_loc, servers_prague_loc)

        for ip in (self.master.ip, self.replicas[1].ip):
            self._test_against_server(
                ip, domain_without_loc, servers_without_loc)

    def test_two_replicas_in_location(self):
        """Put second replica to location and test if records changed properly
        """

        # create location paris, replica1 --> location prague
        self.master.run_command(['ipa', 'location-add', self.LOC_PARIS])
        self.master.run_command([
            'ipa', 'server-mod', self.replicas[1].hostname, '--location',
            self.LOC_PARIS])
        tasks.restart_named(self.replicas[1])

        servers_without_loc = (
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_without_loc = DNSName(self.master.domain.name).make_absolute()

        servers_prague_loc = (
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_prague_loc = (
            DNSName('{}._locations'.format(self.LOC_PRAGUE)) + DNSName(
                self.master.domain.name).make_absolute())

        servers_paris_loc = (
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_paris_loc = (
            DNSName('{}._locations'.format(self.LOC_PARIS)) + DNSName(
                self.master.domain.name).make_absolute())

        self._test_against_server(
            self.replicas[0].ip, domain_prague_loc, servers_prague_loc)

        self._test_against_server(
            self.replicas[1].ip, domain_paris_loc, servers_paris_loc)

        self._test_against_server(
            self.master.ip, domain_without_loc, servers_without_loc)

    def test_all_servers_in_location(self):
        """Put master (as second server) to location and test if records
        changed properly
        """

        # master --> location paris
        self.master.run_command([
            'ipa', 'server-mod', self.master.hostname, '--location',
            self.LOC_PARIS])
        tasks.restart_named(self.master)

        servers_prague_loc = (
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_prague_loc = (
            DNSName('{}._locations'.format(self.LOC_PRAGUE)) + DNSName(
                self.master.domain.name).make_absolute())

        servers_paris_loc = (
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.master.hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_paris_loc = (
            DNSName('{}._locations'.format(self.LOC_PARIS)) + DNSName(
                self.master.domain.name).make_absolute())

        self._test_against_server(
            self.replicas[0].ip, domain_prague_loc, servers_prague_loc)

        for ip in (self.replicas[1].ip, self.master.ip):
            self._test_against_server(ip, domain_paris_loc, servers_paris_loc)

    def test_change_weight(self):
        """Change weight of master and test if records changed properly
        """

        new_weight = 2000

        self.master.run_command([
            'ipa', 'server-mod', self.master.hostname, '--service-weight',
            str(new_weight)
        ])

        # all servers must be restarted
        tasks.restart_named(self.master, self.replicas[0], self.replicas[1])

        servers_prague_loc = (
            (self.PRIO_LOW, new_weight, DNSName(self.master.hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_prague_loc = (
            DNSName('{}._locations'.format(self.LOC_PRAGUE)) + DNSName(
                self.master.domain.name).make_absolute())

        servers_paris_loc = (
            (self.PRIO_HIGH, new_weight, DNSName(self.master.hostname)),
            (self.PRIO_LOW, self.WEIGHT, DNSName(self.replicas[0].hostname)),
            (self.PRIO_HIGH, self.WEIGHT, DNSName(self.replicas[1].hostname)),
        )
        domain_paris_loc = (
            DNSName('{}._locations'.format(self.LOC_PARIS)) + DNSName(
                self.master.domain.name).make_absolute())

        self._test_against_server(
            self.replicas[0].ip, domain_prague_loc, servers_prague_loc)

        for ip in (self.replicas[1].ip, self.master.ip):
            self._test_against_server(ip, domain_paris_loc, servers_paris_loc)
