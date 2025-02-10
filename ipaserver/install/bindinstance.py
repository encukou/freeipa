# Authors: Simo Sorce <ssorce@redhat.com>
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
from __future__ import print_function

import logging
import tempfile
import os
import netaddr
import re
import shutil
import sys
import time
import textwrap

import ldap
import six
from dns.exception import DNSException

from ipaserver.dns_data_management import (
    IPASystemRecords,
    IPADomainIsNotManagedByIPAError,
)
from ipaserver.install import installutils
from ipaserver.install import service
from ipaserver.install import sysupgrade
from ipaserver.masters import get_masters
from ipapython import ipaldap
from ipapython import ipautil
from ipapython import dnsutil
from ipapython.dnsutil import DNSName
from ipapython.dn import DN
from ipapython.admintool import ScriptError
import ipalib
from ipalib import api, errors
from ipalib.constants import IPA_CA_RECORD
from ipalib.install import dnsforwarders, certmonger
from ipaplatform import services
from ipaplatform.tasks import tasks
from ipaplatform.constants import constants
from ipaplatform.paths import paths
from ipalib.util import (validate_zonemgr_str, normalize_zonemgr,
                         get_dns_forward_zone_update_policy,
                         get_dns_reverse_zone_update_policy,
                         normalize_zone, get_reverse_zone_default,
                         zone_is_reverse, validate_dnssec_global_forwarder,
                         DNSSECSignatureMissingError, EDNS0UnsupportedError,
                         UnresolvableRecordError)

if six.PY3:
    unicode = str

logger = logging.getLogger(__name__)

named_conf_section_ipa_start_re = re.compile(r'\s*dyndb\s+"ipa"\s+"[^"]+"\s+{')
named_conf_section_options_start_re = re.compile(r'\s*options\s+{')
named_conf_section_end_re = re.compile('};')
named_conf_arg_ipa_re = re.compile(
    r'(?P<indent>\s*)(?P<name>\S+)\s"(?P<value>[^"]+)";')
named_conf_arg_options_re = re.compile(
    r'(?P<indent>\s*)(?P<name>\S+)\s+"(?P<value>[^"]+)"\s*;')
named_conf_arg_ipa_template = "%(indent)s%(name)s \"%(value)s\";\n"
named_conf_arg_options_template = "%(indent)s%(name)s \"%(value)s\";\n"
# non string args for options section
named_conf_arg_options_re_nonstr = re.compile(
    r'(?P<indent>\s*)(?P<name>\S+)\s+(?P<value>[^"]+)\s*;')
named_conf_arg_options_template_nonstr = "%(indent)s%(name)s %(value)s;\n"
# include directive
named_conf_include_re = re.compile(r'\s*include\s+"(?P<path>.*)"\s*;')
named_conf_include_template = "include \"%(path)s\";\n"

NAMED_SECTION_OPTIONS = "options"
NAMED_SECTION_IPA = "ipa"


def create_reverse():
    return ipautil.user_input(
        "Do you want to search for missing reverse zones?",
        True
    )


def named_conf_exists():
    """
    Checks that named.conf exists AND that it contains IPA-related config.

    """
    try:
        with open(paths.NAMED_CONF, 'r') as named_fd:
            lines = named_fd.readlines()
    except IOError:
        return False
    for line in lines:
        if named_conf_section_ipa_start_re.match(line):
            return True
    return False


def named_conf_get_directive(name, section=NAMED_SECTION_IPA, str_val=True):
    """Get a configuration option in bind-dyndb-ldap section of named.conf

    :str_val - set to True if directive value is string
        (only for NAMED_SECTION_OPTIONS)
    """
    if section == NAMED_SECTION_IPA:
        named_conf_section_start_re = named_conf_section_ipa_start_re
        named_conf_arg_re = named_conf_arg_ipa_re
    elif section == NAMED_SECTION_OPTIONS:
        named_conf_section_start_re = named_conf_section_options_start_re
        if str_val:
            named_conf_arg_re = named_conf_arg_options_re
        else:
            named_conf_arg_re = named_conf_arg_options_re_nonstr
    else:
        raise NotImplementedError('Section "%s" is not supported' % section)

    with open(paths.NAMED_CONF, 'r') as f:
        target_section = False
        for line in f:
            if named_conf_section_start_re.match(line):
                target_section = True
                continue
            if named_conf_section_end_re.match(line):
                if target_section:
                    break

            if target_section:
                match = named_conf_arg_re.match(line)

                if match and name == match.group('name'):
                    return match.group('value')
    return None


def named_conf_set_directive(name, value, section=NAMED_SECTION_IPA,
                             str_val=True):
    """
    Set configuration option in bind-dyndb-ldap section of named.conf.

    When the configuration option with given name does not exist, it
    is added at the end of ipa section in named.conf.

    If the value is set to None, the configuration option is removed
    from named.conf.

    :str_val - set to True if directive value is string
        (only for NAMED_SECTION_OPTIONS)
    """
    new_lines = []

    if section == NAMED_SECTION_IPA:
        named_conf_section_start_re = named_conf_section_ipa_start_re
        named_conf_arg_re = named_conf_arg_ipa_re
        named_conf_arg_template = named_conf_arg_ipa_template
    elif section == NAMED_SECTION_OPTIONS:
        named_conf_section_start_re = named_conf_section_options_start_re
        if str_val:
            named_conf_arg_re = named_conf_arg_options_re
            named_conf_arg_template = named_conf_arg_options_template
        else:
            named_conf_arg_re = named_conf_arg_options_re_nonstr
            named_conf_arg_template = named_conf_arg_options_template_nonstr
    else:
        raise NotImplementedError('Section "%s" is not supported' % section)

    with open(paths.NAMED_CONF, 'r') as f:
        target_section = False
        matched = False
        last_indent = "\t"
        for line in f:
            if named_conf_section_start_re.match(line):
                target_section = True
            if named_conf_section_end_re.match(line):
                if target_section and not matched and \
                        value is not None:
                    # create a new conf
                    new_conf = named_conf_arg_template \
                            % dict(indent=last_indent,
                                   name=name,
                                   value=value)
                    new_lines.append(new_conf)
                target_section = False

            if target_section and not matched:
                match = named_conf_arg_re.match(line)

                if match:
                    last_indent = match.group('indent')
                    if name == match.group('name'):
                        matched = True
                        if value is not None:
                            if not isinstance(value, str):
                                value = str(value)
                            new_conf = named_conf_arg_template \
                                    % dict(indent=last_indent,
                                           name=name,
                                           value=value)
                            new_lines.append(new_conf)
                        continue
            new_lines.append(line)

    # write new configuration
    with open(paths.NAMED_CONF, 'w') as f:
        f.write("".join(new_lines))


def named_conf_include_exists(path):
    """
    Check if include exists in named.conf
    :param path: path in include directive
    :return: True if include exists, else False
    """
    with open(paths.NAMED_CONF, 'r') as f:
        for line in f:
            match = named_conf_include_re.match(line)
            if match and path == match.group('path'):
                return True

    return False


def named_conf_add_include(path):
    """
    append include at the end of file
    :param path: path to be insert to include directive
    """
    with open(paths.NAMED_CONF, 'a') as f:
        f.write(named_conf_include_template % {'path': path})


def dns_container_exists(suffix):
    """
    Test whether the dns container exists.
    """
    assert isinstance(suffix, DN)
    return api.Backend.ldap2.entry_exists(DN(('cn', 'dns'), suffix))


def dns_zone_exists(name, api=api):
    try:
        zone = api.Command.dnszone_show(unicode(name))
    except ipalib.errors.NotFound:
        return False

    if len(zone) == 0:
        return False
    else:
        return True


def get_reverse_record_name(zone, ip_address):
    ip = netaddr.IPAddress(ip_address)
    rev = '.' + normalize_zone(zone)
    fullrev = '.' + normalize_zone(ip.reverse_dns)

    if not fullrev.endswith(rev):
        raise ValueError("IP address does not match reverse zone")

    return fullrev[1:-len(rev)]


def verify_reverse_zone(zone, ip_address):
    try:
        get_reverse_record_name(zone, ip_address)
    except ValueError:
        return False

    return True


def find_reverse_zone(ip_address, api=api):
    ip = netaddr.IPAddress(ip_address)
    zone = normalize_zone(ip.reverse_dns)

    while len(zone) > 0:
        if dns_zone_exists(zone, api):
            return zone
        zone = zone.partition('.')[2]

    return None


def read_reverse_zone(default, ip_address, allow_zone_overlap=False):
    while True:
        zone = ipautil.user_input("Please specify the reverse zone name", default=default)
        if not zone:
            return None
        if not verify_reverse_zone(zone, ip_address):
            logger.error("Invalid reverse zone %s for IP address %s",
                         zone, ip_address)
            continue
        if not allow_zone_overlap:
            try:
                dnsutil.check_zone_overlap(zone, raise_on_error=False)
            except dnsutil.DNSZoneAlreadyExists as e:
                logger.error("Reverse zone %s will not be used: %s",
                             zone, e)
                continue
        break

    return normalize_zone(zone)


def get_auto_reverse_zones(ip_addresses, allow_zone_overlap=False):
    auto_zones = []
    for ip in ip_addresses:
        try:
            dnsutil.resolve_address(str(ip))
        except DNSException:
            pass
        else:
            # PTR exist there is no reason to create reverse zone
            logger.info("Reverse record for IP address %s already exists", ip)
            continue

        default_reverse = get_reverse_zone_default(ip)
        if not allow_zone_overlap:
            try:
                dnsutil.check_zone_overlap(default_reverse)
            except ValueError as e:
                logger.info("Reverse zone %s for IP address %s already exists",
                            default_reverse, ip)
                logger.debug('%s', e)
                continue
        auto_zones.append((ip, default_reverse))
    return auto_zones


def add_zone(name, zonemgr=None, dns_backup=None, ns_hostname=None,
             update_policy=None, force=False, skip_overlap_check=False,
             api=api):

    # always normalize zones
    name = normalize_zone(name)

    if update_policy is None:
        if zone_is_reverse(name):
            update_policy = get_dns_reverse_zone_update_policy(api.env.realm, name)
        else:
            update_policy = get_dns_forward_zone_update_policy(api.env.realm)

    if not zonemgr:
        zonemgr = 'hostmaster.%s' % name

    if ns_hostname:
        ns_hostname = normalize_zone(ns_hostname)
        ns_hostname = unicode(ns_hostname)

    try:
        api.Command.dnszone_add(unicode(name),
                                idnssoamname=ns_hostname,
                                idnssoarname=unicode(zonemgr),
                                idnsallowdynupdate=True,
                                idnsupdatepolicy=unicode(update_policy),
                                idnsallowquery=u'any',
                                idnsallowtransfer=u'none',
                                skip_overlap_check=skip_overlap_check,
                                force=force)
    except (errors.DuplicateEntry, errors.EmptyModlist):
        pass


def add_rr(zone, name, type, rdata, dns_backup=None, api=api, **kwargs):
    addkw = {'%srecord' % str(type.lower()): unicode(rdata)}
    addkw.update(kwargs)
    try:
        api.Command.dnsrecord_add(unicode(zone), unicode(name), **addkw)
    except (errors.DuplicateEntry, errors.EmptyModlist):
        pass
    if dns_backup:
        dns_backup.add(zone, type, name, rdata)


def add_fwd_rr(zone, host, ip_address, api=api):
    addr = netaddr.IPAddress(ip_address)
    if addr.version == 4:
        add_rr(zone, host, "A", ip_address, None, api)
    elif addr.version == 6:
        add_rr(zone, host, "AAAA", ip_address, None, api)


def add_ptr_rr(zone, ip_address, fqdn, dns_backup=None, api=api):
    name = get_reverse_record_name(zone, ip_address)
    add_rr(zone, name, "PTR", normalize_zone(fqdn), dns_backup, api)


def add_ns_rr(zone, hostname, dns_backup=None, force=True, api=api):
    hostname = normalize_zone(hostname)
    add_rr(zone, "@", "NS", hostname, dns_backup=dns_backup,
           force=force, api=api)


def del_rr(zone, name, type, rdata, api=api):
    delkw = { '%srecord' % str(type.lower()) : unicode(rdata) }
    try:
        api.Command.dnsrecord_del(unicode(zone), unicode(name), **delkw)
    except (errors.NotFound, errors.AttrValueNotFound, errors.EmptyModlist):
        pass


def del_fwd_rr(zone, host, ip_address, api=api):
    addr = netaddr.IPAddress(ip_address)
    if addr.version == 4:
        del_rr(zone, host, "A", ip_address, api=api)
    elif addr.version == 6:
        del_rr(zone, host, "AAAA", ip_address, api=api)


def del_ns_rr(zone, name, rdata, api=api):
    del_rr(zone, name, 'NS', rdata, api=api)


def get_rr(zone, name, type, api=api):
    rectype = '%srecord' % unicode(type.lower())
    ret = api.Command.dnsrecord_find(unicode(zone), unicode(name))
    if ret['count'] > 0:
        for r in ret['result']:
            if rectype in r:
                return r[rectype]

    return []


def get_fwd_rr(zone, host, api=api):
    return [x for t in ("A", "AAAA") for x in get_rr(zone, host, t, api)]


def zonemgr_callback(option, opt_str, value, parser):
    """
    Properly validate and convert --zonemgr Option to IA5String
    """
    if value is not None:
        # validate the value first
        if six.PY3:
            try:
                validate_zonemgr_str(value)
            except ValueError as e:
                parser.error("invalid zonemgr: {}".format(e))
        else:
            try:
                # IDNA support requires unicode
                encoding = getattr(sys.stdin, 'encoding', None)
                if encoding is None:
                    encoding = 'utf-8'

                # value is of a string type in both py2 and py3
                if not isinstance(value, unicode):
                    value = value.decode(encoding)

                validate_zonemgr_str(value)
            except ValueError as e:
                # FIXME we can do this in better way
                # https://fedorahosted.org/freeipa/ticket/4804
                # decode to proper stderr encoding
                stderr_encoding = getattr(sys.stderr, 'encoding', None)
                if stderr_encoding is None:
                    stderr_encoding = 'utf-8'
                error = unicode(e).encode(stderr_encoding)
                parser.error(b"invalid zonemgr: " + error)

    parser.values.zonemgr = value


def check_reverse_zones(ip_addresses, reverse_zones, options, unattended,
                        search_reverse_zones=False):
    checked_reverse_zones = []

    if (not options.no_reverse and not reverse_zones
            and not options.auto_reverse):
        if unattended:
            options.no_reverse = True
        else:
            options.no_reverse = not create_reverse()

    # shortcut
    if options.no_reverse:
        return []

    # verify zones passed in options
    for rz in reverse_zones:
        # isn't the zone managed by someone else
        if not options.allow_zone_overlap:
            try:
                dnsutil.check_zone_overlap(rz)
            except ValueError as e:
                msg = "Reverse zone %s will not be used: %s" % (rz, e)
                if unattended:
                    raise ScriptError(msg)
                else:
                    logger.warning('%s', msg)
                continue
        checked_reverse_zones.append(normalize_zone(rz))

    # check that there is reverse zone for every IP
    ips_missing_reverse = []
    for ip in ip_addresses:
        if search_reverse_zones and find_reverse_zone(str(ip)):
            # reverse zone is already in LDAP
            continue
        for rz in checked_reverse_zones:
            if verify_reverse_zone(rz, ip):
                # reverse zone was entered by user
                break
        else:
            ips_missing_reverse.append(ip)

    # create reverse zone for IP addresses that does not have one
    for (ip, rz) in get_auto_reverse_zones(ips_missing_reverse,
                                           options.allow_zone_overlap):
        if options.auto_reverse:
            logger.info("Reverse zone %s will be created", rz)
            checked_reverse_zones.append(rz)
        elif unattended:
            logger.warning("Missing reverse record for IP address %s", ip)
        else:
            if ipautil.user_input("Do you want to create reverse zone for IP "
                                  "%s" % ip, True):
                rz = read_reverse_zone(rz, str(ip), options.allow_zone_overlap)
                checked_reverse_zones.append(rz)

    return checked_reverse_zones


def check_forwarders(dns_forwarders):
    print("Checking DNS forwarders, please wait ...")
    forwarders_dnssec_valid = True
    for forwarder in dns_forwarders:
        logger.debug("Checking DNS server: %s", forwarder)
        try:
            validate_dnssec_global_forwarder(forwarder)
        except DNSSECSignatureMissingError as e:
            forwarders_dnssec_valid = False
            logger.warning("DNS server %s does not support DNSSEC: %s",
                           forwarder, e)
            logger.warning(
                "Please fix forwarder configuration to enable DNSSEC "
                "support.\n"
            )
            print("DNS server %s: %s" % (forwarder, e))
            print("Please fix forwarder configuration to enable DNSSEC support.")
        except EDNS0UnsupportedError as e:
            forwarders_dnssec_valid = False
            logger.warning("DNS server %s does not support ENDS0 "
                           "(RFC 6891): %s", forwarder, e)
            logger.warning("Please fix forwarder configuration. "
                           "DNSSEC support cannot be enabled without EDNS0")
            print(("WARNING: DNS server %s does not support EDNS0 "
                   "(RFC 6891): %s" % (forwarder, e)))
        except UnresolvableRecordError as e:
            logger.error("DNS server %s: %s", forwarder, e)
            raise RuntimeError("DNS server %s: %s" % (forwarder, e))

    return forwarders_dnssec_valid


def remove_master_dns_records(hostname, realm):
    bind = BindInstance()
    bind.remove_master_dns_records(hostname, realm, realm.lower())
    bind.remove_server_ns_records(hostname)


def ensure_dnsserver_container_exists(ldap, api_instance, logger=logger):
    """
    Create cn=servers,cn=dns,$SUFFIX container. If logger is not None, emit a
    message that the container already exists when DuplicateEntry is raised
    """

    entry = ldap.make_entry(
        DN(api_instance.env.container_dnsservers, api_instance.env.basedn),
        {
            u'objectclass': [u'top', u'nsContainer'],
            u'cn': [u'servers']
        }
    )
    try:
        ldap.add_entry(entry)
    except errors.DuplicateEntry:
        logger.debug('cn=servers,cn=dns container already exists')


class DnsBackup:
    def __init__(self, service):
        self.service = service
        self.zones = {}

    def add(self, zone, record_type, host, rdata):
        """
        Backup a DNS record in the file store so it can later be removed.
        """
        if zone not in self.zones:
            zone_id = len(self.zones)
            self.zones[zone] = (zone_id, 0)
            self.service.backup_state("dns_zone_%s" % zone_id, zone)

        (zone_id, record_id) = self.zones[zone]
        self.service.backup_state("dns_record_%s_%s" % (zone_id, record_id),
                                  "%s %s %s" % (record_type, host, rdata))
        self.zones[zone] = (zone_id, record_id + 1)

    def clear_records(self, have_ldap):
        """
        Remove all records from the file store. If we are connected to
        ldap, we will also remove them there.
        """
        i = 0
        while True:
            zone = self.service.restore_state("dns_zone_%s" % i)
            if not zone:
                return

            j = 0
            while True:
                dns_record = self.service.restore_state("dns_record_%s_%s" % (i, j))
                if not dns_record:
                    break
                if have_ldap:
                    type, host, rdata = dns_record.split(" ", 2)
                    try:
                        delkw = { '%srecord' % str(type.lower()) : unicode(rdata) }
                        api.Command.dnsrecord_del(unicode(zone), unicode(host), **delkw)
                    except Exception:
                        pass
                j += 1

            i += 1


class BindInstance(service.Service):
    def __init__(self, fstore=None, api=api):
        super(BindInstance, self).__init__(
            "named",
            service_desc="DNS",
            fstore=fstore,
            api=api,
            service_user=constants.NAMED_USER,
            service_prefix=u'DNS',
            keytab=paths.NAMED_KEYTAB
        )
        self.dns_backup = DnsBackup(self)
        self.domain = None
        self.host = None
        self.ip_addresses = ()
        self.forwarders = ()
        self.forward_policy = None
        self.zonemgr = None
        self.no_dnssec_validation = False
        self.sub_dict = None
        self.reverse_zones = ()
        self.named_conflict = services.service('named-conflict', api)

    suffix = ipautil.dn_attribute_property('_suffix')

    def setup(self, fqdn, ip_addresses, realm_name, domain_name, forwarders,
              forward_policy, reverse_zones, zonemgr=None,
              no_dnssec_validation=False, dns_over_tls=False,
              dns_over_tls_cert=None, dns_over_tls_key=None,
              dns_policy=None):
        """Setup bindinstance for installation
        """
        self.setup_templating(
            fqdn=fqdn,
            realm_name=realm_name,
            domain_name=domain_name,
            no_dnssec_validation=no_dnssec_validation,
            dns_over_tls=dns_over_tls,
            dns_over_tls_cert=dns_over_tls_cert,
            dns_over_tls_key=dns_over_tls_key,
            dns_policy=dns_policy
        )
        self.ip_addresses = ip_addresses
        self.forwarders = forwarders
        self.forward_policy = forward_policy
        self.reverse_zones = reverse_zones

        if not zonemgr:
            self.zonemgr = 'hostmaster.%s' % normalize_zone(self.domain)
        else:
            self.zonemgr = normalize_zonemgr(zonemgr)

    def setup_templating(
        self, fqdn, realm_name, domain_name, no_dnssec_validation=None,
        dns_over_tls=None, dns_over_tls_cert=None, dns_over_tls_key=None,
        dns_policy=None
    ):
        """Setup bindinstance for templating
        """
        self.fqdn = fqdn
        self.realm = realm_name
        self.domain = domain_name
        self.host = fqdn.split(".")[0]
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.no_dnssec_validation = no_dnssec_validation
        self.dns_over_tls = dns_over_tls
        self.dns_over_tls_cert = dns_over_tls_cert
        self.dns_over_tls_key = dns_over_tls_key
        self.dns_policy = dns_policy
        self._setup_sub_dict()

    @property
    def host_domain(self):
        return self.fqdn.split(".", 1)[1]

    @property
    def first_instance(self):
        return not dns_container_exists(self.suffix)

    @property
    def host_in_rr(self):
        # when a host is not in a default domain, it needs to be referred
        # with FQDN and not in a domain-relative host name
        if not self.host_in_default_domain():
            return normalize_zone(self.fqdn)
        return self.host

    def host_in_default_domain(self):
        return normalize_zone(self.host_domain) == normalize_zone(self.domain)

    def create_file_with_system_records(self):
        system_records = IPASystemRecords(self.api, all_servers=True)
        text = u'\n'.join(
            IPASystemRecords.records_list_from_zone(
                system_records.get_base_records()
            )
        )
        with tempfile.NamedTemporaryFile(
                mode="w", prefix="ipa.system.records.",
                suffix=".db", delete=False
        ) as f:
            f.write(text)
            print("Please add records in this file to your DNS system:",
                  f.name)

    def create_instance(self):
        try:
            self.stop()
        except Exception:
            pass

        for ip_address in self.ip_addresses:
            if installutils.record_in_hosts(str(ip_address), self.fqdn) is None:
                installutils.add_record_to_hosts(str(ip_address), self.fqdn)

        # Make sure generate-rndc-key.sh runs before named restart
        self.step("generating rndc key file", self.__generate_rndc_key)

        if self.first_instance:
            self.step("adding DNS container", self.__setup_dns_container)

        if not dns_zone_exists(self.domain, self.api):
            self.step("setting up our zone", self.__setup_zone)
        if self.reverse_zones:
            self.step("setting up reverse zone", self.__setup_reverse_zone)

        self.step("setting up our own record", self.__add_self)
        if self.first_instance:
            self.step("setting up records for other masters", self.__add_others)
        # all zones must be created before this step
        self.step("adding NS record to the zones", self.__add_self_ns)
        # The service entry is used for LDAPI autobind. The keytab is no
        # longer used to authenticate the server. The server still needs
        # the keytab to handle incoming nsupdate requests with TSIG.
        self.step("setting up kerberos principal", self.__setup_principal)
        self.step("setting up LDAPI autobind", self.setup_autobind)
        self.step("setting up named.conf", self.setup_named_conf)
        self.step("setting up server configuration",
            self.__setup_server_configuration)

        # named has to be started after softhsm initialization
        # self.step("restarting named", self.__start)

        self.step("configuring named to start on boot", self.switch_service)
        self.step(
            "changing resolv.conf to point to ourselves",
            self.setup_resolv_conf
        )
        self.start_creation()

    def start_named(self):
        self.print_msg("Restarting named")
        self.__start()

    def __start(self):
        try:
            self.restart()
        except Exception as e:
            logger.error("Named service failed to start (%s)", e)
            print("named service failed to start")

    def switch_service(self):
        self.mask_conflict()
        self.__enable()

    def __enable(self):
        # We do not let the system start IPA components on its own,
        # Instead we reply on the IPA init script to start only enabled
        # components as found in our LDAP configuration tree
        try:
            self.ldap_configure('DNS', self.fqdn, None, self.suffix)
        except errors.DuplicateEntry:
            # service already exists (forced DNS reinstall)
            # don't crash, just report error
            logger.error("DNS service already exists")

    def mask_conflict(self):
        # disable named-conflict (either named or named-pkcs11)
        try:
            self.named_conflict.stop()
        except Exception as e:
            logger.debug("Unable to stop %s (%s)",
                         self.named_conflict.systemd_name, e)

        try:
            self.named_conflict.mask()
        except Exception as e:
            logger.debug("Unable to mask %s (%s)",
                         self.named_conflict.systemd_name, e)

    def _get_dnssec_validation(self):
        """get dnssec-validation value

        1) command line overwrite --no-dnssec-validation
        2) setting dnssec-enabled or dnssec-validation from named.conf
        3) "yes" by default

        Note: The dnssec-enabled is deprecated and defaults to "yes". If the
        setting is "no", then it is migrated as "dnssec-validation no".
        """
        dnssec_validation = "yes"
        if self.no_dnssec_validation:
            # command line overwrite
            logger.debug(
                "dnssec-validation 'no' command line overwrite"
            )
            dnssec_validation = "no"
        elif os.path.isfile(paths.NAMED_CONF):
            # get prev_ value from /etc/named.conf
            prev_dnssec_validation = named_conf_get_directive(
                "dnssec-validation",
                NAMED_SECTION_OPTIONS,
                str_val=False
            )
            prev_dnssec_enable = named_conf_get_directive(
                "dnssec-enable",
                NAMED_SECTION_OPTIONS,
                str_val=False
            )
            if prev_dnssec_validation == "no" or prev_dnssec_enable == "no":
                logger.debug(
                    "Setting dnssec-validation 'no' from existing %s",
                    paths.NAMED_CONF
                )
                logger.debug(
                    "dnssec-enabled was %s (None is yes)", prev_dnssec_enable
                )
                logger.debug(
                    "dnssec-validation was %s", prev_dnssec_validation
                )
                dnssec_validation = "no"
        assert dnssec_validation in {"yes", "no"}
        logger.info("dnssec-validation %s", dnssec_validation)
        return dnssec_validation

    def _setup_sub_dict(self):
        if paths.NAMED_CRYPTO_POLICY_FILE is not None:
            crypto_policy = 'include "{}";'.format(
                paths.NAMED_CRYPTO_POLICY_FILE
            )
        else:
            crypto_policy = "// not available"

        if self.dns_over_tls:
            named_tls_conf = textwrap.dedent("""\
                tls local-tls {{
                    \tkey-file "{}";
                    \tcert-file "{}";
                }};
            """).format(self.dns_over_tls_key, self.dns_over_tls_cert)
            unencrypted_iface = ("127.0.0.1" if self.dns_policy == "enforced"
                                 else "any")
            named_tls_options = textwrap.dedent("""\
                \tlisten-on { %s; };
                \tlisten-on tls local-tls { any; };
                \tlisten-on-v6 tls local-tls { any; };
            """ % unencrypted_iface)
        else:
            named_tls_options = ""
            named_tls_conf = ""

        self.sub_dict = dict(
            FQDN=self.fqdn,
            SERVER_ID=ipaldap.realm_to_serverid(self.realm),
            SUFFIX=self.suffix,
            MANAGED_KEYS_DIR=paths.NAMED_MANAGED_KEYS_DIR,
            ROOT_KEY=paths.NAMED_ROOT_KEY,
            NAMED_KEYTAB=self.keytab,
            RFC1912_ZONES=paths.NAMED_RFC1912_ZONES,
            NAMED_PID=paths.NAMED_PID,
            NAMED_VAR_DIR=paths.NAMED_VAR_DIR,
            BIND_LDAP_SO=paths.BIND_LDAP_SO,
            INCLUDE_CRYPTO_POLICY=crypto_policy,
            NAMED_CONF=paths.NAMED_CONF,
            NAMED_CUSTOM_CONF=paths.NAMED_CUSTOM_CONF,
            NAMED_CUSTOM_OPTIONS_CONF=paths.NAMED_CUSTOM_OPTIONS_CONF,
            NAMED_LOGGING_OPTIONS_CONF=paths.NAMED_LOGGING_OPTIONS_CONF,
            NAMED_DATA_DIR=constants.NAMED_DATA_DIR,
            NAMED_ZONE_COMMENT=constants.NAMED_ZONE_COMMENT,
            NAMED_DNSSEC_VALIDATION=self._get_dnssec_validation(),
            NAMED_DNS_OVER_TLS_OPTIONS_CONF=named_tls_options,
            NAMED_DNS_OVER_TLS_CONF=named_tls_conf,
        )

    def __setup_dns_container(self):
        self._ldap_mod("dns.ldif", self.sub_dict)
        self.__fix_dns_privilege_members()

    def __fix_dns_privilege_members(self):
        ldap = self.api.Backend.ldap2

        cn = 'Update PBAC memberOf %s' % time.time()
        task_dn = DN(('cn', cn), ('cn', 'memberof task'), ('cn', 'tasks'),
                     ('cn', 'config'))
        basedn = DN(self.api.env.container_privilege, self.api.env.basedn)
        entry = ldap.make_entry(
            task_dn,
            objectclass=['top', 'extensibleObject'],
            cn=[cn],
            basedn=[basedn],
            filter=['(objectclass=*)'],
            ttl=[10])
        ldap.add_entry(entry)

        start_time = time.time()
        while True:
            try:
                task = ldap.get_entry(task_dn)
            except errors.NotFound:
                break
            if 'nstaskexitcode' in task:
                break
            time.sleep(1)
            if time.time() > (start_time + 60):
                raise errors.TaskTimeout(task='memberof', task_dn=task_dn)

    def __setup_zone(self):
        # Always use force=True as named is not set up yet
        add_zone(self.domain, self.zonemgr, dns_backup=self.dns_backup,
                 ns_hostname=self.api.env.host, force=True,
                 skip_overlap_check=True, api=self.api)

        add_rr(self.domain, "_kerberos", "TXT", self.realm, api=self.api)

    def __add_self_ns(self):
        # add NS record to all zones
        ns_hostname = normalize_zone(self.api.env.host)
        result = self.api.Command.dnszone_find()
        for zone in result['result']:
            zone = unicode(zone['idnsname'][0])  # we need unicode due to backup
            logger.debug("adding self NS to zone %s apex", zone)
            add_ns_rr(zone, ns_hostname, self.dns_backup, force=True,
                      api=self.api)

    def __setup_reverse_zone(self):
        # Always use force=True as named is not set up yet
        for reverse_zone in self.reverse_zones:
            add_zone(reverse_zone, self.zonemgr, ns_hostname=self.api.env.host,
                     dns_backup=self.dns_backup, force=True,
                     skip_overlap_check=True, api=self.api)

    def __add_master_records(self, fqdn, addrs):
        host, zone = fqdn.split(".", 1)

        # Add forward and reverse records to self
        for addr in addrs:
            # Check first if the zone is a master zone
            # (if it is a forward zone, dns_zone_exists will return False)
            if dns_zone_exists(zone, api=self.api):
                add_fwd_rr(zone, host, addr, self.api)
            else:
                logger.debug("Skip adding record %s to a zone %s "
                             "not managed by IPA", addr, zone)

            reverse_zone = find_reverse_zone(addr, self.api)
            if reverse_zone:
                add_ptr_rr(reverse_zone, addr, fqdn, None, api=self.api)

    def __add_self(self):
        self.__add_master_records(self.fqdn, self.ip_addresses)

    def __add_others(self):
        entries = api.Backend.ldap2.get_entries(
            DN(api.env.container_masters, self.suffix),
            api.Backend.ldap2.SCOPE_ONELEVEL, None, ['dn'])

        for entry in entries:
            fqdn = entry.dn[0]['cn']
            if fqdn == self.fqdn:
                continue

            addrs = installutils.resolve_ip_addresses_nss(fqdn)

            logger.debug("Adding DNS records for master %s", fqdn)
            self.__add_master_records(fqdn, addrs)

    def __setup_principal(self):
        installutils.kadmin_addprinc(self.principal)

        # Store the keytab on disk
        self.fstore.backup_file(self.keytab)
        installutils.create_keytab(self.keytab, self.principal)
        p = self.move_service(self.principal)
        if p is None:
            # the service has already been moved, perhaps we're doing a DNS reinstall
            dns_principal = DN(('krbprincipalname', self.principal),
                               ('cn', 'services'), ('cn', 'accounts'), self.suffix)
        else:
            dns_principal = p

        # Make sure access is strictly reserved to the named user
        self.service_user.chown(self.keytab)
        os.chmod(self.keytab, 0o400)

        # modify the principal so that it is marked as an ipa service so that
        # it can host the memberof attribute, then also add it to the
        # dnsserver role group, this way the DNS is allowed to perform
        # DNS Updates
        dns_group = DN(('cn', 'DNS Servers'), ('cn', 'privileges'), ('cn', 'pbac'), self.suffix)
        mod = [(ldap.MOD_ADD, 'member', dns_principal)]

        try:
            api.Backend.ldap2.modify_s(dns_group, mod)
        except ldap.TYPE_OR_VALUE_EXISTS:
            pass
        except Exception as e:
            logger.critical("Could not modify principal's %s entry: %s",
                            dns_principal, str(e))
            raise

        # bind-dyndb-ldap persistent search feature requires both size and time
        # limit-free connection
        mod = [(ldap.MOD_REPLACE, 'nsTimeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsSizeLimit', '-1'),
               (ldap.MOD_REPLACE, 'nsIdleTimeout', '-1'),
               (ldap.MOD_REPLACE, 'nsLookThroughLimit', '-1')]
        try:
            api.Backend.ldap2.modify_s(dns_principal, mod)
        except Exception as e:
            logger.critical("Could not set principal's %s LDAP limits: %s",
                            dns_principal, str(e))
            raise

    def setup_autobind(self):
        self.add_autobind_entry(
            constants.NAMED_USER, constants.NAMED_GROUP, self.principal
        )

    def setup_named_conf(self, backup=False):
        """Create, update, or migrate named configuration files

        The method is used by installer and upgrade process. The named.conf
        is backed up the first time and overwritten every time. The user
        specific config files are created once and not modified in subsequent
        calls.

        The "dnssec-validation" option is migrated

        :returns: True if any config file was modified, else False
        """
        # files are owned by root:named and are readable by user and group
        uid = 0
        gid = constants.NAMED_GROUP.gid
        mode = 0o640

        changed = False

        if not self.fstore.has_file(paths.NAMED_CONF):
            self.fstore.backup_file(paths.NAMED_CONF)

        # named.conf
        txt = ipautil.template_file(
            os.path.join(paths.NAMED_CONF_SRC), self.sub_dict
        )
        with open(paths.NAMED_CONF) as f:
            old_txt = f.read()
        if txt == old_txt:
            logger.debug("%s is unmodified", paths.NAMED_CONF)
        else:
            if backup:
                if not os.path.isfile(paths.NAMED_CONF_BAK):
                    shutil.copyfile(paths.NAMED_CONF, paths.NAMED_CONF_BAK)
                    logger.info("created backup %s", paths.NAMED_CONF_BAK)
                else:
                    logger.warning(
                        "backup %s already exists", paths.NAMED_CONF_BAK
                    )

            with open(paths.NAMED_CONF, "w") as f:
                os.fchmod(f.fileno(), mode)
                os.fchown(f.fileno(), uid, gid)
                f.write(txt)

            logger.info("created new %s", paths.NAMED_CONF)
            changed = True

        # user configurations
        user_configs = (
            (paths.NAMED_CUSTOM_CONF_SRC, paths.NAMED_CUSTOM_CONF),
            (
                paths.NAMED_CUSTOM_OPTIONS_CONF_SRC,
                paths.NAMED_CUSTOM_OPTIONS_CONF
            ),
            (
                paths.NAMED_LOGGING_OPTIONS_CONF_SRC,
                paths.NAMED_LOGGING_OPTIONS_CONF,
            ),
        )
        for src, dest in user_configs:
            if not os.path.exists(dest):
                txt = ipautil.template_file(src, self.sub_dict)
                with open(dest, "w") as f:
                    os.fchmod(f.fileno(), mode)
                    os.fchown(f.fileno(), uid, gid)
                    f.write(txt)
                logger.info("created named user config '%s'", dest)
                changed = True
            else:
                logger.info("named user config '%s' already exists", dest)

        return changed

    def __setup_server_configuration(self):
        ensure_dnsserver_container_exists(api.Backend.ldap2, self.api)
        try:
            self.api.Command.dnsserver_add(
                self.fqdn, idnssoamname=DNSName(self.fqdn).make_absolute(),
            )
        except errors.DuplicateEntry:
            # probably reinstallation of DNS
            pass

        try:
            self.api.Command.dnsserver_mod(
                self.fqdn,
                idnsforwarders=[unicode(f) for f in self.forwarders],
                idnsforwardpolicy=unicode(self.forward_policy)
            )
        except errors.EmptyModlist:
            pass

        sysupgrade.set_upgrade_state('dns', 'server_config_to_ldap', True)

    def setup_resolv_conf(self):
        searchdomains = [self.domain]
        nameservers = set()
        resolve1_enabled = dnsforwarders.detect_resolve1_resolv_conf()

        for ip_address in self.ip_addresses:
            if ip_address.version == 4:
                nameservers.add("127.0.0.1")
            elif ip_address.version == 6:
                nameservers.add("::1")

        try:
            tasks.configure_dns_resolver(
                sorted(nameservers), searchdomains,
                resolve1_enabled=resolve1_enabled, fstore=self.fstore
            )
        except IOError as e:
            logger.error('Could not update DNS config: %s', e)
        else:
            # python DNS might have global resolver cached in this variable
            # we have to re-initialize it because resolv.conf has changed
            dnsutil.reset_default_resolver()

    def __generate_rndc_key(self):
        installutils.check_entropy()
        ipautil.run([paths.GENERATE_RNDC_KEY])

    def add_master_dns_records(self, fqdn, ip_addresses, realm_name, domain_name,
                               reverse_zones):
        self.fqdn = fqdn
        self.ip_addresses = ip_addresses
        self.realm = realm_name
        self.domain = domain_name
        self.host = fqdn.split(".")[0]
        self.suffix = ipautil.realm_to_suffix(self.realm)
        self.reverse_zones = reverse_zones
        self.zonemgr = 'hostmaster.%s' % self.domain

        self.__add_self()

    def remove_ipa_ca_cnames(self, domain_name):
        # get ipa-ca CNAMEs
        try:
            cnames = get_rr(domain_name, IPA_CA_RECORD, "CNAME", api=self.api)
        except errors.NotFound:
            # zone does not exists
            cnames = None
        if not cnames:
            return

        logger.info('Removing IPA CA CNAME records')

        # create CNAME to FQDN mapping
        cname_fqdn = {}
        for cname in cnames:
            if cname.endswith('.'):
                fqdn = cname[:-1]
            else:
                fqdn = '%s.%s' % (cname, domain_name)
            cname_fqdn[cname] = fqdn

        # get FQDNs of all IPA masters
        try:
            masters = set(get_masters(self.api.Backend.ldap2))
        except errors.NotFound:
            masters = set()

        # check if all CNAMEs point to IPA masters
        for cname in cnames:
            fqdn = cname_fqdn[cname]
            if fqdn not in masters:
                logger.warning(
                    "Cannot remove IPA CA CNAME please remove them manually "
                    "if necessary")
                return

        # delete all CNAMEs
        for cname in cnames:
            del_rr(domain_name, IPA_CA_RECORD, "CNAME", cname, api=self.api)

    def remove_master_dns_records(self, fqdn, realm_name, domain_name):
        host, zone = fqdn.split(".", 1)
        self.host = host
        self.fqdn = fqdn
        self.domain = domain_name

        if not dns_zone_exists(zone, api=self.api):
            # Zone may be a forward zone, skip update
            return

        areclist = get_fwd_rr(zone, host, api=self.api)
        for rdata in areclist:
            del_fwd_rr(zone, host, rdata, api=self.api)

            rzone = find_reverse_zone(rdata)
            if rzone is not None:
                record = get_reverse_record_name(rzone, rdata)
                del_rr(rzone, record, "PTR", normalize_zone(fqdn),
                       api=self.api)
        self.update_system_records()

    def remove_server_ns_records(self, fqdn):
        """
        Remove all NS records pointing to this server
        """
        ldap = self.api.Backend.ldap2
        ns_rdata = normalize_zone(fqdn)

        # find all NS records pointing to this server
        search_kw = {}
        search_kw['nsrecord'] = ns_rdata
        attr_filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
        attributes = ['idnsname', 'objectclass']
        dn = DN(self.api.env.container_dns, self.api.env.basedn)

        entries, _truncated = ldap.find_entries(
            attr_filter, attributes, base_dn=dn)

        # remove records
        if entries:
            logger.debug("Removing all NS records pointing to %s:", ns_rdata)

        for entry in entries:
            if 'idnszone' in entry['objectclass']:
                # zone record
                zone = entry.single_value['idnsname']
                logger.debug("zone record %s", zone)
                del_ns_rr(zone, u'@', ns_rdata, api=self.api)
            else:
                zone = entry.dn[1].value  # get zone from DN
                record = entry.single_value['idnsname']
                logger.debug("record %s in zone %s", record, zone)
                del_ns_rr(zone, record, ns_rdata, api=self.api)

    def update_system_records(self):
        self.print_msg("Updating DNS system records")
        system_records = IPASystemRecords(self.api)
        try:
            (
                (_ipa_rec, failed_ipa_rec),
                (_loc_rec, failed_loc_rec)
            ) = system_records.update_dns_records()
        except IPADomainIsNotManagedByIPAError:
            logger.error(
                "IPA domain is not managed by IPA, please update records "
                "manually")
        else:
            if failed_ipa_rec or failed_loc_rec:
                logger.error("Update of following records failed:")
                for attr in (failed_ipa_rec, failed_loc_rec):
                    for rname, node, error in attr:
                        for record in IPASystemRecords.records_list_from_node(
                                rname, node
                        ):
                            logger.error("%s (%s)", record, error)

    def check_global_configuration(self):
        """
        Check global DNS configuration in LDAP server and inform user when it
        set and thus overrides his configured options in named.conf.
        """
        result = self.api.Command.dnsconfig_show()

        global_conf_set = any(
            param.name in result['result'] for param in
            self.api.Object['dnsconfig'].params() if
            u'virtual_attribute' not in param.flags
        )

        if not global_conf_set:
            print("Global DNS configuration in LDAP server is empty")
            print("You can use 'dnsconfig-mod' command to set global DNS options that")
            print("would override settings in local named.conf files")
            return

        print("Global DNS configuration in LDAP server is not empty")
        print("The following configuration options override local settings in named.conf:")
        print("")
        textui = ipalib.cli.textui(self.api)
        self.api.Command.dnsconfig_show.output_for_cli(textui, result, None,
                                                       reverse=False)

    def is_configured(self):
        """
        Override the default logic querying StateFile for configuration status
        and look whether named.conf was already modified by IPA installer.
        """
        return named_conf_exists()

    def uninstall(self):
        if self.is_configured():
            self.print_msg("Unconfiguring %s" % self.service_name)

        self.dns_backup.clear_records(self.api.Backend.ldap2.isconnected())

        try:
            self.fstore.restore_file(paths.NAMED_CONF)
        except ValueError as error:
            logger.debug('%s', error)

        try:
            tasks.unconfigure_dns_resolver(fstore=self.fstore)
        except Exception:
            logger.exception("Failed to unconfigure DNS resolver")

        ipautil.rmtree(paths.BIND_LDAP_DNS_IPA_WORKDIR)

        self.disable()
        self.stop()

        self.named_conflict.unmask()

        certmonger.stop_tracking(certfile=paths.BIND_DNS_OVER_TLS_CRT)
        certmonger.stop_tracking(certfile=paths.BIND_DNS_OVER_TLS_KEY)
        services.knownservices.unbound.disable()
        services.knownservices.unbound.stop()

        ipautil.remove_file(paths.NAMED_CONF_BAK)
        ipautil.remove_file(paths.NAMED_CUSTOM_CONF)
        ipautil.remove_file(paths.NAMED_CUSTOM_OPTIONS_CONF)
        ipautil.remove_file(paths.NAMED_LOGGING_OPTIONS_CONF)
        ipautil.remove_file(paths.RNDC_KEY)
        ipautil.remove_file(
            os.path.join(paths.NAMED_VAR_DIR, "_default.tsigkeys")
        )
        try:
            while self.fstore.restore_file(self.keytab):
                pass
        except ValueError:
            pass
        ipautil.remove_file(paths.BIND_DNS_OVER_TLS_CRT)
        ipautil.remove_file(paths.BIND_DNS_OVER_TLS_KEY)
        ipautil.remove_keytab(self.keytab)

        ipautil.remove_ccache(run_as=self.service_user)
