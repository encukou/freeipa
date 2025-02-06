#
# Copyright (C) 2014  FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

from datetime import datetime
import logging

import dns.name
import errno
import os
import shutil
import stat

import six

import ipalib.constants

from ipapython.dn import DN
from ipapython import ipautil
from ipaplatform.constants import constants as platformconstants
from ipaplatform.paths import paths

from ipaserver.dnssec.temp import TemporaryDirectory
from ipaserver.install import installutils

logger = logging.getLogger(__name__)

time_bindfmt = '%Y%m%d%H%M%S'

# this daemon should run under ods:named user:group
# user has to be ods because ODSMgr.py sends signal to ods-enforcerd
FILE_PERM = (stat.S_IRUSR | stat.S_IRGRP | stat.S_IWGRP | stat.S_IWUSR)
DIR_PERM = (stat.S_IRWXU | stat.S_IRWXG)


class BINDMgr:
    """BIND key manager. It does LDAP->BIND key files synchronization.

    One LDAP object with idnsSecKey object class will produce
    single pair of BIND key files.
    """
    def __init__(self, api):
        self.api = api
        self.ldap_keys = {}
        self.modified_zones = set()

    def notify_zone(self, zone):
        cmd = ['rndc', 'sign', zone.to_text()]
        result = ipautil.run(cmd, capture_output=True)
        logger.info('%s', result.output_log)

    def dn2zone_name(self, dn):
        """cn=KSK-20140813162153Z-cede9e182fc4af76c4bddbc19123a565,cn=keys,idnsname=test,cn=dns,dc=ipa,dc=example"""
        # verify that metadata object is under DNS sub-tree
        dn = DN(dn)
        container = DN(self.api.env.container_dns, self.api.env.basedn)
        idx = dn.rfind(container)
        assert idx != -1, 'Metadata object %s is not inside %s' % (dn, container)
        assert len(dn[idx - 1]) == 1, 'Multi-valued RDN as zone name is not supported'
        return dns.name.from_text(dn[idx - 1]['idnsname'])

    def time_ldap2bindfmt(self, str_val):
        if isinstance(str_val, bytes):
            str_val = str_val.decode('utf-8')
        dt = datetime.strptime(
            str_val,
            ipalib.constants.LDAP_GENERALIZED_TIME_FORMAT
        )
        return dt.strftime(time_bindfmt).encode('utf-8')

    def dates2params(self, ldap_attrs):
        """Convert LDAP timestamps to list of parameters suitable
        for dnssec-keyfromlabel utility"""
        attr2param = {'idnsseckeypublish': '-P',
                'idnsseckeyactivate': '-A',
                'idnsseckeyinactive': '-I',
                'idnsseckeydelete': '-D'}

        params = []
        for attr, param in attr2param.items():
            params.append(param)
            if attr in ldap_attrs:
                assert len(ldap_attrs[attr]) == 1, 'Timestamp %s is expected to be single-valued' % attr
                params.append(self.time_ldap2bindfmt(ldap_attrs[attr][0]))
            else:
                params.append('none')

        return params

    def ldap_event(self, op, uuid, attrs):
        """Record single LDAP event - key addition, deletion or modification.

        Change is only recorded to memory.
        self.sync() has to be called to synchronize change to BIND."""
        assert op in ('add', 'del', 'mod')
        zone = self.dn2zone_name(attrs['dn'])
        self.modified_zones.add(zone)
        zone_keys = self.ldap_keys.setdefault(zone, {})
        if op == 'add':
            logger.info('Key metadata %s added to zone %s',
                        attrs['dn'], zone)
            zone_keys[uuid] = attrs

        elif op == 'del':
            logger.info('Key metadata %s deleted from zone %s',
                        attrs['dn'], zone)
            zone_keys.pop(uuid)

        elif op == 'mod':
            logger.info('Key metadata %s updated in zone %s',
                        attrs['dn'], zone)
            zone_keys[uuid] = attrs

    def install_key(self, zone, uuid, attrs, workdir):
        """Run dnssec-keyfromlabel on given LDAP object.
        :returns: base file name of output files, e.g. Kaaa.test.+008+19719
        """
        logger.info('attrs: %s', attrs)
        assert attrs.get('idnsseckeyzone', [b'FALSE'])[0] == b'TRUE', \
            b'object %s is not a DNS zone key' % attrs['dn']

        uri = None
        if platformconstants.NAMED_OPENSSL_ENGINE is not None:
            uri = "%s;pin-source=%s" % (
                attrs['idnsSecKeyRef'][0],
                paths.DNSSEC_SOFTHSM_PIN.encode('utf-8')
            )
        elif platformconstants.NAMED_OPENSSL_PROVIDER is not None:
            uri = "%s;token=%s" % (
                attrs['idnsSecKeyRef'][0],
                ipalib.constants.SOFTHSM_DNSSEC_TOKEN_LABEL.encode('utf-8')
            )
        cmd = [
            paths.DNSSEC_KEYFROMLABEL,
            '-K', workdir,
            '-a', attrs['idnsSecAlgorithm'][0].encode('utf-8'),
        ]
        if uri is not None:
            cmd.extend(['-l', uri])
        cmd.extend(self.dates2params(attrs))
        if attrs.get('idnsSecKeySep', [b'FALSE'])[0].upper() == b'TRUE':
            cmd.extend(['-f', 'KSK'])
        if attrs.get('idnsSecKeyRevoke', [b'FALSE'])[0].upper() == b'TRUE':
            cmd.extend(['-R', datetime.now().strftime(time_bindfmt)])
        if platformconstants.NAMED_OPENSSL_ENGINE is not None:
            cmd.extend(['-E', platformconstants.NAMED_OPENSSL_ENGINE])
        cmd.append(zone.to_text())

        installutils.check_entropy()
        # keys has to be readable by ODS & named
        result = ipautil.run(cmd, capture_output=True)
        basename = result.output.strip()
        private_fn = "%s/%s.private" % (workdir, basename)
        os.chmod(private_fn, FILE_PERM)
        # this is useful mainly for debugging
        with open("%s/%s.uuid" % (workdir, basename), 'w') as uuid_file:
            uuid_file.write(uuid)
        with open("%s/%s.dn" % (workdir, basename), 'w') as dn_file:
            dn_file.write(attrs['dn'])

    def get_zone_dir_name(self, zone):
        """Escape zone name to form suitable for file-system.

        This method has to be equivalent to zr_get_zone_path()
        in bind-dyndb-ldap/zone_register.c."""

        if zone == dns.name.root:
            return "@"

        # strip final (empty) label
        zone = zone.relativize(dns.name.root)
        escaped = []
        for label in zone:
            for char in label:
                if six.PY3:
                    char = chr(char)
                if char.isalnum() or char in "-_":
                    escaped.append(char.lower())
                else:
                    escaped.append("%%%02X" % ord(char))
            escaped.append('.')

        # strip trailing period
        return ''.join(escaped[:-1])

    def sync_zone(self, zone):
        logger.info('Synchronizing zone %s', zone)
        zone_path = os.path.join(paths.BIND_LDAP_DNS_ZONE_WORKDIR,
                self.get_zone_dir_name(zone))
        try:
            os.mkdir(zone_path, 0o770)
        except FileExistsError:
            pass

        # fix HSM permissions
        # TODO: move out
        for prefix, dirs, files in os.walk(paths.DNSSEC_TOKENS_DIR, topdown=True):
            for name in dirs:
                fpath = os.path.join(prefix, name)
                logger.debug('Fixing directory permissions: %s', fpath)
                os.chmod(fpath, DIR_PERM | stat.S_ISGID)
            for name in files:
                fpath = os.path.join(prefix, name)
                logger.debug('Fixing file permissions: %s', fpath)
                os.chmod(fpath, FILE_PERM)
        # TODO: move out

        with TemporaryDirectory(zone_path) as tempdir:
            for uuid, attrs in self.ldap_keys[zone].items():
                self.install_key(zone, uuid, attrs, tempdir)
            # keys were generated in a temporary directory, swap directories
            target_dir = "%s/keys" % zone_path
            try:
                shutil.rmtree(target_dir)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise e
            shutil.move(tempdir, target_dir)
            os.chmod(target_dir, DIR_PERM)

        self.notify_zone(zone)

    def sync(self, dnssec_zones):
        """Synchronize list of zones in LDAP with BIND.

        dnssec_zones lists zones which should be processed. All other zones
        will be ignored even though they were modified using ldap_event().

        This filter is useful in cases where LDAP contains DNS zones which
        have old metadata objects and DNSSEC disabled. Such zones must be
        ignored to prevent errors while calling dnssec-keyfromlabel or rndc.
        """
        logger.debug('Key metadata in LDAP: %s', self.ldap_keys)
        logger.debug('Zones modified but skipped during bindmgr.sync: %s',
                     self.modified_zones - dnssec_zones)
        for zone in self.modified_zones.intersection(dnssec_zones):
            self.sync_zone(zone)

        self.modified_zones = set()

    def diff_zl(self, s1, s2):
        """Compute zones present in s1 but not present in s2.

        Returns: List of (uuid, name) tuples with zones present only in s1."""
        s1_extra = s1.uuids - s2.uuids
        removed = [(uuid, name) for (uuid, name) in s1.mapping.items()
                   if uuid in s1_extra]
        return removed
