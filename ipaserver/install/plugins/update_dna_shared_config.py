#
# Copyright (C) 2016  FreeIPA Contributors see COPYING for license
#

import logging
import time
import ldap

from ipalib.plugable import Registry
from ipalib import errors
from ipalib import Updater
from ipapython.dn import DN

logger = logging.getLogger(__name__)

register = Registry()

@register()
class update_dna_shared_config(Updater):
    dna_plugin_names = ('posix IDs', 'Subordinate IDs')

    dna_plugin_dn = DN(
        ('cn', 'Distributed Numeric Assignment Plugin'),
        ('cn', 'plugins'),
        ('cn', 'config')
    )

    def is_dna_enabled(self):
        """Check the plugin is enabled

        Else it is useless to update the shared entry
        """
        try:
            entry = self.api.Backend.ldap2.get_entry(self.dna_plugin_dn)
            enabled = entry.single_value.get('nsslapd-pluginenabled')
            if enabled.lower() == 'off':
                return False
            else:
                return True
        except errors.NotFound:
            logger.error("Could not find DNA plugin entry: %s",
                         self.dna_plugin_dn)
            return False

    def get_shared_cfg(self, plugin_name):
        dna_config_base = DN(('cn', plugin_name), self.dna_plugin_dn)
        try:
            entry = self.api.Backend.ldap2.get_entry(dna_config_base)
        except errors.NotFound:
            logger.error("Could not find DNA config entry: %s",
                         dna_config_base)
            return False, ()
        else:
            logger.debug('Found DNA config %s', dna_config_base)

        remote_bind_method = entry.single_value.get("dnaRemoteBindMethod")
        if remote_bind_method is not None:
            logger.error(
                "dnaRemoteBindMethod is set on the global DNA entry already.")
            return None
        sharedcfgdn = entry.single_value.get("dnaSharedCfgDN")
        if sharedcfgdn is not None:
            sharedcfgdn = DN(sharedcfgdn)
            logger.debug("dnaSharedCfgDN: %s", sharedcfgdn)
            return sharedcfgdn
        else:
            logger.error(
                "Could not find DNA shared config DN in entry: %s",
                dna_config_base)
            return None

    def update_shared_cfg(self, sharedcfgdn, **options):
        """Update the shared config entry related to that host

        If the shared config entry already exists (like upgrade)
        the update occurs immediately without sleep.

        If the shared config entry does not exist (fresh install)
        DS server waits for 30s after its startup to create it.
        Startup likely occurred few sec before this function is
        called so this loop will wait for 30s max.

        In case the server is not able to create the entry
        The loop gives a grace period of slightly more than 60 seconds
        before it logs a failure and aborts the update.
        """
        method = options.get('method', "SASL/GSSAPI")
        protocol = options.get('protocol', "LDAP")

        max_wait = 30  # times 2 second sleep

        conn = self.api.Backend.ldap2
        fqdn = self.api.env.host

        for _i in range(0, max_wait + 1):
            try:
                entries = conn.get_entries(
                    sharedcfgdn, scope=ldap.SCOPE_ONELEVEL,
                    filter='dnaHostname=%s' % fqdn
                )
                # There must be two entries:
                # - dnaHostname=fqdn+dnaPortNum=0
                # - dnaHostname=fqdn+dnaPortNum=389
                if len(entries) >= 2:
                    break

                logger.debug("Got only one entry. Retry again in 2 sec.")
                time.sleep(2)
            except errors.NotFound:
                logger.debug(
                    "Unable to find DNA shared config entry for "
                    "dnaHostname=%s (under %s) so far. Retry in 2 sec.",
                    fqdn, sharedcfgdn
                )
                time.sleep(2)
        else:
            logger.error(
                "Could not get dnaHostname entries in %s seconds",
                max_wait * 2
            )
            return False

        # time to set the bind method and the protocol in the
        # shared config entries
        for entry in entries:
            entry["dnaRemoteBindMethod"] = method
            entry["dnaRemoteConnProtocol"] = protocol
            try:
                conn.update_entry(entry)
            except errors.EmptyModlist:
                logger.debug("Entry %s is already updated", entry.dn)
            except Exception as e:
                logger.error(
                    "Failed to set SASL/GSSAPI bind method/protocol "
                    "in entry %s: %s", entry, e
                )
            else:
                logger.debug("Updated entry %s", entry.dn)

        return True

    def execute(self, **options):
        if not self.is_dna_enabled():
            return False, ()

        for plugin_name in self.dna_plugin_names:
            sharedcfgdn = self.get_shared_cfg(plugin_name)
            if sharedcfgdn is not None:
                self.update_shared_cfg(sharedcfgdn, **options)

        # no restart, no update
        return False, ()
