#
# Copyright (C) 2020 FreeIPA Contributors, see COPYING for license
#

"""
This module contains default SUSE OS family-specific implementations of
system tasks.
"""

import logging

from ipaplatform.paths import paths
from ipaplatform.base.tasks import BaseTaskNamespace as BaseTask
from ipaplatform.redhat.tasks import RedHatTaskNamespace
from ipapython import ipautil

logger = logging.getLogger(__name__)


class SuseTaskNamespace(RedHatTaskNamespace):
    def set_nisdomain(self, nisdomain):
        nis_variable = "NETCONFIG_NIS_STATIC_DOMAIN"
        try:
            with open(paths.SYSCONF_NETWORK, "r") as f:
                content = [
                    line
                    for line in f
                    if not line.strip().upper().startswith(nis_variable)
                ]
        except IOError:
            content = []

        content.append("{}={}\n".format(nis_variable, nisdomain))

        with open(paths.SYSCONF_NETWORK, "w") as f:
            f.writelines(content)

    def modify_nsswitch_pam_stack(self, sssd, mkhomedir, statestore,
                                  sudo=True, subid=False):
        # pylint: disable=ipa-forbidden-import
        from ipalib import sysrestore  # FixMe: break import cycle
        # pylint: enable=ipa-forbidden-import
        fstore = sysrestore.FileStore(paths.IPA_CLIENT_SYSRESTORE)
        logger.debug('Enabling SSSD in nsswitch')
        BaseTask.configure_nsswitch_database(self, fstore, 'group',
                                             ['sss'], default_value=['compat'])
        BaseTask.configure_nsswitch_database(self, fstore, 'passwd',
                                             ['sss'], default_value=['compat'])
        BaseTask.configure_nsswitch_database(self, fstore, 'shadow',
                                             ['sss'], default_value=['compat'])
        BaseTask.configure_nsswitch_database(self, fstore, 'netgroup',
                                             ['files','sss'], preserve=False,
                                             default_value=['files','nis'])
        BaseTask.configure_nsswitch_database(self, fstore, 'automount',
                                             ['files','sss'], preserve=False,
                                             default_value=['files','nis'])
        if sudo:
            BaseTask.enable_sssd_sudo(self,fstore)
        logger.debug('Enabling sss in PAM')
        try:
            ipautil.run([paths.PAM_CONFIG, '--add', '--sss'])
            if mkhomedir:
                logger.debug('Enabling mkhomedir in PAM')
                try:
                    ipautil.run([paths.PAM_CONFIG, '--add', '--mkhomedir',
                                 '--mkhomedir-umask=0077'])
                except ipautil.CalledProcessError:
                    logger.debug('Failed to configure PAM mkhomedir')
                    return False
        except ipautil.CalledProcessError:
            logger.debug('Failed to configure PAM to use SSSD')
            return False
        return True

    def restore_pre_ipa_client_configuration(self, fstore, statestore,
                                             was_sssd_installed,
                                             was_sssd_configured):
        if fstore.has_file(paths.NSSWITCH_CONF):
            logger.debug('Restoring nsswitch from fstore')
            fstore.restore_file(paths.NSSWITCH_CONF)
        else:
            logger.info('nsswitch not restored')
            return False
        try:
            logger.debug('Removing sssd from PAM')
            ipautil.run([paths.PAM_CONFIG, '--delete', '--mkhomedir'])
            ipautil.run([paths.PAM_CONFIG, '--delete', '--sss'])
            logger.debug('Removing sssd from PAM successed')
        except ipautil.CalledProcessError:
            logger.debug('Faled to remove sssd from PAM')
            return False
        return True

    def disable_ldap_automount(self, statestore):
        # SUSE does not use authconfig or authselect
        return BaseTask.disable_ldap_automount(self, statestore)

    def modify_pam_to_use_krb5(self, statestore):
        # SUSE doesn't use authconfig, this is handled by pam-config
        return True

    def backup_auth_configuration(self, path):
        # SUSE doesn't use authconfig, nothing to backup
        return True

    def restore_auth_configuration(self, path):
        # SUSE doesn't use authconfig, nothing to restore
        return True

    def migrate_auth_configuration(self, statestore):
        # SUSE doesn't have authselect
        return True

tasks = SuseTaskNamespace()
