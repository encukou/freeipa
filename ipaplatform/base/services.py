# Author: Alexander Bokovoy <abokovoy@redhat.com>
#         Tomas Babej <tbabej@redhat.com>
#
# Copyright (C) 2014   Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

'''
This base module contains default implementations of IPA interface for
interacting with system services.
'''

from __future__ import absolute_import

import os
import json
import time
import logging
import warnings

import six

from ipapython import ipautil
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks

from collections.abc import Mapping

logger = logging.getLogger(__name__)

# Canonical names of services as IPA wants to see them. As we need to have
# *some* naming, set them as in Red Hat distributions. Actual implementation
# should make them available through knownservices.<name> and take care of
# re-mapping internally, if needed
wellknownservices = [
    'certmonger', 'dirsrv', 'httpd', 'ipa', 'krb5kdc',
    'dbus', 'nslcd', 'nscd', 'ntpd', 'portmap',
    'rpcbind', 'kadmin', 'sshd', 'autofs', 'rpcgssd',
    'rpcidmapd', 'pki_tomcatd', 'chronyd', 'domainname',
    'named', 'ods_enforcerd', 'ods_signerd', 'gssproxy',
    'nfs-utils', 'sssd', 'NetworkManager', 'ipa-custodia',
    'ipa-dnskeysyncd', 'ipa-otpd', 'ipa-ods-exporter',
    'systemd-resolved', 'unbound',
]

# The common ports for these services. This is used to wait for the
# service to become available.
wellknownports = {
    'dirsrv': [389],  # only used if the incoming instance name is blank
    'pki-tomcatd@pki-tomcat.service': [8080, 8443],
    'pki-tomcat': [8080, 8443],
    'pki-tomcatd': [8080, 8443],  # used if the incoming instance name is blank
}

SERVICE_POLL_INTERVAL = 0.1 # seconds


class KnownServices(Mapping):
    """
    KnownServices is an abstract class factory that should give out instances
    of well-known platform services. Actual implementation must create these
    instances as its own attributes on first access (or instance creation)
    and cache them.
    """
    def __init__(self, d):
        self.__d = d

    def __getitem__(self, key):
        return self.__d[key]

    def __iter__(self):
        return iter(self.__d)

    def __len__(self):
        return len(self.__d)

    def __call__(self):
        return six.itervalues(self.__d)

    def __getattr__(self, name):
        try:
            return self.__d[name]
        except KeyError:
            raise AttributeError(name)


class PlatformService:
    """
    PlatformService abstracts out external process running on the system
    which is possible to administer (start, stop, check status, etc).

    """

    def __init__(self, service_name, api=None):
        # pylint: disable=ipa-forbidden-import
        import ipalib  # FixMe: break import cycle
        # pylint: enable=ipa-forbidden-import
        self.service_name = service_name
        if api is not None:
            self.api = api
        else:
            self.api = ipalib.api
            warnings.warn(
                "{s.__class__.__name__}('{s.service_name}', api=None) "
                "is deprecated.".format(s=self),
                RuntimeWarning, stacklevel=2)

    def start(self, instance_name="", capture_output=True, wait=True,
        update_service_list=True):
        """
        When a service is started record the fact in a special file.
        This allows ipactl stop to always stop all services that have
        been started via ipa tools
        """
        if not update_service_list:
            return
        svc_list = []
        try:
            with open(paths.SVC_LIST_FILE, 'r') as f:
                svc_list = json.load(f)
        except Exception:
            # not fatal, may be the first service
            pass

        if self.service_name not in svc_list:
            svc_list.append(self.service_name)

        with open(paths.SVC_LIST_FILE, 'w') as f:
            json.dump(svc_list, f)

    def stop(self, instance_name="", capture_output=True,
             update_service_list=True):
        """
        When a service is stopped remove it from the service list file.
        """
        if not update_service_list:
            return
        svc_list = []
        try:
            with open(paths.SVC_LIST_FILE, 'r') as f:
                svc_list = json.load(f)
        except Exception:
            # not fatal, may be the first service
            pass

        while self.service_name in svc_list:
            svc_list.remove(self.service_name)

        with open(paths.SVC_LIST_FILE, 'w') as f:
            json.dump(svc_list, f)

    def reload_or_restart(self, instance_name="", capture_output=True,
                          wait=True):
        pass

    def restart(self, instance_name="", capture_output=True, wait=True):
        pass

    def try_restart(self, instance_name="", capture_output=True, wait=True):
        pass

    def is_running(self, instance_name="", wait=True):
        return False

    def is_installed(self):
        return False

    def is_enabled(self, instance_name=""):
        return False

    def is_masked(self, instance_name=""):
        return False

    def enable(self, instance_name=""):
        pass

    def disable(self, instance_name=""):
        pass

    def mask(self, instance_name=""):
        pass

    def unmask(self, instance_name=""):
        pass

    def install(self, instance_name=""):
        pass

    def remove(self, instance_name=""):
        pass


class SystemdService(PlatformService):
    SYSTEMD_SRV_TARGET = "%s.target.wants"

    def __init__(self, service_name, systemd_name, api=None):
        super(SystemdService, self).__init__(service_name, api=api)
        self.systemd_name = systemd_name
        self.lib_path = os.path.join(paths.LIB_SYSTEMD_SYSTEMD_DIR,
                                     self.systemd_name)
        self.lib_path_exists = None

    def service_instance(self, instance_name, operation=None):
        if self.lib_path_exists is None:
            self.lib_path_exists = os.path.exists(self.lib_path)

        elements = self.systemd_name.split("@")

        # Make sure the correct DS instance is returned
        if elements[0] == 'dirsrv' and not instance_name:

            return ('dirsrv@%s.service'
                    % str(self.api.env.realm.replace('.', '-')))

        # Short-cut: if there is already exact service name, return it
        if self.lib_path_exists and instance_name:
            if len(elements) == 1:
                # service name is like pki-tomcatd.target or krb5kdc.service
                return self.systemd_name
            if len(elements) > 1 and elements[1][0] != '.':
                # Service name is like pki-tomcatd@pki-tomcat.service
                # and that file exists
                return self.systemd_name

        if len(elements) > 1:
            # We have dynamic service
            if instance_name:
                # Instanciate dynamic service
                return "%s@%s.service" % (elements[0], instance_name)
            else:
                # No instance name, try with target
                tgt_name = "%s.target" % (elements[0])
                srv_lib = os.path.join(paths.LIB_SYSTEMD_SYSTEMD_DIR, tgt_name)
                if os.path.exists(srv_lib):
                    return tgt_name

        return self.systemd_name

    def parse_variables(self, text, separator=None):
        """
        Parses 'systemctl show' output and returns a dict[variable]=value
        Arguments: text -- 'systemctl show' output as string
                   separator -- optional (defaults to None), what separates
                                the key/value pairs in the text
        """

        def splitter(x, separator=None):
            if len(x) > 1:
                y = x.split(separator)
                return (y[0], y[-1])
            return (None, None)

        return dict(splitter(x, separator=separator) for x in text.split("\n"))

    def wait_for_open_ports(self, instance_name=""):
        """
        If this is a service we need to wait for do so.
        """
        ports = None
        if instance_name in wellknownports:
            ports = wellknownports[instance_name]
        else:
            elements = self.systemd_name.split("@")
            if elements[0] in wellknownports:
                ports = wellknownports[elements[0]]
        if ports:
            ipautil.wait_for_open_ports('localhost', ports,
                                        self.api.env.startup_timeout)

    def stop(self, instance_name="", capture_output=True):
        instance = self.service_instance(instance_name)
        args = [paths.SYSTEMCTL, "stop", instance]

        # The --ignore-dependencies switch is used to avoid possible
        # deadlock during the shutdown transaction. For more details, see
        # https://fedorahosted.org/freeipa/ticket/3729#comment:1 and
        # https://bugzilla.redhat.com/show_bug.cgi?id=973331#c11
        if instance == "ipa-otpd.socket":
            args.append("--ignore-dependencies")
        # ipa-ods-exporter is socket-activated, both the service and the
        # socket have to be stopped
        if instance == "ipa-ods-exporter.service":
            args.append("ipa-ods-exporter.socket")

        ipautil.run(args, skip_output=not capture_output)

        update_service_list = getattr(self.api.env, 'context',
                                      None) in ['ipactl', 'installer']
        super(SystemdService, self).stop(
            instance_name,
            update_service_list=update_service_list)
        logger.debug('Stop of %s complete', instance)

    def start(self, instance_name="", capture_output=True, wait=True):
        ipautil.run([paths.SYSTEMCTL, "start",
                     self.service_instance(instance_name)],
                    skip_output=not capture_output)

        update_service_list = getattr(self.api.env, 'context',
                                      None) in ['ipactl', 'installer']

        if wait and self.is_running(instance_name):
            self.wait_for_open_ports(self.service_instance(instance_name))
        super(SystemdService, self).start(
            instance_name,
            update_service_list=update_service_list)
        logger.debug('Start of %s complete',
                     self.service_instance(instance_name))

    def _restart_base(self, instance_name, operation, capture_output=True,
                      wait=False):

        ipautil.run([paths.SYSTEMCTL, operation,
                    self.service_instance(instance_name)],
                    skip_output=not capture_output)

        if wait and self.is_running(instance_name):
            self.wait_for_open_ports(self.service_instance(instance_name))
        logger.debug('Restart of %s complete',
                     self.service_instance(instance_name))

    def reload_or_restart(self, instance_name="", capture_output=True,
                          wait=True):
        self._restart_base(instance_name, "reload-or-restart",
                           capture_output, wait)

    def restart(self, instance_name="", capture_output=True, wait=True):
        self._restart_base(instance_name, "restart",
                           capture_output, wait)

    def try_restart(self, instance_name="", capture_output=True, wait=True):
        self._restart_base(instance_name, "try-restart",
                           capture_output, wait)

    def is_running(self, instance_name="", wait=True):
        instance = self.service_instance(instance_name, 'is-active')

        while True:
            try:
                result = ipautil.run(
                    [paths.SYSTEMCTL, "is-active", instance],
                    capture_output=True
                )
            except ipautil.CalledProcessError as e:
                if e.returncode == 3 and 'activating' in str(e.output):
                    time.sleep(SERVICE_POLL_INTERVAL)
                    continue
                return False
            else:
                # activating
                if result.returncode == 3 and 'activating' in result.output:
                    time.sleep(SERVICE_POLL_INTERVAL)
                    continue
                # active
                if result.returncode == 0:
                    return True
                # not active
                return False

    def is_installed(self):
        try:
            result = ipautil.run(
                [paths.SYSTEMCTL, "list-unit-files", "--full"],
                capture_output=True)
            if result.returncode != 0:
                return False
            else:
                svar = self.parse_variables(result.output)
                if self.service_instance("") not in svar:
                    # systemd doesn't show the service
                    return False
        except ipautil.CalledProcessError:
                return False

        return True

    def is_enabled(self, instance_name=""):
        enabled = True
        try:
            result = ipautil.run(
                [paths.SYSTEMCTL, "is-enabled",
                 self.service_instance(instance_name)])

            if result.returncode != 0:
                enabled = False

        except ipautil.CalledProcessError:
                enabled = False
        return enabled

    def is_masked(self, instance_name=""):
        masked = False
        try:
            result = ipautil.run(
                [paths.SYSTEMCTL, "is-enabled",
                 self.service_instance(instance_name)],
                capture_output=True)

            if result.returncode == 1 and result.output == 'masked':
                masked = True

        except ipautil.CalledProcessError:
                pass
        return masked

    def enable(self, instance_name=""):
        if self.lib_path_exists is None:
            self.lib_path_exists = os.path.exists(self.lib_path)
        elements = self.systemd_name.split("@")
        l = len(elements)

        if self.lib_path_exists and (l > 1 and elements[1][0] != '.'):
            # There is explicit service unit supporting this instance,
            # follow normal systemd enabler
            self.__enable(instance_name)
            return

        if self.lib_path_exists and (l == 1):
            # There is explicit service unit which does not support
            # the instances, ignore instance
            self.__enable()
            return

        if len(instance_name) > 0 and l > 1:
            # New instance, we need to do following:
            # 1. Make /etc/systemd/system/<service>.target.wants/
            #    if it is not there
            # 2. Link /etc/systemd/system/<service>.target.wants/
            #    <service>@<instance_name>.service to
            #    /lib/systemd/system/<service>@.service

            srv_tgt = os.path.join(paths.ETC_SYSTEMD_SYSTEM_DIR,
                                   self.SYSTEMD_SRV_TARGET % (elements[0]))
            srv_lnk = os.path.join(srv_tgt,
                                   self.service_instance(instance_name))

            try:
                if not os.path.isdir(srv_tgt):
                    os.mkdir(srv_tgt)
                    os.chmod(srv_tgt, 0o755)
                if os.path.exists(srv_lnk):
                    # Remove old link
                    os.unlink(srv_lnk)
                if not os.path.exists(srv_lnk):
                    # object does not exist _or_ is a broken link
                    if not os.path.islink(srv_lnk):
                        # if it truly does not exist, make a link
                        os.symlink(self.lib_path, srv_lnk)
                    else:
                        # Link exists and it is broken, make new one
                        os.unlink(srv_lnk)
                        os.symlink(self.lib_path, srv_lnk)
                tasks.systemd_daemon_reload()
            except Exception:
                pass
        else:
            self.__enable(instance_name)

    def disable(self, instance_name=""):
        elements = self.systemd_name.split("@")
        if instance_name != "" and len(elements) > 1:
            # Remove instance, we need to do following:
            # Remove link from /etc/systemd/system/<service>.target.wants/
            # <service>@<instance_name>.service
            # to /lib/systemd/system/<service>@.service

            srv_tgt = os.path.join(paths.ETC_SYSTEMD_SYSTEM_DIR,
                                   self.SYSTEMD_SRV_TARGET % (elements[0]))
            srv_lnk = os.path.join(srv_tgt,
                                   self.service_instance(instance_name))

            try:
                if os.path.isdir(srv_tgt):
                    if os.path.islink(srv_lnk):
                        os.unlink(srv_lnk)
                tasks.systemd_daemon_reload()
            except Exception:
                pass
        else:
            try:
                ipautil.run([paths.SYSTEMCTL, "disable",
                             self.service_instance(instance_name)])
            except ipautil.CalledProcessError:
                pass

    def mask(self, instance_name=""):
        srv_tgt = os.path.join(paths.ETC_SYSTEMD_SYSTEM_DIR, self.service_instance(instance_name))
        if os.path.exists(srv_tgt):
            os.unlink(srv_tgt)
        try:
            ipautil.run([paths.SYSTEMCTL, "mask",
                         self.service_instance(instance_name)])
        except ipautil.CalledProcessError:
            pass

    def unmask(self, instance_name=""):
        try:
            ipautil.run([paths.SYSTEMCTL, "unmask",
                         self.service_instance(instance_name)])
        except ipautil.CalledProcessError:
            pass

    def __enable(self, instance_name=""):
        try:
            ipautil.run([paths.SYSTEMCTL, "enable",
                         self.service_instance(instance_name)])
        except ipautil.CalledProcessError:
            pass

    def install(self):
        self.enable()

    def remove(self):
        self.disable()


# Objects below are expected to be exported by platform module

def base_service_class_factory(name, api=None):
    raise NotImplementedError


service = base_service_class_factory
knownservices = KnownServices({})

# System may support more time&date services. FreeIPA supports chrony only.
# Other services will be disabled during IPA installation
timedate_services = ['ntpd', 'chronyd', 'systemd-timesyncd']
