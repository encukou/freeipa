# Authors: Jan Cholasta <jcholast@redhat.com>
#
# Copyright (C) 2014  Red Hat
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

import logging
import os

from urllib.parse import urlsplit

from ipalib.install import certmonger, certstore
from ipalib.facts import is_ipa_configured
from ipapython import admintool, certdb, ipaldap, ipautil
from ipaplatform import services
from ipaplatform.paths import paths
from ipaplatform.tasks import tasks
from ipalib import api, errors, x509
from ipalib.constants import FQDN, IPA_CA_NICKNAME, RENEWAL_CA_NAME
from ipalib.util import check_client_configuration

logger = logging.getLogger(__name__)


class CertUpdate(admintool.AdminTool):
    command_name = 'ipa-certupdate'

    usage = "%prog [options]"

    description = ("Update local IPA certificate databases with certificates "
                   "from the server.")

    def validate_options(self):
        super(CertUpdate, self).validate_options(needs_root=True)

    def run(self):
        check_client_configuration()

        old_krb5ccname = os.environ.get('KRB5CCNAME')
        os.environ['KRB5_CLIENT_KTNAME'] = '/etc/krb5.keytab'
        os.environ['KRB5CCNAME'] = "MEMORY:"

        try:
            api.bootstrap(context='cli_installer', confdir=paths.ETC_IPA)
            api.finalize()

            api.Backend.rpcclient.connect()
            run_with_args(api)
            api.Backend.rpcclient.disconnect()
        except errors.CCacheError:
            logger.error(
                "Unable to obtain credentials for %s from /etc/krb5.keytab",
                FQDN
            )
            raise
        finally:
            if old_krb5ccname is None:
                os.environ.pop('KRB5CCNAME', None)
            else:
                os.environ['KRB5CCNAME'] = old_krb5ccname


def run_with_args(api):
    """
    Run the certupdate procedure with the given API object.

    :param api: API object with ldap2/rpcclient backend connected
                (such that Commands can be invoked)

    """
    server = urlsplit(api.env.jsonrpc_uri).hostname
    ldap = ipaldap.LDAPClient.from_hostname_secure(server)

    try:
        result = api.Command.ca_is_enabled(version=u'2.107')
        ca_enabled = result['result']
    except (errors.CommandError, errors.NetworkError):
        result = api.Command.env(server=True, version=u'2.0')
        ca_enabled = result['result']['enable_ra']

    ldap.gssapi_bind()

    certs = certstore.get_ca_certs(
        ldap, api.env.basedn, api.env.realm, ca_enabled)

    if ca_enabled:
        lwcas = api.Command.ca_find()['result']
    else:
        lwcas = []

    # update client certs before KDC and HTTPd are restarted.
    update_client(certs)

    if is_ipa_configured():
        # look up CA servers before service restarts
        resp = api.Command.server_role_find(
            role_servrole=u'CA server',
            status='enabled',
        )
        ca_servers = [server['server_server'] for server in resp['result']]

        update_server(certs)

        # pylint: disable=ipa-forbidden-import
        from ipaserver.install import cainstance, custodiainstance
        # pylint: enable=ipa-forbidden-import

        # Add LWCA tracking requests.  Only execute if *this server*
        # has CA installed (ca_enabled indicates CA-ful topology).
        if cainstance.CAInstance().is_configured():
            try:
                cainstance.add_lightweight_ca_tracking_requests(lwcas)
            except Exception:
                logger.exception(
                    "Failed to add lightweight CA tracking requests")

        try:
            update_server_ra_config(
                cainstance, custodiainstance,
                api.env.enable_ra, api.env.ca_host, ca_servers,
            )
        except Exception:
            logger.exception("Failed to update RA config")

        # update_server_ra_config possibly updated default.conf;
        # restart httpd to pick up changes.
        if services.knownservices.httpd.is_running():
            services.knownservices.httpd.restart()

        # update_client() may have updated KDC cert bundle; restart KDC to pick
        # up changes.
        if services.knownservices.krb5kdc.is_running():
            services.knownservices.krb5kdc.restart()


def update_client(certs):
    update_file(paths.IPA_CA_CRT, certs)
    update_file(paths.KDC_CA_BUNDLE_PEM, certs)
    update_file(paths.CA_BUNDLE_PEM, certs)

    ipa_db = certdb.NSSDatabase(api.env.nss_dir)

    # Remove old IPA certs from /etc/ipa/nssdb
    for nickname in ('IPA CA', 'External CA cert'):
        while ipa_db.has_nickname(nickname):
            try:
                ipa_db.delete_cert(nickname)
            except ipautil.CalledProcessError as e:
                logger.error(
                    "Failed to remove %s from %s: %s",
                    nickname, ipa_db.secdir, e)
                break

    update_db(ipa_db.secdir, certs)

    tasks.remove_ca_certs_from_systemwide_ca_store()
    tasks.insert_ca_certs_into_systemwide_ca_store(certs)


def update_server(certs):
    instance = '-'.join(api.env.realm.split('.'))
    update_db(paths.ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE % instance, certs)
    if services.knownservices.dirsrv.is_running():
        services.knownservices.dirsrv.restart(instance)

    criteria = {
        'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
        'cert-nickname': IPA_CA_NICKNAME,
        'ca-name': RENEWAL_CA_NAME,
    }
    request_id = certmonger.get_request_id(criteria)
    if request_id is not None:
        timeout = api.env.startup_timeout + 60

        # The dogtag-ipa-ca-renew-agent-reuse Certmonger CA never
        # actually renews the certificate; it only pulls it from the
        # ca_renewal LDAP cert store.
        #
        # Why is this needed?  If the CA cert gets renewed long
        # before its notAfter (expiry) date (e.g. to switch from
        # self-signed to external, or to switch to new external CA),
        # then the other (i.e. not caRenewalMaster) CA replicas will
        # not promptly pick up the new CA cert.  So we make
        # ipa-certupdate always check for an updated CA cert.
        #
        logger.debug("resubmitting certmonger request '%s'", request_id)
        certmonger.resubmit_request(
            request_id, ca='dogtag-ipa-ca-renew-agent-reuse')
        try:
            state = certmonger.wait_for_request(request_id, timeout)
        except RuntimeError:
            raise admintool.ScriptError(
                "Resubmitting certmonger request '%s' timed out, "
                "please check the request manually" % request_id)
        ca_error = certmonger.get_request_value(request_id, 'ca-error')
        if state != 'MONITORING' or ca_error:
            raise admintool.ScriptError(
                "Error resubmitting certmonger request '%s', "
                "please check the request manually" % request_id)

        logger.debug("modifying certmonger request '%s'", request_id)
        certmonger.modify(request_id, ca='dogtag-ipa-ca-renew-agent')

    update_file(paths.CA_CRT, certs)
    update_file(paths.CACERT_PEM, certs)


def update_server_ra_config(
    cainstance, custodiainstance,
    enable_ra, ca_host, ca_servers,
):
    """
    After promoting a CA-less deployment to CA-ful, or after removal
    of a CA server from the topology, it may be necessary to update
    the default.conf ca_host setting on non-CA replicas.

    """
    if len(ca_servers) == 0:
        return  # nothing to do

    # In case ca_host setting is not valid, select a new ca_host.
    # Just choose the first server.  (Choosing a server in the same
    # location might be better, but we should only incur that
    # complexity if a need is proven).
    new_ca_host = ca_servers[0]

    if not enable_ra:
        # RA is not enabled, but deployment is CA-ful.
        # Retrieve IPA RA credential and update ipa.conf.
        cainstance.CAInstance.configure_certmonger_renewal_helpers()
        custodia = custodiainstance.CustodiaInstance(
            host_name=api.env.host,
            realm=api.env.realm,
            custodia_peer=new_ca_host,
        )
        cainstance.import_ra_key(custodia)
        cainstance.update_ipa_conf(new_ca_host)

    elif ca_host not in ca_servers:
        # RA is enabled but ca_host is not among the deployment's
        # CA servers.  Set a valid ca_host.
        cainstance.update_ipa_conf(new_ca_host)


def update_file(filename, certs, mode=0o644):
    certs = (c[0] for c in certs if c[2] is not False)
    try:
        x509.write_certificate_list(certs, filename, mode=mode)
    except Exception as e:
        logger.error("failed to update %s: %s", filename, e)


def update_db(path, certs):
    """Drop all CA certs from db then add certs from list provided

       This may result in some churn as existing certs are dropped
       and re-added but this also provides the ability to change
       the trust flags.
    """
    db = certdb.NSSDatabase(path)
    for name, flags in db.list_certs():
        if flags.ca:
            db.delete_cert(name)
    for cert, nickname, trusted, eku, _serial in certs:
        trust_flags = certstore.key_policy_to_trust_flags(trusted, True, eku)
        try:
            db.add_cert(cert, nickname, trust_flags)
        except ipautil.CalledProcessError as e:
            logger.error("failed to update %s in %s: %s", nickname, path, e)
