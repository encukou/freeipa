# Authors:
#   Tomas Babej <tbabej@redhat.com>
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

'''
This base platform module exports default filesystem paths.
'''

import os


class BasePathNamespace:
    BIN_HOSTNAMECTL = "/bin/hostnamectl"
    CRYPTO_POLICY_OPENSSLCNF_FILE = None
    ECHO = "/bin/echo"
    FIPS_MODE_SETUP = "/bin/fips-mode-setup"
    GZIP = "/bin/gzip"
    LS = "/bin/ls"
    SYSTEMCTL = "/bin/systemctl"
    SYSTEMD_RUN = "/bin/systemd-run"
    SYSTEMD_DETECT_VIRT = "/usr/bin/systemd-detect-virt"
    SYSTEMD_TMPFILES = "/bin/systemd-tmpfiles"
    TAR = "/bin/tar"
    ETC_FEDORA_RELEASE = "/etc/fedora-release"
    GROUP = "/etc/group"
    ETC_HOSTNAME = "/etc/hostname"
    HOSTS = "/etc/hosts"
    ETC_HTTPD_DIR = "/etc/httpd"
    HTTPD_ALIAS_DIR = "/etc/httpd/alias"
    GSSAPI_SESSION_KEY = "/etc/httpd/alias/ipasession.key"
    OLD_KRA_AGENT_PEM = "/etc/httpd/alias/kra-agent.pem"
    HTTPD_CONF_D_DIR = "/etc/httpd/conf.d/"
    HTTPD_IPA_KDCPROXY_CONF = "/etc/ipa/kdcproxy/ipa-kdc-proxy.conf"
    HTTPD_IPA_KDCPROXY_CONF_SYMLINK = "/etc/httpd/conf.d/ipa-kdc-proxy.conf"
    HTTPD_IPA_PKI_PROXY_CONF = "/etc/httpd/conf.d/ipa-pki-proxy.conf"
    HTTPD_IPA_REWRITE_CONF = "/etc/httpd/conf.d/ipa-rewrite.conf"
    HTTPD_IPA_CONF = "/etc/httpd/conf.d/ipa.conf"
    HTTPD_NSS_CONF = "/etc/httpd/conf.d/nss.conf"
    HTTPD_SSL_CONF = "/etc/httpd/conf.d/ssl.conf"
    HTTPD_SSL_SITE_CONF = "/etc/httpd/conf.d/ssl.conf"
    HTTPD_CERT_FILE = "/var/lib/ipa/certs/httpd.crt"
    HTTPD_KEY_FILE = "/var/lib/ipa/private/httpd.key"
    HTTPD_PASSWD_FILE_FMT = "/var/lib/ipa/passwds/{host}-443-RSA"
    # only used on Fedora
    HTTPD_IPA_WSGI_MODULES_CONF = None
    OLD_IPA_KEYTAB = "/etc/httpd/conf/ipa.keytab"
    HTTP_KEYTAB = "/var/lib/ipa/gssproxy/http.keytab"
    HTTPD_PASSWORD_CONF = "/etc/httpd/conf/password.conf"
    IDMAPD_CONF = "/etc/idmapd.conf"
    ETC_IPA = "/etc/ipa"
    CONNCHECK_CCACHE = "/etc/ipa/.conncheck_ccache"
    IPA_DNS_CCACHE = "/etc/ipa/.dns_ccache"
    IPA_DNS_UPDATE_TXT = "/etc/ipa/.dns_update.txt"
    IPA_CA_CRT = "/etc/ipa/ca.crt"
    IPA_DEFAULT_CONF = "/etc/ipa/default.conf"
    IPA_DNSKEYSYNCD_KEYTAB = "/etc/ipa/dnssec/ipa-dnskeysyncd.keytab"
    IPA_ODS_EXPORTER_KEYTAB = "/etc/ipa/dnssec/ipa-ods-exporter.keytab"
    IPA_SERVER_CONF = "/etc/ipa/server.conf"
    DNSSEC_OPENSSL_CONF = "/etc/ipa/dnssec/openssl.cnf"
    DNSSEC_SOFTHSM2_CONF = "/etc/ipa/dnssec/softhsm2.conf"
    DNSSEC_SOFTHSM_PIN_SO = "/etc/ipa/dnssec/softhsm_pin_so"
    IPA_NSSDB_DIR = "/etc/ipa/nssdb"
    IPA_NSSDB_PWDFILE_TXT = "/etc/ipa/nssdb/pwdfile.txt"
    COMMON_KRB5_CONF_DIR = "/etc/krb5.conf.d/"
    KRB5_CONF = "/etc/krb5.conf"
    KRB5_FREEIPA = COMMON_KRB5_CONF_DIR + "freeipa"
    KRB5_FREEIPA_SERVER = COMMON_KRB5_CONF_DIR + "freeipa-server"
    KRB5_KEYTAB = "/etc/krb5.keytab"
    LDAP_CONF = "/etc/ldap.conf"
    LIBNSS_LDAP_CONF = "/etc/libnss-ldap.conf"
    NAMED_CONF = "/etc/named.conf"
    NAMED_CONF_BAK = "/etc/named.conf.ipa-backup"
    NAMED_CUSTOM_CONF = "/etc/named/ipa-ext.conf"
    NAMED_LOGGING_OPTIONS_CONF = "/etc/named/ipa-logging-ext.conf"
    NAMED_CUSTOM_OPTIONS_CONF = "/etc/named/ipa-options-ext.conf"
    NAMED_CONF_SRC = '/usr/share/ipa/bind.named.conf.template'
    NAMED_CUSTOM_CONF_SRC = '/usr/share/ipa/bind.ipa-ext.conf.template'
    NAMED_CUSTOM_OPTIONS_CONF_SRC = (
        '/usr/share/ipa/bind.ipa-options-ext.conf.template'
    )
    NAMED_LOGGING_OPTIONS_CONF_SRC = (
        "/usr/share/ipa/bind.ipa-logging-ext.conf.template"
    )
    NAMED_VAR_DIR = "/var/named"
    NAMED_KEYTAB = "/etc/named.keytab"
    NAMED_RFC1912_ZONES = "/etc/named.rfc1912.zones"
    NAMED_ROOT_KEY = "/etc/named.root.key"
    NAMED_MANAGED_KEYS_DIR = "/var/named/dynamic"
    NAMED_CRYPTO_POLICY_FILE = None
    UNBOUND_CONF_SRC = '/usr/share/ipa/client/unbound.conf.template'
    UNBOUND_CONF = "/etc/unbound/conf.d/zzz-ipa.conf"
    NSLCD_CONF = "/etc/nslcd.conf"
    NSS_LDAP_CONF = "/etc/nss_ldap.conf"
    NSSWITCH_CONF = "/etc/nsswitch.conf"
    CHRONY_CONF = "/etc/chrony.conf"
    NTP_CONF = "/etc/ntp.conf"
    NTP_STEP_TICKERS = "/etc/ntp/step-tickers"
    ETC_OPENDNSSEC_DIR = "/etc/opendnssec"
    OPENDNSSEC_CONF_FILE = "/etc/opendnssec/conf.xml"
    OPENDNSSEC_KASP_FILE = "/etc/opendnssec/kasp.xml"
    OPENDNSSEC_ZONELIST_FILE = "/etc/opendnssec/zonelist.xml"
    OPENLDAP_LDAP_CONF = "/etc/openldap/ldap.conf"
    PAM_LDAP_CONF = "/etc/pam_ldap.conf"
    PASSWD = "/etc/passwd"
    # Trusted CA certificates used to be written out to this file. In newer
    # versions of FreeIPA, it has been replaced by IPA_P11_KIT.
    SYSTEMWIDE_IPA_CA_CRT = "/etc/pki/ca-trust/source/anchors/ipa-ca.crt"
    IPA_P11_KIT = "/etc/pki/ca-trust/source/ipa.p11-kit"
    CA_CERTIFICATES_BUNDLE_PEM = None
    CA_CERTIFICATES_DIR = None
    NSS_DB_DIR = "/etc/pki/nssdb"
    PKI_CONFIGURATION = "/etc/pki"
    PKI_TOMCAT = "/etc/pki/pki-tomcat"
    PKI_TOMCAT_ALIAS_DIR = "/etc/pki/pki-tomcat/alias"
    PKI_TOMCAT_ALIAS_PWDFILE_TXT = "/etc/pki/pki-tomcat/alias/pwdfile.txt"
    PKI_TOMCAT_PASSWORD_CONF = "/etc/pki/pki-tomcat/password.conf"
    PKI_TOMCAT_SERVER_XML = "/etc/pki/pki-tomcat/server.xml"
    PKI_ACME_CONFIGSOURCES_CONF = "/etc/pki/pki-tomcat/acme/configsources.conf"
    PKI_ACME_DATABASE_CONF = "/etc/pki/pki-tomcat/acme/database.conf"
    PKI_ACME_ENGINE_CONF = "/etc/pki/pki-tomcat/acme/engine.conf"
    PKI_ACME_ISSUER_CONF = "/etc/pki/pki-tomcat/acme/issuer.conf"
    PKI_ACME_REALM_CONF = "/etc/pki/pki-tomcat/acme/realm.conf"
    ETC_REDHAT_RELEASE = "/etc/redhat-release"
    RESOLV_CONF = "/etc/resolv.conf"
    SAMBA_KEYTAB = "/etc/samba/samba.keytab"
    SMB_CONF = "/etc/samba/smb.conf"
    LIMITS_CONF = "/etc/security/limits.conf"
    SSH_CONFIG_DIR = "/etc/ssh"
    SSH_CONFIG = "/etc/ssh/ssh_config"
    SSH_IPA_CONFIG_TEMPLATE = "/usr/share/ipa/client/ssh_ipa.conf.template"
    SSH_IPA_CONFIG = "/etc/ssh/ssh_config.d/04-ipa.conf"
    SSHD_CONFIG = "/etc/ssh/sshd_config"
    SSHD_IPA_CONFIG = "/etc/ssh/sshd_config.d/04-ipa.conf"
    SSHD_IPA_CONFIG_TEMPLATE = "/usr/share/ipa/client/sshd_ipa.conf.template"
    SSSD_CONF = "/etc/sssd/sssd.conf"
    SSSD_CONF_BKP = "/etc/sssd/sssd.conf.bkp"
    SSSD_CONF_DELETED = "/etc/sssd/sssd.conf.deleted"
    ETC_SYSCONFIG_DIR = "/etc/sysconfig"
    ETC_SYSCONFIG_AUTHCONFIG = "/etc/sysconfig/authconfig"
    SYSCONFIG_AUTOFS = "/etc/sysconfig/autofs"
    SYSCONFIG_DIRSRV = "/etc/sysconfig/dirsrv"
    SYSCONFIG_DIRSRV_INSTANCE = "/etc/sysconfig/dirsrv-%s"
    SYSCONFIG_DIRSRV_SYSTEMD = "/etc/sysconfig/dirsrv.systemd"
    SYSCONFIG_IPA_DNSKEYSYNCD = "/etc/sysconfig/ipa-dnskeysyncd"
    SYSCONFIG_IPA_ODS_EXPORTER = "/etc/sysconfig/ipa-ods-exporter"
    SYSCONFIG_HTTPD = "/etc/sysconfig/httpd"
    SYSCONFIG_KRB5KDC_DIR = "/etc/sysconfig/krb5kdc"
    SYSCONFIG_NAMED = "/etc/sysconfig/named"
    SYSCONFIG_NFS = "/etc/sysconfig/nfs"
    SYSCONFIG_NTPD = "/etc/sysconfig/ntpd"
    SYSCONFIG_ODS = "/etc/sysconfig/ods"
    SYSCONFIG_PKI = "/etc/sysconfig/pki"
    SYSCONFIG_PKI_TOMCAT = "/etc/sysconfig/pki-tomcat"
    SYSCONFIG_PKI_TOMCAT_PKI_TOMCAT_DIR = "/etc/sysconfig/pki/tomcat/pki-tomcat"
    ETC_SYSTEMD_SYSTEM_DIR = "/etc/systemd/system/"
    SYSTEMD_SYSTEM_HTTPD_D_DIR = "/etc/systemd/system/httpd.service.d/"
    SYSTEMD_SYSTEM_HTTPD_IPA_CONF = "/etc/systemd/system/httpd.service.d/ipa.conf"
    SYSTEMD_CERTMONGER_SERVICE = "/etc/systemd/system/multi-user.target.wants/certmonger.service"
    SYSTEMD_IPA_SERVICE = "/etc/systemd/system/multi-user.target.wants/ipa.service"
    SYSTEMD_SSSD_SERVICE = "/etc/systemd/system/multi-user.target.wants/sssd.service"
    SYSTEMD_PKI_TOMCAT_SERVICE = "/etc/systemd/system/pki-tomcatd.target.wants/pki-tomcatd@pki-tomcat.service"
    SYSTEMD_PKI_TOMCAT_IPA_CONF = \
        "/etc/systemd/system/pki-tomcatd@pki-tomcat.service.d/ipa.conf"
    ETC_TMPFILESD_DIRSRV = "/etc/tmpfiles.d/dirsrv-%s.conf"
    DNSSEC_TRUSTED_KEY = "/etc/trusted-key.key"
    HOME_DIR = "/home"
    PROC_FIPS_ENABLED = "/proc/sys/crypto/fips_enabled"
    ROOT_IPA_CACHE = "/root/.ipa_cache"
    ROOT_PKI = "/root/.pki"
    DOGTAG_ADMIN_P12 = "/root/ca-agent.p12"
    RA_AGENT_PEM = "/var/lib/ipa/ra-agent.pem"
    RA_AGENT_KEY = "/var/lib/ipa/ra-agent.key"
    CACERT_P12 = "/root/cacert.p12"
    ROOT_IPA_CSR = "/root/ipa.csr"
    NAMED_PID = "/run/named/named.pid"
    NOLOGIN = "/sbin/nologin"
    SBIN_REBOOT = "/sbin/reboot"
    SBIN_RESTORECON = "/sbin/restorecon"
    SBIN_SERVICE = "/sbin/service"
    TMP = "/tmp"
    TMP_CA_P12 = "/tmp/ca.p12"
    TMP_KRB5CC = "/tmp/krb5cc_%d"
    USR_DIR = "/usr"
    CERTMONGER_COMMAND_TEMPLATE = "/usr/libexec/ipa/certmonger/%s"
    PKCS12EXPORT = "/usr/bin/PKCS12Export"
    CERTUTIL = "/usr/bin/certutil"
    CHROMIUM_BROWSER = "/usr/bin/chromium-browser"
    FIREFOX = "/usr/bin/firefox"
    GETCERT = "/usr/bin/getcert"
    GPG2 = "/usr/bin/gpg"
    GPG_CONF = "/usr/bin/gpgconf"
    GPG_CONNECT_AGENT = "/usr/bin/gpg-connect-agent"
    GPG_AGENT = "/usr/bin/gpg-agent"
    IPA_GETCERT = "/usr/bin/ipa-getcert"
    KADMIN_LOCAL = '/usr/sbin/kadmin.local'
    KDESTROY = "/usr/bin/kdestroy"
    KINIT = "/usr/bin/kinit"
    KLIST = "/usr/bin/klist"
    KTUTIL = "/usr/bin/ktutil"
    BIN_KVNO = "/usr/bin/kvno"
    LDAPMODIFY = "/usr/bin/ldapmodify"
    LDAPPASSWD = "/usr/bin/ldappasswd"
    MODUTIL = "/usr/bin/modutil"
    NET = "/usr/bin/net"
    BIN_NISDOMAINNAME = "/usr/bin/nisdomainname"
    NSUPDATE = "/usr/bin/nsupdate"
    ODS_KSMUTIL = "/usr/bin/ods-ksmutil"
    ODS_SIGNER = "/usr/sbin/ods-signer"
    ODS_ENFORCER = "/usr/sbin/ods-enforcer"
    ODS_ENFORCER_DB_SETUP = "/usr/sbin/ods-enforcer-db-setup"
    OPENSSL = "/usr/bin/openssl"
    OPENSSL_DIR = "/etc/pki/tls"
    OPENSSL_CERTS_DIR = "/etc/pki/tls/certs"
    OPENSSL_PRIVATE_DIR = "/etc/pki/tls/private"
    BIND_DNS_OVER_TLS_CRT = "/etc/pki/tls/certs/bind_dot.crt"
    BIND_DNS_OVER_TLS_KEY = "/etc/pki/tls/private/bind_dot.key"
    PK12UTIL = "/usr/bin/pk12util"
    SOFTHSM2_UTIL = "/usr/bin/softhsm2-util"
    SSLGET = "/usr/bin/sslget"
    SSS_SSH_AUTHORIZEDKEYS = "/usr/bin/sss_ssh_authorizedkeys"
    SSS_SSH_KNOWNHOSTS = "/usr/bin/sss_ssh_knownhosts"
    SSS_SSH_KNOWNHOSTSPROXY = "/usr/bin/sss_ssh_knownhostsproxy"
    BIN_TIMEOUT = "/usr/bin/timeout"
    UPDATE_CA_TRUST = "/usr/bin/update-ca-trust"
    BIN_CURL = "/usr/bin/curl"
    BIND_LDAP_SO = "/usr/lib/bind/ldap.so"
    BIND_LDAP_DNS_IPA_WORKDIR = "/var/named/dyndb-ldap/ipa/"
    BIND_LDAP_DNS_ZONE_WORKDIR = "/var/named/dyndb-ldap/ipa/master/"
    LIB_FIREFOX = "/usr/lib/firefox"
    LIBSOFTHSM2_SO = "/usr/lib/pkcs11/libsofthsm2.so"
    PAM_KRB5_SO = "/usr/lib/security/pam_krb5.so"
    LIB_SYSTEMD_SYSTEMD_DIR = "/usr/lib/systemd/system/"
    BIND_LDAP_SO_64 = "/usr/lib64/bind/ldap.so"
    LIB64_FIREFOX = "/usr/lib64/firefox"
    LIBSOFTHSM2_SO_64 = "/usr/lib64/pkcs11/libsofthsm2.so"
    PAM_KRB5_SO_64 = "/usr/lib64/security/pam_krb5.so"
    LIBEXEC_CERTMONGER_DIR = "/usr/libexec/certmonger"
    DOGTAG_IPA_CA_RENEW_AGENT_SUBMIT = "/usr/libexec/certmonger/dogtag-ipa-ca-renew-agent-submit"
    DOGTAG_IPA_RENEW_AGENT_SUBMIT = "/usr/libexec/certmonger/dogtag-ipa-renew-agent-submit"
    CERTMONGER_DOGTAG_SUBMIT = "/usr/libexec/certmonger/dogtag-submit"
    IPA_SERVER_GUARD = "/usr/libexec/certmonger/ipa-server-guard"
    GENERATE_RNDC_KEY = "/usr/libexec/generate-rndc-key.sh"
    RNDC_KEY = "/etc/rndc.key"
    LIBEXEC_IPA_DIR = "/usr/libexec/ipa"
    IPA_DNSKEYSYNCD_REPLICA = "/usr/libexec/ipa/ipa-dnskeysync-replica"
    IPA_DNSKEYSYNCD = "/usr/libexec/ipa/ipa-dnskeysyncd"
    IPA_HTTPD_KDCPROXY = "/usr/libexec/ipa/ipa-httpd-kdcproxy"
    IPA_ODS_EXPORTER = "/usr/libexec/ipa/ipa-ods-exporter"
    IPA_PKI_RETRIEVE_KEY = "/usr/libexec/ipa/ipa-pki-retrieve-key"
    IPA_HTTPD_PASSWD_READER = "/usr/libexec/ipa/ipa-httpd-pwdreader"
    IPA_PKI_WAIT_RUNNING = "/usr/libexec/ipa/ipa-pki-wait-running"
    DNSSEC_KEYFROMLABEL = "/usr/sbin/dnssec-keyfromlabel"
    DNSSEC_KEYFROMLABEL_9_17 = "/usr/bin/dnssec-keyfromlabel"
    GETSEBOOL = "/usr/sbin/getsebool"
    GROUPADD = "/usr/sbin/groupadd"
    USERMOD = "/usr/sbin/usermod"
    HTTPD = "/usr/sbin/httpd"
    IPA_CLIENT_AUTOMOUNT = "/usr/sbin/ipa-client-automount"
    IPA_CLIENT_INSTALL = "/usr/sbin/ipa-client-install"
    IPA_DNS_INSTALL = "/usr/sbin/ipa-dns-install"
    SBIN_IPA_JOIN = "/usr/sbin/ipa-join"
    IPA_REPLICA_CONNCHECK = "/usr/sbin/ipa-replica-conncheck"
    IPA_RMKEYTAB = "/usr/sbin/ipa-rmkeytab"
    IPACTL = "/usr/sbin/ipactl"
    CHRONYC = "/usr/bin/chronyc"
    CHRONYD = "/usr/sbin/chronyd"
    PKIDESTROY = "/usr/sbin/pkidestroy"
    PKISPAWN = "/usr/sbin/pkispawn"
    PKI = "/usr/bin/pki"
    RESTORECON = "/usr/sbin/restorecon"
    SELINUXENABLED = "/usr/sbin/selinuxenabled"
    SETSEBOOL = "/usr/sbin/setsebool"
    SEMODULE = "/usr/sbin/semodule"
    SMBD = "/usr/sbin/smbd"
    USERADD = "/usr/sbin/useradd"
    FONTS_DIR = "/usr/share/fonts"
    FONTS_OPENSANS_DIR = "/usr/share/fonts/open-sans"
    FONTS_FONTAWESOME_DIR = "/usr/share/fonts/fontawesome"
    USR_SHARE_IPA_DIR = "/usr/share/ipa/"
    USR_SHARE_IPA_CLIENT_DIR = "/usr/share/ipa/client"
    CA_TOPOLOGY_ULDIF = "/usr/share/ipa/ca-topology.uldif"
    IPA_HTML_DIR = "/usr/share/ipa/html"
    CA_CRT = "/usr/share/ipa/html/ca.crt"
    KRB_CON = "/usr/share/ipa/html/krb.con"
    HTML_KRB5_INI = "/usr/share/ipa/html/krb5.ini"
    HTML_KRBREALM_CON = "/usr/share/ipa/html/krbrealm.con"
    SCHEMA_COMPAT_ULDIF = "/usr/share/ipa/updates/91-schema_compat.update"
    SCHEMA_COMPAT_POST_ULDIF = "/usr/share/ipa/schema_compat_post.uldif"
    IPA_JS_PLUGINS_DIR = "/usr/share/ipa/ui/js/plugins"
    UPDATES_DIR = "/usr/share/ipa/updates/"
    DICT_WORDS = "/usr/share/dict/words"
    VAR_KERBEROS_KRB5KDC_DIR = "/var/kerberos/krb5kdc/"
    VAR_KRB5KDC_K5_REALM = "/var/kerberos/krb5kdc/.k5."
    CACERT_PEM = "/var/kerberos/krb5kdc/cacert.pem"
    KRB5KDC_KADM5_ACL = "/var/kerberos/krb5kdc/kadm5.acl"
    KRB5KDC_KADM5_KEYTAB = "/var/kerberos/krb5kdc/kadm5.keytab"
    KRB5KDC_KDC_CONF = "/var/kerberos/krb5kdc/kdc.conf"
    KDC_CERT = "/var/kerberos/krb5kdc/kdc.crt"
    KDC_KEY = "/var/kerberos/krb5kdc/kdc.key"
    VAR_LIB = "/var/lib"
    AUTHCONFIG_LAST = "/var/lib/authconfig/last"
    VAR_LIB_CERTMONGER_DIR = "/var/lib/certmonger"
    CERTMONGER_CAS_DIR = "/var/lib/certmonger/cas/"
    CERTMONGER_CAS_CA_RENEWAL = "/var/lib/certmonger/cas/ca_renewal"
    CERTMONGER_REQUESTS_DIR = "/var/lib/certmonger/requests/"
    VAR_LIB_DIRSRV = "/var/lib/dirsrv"
    DIRSRV_BOOT_LDIF = "/var/lib/dirsrv/boot.ldif"
    VAR_LIB_IPA = "/var/lib/ipa"
    IPA_CLIENT_SYSRESTORE = "/var/lib/ipa-client/sysrestore"
    SYSRESTORE_INDEX = "/var/lib/ipa-client/sysrestore/sysrestore.index"
    IPA_BACKUP_DIR = "/var/lib/ipa/backup"
    IPA_DNSSEC_DIR = "/var/lib/ipa/dnssec"
    IPA_KASP_DB_BACKUP = "/var/lib/ipa/ipa-kasp.db.backup"
    DNSSEC_TOKENS_DIR = "/var/lib/ipa/dnssec/tokens"
    DNSSEC_SOFTHSM_PIN = "/var/lib/ipa/dnssec/softhsm_pin"
    DNSSEC_ENGINE_SOCK = "/run/opendnssec/engine.sock"
    IPA_CA_CSR = "/var/lib/ipa/ca.csr"
    IPA_CACERT_MANAGE = "/usr/sbin/ipa-cacert-manage"
    IPA_CERTUPDATE = "/usr/sbin/ipa-certupdate"
    PKI_CA_PUBLISH_DIR = "/var/lib/ipa/pki-ca/publish"
    REPLICA_INFO_TEMPLATE = "/var/lib/ipa/replica-info-%s"
    REPLICA_INFO_GPG_TEMPLATE = "/var/lib/ipa/replica-info-%s.gpg"
    SYSRESTORE = "/var/lib/ipa/sysrestore"
    STATEFILE_DIR = "/var/lib/ipa/sysupgrade"
    VAR_LIB_KDCPROXY = "/var/lib/kdcproxy"
    VAR_LIB_PKI_DIR = "/var/lib/pki"
    VAR_LIB_PKI_CA_ALIAS_DIR = "/var/lib/pki-ca/alias"
    VAR_LIB_PKI_TOMCAT_DIR = "/var/lib/pki/pki-tomcat"
    CA_BACKUP_KEYS_P12 = "/var/lib/pki/pki-tomcat/alias/ca_backup_keys.p12"
    KRA_BACKUP_KEYS_P12 = "/var/lib/pki/pki-tomcat/alias/kra_backup_keys.p12"
    CA_CS_CFG_PATH = "/var/lib/pki/pki-tomcat/conf/ca/CS.cfg"
    CASIGNEDLOGCERT_CFG = (
        "/var/lib/pki/pki-tomcat/ca/profiles/ca/caSignedLogCert.cfg")
    KRA_CS_CFG_PATH = "/var/lib/pki/pki-tomcat/conf/kra/CS.cfg"
    KRACERT_P12 = "/root/kracert.p12"
    SAMBA_DIR = "/var/lib/samba"
    SSSD_DB = "/var/lib/sss/db"
    SSSD_MC_GROUP = "/var/lib/sss/mc/group"
    SSSD_MC_PASSWD = "/var/lib/sss/mc/passwd"
    SSSD_MC_INITGROUPS = "/var/lib/sss/mc/initgroups"
    SSSD_MC_SID = "/var/lib/sss/mc/sid"
    SSSD_PIPES = "/var/lib/sss/pipes"
    SSSD_LDB = "/var/lib/sss/db/sssd.ldb"
    SSSD_CONFIG_LDB = "/var/lib/sss/db/config.ldb"
    SSSD_SECRETS = "/var/lib/sss/secrets/secrets.ldb"
    SSSD_PUBCONF_DIR = "/var/lib/sss/pubconf"
    SSSD_PUBCONF_KNOWN_HOSTS = "/var/lib/sss/pubconf/known_hosts"
    SSSD_PUBCONF_KRB5_INCLUDE_D_DIR = "/var/lib/sss/pubconf/krb5.include.d/"
    SSSD_KEYTABS_DIR = "/var/lib/sss/keytabs"
    VAR_LOG_AUDIT = "/var/log/audit/audit.log"
    VAR_LOG_HTTPD_DIR = "/var/log/httpd"
    VAR_LOG_HTTPD_ERROR = "/var/log/httpd/error_log"
    IPABACKUP_LOG = "/var/log/ipabackup.log"
    IPACLIENT_INSTALL_LOG = "/var/log/ipaclient-install.log"
    IPACLIENT_UNINSTALL_LOG = "/var/log/ipaclient-uninstall.log"
    IPACLIENTSAMBA_INSTALL_LOG = "/var/log/ipaclientsamba-install.log"
    IPACLIENTSAMBA_UNINSTALL_LOG = "/var/log/ipaclientsamba-uninstall.log"
    IPAREPLICA_CA_INSTALL_LOG = "/var/log/ipareplica-ca-install.log"
    IPAREPLICA_CONNCHECK_LOG = "/var/log/ipareplica-conncheck.log"
    IPAREPLICA_INSTALL_LOG = "/var/log/ipareplica-install.log"
    IPARESTORE_LOG = "/var/log/iparestore.log"
    IPASERVER_ENABLESID_LOG = "/var/log/ipaserver-enable-sid.log"
    IPASERVER_INSTALL_LOG = "/var/log/ipaserver-install.log"
    IPASERVER_ADTRUST_INSTALL_LOG = "/var/log/ipaserver-adtrust-install.log"
    IPASERVER_DNS_INSTALL_LOG = "/var/log/ipaserver-dns-install.log"
    IPASERVER_KRA_INSTALL_LOG = "/var/log/ipaserver-kra-install.log"
    IPASERVER_UNINSTALL_LOG = "/var/log/ipaserver-uninstall.log"
    IPAUPGRADE_LOG = "/var/log/ipaupgrade.log"
    IPATRUSTENABLEAGENT_LOG = "/var/log/ipatrust-enable-agent.log"
    IPAEPN_LOG = "/var/log/ipaepn.log"
    KADMIND_LOG = "/var/log/kadmind.log"
    KRB5KDC_LOG = "/var/log/krb5kdc.log"
    MESSAGES = "/var/log/messages"
    VAR_LOG_PKI_DIR = "/var/log/pki/"
    BIN_TOMCAT = "/usr/sbin/tomcat"
    TOMCAT_TOPLEVEL_DIR = "/var/log/pki/pki-tomcat"
    TOMCAT_CA_DIR = "/var/log/pki/pki-tomcat/ca"
    TOMCAT_CA_ARCHIVE_DIR = "/var/log/pki/pki-tomcat/ca/archive"
    TOMCAT_SIGNEDAUDIT_DIR = "/var/log/pki/pki-tomcat/ca/signedAudit"
    TOMCAT_KRA_DIR = "/var/log/pki/pki-tomcat/kra"
    TOMCAT_KRA_ARCHIVE_DIR = "/var/log/pki/pki-tomcat/kra/archive"
    TOMCAT_KRA_SIGNEDAUDIT_DIR = "/var/log/pki/pki-tomcat/kra/signedAudit"
    LOG_SECURE = "/var/log/secure"
    VAR_LOG_SSSD_DIR = "/var/log/sssd"
    NAMED_RUN = "/var/named/data/named.run"
    VAR_OPENDNSSEC_DIR = "/var/opendnssec"
    OPENDNSSEC_KASP_DB = "/var/opendnssec/kasp.db"
    IPA_ODS_EXPORTER_CCACHE = "/var/opendnssec/tmp/ipa-ods-exporter.ccache"
    VAR_RUN_DIRSRV_DIR = "/run/dirsrv"
    IPA_CCACHES = "/run/ipa/ccaches"
    CA_BUNDLE_PEM = "/var/lib/ipa-client/pki/ca-bundle.pem"
    KDC_CA_BUNDLE_PEM = "/var/lib/ipa-client/pki/kdc-ca-bundle.pem"
    IPA_RENEWAL_LOCK = "/run/ipa/renewal.lock"
    SVC_LIST_FILE = "/run/ipa/services.list"
    KRB5CC_SAMBA = "/run/samba/krb5cc_samba"
    SLAPD_INSTANCE_SOCKET_TEMPLATE = "/run/slapd-%s.socket"
    ADMIN_CERT_PATH = '/root/.dogtag/pki-tomcat/ca_admin.cert'
    ENTROPY_AVAIL = '/proc/sys/kernel/random/entropy_avail'
    KDCPROXY_CONFIG = '/etc/ipa/kdcproxy/kdcproxy.conf'
    CERTMONGER = '/usr/sbin/certmonger'
    NETWORK_MANAGER_CONFIG = '/etc/NetworkManager/NetworkManager.conf'
    NETWORK_MANAGER_CONFIG_DIR = '/etc/NetworkManager/conf.d'
    NETWORK_MANAGER_IPA_CONF = '/etc/NetworkManager/conf.d/zzz-ipa.conf'
    SYSTEMD_RESOLVED_IPA_CONF = '/etc/systemd/resolved.conf.d/zzz-ipa.conf'
    SYSTEMD_RESOLVED_CONF = '/etc/systemd/resolved.conf'
    SYSTEMD_RESOLVED_CONF_DIR = '/etc/systemd/resolved.conf.d'
    IPA_CUSTODIA_CONF_DIR = '/etc/ipa/custodia'
    IPA_CUSTODIA_CONF = '/etc/ipa/custodia/custodia.conf'
    IPA_CUSTODIA_KEYS = '/etc/ipa/custodia/server.keys'
    IPA_CUSTODIA_SOCKET = '/run/httpd/ipa-custodia.sock'
    IPA_CUSTODIA_AUDIT_LOG = '/var/log/ipa-custodia.audit.log'
    IPA_CUSTODIA_HANDLER = "/usr/libexec/ipa/custodia"
    IPA_CUSTODIA_CHECK = "/usr/libexec/ipa/ipa-custodia-check"
    IPA_GETKEYTAB = '/usr/sbin/ipa-getkeytab'
    IPA_MIGRATE_LOG = '/var/log/ipa-migrate.log'
    EXTERNAL_SCHEMA_DIR = '/usr/share/ipa/schema.d'
    GSSPROXY_CONF = '/etc/gssproxy/10-ipa.conf'
    KRB5CC_HTTPD = '/tmp/krb5cc-httpd'
    IF_INET6 = '/proc/net/if_inet6'
    WSGI_PREFIX_DIR = "/run/httpd/wsgi"
    AUTHCONFIG = None
    AUTHSELECT = None
    SYSCONF_NETWORK = None
    ETC_PKCS11_MODULES_DIR = "/etc/pkcs11/modules"
    # 389 DS related commands.
    DSCREATE = '/usr/sbin/dscreate'
    DSCTL = '/usr/sbin/dsctl'
    DSCONF = '/usr/sbin/dsconf'
    # DS related constants
    ETC_DIRSRV = "/etc/dirsrv"
    DS_KEYTAB = "/etc/dirsrv/ds.keytab"
    ETC_DIRSRV_SLAPD_INSTANCE_TEMPLATE = "/etc/dirsrv/slapd-%s"
    USR_LIB_DIRSRV = "/usr/lib/dirsrv"
    USR_LIB_DIRSRV_64 = "/usr/lib64/dirsrv"
    VAR_LIB_DIRSRV_INSTANCE_SCRIPTS_TEMPLATE = "/var/lib/dirsrv/scripts-%s"
    VAR_LIB_SLAPD_INSTANCE_DIR_TEMPLATE = "/var/lib/dirsrv/slapd-%s"
    SLAPD_INSTANCE_BACKUP_DIR_TEMPLATE = "/var/lib/dirsrv/slapd-%s/bak/%s"
    SLAPD_INSTANCE_DB_DIR_TEMPLATE = "/var/lib/dirsrv/slapd-%s/db/%s"
    SLAPD_INSTANCE_LDIF_DIR_TEMPLATE = "/var/lib/dirsrv/slapd-%s/ldif"
    DIRSRV_LOCK_DIR = "/run/lock/dirsrv"
    ALL_SLAPD_INSTANCE_SOCKETS = "/run/slapd-*.socket"
    VAR_LOG_DIRSRV_INSTANCE_TEMPLATE = "/var/log/dirsrv/slapd-%s"
    VAR_LOG_DIRSRV = "/var/log/dirsrv/"
    SLAPD_INSTANCE_ACCESS_LOG_TEMPLATE = "/var/log/dirsrv/slapd-%s/access"
    SLAPD_INSTANCE_ERROR_LOG_TEMPLATE = "/var/log/dirsrv/slapd-%s/errors"
    SLAPD_INSTANCE_AUDIT_LOG_TEMPLATE = "/var/log/dirsrv/slapd-%s/audit"
    SLAPD_INSTANCE_SYSTEMD_IPA_ENV_TEMPLATE = \
        "/etc/systemd/system/dirsrv@%s.service.d/ipa-env.conf"
    IPA_SERVER_UPGRADE = '/usr/sbin/ipa-server-upgrade'
    KEYCTL = '/bin/keyctl'
    GETENT = '/usr/bin/getent'
    SSHD = '/usr/sbin/sshd'
    SSSCTL = '/usr/sbin/sssctl'
    LIBARCH = "64"
    TDBTOOL = '/usr/bin/tdbtool'
    SECRETS_TDB = '/var/lib/samba/private/secrets.tdb'
    LETS_ENCRYPT_LOG = '/var/log/letsencrypt/letsencrypt.log'
    IPA_CCACHE_SWEEPER_GSSPROXY_SOCK = (
        "/var/lib/gssproxy/ipa_ccache_sweeper.sock"
    )
    PAM_CONFIG = None
    PASSKEY_CHILD = '/usr/libexec/sssd/passkey_child'

    def check_paths(self):
        """Check paths for missing files

        python3 -c 'from ipaplatform.paths import paths; paths.check_paths()'
        """
        executables = (
            "/bin", "/sbin", "/usr/bin", "/usr/sbin",
            self.LIBEXEC_IPA_DIR, self.LIBEXEC_CERTMONGER_DIR
        )
        for name in sorted(dir(self)):
            if not name[0].isupper():
                continue

            value = getattr(self, name)
            if not value or not isinstance(value, str):
                # skip empty values
                continue
            if "%" in value or "{" in value:
                # skip templates
                continue

            if value.startswith(executables) and value not in executables:
                if not os.path.isfile(value):
                    print("Missing executable {}={}".format(name, value))


paths = BasePathNamespace()
