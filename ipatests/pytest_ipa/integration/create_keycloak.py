import os
import textwrap
import time

from ipaplatform.paths import paths
from ipatests.pytest_ipa.integration import tasks


def setup_keycloakserver(host, version='24.0.2'):
    dir = "/opt/keycloak"
    password = host.config.admin_password
    tasks.install_packages(host, ["unzip", "java-11-openjdk-headless",
                                  "openssl", "maven", "wget",
                                  "firefox", "xorg-x11-server-Xvfb"])
    #  add keycloak system user/group and folder
    url = "https://github.com/keycloak/keycloak/releases/download/{0}/keycloak-{0}.zip".format(version)  # noqa: E501
    host.run_command(["wget", url, "-O", "{0}-{1}.zip".format(dir, version)])
    host.run_command(
        ["unzip", "{0}-{1}.zip".format(dir, version), "-d", "/opt/"]
    )
    host.run_command(["mv", "{0}-{1}".format(dir, version), dir])
    host.run_command(["groupadd", "keycloak"])
    host.run_command(
        ["useradd", "-r", "-g", "keycloak", "-d", dir, "keycloak"]
    )
    host.run_command(["chown", "-R", "keycloak:", dir])
    host.run_command(["chmod", "o+x", "{0}/bin/".format(dir)])
    host.run_command(["restorecon", "-R", dir])

    # setup TLS certificate using IPA CA
    host.run_command(["kinit", "-k"])
    host.run_command(["ipa", "service-add", "HTTP/{0}".format(host.hostname)])

    key = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.key")
    crt = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.crt")
    keystore = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.store")

    host.run_command(["ipa-getcert", "request", "-K",
                      "HTTP/{0}".format(host.hostname),
                      "-D", host.hostname, "-o", "keycloak",
                      "-O", "keycloak", "-m", "0600",
                      "-M", "0644",
                      "-k", key, "-f", crt, "-w"])
    host.run_command(["keytool", "-import", "-keystore", keystore,
                      "-file", "/etc/ipa/ca.crt",
                      "-alias", "ipa_ca",
                      "-trustcacerts", "-storepass", password, "-noprompt"])
    host.run_command(["chown", "keycloak:keycloak", keystore])

    # Setup keycloak service and config files
    contents = textwrap.dedent("""
    KEYCLOAK_ADMIN=admin
    KEYCLOAK_ADMIN_PASSWORD={admin_pswd}
    KC_HOSTNAME={host}:8443
    KC_HTTPS_CERTIFICATE_FILE={crt}
    KC_HTTPS_CERTIFICATE_KEY_FILE={key}
    KC_HTTPS_TRUST_STORE_FILE={store}
    KC_HTTPS_TRUST_STORE_PASSWORD={store_pswd}
    KC_HTTP_RELATIVE_PATH=/auth
    """).format(admin_pswd=password, host=host.hostname, crt=crt, key=key,
                store=keystore, store_pswd=password)
    host.put_file_contents("/etc/sysconfig/keycloak", contents)

    contents = textwrap.dedent("""
    [Unit]
    Description=Keycloak Server
    After=network.target

    [Service]
    Type=idle
    EnvironmentFile=/etc/sysconfig/keycloak

    User=keycloak
    Group=keycloak
    ExecStart=/opt/keycloak/bin/kc.sh start
    TimeoutStartSec=600
    TimeoutStopSec=600

    [Install]
    WantedBy=multi-user.target
    """)
    host.put_file_contents("/etc/systemd/system/keycloak.service", contents)
    host.run_command(["systemctl", "daemon-reload"])

    # Run build stage first
    env_vars = textwrap.dedent("""
    export KEYCLOAK_ADMIN=admin
    export KC_HOSTNAME={hostname}:8443
    export KC_HTTPS_CERTIFICATE_FILE=/etc/pki/tls/certs/keycloak.crt
    export KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/pki/tls/private/keycloak.key
    export KC_HTTPS_TRUST_STORE_FILE=/etc/pki/tls/private/keycloak.store
    export KC_HTTPS_TRUST_STORE_PASSWORD={STORE_PASS}
    export KEYCLOAK_ADMIN_PASSWORD={ADMIN_PASS}
    export KC_HTTP_RELATIVE_PATH=/auth
    """).format(hostname=host.hostname, STORE_PASS=password,
                ADMIN_PASS=password)

    tasks.backup_file(host, '/etc/bashrc')
    content = host.get_file_contents('/etc/bashrc',
                                     encoding='utf-8')
    new_content = content + "\n{}".format(env_vars)
    host.put_file_contents('/etc/bashrc', new_content)
    host.run_command(['bash'])
    host.run_command(
        ['su', '-', 'keycloak', '-c', '/opt/keycloak/bin/kc.sh build'])
    host.run_command(["systemctl", "start", "keycloak"])
    host.run_command(["/opt/keycloak/bin/kc.sh", "show-config"])

    # Setup keycloak for use:
    kcadmin_sh = "/opt/keycloak/bin/kcadm.sh"

    host.run_command([kcadmin_sh, "config", "truststore",
                      "--trustpass", password, keystore])
    kcadmin = [kcadmin_sh, "config", "credentials", "--server",
               "https://{0}:8443/auth/".format(host.hostname),
               "--realm", "master", "--user", "admin",
               "--password", password
               ]
    tasks.run_repeatedly(
        host, kcadmin, timeout=60)
    host.run_command(
        [kcadmin_sh, "create", "users", "-r", "master",
         "-s", "username=testuser1", "-s", "enabled=true",
         "-s", "email=testuser1@ipa.test"]
    )
    host.run_command(
        [kcadmin_sh, "set-password", "-r", "master",
         "--username", "testuser1", "--new-password", password]
    )


def setup_keycloak_client(host):
    password = host.config.admin_password
    host.run_command(["/opt/keycloak/bin/kcreg.sh",
                      "config", "credentials", "--server",
                      "https://{0}:8443/auth/".format(host.hostname),
                      "--realm", "master", "--user", "admin",
                      "--password", password]
                     )

    client_json = textwrap.dedent("""
    {{
      "enabled" : true,
      "clientAuthenticatorType" : "client-secret",
      "redirectUris" : [ "https://ipa-ca.{redirect}/ipa/idp/*" ],
      "webOrigins" : [ "https://ipa-ca.{web}" ],
      "protocol" : "openid-connect",
      "attributes" : {{
      "oauth2.device.authorization.grant.enabled" : "true",
      "oauth2.device.polling.interval": "5"
      }}
    }}
    """).format(redirect=host.domain.name, web=host.domain.name)
    host.put_file_contents("/tmp/ipa_client.json", client_json)
    host.run_command(["/opt/keycloak/bin/kcreg.sh", "create",
                      "-f", "/tmp/ipa_client.json",
                      "-s", "clientId=ipa_oidc_client",
                      "-s", "secret={0}".format(password)]
                     )
    time.sleep(60)


def uninstall_keycloak(host):
    key = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.key")
    crt = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.crt")
    keystore = os.path.join(paths.OPENSSL_PRIVATE_DIR, "keycloak.store")

    host.run_command(["systemctl", "stop", "keycloak"], raiseonerr=False)
    host.run_command(["getcert", "stop-tracking", "-k", key, "-f", crt],
                     raiseonerr=False)
    host.run_command(["rm", "-rf", "/opt/keycloak",
                      "/etc/sysconfig/keycloak",
                      "/etc/systemd/system/keycloak.service",
                      key, crt, keystore])
    host.run_command(["systemctl", "daemon-reload"])
    host.run_command(["userdel", "keycloak"])
    host.run_command(["groupdel", "keycloak"], raiseonerr=False)
    tasks.restore_files(host)
