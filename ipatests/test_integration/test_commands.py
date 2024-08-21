#
# Copyright (C) 2018  FreeIPA Contributors see COPYING for license
#
"""Misc test for 'ipa' CLI regressions
"""
from __future__ import absolute_import

import base64
import re
import os
import logging
import random
import shlex
import ssl
from itertools import chain, repeat
import sys
import textwrap
import time
import pytest
from subprocess import CalledProcessError

from cryptography.hazmat.backends import default_backend
from cryptography import x509
from datetime import datetime, timedelta

from ipalib.constants import IPAAPI_USER

from ipaplatform.paths import paths

from ipapython.dn import DN

from ipapython.certdb import get_ca_nickname

from ipatests.test_integration.base import IntegrationTest

from ipatests.pytest_ipa.integration import tasks
from ipaplatform.tasks import tasks as platform_tasks
from ipatests.create_external_ca import ExternalCA
from ipatests.test_ipalib.test_x509 import good_pkcs7, badcert
from ipapython.ipautil import realm_to_suffix, ipa_generate_password
from ipaserver.install.installutils import realm_to_serverid
from pkg_resources import parse_version

logger = logging.getLogger(__name__)

# from ipaserver.masters
CONFIGURED_SERVICE = u'configuredService'
ENABLED_SERVICE = u'enabledService'
HIDDEN_SERVICE = u'hiddenService'

DIRSRV_SLEEP = 5

isrgrootx1 = (
    b'-----BEGIN CERTIFICATE-----\n'
    b'MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\n'
    b'TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n'
    b'cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4\n'
    b'WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu\n'
    b'ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY\n'
    b'MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc\n'
    b'h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+\n'
    b'0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U\n'
    b'A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW\n'
    b'T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH\n'
    b'B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC\n'
    b'B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv\n'
    b'KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn\n'
    b'OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn\n'
    b'jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw\n'
    b'qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI\n'
    b'rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\n'
    b'HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq\n'
    b'hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL\n'
    b'ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ\n'
    b'3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK\n'
    b'NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5\n'
    b'ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur\n'
    b'TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC\n'
    b'jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc\n'
    b'oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq\n'
    b'4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA\n'
    b'mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d\n'
    b'emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=\n'
    b'-----END CERTIFICATE-----\n'
)
isrgrootx1_nick = 'CN=ISRG Root X1,O=Internet Security Research Group,C=US'

# This sub-CA expires on Sep 15, 2025 and will need to be replaced
# after this date. Otherwise TestIPACommand::test_cacert_manage fails.
letsencryptauthorityr3 = (
    b'-----BEGIN CERTIFICATE-----\n'
    b'MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\n'
    b'TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\n'
    b'cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\n'
    b'WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\n'
    b'RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n'
    b'AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\n'
    b'R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\n'
    b'sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\n'
    b'NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\n'
    b'Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n'
    b'/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\n'
    b'AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\n'
    b'Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\n'
    b'FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\n'
    b'AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\n'
    b'Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\n'
    b'gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\n'
    b'PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\n'
    b'ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\n'
    b'CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\n'
    b'lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\n'
    b'avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\n'
    b'yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\n'
    b'yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\n'
    b'hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\n'
    b'HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\n'
    b'MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\n'
    b'nLRbwHOoq7hHwg==\n'
    b'-----END CERTIFICATE-----\n'
)
le_r3_nick = "CN=R3,O=Let's Encrypt,C=US"

# Certificates for reproducing duplicate ipaCertSubject values.
# The trick to creating the second intermediate is for the validity
# period to be different. In this case the second CA certificate
# was issued 3 years+1day after the original.
originalsubjectchain = (
    b'-----BEGIN CERTIFICATE-----\n'
    b'MIIDcjCCAlqgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwRDEeMBwGA1UECgwVQ2Vy\n'
    b'dGlmaWNhdGUgU2hhY2sgTHRkMSIwIAYDVQQDDBlDZXJ0aWZpY2F0ZSBTaGFjayBS\n'
    b'b290IENBMB4XDTIxMDgwNzE4MDQyNloXDTQxMDgwMTE4MDQyNlowTDEeMBwGA1UE\n'
    b'CgwVQ2VydGlmaWNhdGUgU2hhY2sgTHRkMSowKAYDVQQDDCFDZXJ0aWZpY2F0ZSBT\n'
    b'aGFjayBJbnRlcm1lZGlhdGUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n'
    b'AoIBAQC2RNo7atuVWC/6tDCGforNFvvSFdUwqHxltFmg61i2hmdHAjTaYI1ZJdgB\n'
    b'y7ApGc8RYc7tfaNrUNA8Chd/9Cu4eW2KuTnAozxytXQneNXloK2xb9iLIhETa1FC\n'
    b'Hw5BbrmJSWjiVYQsM6bzeiFsKJs4qnP1T9iFHuqmggTtCTPajoYhn6ZKfK3pmB8P\n'
    b'6XRcp5O9vUhNHJWdpuUjOL32fsBEpV0vKWlsemqDhJrhzj3+YCKt6xrSdpK64HUW\n'
    b'Kf3YM/K4G6vU5M8DgSFex6T1u2vCsQYJ4Mv8LVCho8awTZoBsimy1tiM0V7GmmBE\n'
    b'0Uck/U0381NBpNYdv7eyF682SbihAgMBAAGjZjBkMB0GA1UdDgQWBBTtHQCp1dBF\n'
    b'ypsegtWcXhXDdopIgDAfBgNVHSMEGDAWgBRJuz/14J1ZXqvpOuikJJ62NtuiGTAS\n'
    b'BgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsF\n'
    b'AAOCAQEAkCBm6u+k/x4QoqqwOJvy8sjq7bUCh73qNPAFlqVSSB8UdCyu21EaXCj8\n'
    b'dbZa3GNRGk6JACTEUVQ1SD8SkC1E1/IWuEzYOKOP6FmTFbC4V5zU9LAnGFJapS6Q\n'
    b'CGwU2F44oflBbfOodFznqKPPuENX0gmm4ddvoT915WUOvVLKLuVujkU/ffGKAc8U\n'
    b'RxRIJ3W2Ybjs9ANg7JqB3Ny8i5QAGHzjRVwU+IgTrJCYPS2DrRYtN3glKBTlyKyR\n'
    b'xMy0PVKwVo/ItDO3fZ0fsAiIO+4pI51A0lFge5Bg/DzsotZxcWhdTelWjYI9JNca\n'
    b'y2GPzV1wlxK+ui1uLCWEvKbPtaCfeQ==\n'
    b'-----END CERTIFICATE-----\n'
    b'-----BEGIN CERTIFICATE-----\n'
    b'MIIDeTCCAmGgAwIBAgIUUbo+eGRT5jiS2eIoEzRhXaUx4gwwDQYJKoZIhvcNAQEL\n'
    b'BQAwRDEeMBwGA1UECgwVQ2VydGlmaWNhdGUgU2hhY2sgTHRkMSIwIAYDVQQDDBlD\n'
    b'ZXJ0aWZpY2F0ZSBTaGFjayBSb290IENBMB4XDTIxMDgwNzE4MDQyNloXDTQxMDgw\n'
    b'MjE4MDQyNlowRDEeMBwGA1UECgwVQ2VydGlmaWNhdGUgU2hhY2sgTHRkMSIwIAYD\n'
    b'VQQDDBlDZXJ0aWZpY2F0ZSBTaGFjayBSb290IENBMIIBIjANBgkqhkiG9w0BAQEF\n'
    b'AAOCAQ8AMIIBCgKCAQEArh41PPmI6rg7nz3cRqsbCqGgD3+vAD4DNs/Cnp+vhM//\n'
    b'7Di8FuMoyyLDpD+RdT/Vkvh2Xhp+OcjYSFLX8xeFRy0blfzel2Tq7PiD83BwewsG\n'
    b'BOarlhkbQGxlGxkr4Fi6z0kNNAfbE2ZzBIs4XSppm7xl4YJyLQD0FkzdrU+zrZuK\n'
    b'3ELQzk3UWfSSrnbYABY2LBgkny5m7y/kJOMyqn+/T1CUthXD3OpGtyQm2kuEooDZ\n'
    b'xP1eq30gS8oGYAw2nR/8vJPuyeZaMxM4eNLuc35uq8/6pI+xNEpzGt7xAk1ul/xc\n'
    b'ewOY2kjh4KJCNK/nCjALzxqhNRHhnH8bA6xtOcgdBwIDAQABo2MwYTAdBgNVHQ4E\n'
    b'FgQUSbs/9eCdWV6r6TropCSetjbbohkwHwYDVR0jBBgwFoAUSbs/9eCdWV6r6Tro\n'
    b'pCSetjbbohkwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZI\n'
    b'hvcNAQELBQADggEBAC35stv/1WZhWblRTZP3XHhH0usHRGTUY7zNSrgS5sb3ERsf\n'
    b'hgbmFbomra5jKaBqffToOZKLEo+n3tfIPokus35NUQn7ox/6qPp0rJEK8dfLx9jA\n'
    b'0VTqREbgaAf5xLaX874++OTiM1sPVYG3Egsb1A/YCtDek8mZkKk21g+DZlFMOSDl\n'
    b'Hw+c3gZUnv6bIT8P09z+9yca2Lvg/dpj2ln3PbOykXzwuGSoNxjUt2OSdCbwyN+f\n'
    b'hO4NFtDvx74Ggi5bcTrz0ZKO6g8SQotii7cSKAdpIWDpXl8cfsK3SRbkCsg+Fg1S\n'
    b'kMJEFyDEkKu8Qe6zwKXIAoeKULLO6ADgFVH9CmM=\n'
    b'-----END CERTIFICATE-----\n'
)
interm_nick = "CN=Certificate Shack Intermediate CA,O=Certificate Shack Ltd"
intermediate_serial = "4096"

duplicatesubject = (
    b'-----BEGIN CERTIFICATE-----\n'
    b'MIIDcjCCAlqgAwIBAgICEAEwDQYJKoZIhvcNAQELBQAwRDEeMBwGA1UECgwVQ2Vy\n'
    b'dGlmaWNhdGUgU2hhY2sgTHRkMSIwIAYDVQQDDBlDZXJ0aWZpY2F0ZSBTaGFjayBS\n'
    b'b290IENBMB4XDTI0MDgwODE4MDQyNloXDTQ0MDgwMjE4MDQyNlowTDEeMBwGA1UE\n'
    b'CgwVQ2VydGlmaWNhdGUgU2hhY2sgTHRkMSowKAYDVQQDDCFDZXJ0aWZpY2F0ZSBT\n'
    b'aGFjayBJbnRlcm1lZGlhdGUgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n'
    b'AoIBAQCzUmUBEO/w1wslS8H304/qfsbeIJX0C5Tm8K2H9JXoauFFej1GZoHqeE+x\n'
    b'YQvSMuMFcKks3ps9+9yVKuBPtMwbmXsqwlQXORU8DuKhtRzKIOj7nEGw6AQIsfkG\n'
    b'Q4DjD1ytXliyM7vVfxYD+P1CFDK4NR+K1JLdi3WkYOdCelOQMwNspN/ebiqvwonl\n'
    b'2asQ6+a13Y0ln1AdrLBvqtR5Z+Gq5+tiC5tA+LKea0e3neQGKjfp/BNPJ+ooNHPR\n'
    b'86iKDjBKAabvfrHLG2t6oo9+N4xRBGtPYQh9LOQPZ4OedciCo1s2zs+F+4/6co6T\n'
    b'DsbQt7NJKQ3BJKosvZBhC62lc4evAgMBAAGjZjBkMB0GA1UdDgQWBBTvALT5i2gq\n'
    b'8yq2Uh8lZGgMoKVClzAfBgNVHSMEGDAWgBRJuz/14J1ZXqvpOuikJJ62NtuiGTAS\n'
    b'BgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsF\n'
    b'AAOCAQEAVjx1aGNK08/Nhf0JYMxMb9Dqg5m7LNOVBs1jurPtwS3uN+84997GRqIQ\n'
    b'i+gp/tQVF2YT/RAmt+X0aDLFiSkBcOk87zoFRkR7PZrhhtPo6pSVMN7ngD4/dmp9\n'
    b'ESbiI8+iF5ZxqI7c3o2N/LtZpi+hWSCJ/xwbOl05jpNQ6ddl+UzDpJ0oNsyndiJA\n'
    b'yciaCvluK027J4xNym166lqwm6CqiOkm8R/G6NJrEH2Xs5XBCyfeH9V0pkXDbrUe\n'
    b'Ldqc9ys7l7/MGZi6Qg2nA7J8ErCkrI6eZOocJktSF6SRfXd1NqiqCiNZZQjD6XKZ\n'
    b'4fMKTKPX6Q2k10iriAIn4RgVjzM05A==\n'
    b'-----END CERTIFICATE-----\n'
)
duplicate_serial = "4097"


class TestIPACommand(IntegrationTest):
    """
    A lot of commands can be executed against a single IPA installation
    so provide a generic class to execute one-off commands that need to be
    tested without having to fire up a full server to run one command.
    """
    topology = 'line'
    num_replicas = 1
    num_clients = 1

    @pytest.fixture
    def pwpolicy_global(self):
        """Fixture to change global password history policy and reset it"""
        tasks.kinit_admin(self.master)
        self.master.run_command(
            ["ipa", "pwpolicy-mod", "--history=5", "--minlife=0"],
        )
        yield
        self.master.run_command(
            ["ipa", "pwpolicy-mod", "--history=0", "--minlife=1"],
        )

    def get_cert_base64(self, host, path):
        """Retrieve cert and return content as single line, base64 encoded
        """
        cacrt = host.get_file_contents(path, encoding='ascii')
        cader = ssl.PEM_cert_to_DER_cert(cacrt)
        return base64.b64encode(cader).decode('ascii')

    def test_aes_sha_kerberos_enctypes(self):
        """Test AES SHA 256 and 384 Kerberos enctypes enabled

        AES SHA 256 and 384-bit enctypes supported by MIT kerberos but
        was not enabled in IPA. This test is to check if these types are
        enabled.

        related: https://pagure.io/freeipa/issue/8110
        """
        tasks.kinit_admin(self.master)
        dn = DN(("cn", self.master.domain.realm), ("cn", "kerberos"),
                realm_to_suffix(self.master.domain.realm))
        result = tasks.ldapsearch_dm(self.master, str(dn),
                                     ["krbSupportedEncSaltTypes"],
                                     scope="base")
        assert "aes128-sha2:normal" in result.stdout_text
        assert "aes128-sha2:special" in result.stdout_text
        assert "aes256-sha2:normal" in result.stdout_text
        assert "aes256-sha2:special" in result.stdout_text

    def test_certmap_match_issue7520(self):
        # https://pagure.io/freeipa/issue/7520
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ['ipa', 'certmap-match', paths.IPA_CA_CRT],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert not result.stderr_text
        assert "0 users matched" in result.stdout_text

        cab64 = self.get_cert_base64(self.master, paths.IPA_CA_CRT)
        result = self.master.run_command(
            ['ipa', 'certmap-match', '--certificate', cab64],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert not result.stderr_text
        assert "0 users matched" in result.stdout_text

    def test_cert_find_issue7520(self):
        # https://pagure.io/freeipa/issue/7520
        tasks.kinit_admin(self.master)
        subject = 'CN=Certificate Authority,O={}'.format(
            self.master.domain.realm)

        # by cert file
        result = self.master.run_command(
            ['ipa', 'cert-find', '--file', paths.IPA_CA_CRT]
        )
        assert subject in result.stdout_text
        assert '1 certificate matched' in result.stdout_text

        # by base64 cert
        cab64 = self.get_cert_base64(self.master, paths.IPA_CA_CRT)
        result = self.master.run_command(
            ['ipa', 'cert-find', '--certificate', cab64]
        )
        assert subject in result.stdout_text
        assert '1 certificate matched' in result.stdout_text

    def test_add_permission_failure_issue5923(self):
        # https://pagure.io/freeipa/issue/5923
        # error response used to contain bytes instead of text

        tasks.kinit_admin(self.master)
        # neither privilege nor permission exists
        result = self.master.run_command(
            ["ipa", "privilege-add-permission", "loc",
             "--permission='System: Show IPA Locations"],
            raiseonerr=False
        )
        assert result.returncode == 2
        err = result.stderr_text.strip()
        assert err == "ipa: ERROR: loc: privilege not found"
        # add privilege
        result = self.master.run_command(
            ["ipa", "privilege-add", "loc"],
        )
        assert 'Added privilege "loc"' in result.stdout_text
        # permission is still missing
        result = self.master.run_command(
            ["ipa", "privilege-add-permission", "loc",
             "--permission='System: Show IPA Locations"],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert "Number of permissions added 0" in result.stdout_text

    def test_change_sysaccount_password_issue7561(self):
        sysuser = 'system'
        original_passwd = 'Secret123'
        new_passwd = 'userPasswd123'

        master = self.master

        base_dn = str(master.domain.basedn)
        entry_ldif = textwrap.dedent("""
            dn: uid={sysuser},cn=sysaccounts,cn=etc,{base_dn}
            changetype: add
            objectclass: account
            objectclass: simplesecurityobject
            uid: {sysuser}
            userPassword: {original_passwd}
            passwordExpirationTime: 20380119031407Z
            nsIdleTimeout: 0
        """).format(
            base_dn=base_dn,
            original_passwd=original_passwd,
            sysuser=sysuser)
        tasks.ldapmodify_dm(master, entry_ldif)

        tasks.ldappasswd_sysaccount_change(sysuser, original_passwd,
                                           new_passwd, master)

    def get_krbinfo(self, user):
        base_dn = str(self.master.domain.basedn)
        result = tasks.ldapsearch_dm(
            self.master,
            'uid={user},cn=users,cn=accounts,{base_dn}'.format(
                user=user, base_dn=base_dn),
            ['krblastpwdchange', 'krbpasswordexpiration'],
            scope='base'
        )
        output = result.stdout_text.lower()

        # extract krblastpwdchange and krbpasswordexpiration
        krbchg_pattern = 'krblastpwdchange: (.+)\n'
        krbexp_pattern = 'krbpasswordexpiration: (.+)\n'
        krblastpwdchange = re.findall(krbchg_pattern, output)[0]
        krbexp = re.findall(krbexp_pattern, output)[0]
        return krblastpwdchange, krbexp

    def test_ldapmodify_password_issue7601(self):
        user = 'ipauser'
        original_passwd = 'Secret123'
        new_passwd = 'userPasswd123'
        new_passwd2 = 'mynewPwd123'
        master = self.master
        base_dn = str(master.domain.basedn)

        # Create a user with a password
        tasks.kinit_admin(master)
        add_password_stdin_text = "{pwd}\n{pwd}".format(pwd=original_passwd)
        master.run_command(['ipa', 'user-add', user,
                            '--first', user,
                            '--last', user,
                            '--password'],
                           stdin_text=add_password_stdin_text)
        # kinit as that user in order to modify the pwd
        user_kinit_stdin_text = "{old}\n%{new}\n%{new}\n".format(
            old=original_passwd,
            new=original_passwd)
        master.run_command(['kinit', user], stdin_text=user_kinit_stdin_text)
        # Retrieve krblastpwdchange and krbpasswordexpiration
        krblastpwdchange, krbexp = self.get_krbinfo(user)

        # sleep 1 sec (krblastpwdchange and krbpasswordexpiration have at most
        # a 1s precision)
        time.sleep(1)
        # perform ldapmodify on userpassword as dir mgr
        entry_ldif = textwrap.dedent("""
            dn: uid={user},cn=users,cn=accounts,{base_dn}
            changetype: modify
            replace: userpassword
            userpassword: {new_passwd}
        """).format(
            user=user,
            base_dn=base_dn,
            new_passwd=new_passwd)
        tasks.ldapmodify_dm(master, entry_ldif)

        # Test new password with kinit
        master.run_command(['kinit', user], stdin_text=new_passwd)

        # both should have changed
        newkrblastpwdchange, newkrbexp = self.get_krbinfo(user)
        assert newkrblastpwdchange != krblastpwdchange
        assert newkrbexp != krbexp

        # Now test passwd modif with ldappasswd
        time.sleep(1)
        master.run_command([
            paths.LDAPPASSWD,
            '-D', str(master.config.dirman_dn),
            '-w', master.config.dirman_password,
            '-a', new_passwd,
            '-s', new_passwd2,
            '-x', '-ZZ',
            '-H', 'ldap://{hostname}'.format(hostname=master.hostname),
            'uid={user},cn=users,cn=accounts,{base_dn}'.format(
                user=user, base_dn=base_dn)]
        )
        # Test new password with kinit
        master.run_command(['kinit', user], stdin_text=new_passwd2)

        # both should have changed
        newkrblastpwdchange2, newkrbexp2 = self.get_krbinfo(user)
        assert newkrblastpwdchange != newkrblastpwdchange2
        assert newkrbexp != newkrbexp2

    def test_change_sysaccount_pwd_history_issue7181(self, pwpolicy_global):
        """
        Test that a sysacount user maintains no password history
        because they do not have a Kerberos identity.
        """
        sysuser = 'sysuser'
        original_passwd = 'Secret123'
        new_passwd = 'userPasswd123'

        master = self.master

        # Add a system account and add it to a group managed by the policy
        base_dn = str(master.domain.basedn)
        entry_ldif = textwrap.dedent("""
            dn: uid={account_name},cn=sysaccounts,cn=etc,{base_dn}
            changetype: add
            objectclass: account
            objectclass: simplesecurityobject
            uid: {account_name}
            userPassword: {original_passwd}
            passwordExpirationTime: 20380119031407Z
            nsIdleTimeout: 0
        """).format(
            account_name=sysuser,
            base_dn=base_dn,
            original_passwd=original_passwd)

        tasks.ldapmodify_dm(master, entry_ldif)

        # Now change the password. It should succeed since password
        # policy doesn't apply to non-Kerberos users.
        tasks.ldappasswd_sysaccount_change(sysuser, original_passwd,
                                           new_passwd, master)
        tasks.ldappasswd_sysaccount_change(sysuser, new_passwd,
                                           original_passwd, master)
        tasks.ldappasswd_sysaccount_change(sysuser, original_passwd,
                                           new_passwd, master)

    def test_change_user_pwd_history_issue7181(self, pwpolicy_global):
        """
        Test that password history for a normal IPA user is honored.
        """
        user = 'user1'
        original_passwd = 'Secret123'
        new_passwd = 'userPasswd123'

        master = self.master

        tasks.user_add(master, user, password=original_passwd)

        tasks.ldappasswd_user_change(user, original_passwd,
                                     new_passwd, master)
        tasks.ldappasswd_user_change(user, new_passwd,
                                     original_passwd, master)
        try:
            tasks.ldappasswd_user_change(user, original_passwd,
                                         new_passwd, master)
        except CalledProcessError as e:
            if e.returncode != 1:
                raise
        else:
            pytest.fail("Password change violating policy did not fail")

    def test_dm_change_user_pwd_history_issue7181(self, pwpolicy_global):
        """
        Test that password policy is not applied with Directory Manager.

        The minimum lifetime of the password is set to 1 hour. Confirm
        that the user cannot re-change their password immediately but
        the DM can.
        """
        user = 'user1'
        original_passwd = 'Secret123'
        new_passwd = 'newPasswd123'

        master = self.master

        # reset minimum life to 1 hour.
        self.master.run_command(
            ["ipa", "pwpolicy-mod", "--minlife=1"],
        )

        try:
            tasks.ldappasswd_user_change(user, original_passwd,
                                         new_passwd, master)
        except CalledProcessError as e:
            if e.returncode != 1:
                raise
        else:
            pytest.fail("Password change violating policy did not fail")

        # DM should be able to change any password regardless of policy
        try:
            tasks.ldappasswd_user_change(user, new_passwd,
                                         original_passwd, master,
                                         use_dirman=True)
        except CalledProcessError:
            pytest.fail("Password change failed when it should not")

    def test_huge_password(self):
        user = 'toolonguser'
        hostname = 'toolong.{}'.format(self.master.domain.name)
        huge_password = ipa_generate_password(min_len=1536)
        original_passwd = 'Secret123'
        master = self.master
        base_dn = str(master.domain.basedn)

        # Create a user with a password that is too long
        tasks.kinit_admin(master)
        add_password_stdin_text = "{pwd}\n{pwd}".format(pwd=huge_password)
        result = master.run_command(['ipa', 'user-add', user,
                                     '--first', user,
                                     '--last', user,
                                     '--password'],
                                    stdin_text=add_password_stdin_text,
                                    raiseonerr=False)
        assert result.returncode != 0

        # Try again with a normal password
        add_password_stdin_text = "{pwd}\n{pwd}".format(pwd=original_passwd)
        master.run_command(['ipa', 'user-add', user,
                            '--first', user,
                            '--last', user,
                            '--password'],
                           stdin_text=add_password_stdin_text)

        # kinit as that user in order to modify the pwd
        user_kinit_stdin_text = "{old}\n%{new}\n%{new}\n".format(
            old=original_passwd,
            new=original_passwd)
        master.run_command(['kinit', user], stdin_text=user_kinit_stdin_text)
        # sleep 1 sec (krblastpwdchange and krbpasswordexpiration have at most
        # a 1s precision)
        time.sleep(1)
        # perform ldapmodify on userpassword as dir mgr
        entry_ldif = textwrap.dedent("""
            dn: uid={user},cn=users,cn=accounts,{base_dn}
            changetype: modify
            replace: userpassword
            userpassword: {new_passwd}
        """).format(
            user=user,
            base_dn=base_dn,
            new_passwd=huge_password)

        result = tasks.ldapmodify_dm(master, entry_ldif, raiseonerr=False)
        assert result.returncode != 0

        # ask_password in ipa-getkeytab will complain about too long password
        keytab_file = os.path.join(self.master.config.test_dir,
                                   'user.keytab')
        password_stdin_text = "{pwd}\n{pwd}".format(pwd=huge_password)
        result = self.master.run_command(['ipa-getkeytab',
                                          '-p', user,
                                          '-P',
                                          '-k', keytab_file,
                                          '-s', self.master.hostname],
                                         stdin_text=password_stdin_text,
                                         raiseonerr=False)
        assert result.returncode != 0
        assert "clear-text password is too long" in result.stderr_text

        # Create a host with a user-set OTP that is too long
        tasks.kinit_admin(master)
        result = master.run_command(['ipa', 'host-add', '--force',
                                     hostname,
                                     '--password', huge_password],
                                    raiseonerr=False)
        assert result.returncode != 0

        # Try again with a valid password
        result = master.run_command(['ipa', 'host-add', '--force',
                                     hostname,
                                     '--password', original_passwd],
                                    raiseonerr=False)
        assert result.returncode == 0

    def test_cleartext_password_httpd_log(self):
        """Test to check password leak in apache error log

        Host enrollment with OTP used to log the password in cleartext
        to apache error log. This test ensures that the password should
        not be log in cleartext.

        related: https://pagure.io/freeipa/issue/8017
        """
        hostname = 'test.{}'.format(self.master.domain.name)
        passwd = 'Secret123'

        self.master.run_command(['ipa', 'host-add', '--force',
                                 hostname, '--password', passwd])

        # remove added host i.e cleanup
        self.master.run_command(['ipa', 'host-del', hostname])

        result = self.master.run_command(['grep', hostname,
                                          paths.VAR_LOG_HTTPD_ERROR])
        assert passwd not in result.stdout_text

    def test_change_selinuxusermaporder(self):
        """
        An update file meant to ensure a more sane default was
        overriding any customization done to the order.
        """
        maporder = "unconfined_u:s0-s0:c0.c1023"

        # set a new default
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ["ipa", "config-mod",
             "--ipaselinuxusermaporder={}".format(maporder)],
            raiseonerr=False
        )
        assert result.returncode == 0

        # apply the update
        result = self.master.run_command(
            ["ipa-server-upgrade"],
            raiseonerr=False
        )
        assert result.returncode == 0

        # ensure result is the same
        result = self.master.run_command(
            ["ipa", "config-show"],
            raiseonerr=False
        )
        assert result.returncode == 0
        assert "SELinux user map order: {}".format(
            maporder) in result.stdout_text

    def test_ipa_console(self):
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ["ipa", "console"],
            stdin_text="api.env"
        )
        assert "ipalib.config.Env" in result.stdout_text

        filename = tasks.upload_temp_contents(
            self.master,
            "print(api.env)\n"
        )
        result = self.master.run_command(
            ["ipa", "console", filename],
        )
        assert "ipalib.config.Env" in result.stdout_text

    def test_list_help_topics(self):
        tasks.kinit_admin(self.master)
        result = self.master.run_command(
            ["ipa", "help", "topics"],
            raiseonerr=False
        )
        assert result.returncode == 0

    def test_ssh_key_connection(self, tmpdir):
        """
        Integration test for https://pagure.io/SSSD/sssd/issue/3747
        """

        test_user = 'test-ssh'

        pub_keys = []

        for i in range(40):
            ssh_key_pair = tasks.generate_ssh_keypair()
            pub_keys.append(ssh_key_pair[1])
            with open(os.path.join(
                    tmpdir, 'ssh_priv_{}'.format(i)), 'w') as fp:
                fp.write(ssh_key_pair[0])
                fp.write(os.linesep)

        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'user-add', test_user,
                                 '--first=tester', '--last=tester'])

        keys_opts = ' '.join(['--ssh "{}"'.format(k) for k in pub_keys])
        self.master.run_command(
            shlex.split('ipa user-mod {} {}'.format(test_user, keys_opts))
        )

        # connect with first SSH key
        first_priv_key_path = os.path.join(tmpdir, 'ssh_priv_1')
        # change private key permission to comply with SS rules
        os.chmod(first_priv_key_path, 0o600)

        # Make sure that / has rwxr-xr-x permissions on the master
        # otherwise sshd will deny login using private key
        # https://access.redhat.com/solutions/6798261
        self.master.run_command(['chmod', '755', '/'])

        # start to look at logs a bit before "now"
        # https://pagure.io/freeipa/issue/8432
        since = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            (datetime.now() - timedelta(seconds=10)).timetuple()
        )

        # Wait for sssd to be back online, hence test-user to become available
        tasks.wait_for_sssd_domain_status_online(self.master)

        tasks.run_ssh_cmd(
            to_host=self.master.external_hostname, username=test_user,
            auth_method="key", private_key_path=first_priv_key_path
        )

        expected_missing_msg = "exited on signal 13"
        # closing session marker(depends on PAM stack of sshd)
        expected_msgs = [
            f"session closed for user {test_user}",
            f"Disconnected from user {test_user}",
        ]

        def test_cb(stdout):
            # check if expected message logged and expected missing one not
            return (
                any(m in stdout for m in expected_msgs)
                and expected_missing_msg not in stdout
            )

        # sshd don't flush its logs to syslog immediately
        cmd = ["journalctl", "-u", "sshd", f"--since={since}"]
        tasks.run_repeatedly(self.master, command=cmd, test=test_cb)

        # cleanup
        self.master.run_command(['ipa', 'user-del', test_user])

    def test_ssh_leak(self):
        """
        Integration test for https://pagure.io/SSSD/sssd/issue/3794
        """

        def count_pipes():

            res = self.master.run_command(['pidof', 'sssd_ssh'])
            pid = res.stdout_text.strip()
            proc_path = '/proc/{}/fd'.format(pid)
            res = self.master.run_command(['ls', '-la', proc_path])
            fds_text = res.stdout_text.strip()
            return sum((1 for _ in re.finditer(r'pipe', fds_text)))

        test_user = 'test-ssh'

        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'user-add', test_user,
                                 '--first=tester', '--last=tester'])

        certs = []

        # we are ok with whatever certificate for this test
        external_ca = ExternalCA()
        for _dummy in range(3):
            cert = external_ca.create_ca()
            cert = tasks.strip_cert_header(cert.decode('utf-8'))
            certs.append('"{}"'.format(cert))

        cert_args = list(
            chain.from_iterable(list(zip(repeat('--certificate'), certs))))
        cmd = 'ipa user-add-cert {} {}'.format(test_user, ' '.join(cert_args))
        self.master.run_command(cmd)

        tasks.clear_sssd_cache(self.master)

        num_of_pipes = count_pipes()

        for _dummy in range(3):
            self.master.run_command([paths.SSS_SSH_AUTHORIZEDKEYS, test_user])
            current_num_of_pipes = count_pipes()
            assert current_num_of_pipes == num_of_pipes

        # cleanup
        self.master.run_command(['ipa', 'user-del', test_user])

    def test_certificate_out_write_to_file(self):
        # commands to test; name of temporary file will be appended
        result = self.master.run_command([
            'openssl', 'x509', '-serial', '-noout', '-in', paths.IPA_CA_CRT
        ])
        serial = result.stdout_text.strip().split('=', maxsplit=1)[1]
        commands = [
            ['ipa', 'cert-show', serial, '--certificate-out'],
            ['ipa', 'cert-show', serial, '--chain', '--certificate-out'],
            ['ipa', 'ca-show', 'ipa', '--certificate-out'],
            ['ipa', 'ca-show', 'ipa', '--chain', '--certificate-out'],
        ]

        for command in commands:
            cmd = self.master.run_command(['mktemp'])
            filename = cmd.stdout_text.strip()

            self.master.run_command(command + [filename])

            # Check that a PEM file was written.  If --chain was
            # used, load_pem_x509_certificate will return the
            # first certificate, which is fine for this test.
            data = self.master.get_file_contents(filename)
            x509.load_pem_x509_certificate(data, backend=default_backend())

            self.master.run_command(['rm', '-f', filename])

        # Ensure that ca/cert-show doesn't leave an empty file when
        # the requested ca/cert does not exist.
        commands = [
            ['ipa', 'cert-show', '0xdeadbeef', '--certificate-out'],
            ['ipa', 'ca-show', 'notfound', '--certificate-out'],
        ]

        for command in commands:
            cmd = self.master.run_command(['mktemp', '--dry-run'])
            filename = cmd.stdout_text.strip()

            result = self.master.run_command(command + [filename],
                                             raiseonerr=False)
            assert result.returncode == 2

            result = self.master.run_command(
                ['stat', filename],
                raiseonerr=False
            )
            assert result.returncode == 1

    def test_sssd_ifp_access_ipaapi(self):
        # check that ipaapi is allowed to access sssd-ifp for smartcard auth
        # https://pagure.io/freeipa/issue/7751
        username = 'admin'
        # get UID for user
        result = self.master.run_command(['ipa', 'user-show', username])
        mo = re.search(r'UID: (\d+)', result.stdout_text)
        assert mo is not None, result.stdout_text
        uid = mo.group(1)

        cmd = [
            'dbus-send',
            '--print-reply', '--system',
            '--dest=org.freedesktop.sssd.infopipe',
            '/org/freedesktop/sssd/infopipe/Users',
            'org.freedesktop.sssd.infopipe.Users.FindByName',
            'string:{}'.format(username)
        ]
        # test IFP as root
        result = self.master.run_command(cmd)
        assert uid in result.stdout_text

        # test IFP as ipaapi
        result = self.master.run_command(
            ['runuser', '-u', IPAAPI_USER, '--'] + cmd
        )
        assert uid in result.stdout_text

    def test_ipa_cacert_manage_install(self):
        # Re-install the IPA CA
        self.master.run_command([
            paths.IPA_CACERT_MANAGE,
            'install',
            paths.IPA_CA_CRT])

        # Test a non-existent file
        result = self.master.run_command([
            paths.IPA_CACERT_MANAGE,
            'install',
            '/run/cert_not_found'], raiseonerr=False)
        assert result.returncode == 1

        cmd = self.master.run_command(['mktemp'])
        filename = cmd.stdout_text.strip()

        for contents in (good_pkcs7,):
            self.master.put_file_contents(filename, contents)
            result = self.master.run_command([
                paths.IPA_CACERT_MANAGE,
                'install',
                filename])

        for contents in (badcert,):
            self.master.put_file_contents(filename, contents)
            result = self.master.run_command([
                paths.IPA_CACERT_MANAGE,
                'install',
                filename], raiseonerr=False)
            assert result.returncode == 1

        self.master.run_command(['rm', '-f', filename])

    def test_hbac_systemd_user(self):
        # https://pagure.io/freeipa/issue/7831
        tasks.kinit_admin(self.master)
        # check for presence
        self.master.run_command(
            ['ipa', 'hbacsvc-show', 'systemd-user']
        )
        result = self.master.run_command(
            ['ipa', 'hbacrule-show', 'allow_systemd-user', '--all']
        )
        lines = set(l.strip() for l in result.stdout_text.split('\n'))
        assert 'User category: all' in lines
        assert 'Host category: all' in lines
        assert 'Enabled: True' in lines
        assert 'HBAC Services: systemd-user' in lines
        assert 'accessruletype: allow' in lines

        # delete both
        self.master.run_command(
            ['ipa', 'hbacrule-del', 'allow_systemd-user']
        )
        self.master.run_command(
            ['ipa', 'hbacsvc-del', 'systemd-user']
        )

        # run upgrade
        result = self.master.run_command(['ipa-server-upgrade'])
        assert 'Created hbacsvc systemd-user' in result.stderr_text
        assert 'Created hbac rule allow_systemd-user' in result.stderr_text

        # check for presence
        result = self.master.run_command(
            ['ipa', 'hbacrule-show', 'allow_systemd-user', '--all']
        )
        lines = set(l.strip() for l in result.stdout_text.split('\n'))
        assert 'User category: all' in lines
        assert 'Host category: all' in lines
        assert 'Enabled: True' in lines
        assert 'HBAC Services: systemd-user' in lines
        assert 'accessruletype: allow' in lines

        self.master.run_command(
            ['ipa', 'hbacsvc-show', 'systemd-user']
        )

        # only delete rule
        self.master.run_command(
            ['ipa', 'hbacrule-del', 'allow_systemd-user']
        )

        # run upgrade
        result = self.master.run_command(['ipa-server-upgrade'])
        assert (
            'hbac service systemd-user already exists' in result.stderr_text
        )
        assert (
            'Created hbac rule allow_systemd-user' not in result.stderr_text
        )
        result = self.master.run_command(
            ['ipa', 'hbacrule-show', 'allow_systemd-user'],
            raiseonerr=False
        )
        assert result.returncode != 0
        assert 'HBAC rule not found' in result.stderr_text

    def test_config_show_configured_services(self):
        # https://pagure.io/freeipa/issue/7929
        states = {CONFIGURED_SERVICE, ENABLED_SERVICE, HIDDEN_SERVICE}
        dn = DN(
            ('cn', 'HTTP'), ('cn', self.master.hostname), ('cn', 'masters'),
            ('cn', 'ipa'), ('cn', 'etc'),
            self.master.domain.basedn
        )

        conn = self.master.ldap_connect()
        entry = conn.get_entry(dn)

        # original setting and all settings without state
        orig_cfg = list(entry['ipaConfigString'])
        other_cfg = [item for item in orig_cfg if item not in states]

        try:
            # test with hidden
            cfg = [HIDDEN_SERVICE]
            cfg.extend(other_cfg)
            entry['ipaConfigString'] = cfg
            conn.update_entry(entry)
            self.master.run_command(['ipa', 'config-show'])

            # test with configured
            cfg = [CONFIGURED_SERVICE]
            cfg.extend(other_cfg)
            entry['ipaConfigString'] = cfg
            conn.update_entry(entry)
            self.master.run_command(['ipa', 'config-show'])
        finally:
            # reset
            entry['ipaConfigString'] = orig_cfg
            conn.update_entry(entry)

    def test_ssh_from_controller(self):
        """https://pagure.io/SSSD/sssd/issue/3979
        Test ssh from test controller after adding
        ldap_deref_threshold=0 to sssd.conf on master

        Steps:
        1. setup a master
        2. add ldap_deref_threshold=0 to sssd.conf on master
        3. add an ipa user
        4. ssh from controller to master using the user created in step 3
        """

        cmd = self.master.run_command(['sssd', '--version'])
        sssd_version = platform_tasks.parse_ipa_version(
            cmd.stdout_text.strip())
        if sssd_version < platform_tasks.parse_ipa_version('2.2.0'):
            pytest.xfail(reason="sssd 2.2.0 unavailable in F29 nightly")

        # add ldap_deref_threshold=0 to /etc/sssd/sssd.conf
        sssd_conf_backup = tasks.FileBackup(self.master, paths.SSSD_CONF)
        with tasks.remote_sssd_config(self.master) as sssd_config:
            sssd_config.edit_domain(
                self.master.domain, 'ldap_deref_threshold', 0)

        test_user = "testuser" + str(random.randint(200000, 9999999))
        password = "Secret123"
        try:
            self.master.run_command(['systemctl', 'restart', 'sssd.service'])

            # kinit admin
            tasks.kinit_admin(self.master)

            # add ipa user
            tasks.create_active_user(
                self.master, test_user, password=password
            )
            tasks.kdestroy_all(self.master)
            tasks.kinit_as_user(
                self.master, test_user, password
            )
            tasks.kdestroy_all(self.master)

            tasks.run_ssh_cmd(
                to_host=self.master.external_hostname, username=test_user,
                auth_method="password", password=password
            )

        finally:
            sssd_conf_backup.restore()
            self.master.run_command(['systemctl', 'restart', 'sssd.service'])

    def test_user_mod_change_capitalization_issue5879(self):
        """
        Test that an existing user which has been modified using ipa user-mod
        and has the first and last name beginning with caps does not
        throw the error 'ipa: ERROR: Type or value exists:' and
        instead gets modified

        This is a test case for Pagure issue
        https://pagure.io/freeipa/issue/5879

        Steps:
        1. setup a master
        2. add ipa user on master
        3. now run ipa user-mod and specifying capital letters in names
        4. user details should be modified
        5. ipa: ERROR: Type or value exists is not displayed on console.
        """
        # Create an ipa-user
        tasks.kinit_admin(self.master)
        ipauser = 'ipauser1'
        first = 'ipauser'
        modfirst = 'IpaUser'
        last = 'test'
        modlast = 'Test'
        password = 'Secret123'
        self.master.run_command(
            ['ipa', 'user-add', ipauser, '--first', first, '--last', last,
             '--password'],
            stdin_text="%s\n%s\n" % (password, password))
        cmd = self.master.run_command(
            ['ipa', 'user-mod', ipauser, '--first', modfirst,
             '--last', modlast])
        assert 'Modified user "%s"' % (ipauser) in cmd.stdout_text
        assert 'First name: %s' % (modfirst) in cmd.stdout_text
        assert 'Last name: %s' % (modlast) in cmd.stdout_text

    @pytest.mark.skip_if_platform(
        "debian", reason="Crypto policy is not supported on Debian"
    )
    def test_enabled_tls_protocols(self):
        """Check Apache has same TLS versions enabled as crypto policy

        This is the regression test for issue
        https://pagure.io/freeipa/issue/7995.
        """
        def is_tls_version_enabled(tls_version):
            res = self.master.run_command(
                ['openssl', 's_client',
                 '-connect', '{}:443'.format(self.master.hostname),
                 '-{}'.format(tls_version)],
                stdin_text='\n',
                ok_returncode=[0, 1]
            )
            return res.returncode == 0

        # get minimum version from current crypto-policy
        openssl_cnf = self.master.get_file_contents(
            paths.CRYPTO_POLICY_OPENSSLCNF_FILE,
            encoding="utf-8"
        )
        mo = re.search(r"MinProtocol\s*=\s*(TLSv[0-9.]+)", openssl_cnf)
        assert mo
        min_tls = mo.group(1)
        # Fedora DEFAULT has TLS 1.0 enabled, NEXT has TLS 1.2
        # even FUTURE crypto policy has TLS 1.2 as minimum version
        assert min_tls in {"TLSv1", "TLSv1.2"}

        # On Fedora FreeIPA still disables TLS 1.0 and 1.1 in ssl.conf.

        assert not is_tls_version_enabled('tls1')
        assert not is_tls_version_enabled('tls1_1')
        assert is_tls_version_enabled('tls1_2')
        assert is_tls_version_enabled('tls1_3')

    def test_sss_ssh_authorizedkeys(self):
        """Login via Ssh using private-key for ipa-user should work.

        Test for : https://pagure.io/SSSD/sssd/issue/3937
        Steps:
        1) setup user with ssh-key and certificate stored in ipaserver
        2) simulate p11_child timeout
        3) try to login via ssh using private key.
        """
        user = 'testsshuser'
        passwd = 'Secret123'
        user_key = tasks.create_temp_file(self.master, create_file=False)
        pem_file = tasks.create_temp_file(self.master)
        # Create a user with a password
        tasks.create_active_user(self.master, user, passwd, extra_args=[
            '--homedir', '/home/{}'.format(user)])
        tasks.kinit_admin(self.master)
        tasks.run_command_as_user(
            self.master, user, ['ssh-keygen', '-N', '',
                                '-f', user_key])
        ssh_pub_key = self.master.get_file_contents('{}.pub'.format(
            user_key), encoding='utf-8')
        openssl_cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-days', '365',
            '-nodes', '-out', pem_file, '-subj', '/CN=' + user]
        self.master.run_command(openssl_cmd)
        cert_b64 = self.get_cert_base64(self.master, pem_file)
        sssd_p11_child = '/usr/libexec/sssd/p11_child'
        backup = tasks.FileBackup(self.master, sssd_p11_child)
        try:
            content = '#!/bin/bash\nsleep 999999'
            # added sleep to simulate the timeout for p11_child
            self.master.put_file_contents(sssd_p11_child, content)
            self.master.run_command(
                ['ipa', 'user-mod', user, '--ssh', ssh_pub_key])
            self.master.run_command([
                'ipa', 'user-add-cert', user, '--certificate', cert_b64])
            # clear cache to avoid SSSD to check the user in old lookup
            tasks.clear_sssd_cache(self.master)
            result = self.master.run_command(
                [paths.SSS_SSH_AUTHORIZEDKEYS, user])
            assert ssh_pub_key in result.stdout_text
            # login to the system
            self.master.run_command(
                ['ssh', '-v', '-o', 'PasswordAuthentication=no',
                 '-o', 'IdentitiesOnly=yes', '-o', 'StrictHostKeyChecking=no',
                 '-o', 'ConnectTimeout=10', '-l', user, '-i', user_key,
                 self.master.hostname, 'true'])
        finally:
            # cleanup
            self.master.run_command(['ipa', 'user-del', user])
            backup.restore()
            self.master.run_command(['rm', '-f', pem_file, user_key,
                                     '{}.pub'.format(user_key)])

    def test_cacert_manage(self):
        """Exercise ipa-cacert-manage delete"""

        # deletion without nickname
        result = self.master.run_command(
            ['ipa-cacert-manage', 'delete'],
            raiseonerr=False
        )
        assert result.returncode != 0

        # deletion with an unknown nickname
        result = self.master.run_command(
            ['ipa-cacert-manage', 'delete', 'unknown'],
            raiseonerr=False
        )
        assert result.returncode != 0
        assert "Unknown CA 'unknown'" in result.stderr_text

        # deletion of IPA CA
        ipa_ca_nickname = get_ca_nickname(self.master.domain.realm)
        result = self.master.run_command(
            ['ipa-cacert-manage', 'delete', ipa_ca_nickname],
            raiseonerr=False
        )
        assert result.returncode != 0
        assert 'The IPA CA cannot be removed with this tool' in \
               result.stderr_text

        # Install 3rd party CA's, Let's Encrypt in this case
        for cert in (isrgrootx1, letsencryptauthorityr3):
            certfile = os.path.join(self.master.config.test_dir, 'cert.pem')
            self.master.put_file_contents(certfile, cert)
            result = self.master.run_command(
                ['ipa-cacert-manage', 'install', certfile],
            )

        # deletion of a root CA needed by a subCA, without -f option
        result = self.master.run_command(
            ['ipa-cacert-manage', 'delete', isrgrootx1_nick],
            raiseonerr=False
        )
        assert result.returncode != 0
        assert "Verifying \'%s\' failed. Removing part of the " \
               "chain? certutil: certificate is invalid: Peer's " \
               "Certificate issuer is not recognized." \
               % isrgrootx1_nick in result.stderr_text

        # deletion of a root CA needed by a subCA, with -f option
        result = self.master.run_command(
            ['ipa-cacert-manage', 'delete', isrgrootx1_nick, '-f'],
            raiseonerr=False
        )
        assert result.returncode == 0

        # deletion of a subca
        result = self.master.run_command(
            ['ipa-cacert-manage', 'delete', le_r3_nick],
            raiseonerr=False
        )
        assert result.returncode == 0

    def test_ipa_adtrust_install_with_locale_issue8066(self):
        """
        This test checks that ipa-adtrust-install command runs successfully
        on a system with locale en_IN.UTF-8 without displaying error below
        'IndexError: list index out of range'
        This is a testcase for Pagure issue
        https://pagure.io/freeipa/issue/8066
        """
        # Set locale to en_IN.UTF-8 in .bashrc file to avoid reboot
        tasks.kinit_admin(self.master)
        BASHRC_CFG = "/root/.bashrc"
        bashrc_backup = tasks.FileBackup(self.master, BASHRC_CFG)
        exp_msg = "en_IN.UTF-8"
        try:
            self.master.run_command(
                'echo "export LC_TIME=en_IN.UTF-8" >> ' + BASHRC_CFG
            )
            result = self.master.run_command('echo "$LC_TIME"')
            assert result.stdout_text.rstrip() == exp_msg
            # Install ipa-server-adtrust and check status
            msg1 = (
                "Unexpected error - see /var/log/ipaserver-install.log"
                "for details"
            )
            msg2 = "IndexError: list index out of range"
            tasks.install_packages(self.master, ["*ipa-server-trust-ad"])
            result = self.master.run_command(
                ["ipa-adtrust-install", "-U"], raiseonerr=False
            )
            assert msg1 not in result.stderr_text
            assert msg2 not in result.stderr_text
        finally:
            bashrc_backup.restore()

    @pytest.fixture
    def user_creation_deletion(self):
        # create user
        self.testuser = 'testuser'
        tasks.create_active_user(self.master, self.testuser, 'Secret123')

        yield

        # cleanup
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'user-del', self.testuser])

    def test_login_wrong_password(self, user_creation_deletion):
        """Test ipa user login with wrong password

        When ipa user login to machine using wrong password, it
        should log proper message

        related: https://github.com/SSSD/sssd/issues/5139
        """
        # try to login with wrong password
        sssd_version = tasks.get_sssd_version(self.master)
        if (sssd_version < tasks.parse_version('2.3.0')):
            pytest.xfail('Fix is part of sssd 2.3.0 and is'
                         ' available from fedora32 onwards')

        # start to look at logs a bit before "now"
        # https://pagure.io/freeipa/issue/8432
        since = time.strftime(
            '%Y-%m-%d %H:%M:%S',
            (datetime.now() - timedelta(seconds=10)).timetuple()
        )

        password = 'WrongPassword'

        tasks.run_ssh_cmd(
            to_host=self.master.external_hostname, username=self.testuser,
            auth_method="password", password=password,
            expect_auth_failure=True
        )

        expected_msg = (
            f"pam_sss(sshd:auth): received for user {self.testuser}: 7"
            " (Authentication failure)"
        )

        def test_cb(stdout):
            # check if proper message logged
            return expected_msg in stdout

        # sshd don't flush its logs to syslog immediately
        cmd = ["journalctl", "-u", "sshd", f"--since={since}"]
        tasks.run_repeatedly(self.master, command=cmd, test=test_cb)

    def get_dirsrv_id(self):
        serverid = realm_to_serverid(self.master.domain.realm)
        return ("dirsrv@%s.service" % serverid)

    def test_pkispawn_log_is_present(self):
        """
        This testcase checks if pkispawn logged properly.
        It is a candidate from being moved out of test_commands.
        """
        result = self.master.run_command(
            ["ls", "/var/log/pki/"]
        )
        pkispawnlogfile = None
        for file in result.stdout_text.splitlines():
            if file.startswith("pki-ca-spawn"):
                pkispawnlogfile = file
                break
        assert pkispawnlogfile is not None
        pkispawnlogfile = os.path.sep.join(("/var/log/pki", pkispawnlogfile))
        pkispawnlog = self.master.get_file_contents(
            pkispawnlogfile, encoding='utf-8'
        )
        # Totally arbitrary. pkispawn debug logs tend to be > 10KiB.
        assert len(pkispawnlog) > 1024
        assert "DEBUG" in pkispawnlog
        assert "INFO" in pkispawnlog

    def test_reset_password_unlock(self):
        """
        Test that when a user is also unlocked when their password
        is administratively reset.
        """
        user = 'tuser'
        original_passwd = 'Secret123'
        new_passwd = 'newPasswd123'
        bad_passwd = 'foo'

        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, user, password=original_passwd)
        tasks.kinit_user(
            self.master, user,
            '{0}\n{1}\n{1}\n'.format(original_passwd, new_passwd)
        )

        # Lock out the user on master
        for _i in range(0, 7):
            tasks.kinit_user(self.master, user, bad_passwd, raiseonerr=False)

        tasks.kinit_admin(self.replicas[0])
        # Administrative reset on a different server
        self.replicas[0].run_command(
            ['ipa', 'passwd', user],
            stdin_text='{0}\n{0}\n'.format(original_passwd)
        )

        # Wait for the password update to be replicated from replicas[0]
        # to other servers
        ldap = self.replicas[0].ldap_connect()
        tasks.wait_for_replication(ldap)

        # The user can log in again
        tasks.kinit_user(
            self.master, user,
            '{0}\n{1}\n{1}\n'.format(original_passwd, new_passwd)
        )

    def test_certupdate_no_schema(self):
        """Test that certupdate without existing API schema.

           With no existing credentials the API schema download
           would cause the whole command to fail.
        """
        tasks.kdestroy_all(self.master)

        self.master.run_command(
            ["rm", "-rf",
             "/root/.cache/ipa/servers",
             "/root/.cache/ipa/schema"]
        )

        # It first has to retrieve schema then can run
        self.master.run_command(["ipa-certupdate"])

        # Run it again for good measure
        self.master.run_command(["ipa-certupdate"])

    def test_proxycommand_invalid_shell(self):
        """Test that ssh works with a user with an invalid shell.

           Specifically for this use-case:
           # getent passwd test
           test:x:1001:1001::/home/test:/sbin/nologin
           # sudo -u user ssh -v root@ipa.example.test

           ruser is our restricted user
           tuser1 is a regular user we ssh to remotely as
        """
        password = 'Secret123'
        restricted_user = 'ruser'
        regular_user = 'tuser1'

        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, restricted_user,
                       extra_args=["--shell", "/sbin/nologin"],
                       password=password)
        tasks.user_add(self.master, regular_user,
                       password=password)

        user_kinit = "{password}\n{password}\n{password}\n".format(
            password=password)
        self.master.run_command([
            'kinit', regular_user],
            stdin_text=user_kinit)
        self.master.run_command([
            'kinit', restricted_user],
            stdin_text=user_kinit)
        tasks.kdestroy_all(self.clients[0])

        # ssh as a restricted user to a user with a valid shell should
        # work
        self.clients[0].run_command(
            ['sudo', '-u', restricted_user,
             'sshpass', '-p', password,
             'ssh', '-v',
             '-o', 'StrictHostKeyChecking=no',
             'tuser1@%s' % self.master.hostname, 'cat /etc/hosts'],
        )

        # Some versions of nologin do not support the -c option.
        # ssh will still fail in a Match properly since it will return
        # non-zero but we don't get the account failure message.
        nologin = self.clients[0].run_command(
            ['nologin', '-c', '/bin/true',],
            raiseonerr=False
        )

        # ssh as a restricted user to a restricted user should fail
        result = self.clients[0].run_command(
            ['sudo', '-u', restricted_user,
             'sshpass', '-p', password,
             'ssh', '-v',
             '-o', 'StrictHostKeyChecking=no',
             'ruser@%s' % self.master.hostname, 'cat /etc/hosts'],
            raiseonerr=False
        )
        assert result.returncode == 1

        if 'invalid option' not in nologin.stderr_text:
            assert 'This account is currently not available' in \
                result.stdout_text

    def test_ipa_getkeytab_server(self):
        """
        Exercise the ipa-getkeytab server options

        This relies on the behavior that without a TGT
        ipa-getkeytab will quit and not do much of anything.

        A bogus keytab and principal are passed in to satisfy the
        minimum requirements.
        """
        tasks.kdestroy_all(self.master)

        # Pass in a server name to use
        result = self.master.run_command(
            [
                paths.IPA_GETKEYTAB,
                "-k",
                "/tmp/keytab",
                "-p",
                "foo",
                "-s",
                self.master.hostname,
                "-v",
            ], raiseonerr=False).stderr_text

        assert 'Using provided server %s' % self.master.hostname in result

        # Don't pass in a name, should use /etc/ipa/default.conf
        result = self.master.run_command(
            [
                paths.IPA_GETKEYTAB,
                "-k",
                "/tmp/keytab",
                "-p",
                "foo",
                "-v",
            ], raiseonerr=False).stderr_text

        assert (
            'Using server from config %s' % self.master.hostname
            in result
        )

        # Use DNS SRV lookup
        result = self.master.run_command(
            [
                paths.IPA_GETKEYTAB,
                "-k",
                "/tmp/keytab",
                "-p",
                "foo",
                "-s",
                "_srv_",
                "-v",
            ], raiseonerr=False).stderr_text

        assert 'Discovered server %s' % self.master.hostname in result

    def test_ipa_context_manager(self):
        """Exercise ipalib.api context manager and KRB5_CLIENT_KTNAME auth

        The example_cli.py script uses the context manager to connect and
        disconnect the global ipalib.api object. The test also checks whether
        KRB5_CLIENT_KTNAME env var automatically acquires a TGT.
        """
        host = self.clients[0]
        tasks.kdestroy_all(host)

        here = os.path.abspath(os.path.dirname(__file__))
        with open(os.path.join(here, "example_cli.py")) as f:
            contents = f.read()

        # upload script and run with Python executable
        script = "/tmp/example_cli.py"
        host.put_file_contents(script, contents)
        # Important: this test is date-sensitive and may fail if executed
        # around Feb 28 or Feb 29 on a leap year.
        # The previous tests are playing with the date by jumping in the
        # future and back to the (expected) current date but calling
        # date -s +15Years and then date -s -15Years doesn't
        # bring the date back to the original value if called around Feb 29.
        # As a consequence, client and server are not synchronized any more
        # and client API authentication may fail with the following error:
        # ipalib.errors.KerberosError:
        # No valid Negotiate header in server response
        # If you see this failure, just ignore and relaunch on March 1.
        result = host.run_command([sys.executable, script])

        # script prints admin account
        admin_princ = f"admin@{host.domain.realm}"
        assert admin_princ in result.stdout_text

        # verify that auto-login did use correct principal
        host_princ = f"host/{host.hostname}@{host.domain.realm}"
        result = host.run_command([paths.KLIST])
        assert host_princ in result.stdout_text

    def test_delete_last_enabled_admin(self):
        """
        The admin user may be disabled. Don't allow all other
        members of admins to be removed if the admin user is
        disabled which would leave the install with no
        usable admins users
        """
        user = 'adminuser2'
        passwd = 'Secret123'
        tasks.create_active_user(self.master, user, passwd)
        tasks.kinit_admin(self.master)
        self.master.run_command(['ipa', 'group-add-member', 'admins',
                                '--users', user])
        tasks.kinit_user(self.master, user, passwd)
        self.master.run_command(['ipa', 'user-disable', 'admin'])
        result = self.master.run_command(
            ['ipa', 'user-del', user],
            raiseonerr=False
        )
        self.master.run_command(['ipa', 'user-enable', 'admin'])
        tasks.kdestroy_all(self.master)

        assert result.returncode == 1
        assert 'cannot be deleted or disabled' in result.stderr_text

    def test_ipa_cacert_manage_prune(self):
        """Test for ipa-cacert-manage prune"""

        certfile = os.path.join(self.master.config.test_dir, 'cert.pem')
        self.master.put_file_contents(certfile, isrgrootx1)
        result = self.master.run_command(
            [paths.IPA_CACERT_MANAGE, 'install', certfile])

        certs_before_prune = self.master.run_command(
            [paths.IPA_CACERT_MANAGE, 'list'], raiseonerr=False
        ).stdout_text

        assert isrgrootx1_nick in certs_before_prune

        # Jump in time to make sure the cert is expired
        self.master.run_command(['date', '-s', '+15Years'])
        result = self.master.run_command(
            [paths.IPA_CACERT_MANAGE, 'prune'], raiseonerr=False
        ).stdout_text
        self.master.run_command(['date', '-s', '-15Years'])

        assert isrgrootx1_nick in result

    def test_ipa_cacert_manage_duplicate_certsubject(self):
        """Test for ipa-cacert-manage install with duplicated
           certificate subjects. This relies on the behavior
           of NSS to show the certificates separately rather than
           lumping the duplicates together. This requires different
           validity periods, say 3 years + 1 day.
        """

        certfile = os.path.join(self.master.config.test_dir, 'chain.pem')
        self.master.put_file_contents(certfile, originalsubjectchain)
        result = self.master.run_command(
            [paths.IPA_CACERT_MANAGE, 'install', certfile])

        certs = self.master.run_command(
            [paths.IPA_CACERT_MANAGE, 'list'], raiseonerr=False
        ).stdout_text

        assert f"{interm_nick}  {intermediate_serial}" in certs

        certfile = os.path.join(self.master.config.test_dir, 'interm.pem')
        self.master.put_file_contents(certfile, duplicatesubject)
        result = self.master.run_command(
            [paths.IPA_CACERT_MANAGE, 'install', certfile])

        certs = self.master.run_command(
            [paths.IPA_CACERT_MANAGE, 'list'], raiseonerr=False
        ).stdout_text

        # If the duplicate subject certificates are not sufficiently
        # different in validity period, or prior to the this fix,
        # the test will fail because only one of the duplicately named
        # subject certificates will be visible: the second one (4097).
        assert f"{interm_nick}  {intermediate_serial}" in certs
        assert f"{interm_nick}  {duplicate_serial}" in certs

        # Make sure we can install the new certs systemwide
        # No assertions needed, it will work or it won't
        self.master.run_command(["ipa-certupdate"])

        # delete one of the duplicate subjects, no serial number
        result = self.master.run_command(
            ['ipa-cacert-manage', 'delete', interm_nick],
            raiseonerr=False
        )
        assert result.returncode == 1
        assert 'Multiple matching certificates' in result.stderr_text

        # delete one of the duplicate subjects by the serial number
        result = self.master.run_command(
            ['ipa-cacert-manage', 'delete', interm_nick,
             '--serial', intermediate_serial,],
            raiseonerr=False
        )
        assert result.returncode == 0

        certs = self.master.run_command(
            [paths.IPA_CACERT_MANAGE, 'list'], raiseonerr=False
        ).stdout_text

        assert f"{interm_nick}  {intermediate_serial}" not in certs
        assert f"{interm_nick}  {duplicate_serial}" in certs


class TestIPACommandWithoutReplica(IntegrationTest):
    """
    Execute tests with scenarios having only single
    IPA server and no replica
    """
    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def test_client_doesnot_throw_responsenotready_error(self):
        """
        This testcase checks that ipa command
        doesn't throw http.client.ResponseNotReady error
        when current users session is deleted from the cache
        """
        user = 'ipauser1'
        orig_pwd = 'Password123'

        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, user, password=orig_pwd)
        # kinit as admin on ipa-server and run ipa command
        tasks.kinit_admin(self.master, raiseonerr=False)
        self.master.run_command(['ipa', 'user-show', "ipauser1"])
        # Delete the current user session cache on IPA server
        self.master.run_command(
            "rm -fv /run/ipa/ccaches/admin@{}-*".format(
                self.master.domain.realm
            )
        )
        # Run the command again after cache is removed
        self.master.run_command(['ipa', 'user-show', 'ipauser1'])

    def test_basesearch_compat_tree(self):
        """Test ldapsearch against compat tree is working

        This to ensure that ldapsearch with base scope is not failing.

        related: https://bugzilla.redhat.com/show_bug.cgi?id=1958909
        """
        version = self.master.run_command(
            ["rpm", "-qa", "--qf", "%{VERSION}", "slapi-nis"]
        )
        if tasks.get_platform(self.master) == "fedora" and parse_version(
                version.stdout_text) <= parse_version("0.56.7"):
            pytest.skip("Test requires slapi-nis with fix on fedora")
        tasks.kinit_admin(self.master)
        base_dn = str(self.master.domain.basedn)
        base = "cn=admins,cn=groups,cn=compat,{basedn}".format(basedn=base_dn)
        tasks.ldapsearch_dm(self.master, base, ldap_args=[], scope='sub')
        tasks.ldapsearch_dm(self.master, base, ldap_args=[], scope='base')

    def test_sid_generation(self):
        """
        Test SID generation

        Check that new users are created with a SID and PAC data is
        added in their Kerberos tickets.
        """
        user = "pacuser"
        passwd = "Secret123"

        try:
            # Create a nonadmin user
            tasks.create_active_user(
                self.master, user, passwd, first=user, last=user,
                krb5_trace=True)

            # Check SID is present in the new entry
            base_dn = str(self.master.domain.basedn)
            result = tasks.ldapsearch_dm(
                self.master,
                'uid={user},cn=users,cn=accounts,{base_dn}'.format(
                    user=user, base_dn=base_dn),
                ['ipantsecurityidentifier'],
                scope='base'
            )
            assert 'ipantsecurityidentifier' in result.stdout_text

            # Defaults: host/... principal for service
            # keytab in /etc/krb5.keytab
            self.master.run_command(["kinit", '-k'])
            result = self.master.run_command(
                [os.path.join(paths.LIBEXEC_IPA_DIR, "ipa-print-pac"),
                 "ticket", user],
                stdin_text=(passwd + '\n')
            )
            assert "PAC_DATA" in result.stdout_text
        finally:
            tasks.kinit_admin(self.master)
            self.master.run_command(['ipa', 'user-del', user])

    @pytest.fixture
    def cleanupgroups(self):
        """Fixture to remove any groups added as part of the tests.

           It isn't necessary to remove all groupss created.

           Ignore all errors.
        """
        yield
        for group in ["testgroup1", "testgroup2", "testgroup3"]:
            try:
                self.master.run_command(['ipa', 'group-del', group])
            except Exception:
                pass

    def test_sequence_processing_ipaexternalgroup(self, cleanupgroups):
        """Test for sequence processing failures

        Issues have been found for group_add sequence processing with
        server context. This test checks that groups have correct userclass
        when external is set to true or false with group-add.

        related: https://pagure.io/freeipa/issue/9349
        """
        user_code_script = textwrap.dedent("""
            from ipalib import api, errors
            api.bootstrap_with_global_options(context='server')
            api.finalize()
            api.Backend.ldap2.connect()

            api.Command["group_add"]("testgroup1", external=True)
            api.Command["group_add"]("testgroup2", external=False)
            result1 = api.Command["group_show"]("testgroup1", all=True)["result"] # noqa: E501
            result2 = api.Command["group_show"]("testgroup2", all=True)["result"] # noqa: E501
            print("'testgroup2' userclass: %s" % repr(result2["objectclass"]))
        """)
        self.master.put_file_contents("/tmp/reproducer1_code.py",
                                      user_code_script)
        result = self.master.run_command(['python3',
                                          '/tmp/reproducer1_code.py'])
        assert "ipaexternalgroup" not in result.stdout_text

    def test_sequence_processing_nonposix_group(self, cleanupgroups):
        """Test for sequence processing failures

        Issues have been found for group_add sequence processing with
        server context after creating a nonposix group. This test checks
        that all following group_add calls to add posix groups calls are
        not failing with missing attribute.

        related: https://pagure.io/freeipa/issue/9349
        """
        user_code_script2 = textwrap.dedent("""
            from ipalib import api, errors
            api.bootstrap_with_global_options(context='server')
            api.finalize()
            api.Backend.ldap2.connect()

            api.Command["group_add"]("testgroup1", nonposix=False)
            try:
                api.Command["group_add"]("testgroup2", nonposix=True)
            except Exception as e:
                print("testgroup2: %s" % e)
            try:
                api.Command["group_add"]("testgroup3", external=True)
            except Exception as e:
                print("testgroup3: %s" % e)
        """)
        self.master.put_file_contents("/tmp/reproducer2_code.py",
                                      user_code_script2)
        result = self.master.run_command(['python3',
                                          '/tmp/reproducer2_code.py'])
        assert "missing attribute" not in result.stdout_text

    def test_sidgen_task_continue_on_error(self):
        """Verify that SIDgen task continue even if it fails to assign sid
        scenario:
            - add a user with no uid (it will be auto-assigned inside
              the range)
            - add a user with uid 2000
            - add a user with no uid (it will be auto-assigned inside
              the range)
            - edit the first and 3rd users, remove the objectclass
              ipaNTUserAttrs and the attribute ipaNTSecurityIdentifier
            - run the sidgen task
            - verify that user1 and user3 have a ipaNTSecurityIdentifier
            - verify that old error message is not seen in dirsrv error log
            - verify that new error message is seen in dirsrv error log

        related: https://pagure.io/freeipa/issue/9618
        """
        test_user1 = 'test_user1'
        test_user2 = 'test_user2'
        test_user2000 = 'test_user2000'
        base_dn = str(self.master.domain.basedn)
        old_err_msg = 'Cannot add SID to existing entry'
        new_err_msg = r'Finished with [0-9]+ failures, please check the log'

        tasks.kinit_admin(self.master)
        tasks.user_add(self.master, test_user1)
        self.master.run_command(
            ['ipa', 'user-add', test_user2000,
             '--first', 'test', '--last', 'user',
             '--uid', '2000']
        )
        tasks.user_add(self.master, test_user2)

        for user in (test_user1, test_user2):
            entry_ldif = textwrap.dedent("""
                dn: uid={user},cn=users,cn=accounts,{base_dn}
                changetype: modify
                delete: ipaNTSecurityIdentifier
                -
                delete: objectclass
                objectclass: ipaNTUserAttrs
            """).format(
                user=user,
                base_dn=base_dn)
            tasks.ldapmodify_dm(self.master, entry_ldif)

        # run sidgen task
        self.master.run_command(
            ['ipa', 'config-mod', '--add-sids', '--enable-sid']
        )

        # ensure that sidgen have added the attr removed above
        for user in (test_user1, test_user2):
            result = tasks.ldapsearch_dm(
                self.master,
                'uid={user},cn=users,cn=accounts,{base_dn}'.format(
                    user=user, base_dn=base_dn),
                ['ipaNTSecurityIdentifier']
            )
            assert 'ipaNTSecurityIdentifier' in result.stdout_text

        dashed_domain = self.master.domain.realm.replace(".", '-')
        dirsrv_error_log = self.master.get_file_contents(
            paths.SLAPD_INSTANCE_ERROR_LOG_TEMPLATE % (dashed_domain),
            encoding='utf-8'
        )
        assert old_err_msg not in dirsrv_error_log
        assert re.search(new_err_msg, dirsrv_error_log)


class TestIPAautomount(IntegrationTest):
    @classmethod
    def install(cls, mh):
        tasks.install_master(cls.master, setup_dns=True)

    def test_tofiles_orphan_keys(self):
        """
        Validate automountlocation-tofiles output

        automount in LDAP is difficult to keep straight so a client-side
        map generator was created.
        """
        tasks.kinit_admin(self.master)

        self.master.run_command(
            [
                'ipa',
                'automountmap-add', 'default',
                'auto.test'
            ]
        )
        self.master.run_command(
            [
                'ipa',
                'automountkey-add', 'default',
                'auto.test',
                '--key', '/test',
                '--info', 'nfs.example.com:/exports/test'
            ]
        )
        self.master.run_command(
            [
                'ipa',
                'automountkey-add', 'default',
                'auto.test',
                '--key', '/test2',
                '--info', 'nfs.example.com:/exports/test2'
            ]
        )
        result = self.master.run_command(
            [
                'ipa', 'automountlocation-tofiles', 'default'
            ]
        ).stdout_text
        assert '/test' in result
        assert '/test2' in result
