# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

"""
Tests to verify Passkey Feature.
"""

from __future__ import absolute_import

import os
import pytest
import textwrap
from ipatests.test_integration.base import IntegrationTest
from ipatests.pytest_ipa.integration import tasks


def setup_files_on_host(host, file):
    dest = "test_integration/data/{0}".format(file)
    here = os.path.dirname(os.path.realpath('__file__'))
    with open(os.path.join(here, dest), 'rb') as f:
        contents = f.read()
    path = "/opt/{0}".format(file)
    host.put_file_contents(path, contents)
    return path


class TestPasskey(IntegrationTest):
    """ Tests for passkey feature.

    This test class covers the tests for Passkey feature using umockdev
    utility. With umockdev utility required files are generated with
    passkey input using umockdev-record and stored in
    ipatests/test_integration/data/passkey_* these files are generated
    using following steps.

    1: dnf install -y umockdev
    2: insert the passkey and run
    3: "LD_PRELOAD=/opt/random.so umockdev-record
    --ioctl /dev/hidraw1=/tmp/hidraw1.ioctl
    --script /dev/hidraw1=/tmp/hidraw1.script
    -- ipa user-add-passkey test2 --register
    --cose-type=es256 --require-user-verification=True"
    4: "umockdev-record /dev/hidraw1 > /tmp/hidraw1.device"
    5: "LD_PRELOAD=/opt/random.so umockdev-run
    --device /tmp/hidraw1.device --ioctl /dev/hidraw1=/tmp/hidraw1.ioctl
    --script /dev/hidraw1=/tmp/hidraw1.script
    -- ipa user-add-passkey test2 --register
    --cose-type=es256 --require-user-verification=True"

    related ticket: https://pagure.io/freeipa/issue/9261
    """

    num_clients = 1

    @pytest.fixture
    def setup_umockdev(self):
        """Fixture to setup umockdev and reset it"""
        randomc_path = setup_files_on_host(self.clients[0], file='random.c')
        self.clients[0].run_command(
            ["gcc", "-fPIC", "-shared", "-o", "/opt/random.so",
             randomc_path, "-lcrypto"]
        )
        BASHRC_CFG = "/root/.bashrc"
        bashrc = tasks.FileBackup(self.clients[0], BASHRC_CFG)
        contents = self.clients[0].get_file_contents(
            BASHRC_CFG, encoding="utf-8"
        )
        add_vars = textwrap.dedent("""
            export HIDRAW=/dev/hidraw1
            export LD_PRELOAD=/opt/random.so
        """)
        new_content = contents + add_vars
        self.clients[0].put_file_contents(BASHRC_CFG, new_content)
        self.clients[0].run_command('bash')
        yield
        bashrc.restore()

    @classmethod
    def install(cls, mh):
        tasks.install_packages(cls.clients[0],
                               ['umockdev', 'expect', 'gcc', 'openssl-devel']
                               )
        tasks.install_master(cls.master, setup_dns=True)
        tasks.install_client(cls.master, cls.clients[0])

    def test_passkey_register_ipa_user(self, setup_umockdev):
        """
        Test case to check that register ipa user with invalid/valid pin
        """
        client = self.clients[0]

        user = "test2"
        tasks.user_add(
            self.master, user, extra_args=["--user-auth-type=passkey"]
        )

        setup_files_on_host(client, file='passkey_hidraw1.device')
        setup_files_on_host(client, file='passkey_test2hidraw1.ioctl')
        setup_files_on_host(client, file='passkey_test2hidraw1.script')

        cred = ("obibdu8+xE2O/D+cfzl0xD4IqXZeGSmWciJJfRRlhJOs+MS22"
                "CZpPfDmC5H5DO5Ic8zE4QXHz9CFPh+RQh8Z1Q==")
        register = ('ipa user-add-passkey test2 --register --cose-type=es256 '
                    '--require-user-verification=True')
        umockdevrun = """
        #!/usr/bin/expect -f
        spawn umockdev-run --device {device} --ioctl /dev/hidraw1={ioctl} --script /dev/hidraw1={script} -- {command}   # noqa: E501
        expect "Enter PIN:"
        send -- "{pin}\\r"
        expect Shell>
        """
        contents = umockdevrun.format(
            device='/opt/passkey_hidraw1.device',
            ioctl='/opt/passkey_test2hidraw1.ioctl',
            script='/opt/passkey_test2hidraw1.script',
            command=register,
            pin='12345'
        )
        client.put_file_contents("/tmp/login.exp", contents)
        expectrun = client.run_command(['expect', '/tmp/login.exp'])
        assert 'Added passkey mappings to user "{0}"'.format(
            user) in expectrun.stdout_text
        test = client.run_command(['ipa', 'user-show', user])
        assert cred in test.stdout_text
