#
# Copyright (C) 2015  FreeIPA Contributors see COPYING for license
#

import re

import pytest

from ipatests.test_integration.base import IntegrationTest
from ipatests.test_integration import tasks
from ipatests.test_integration.env_config import get_global_config
from ipalib.constants import DOMAIN_SUFFIX_NAME
from ipatests.util import assert_deepequal

config = get_global_config()
reasoning = "Topology plugin disabled due to domain level 0"


def find_segment(master, replica):
    result = master.run_command(['ipa', 'topologysegment-find',
                                 DOMAIN_SUFFIX_NAME]).stdout_text
    segment_re = re.compile('Left node: (?P<left>\S+)\n.*Right node: '
                            '(?P<right>\S+)\n')
    allsegments = segment_re.findall(result)
    for segment in allsegments:
        if master.hostname in segment and replica.hostname in segment:
            return '-to-'.join(segment)


def remove_segment(master, host1, host2):
    """
    This removes a segment between host1 and host2 on master. The function is
    needed because test_add_remove_segment expects only one segment, but due to
    track tickete N 6250, the test_topology_updated_on_replica_install_remove
    leaves 2 topology segments
    """
    def wrapper(func):
        def wrapped(*args, **kwargs):
            try:
                func(*args, **kwargs)
            finally:
                segment = find_segment(host1, host2)
                master.run_command(['ipa', 'topologysegment-del',
                                    DOMAIN_SUFFIX_NAME, segment],
                                   raiseonerr=False)
        return wrapped
    return wrapper


@pytest.mark.skipif(config.domain_level == 0, reason=reasoning)
class TestTopologyOptions(IntegrationTest):
    num_replicas = 2
    topology = 'star'
    rawsegment_re = ('Segment name: (?P<name>.*?)',
                     '\s+Left node: (?P<lnode>.*?)',
                     '\s+Right node: (?P<rnode>.*?)',
                     '\s+Connectivity: (?P<connectivity>\S+)')
    segment_re = re.compile("\n".join(rawsegment_re))
    noentries_re = re.compile("Number of entries returned (\d+)")
    segmentnames_re = re.compile('.*Segment name: (\S+?)\n.*')

    @classmethod
    def install(cls, mh):
        tasks.install_topo(cls.topology, cls.master,
                           cls.replicas[:-1],
                           cls.clients)

    def tokenize_topologies(self, command_output):
        """
        takes an output of `ipa topologysegment-find` and returns an array of
        segment hashes
        """
        segments = command_output.split("-----------------")[2]
        raw_segments = segments.split('\n\n')
        result = []
        for i in raw_segments:
            matched = self.segment_re.search(i)
            if matched:
                result.append({'leftnode': matched.group('lnode'),
                               'rightnode': matched.group('rnode'),
                               'name': matched.group('name'),
                               'connectivity': matched.group('connectivity')
                               }
                              )
        return result

    @pytest.mark.xfail(reason="Trac 6250", strict=True)
    @remove_segment(config.domains[0].master,
                    config.domains[0].master,
                    config.domains[0].replicas[1])
    def test_topology_updated_on_replica_install_remove(self):
        """
        Install and remove a replica and make sure topology information is
        updated on all other replicas
        Testcase: http://www.freeipa.org/page/V4/Manage_replication_topology/
        Test_plan#Test_case:
        _Replication_topology_should_be_saved_in_the_LDAP_tree
        """
        tasks.kinit_admin(self.master)
        result1 = self.master.run_command(['ipa', 'topologysegment-find',
                                           DOMAIN_SUFFIX_NAME]).stdout_text
        segment_name = self.segmentnames_re.findall(result1)[0]
        assert(self.master.hostname in segment_name), (
            "Segment %s does not contain master hostname" % segment_name)
        assert(self.replicas[0].hostname in segment_name), (
            "Segment %s does not contain replica hostname" % segment_name)
        tasks.install_replica(self.master, self.replicas[1], setup_ca=False,
                              setup_dns=False)
        # We need to make sure topology information is consistent across all
        # replicas
        result2 = self.master.run_command(['ipa', 'topologysegment-find',
                                           DOMAIN_SUFFIX_NAME])
        result3 = self.replicas[0].run_command(['ipa', 'topologysegment-find',
                                                DOMAIN_SUFFIX_NAME])
        result4 = self.replicas[1].run_command(['ipa', 'topologysegment-find',
                                                DOMAIN_SUFFIX_NAME])
        segments = self.tokenize_topologies(result2.stdout_text)
        assert(len(segments) == 2), "Unexpected number of segments found"
        assert_deepequal(result2.stdout_text, result3.stdout_text)
        assert_deepequal(result3.stdout_text,  result4.stdout_text)
        # Now let's check that uninstalling the replica will update the topology
        # info on the rest of replicas.
        tasks.uninstall_master(self.replicas[1])
        tasks.clean_replication_agreement(self.master, self.replicas[1])
        result5 = self.master.run_command(['ipa', 'topologysegment-find',
                                           DOMAIN_SUFFIX_NAME])
        num_entries = self.noentries_re.search(result5.stdout_text).group(1)
        assert(num_entries == "1"), "Incorrect number of entries displayed"

    def test_add_remove_segment(self):
        """
        Make sure a topology segment can be manually created and deleted
        with the influence on the real topology
        Testcase http://www.freeipa.org/page/V4/Manage_replication_topology/
        Test_plan#Test_case:_Basic_CRUD_test
        """
        tasks.kinit_admin(self.master)
        # Install the second replica
        tasks.install_replica(self.master, self.replicas[1], setup_ca=False,
                              setup_dns=False)
        # turn a star into a ring
        segment, err = tasks.create_segment(self.master,
                                            self.replicas[0],
                                            self.replicas[1])
        assert err == "", err
        # Make sure the new segment is shown by `ipa topologysegment-find`
        result1 = self.master.run_command(['ipa', 'topologysegment-find',
                                           DOMAIN_SUFFIX_NAME]).stdout_text
        assert(segment['name'] in result1), (
            "%s: segment not found" % segment['name'])
        # Remove master <-> replica2 segment and make sure that the changes get
        # there through replica1
        # Since segment name can be one of master-to-replica2 or
        # replica2-to-master, we need to determine the segment name dynamically

        deleteme = find_segment(self.master, self.replicas[1])
        returncode, error = tasks.destroy_segment(self.master, deleteme)
        assert returncode == 0, error
        # Wait till replication ends and make sure replica1 does not have
        # segment that was deleted on master
        replica1_ldap = self.replicas[0].ldap_connect()
        tasks.wait_for_replication(replica1_ldap)
        result3 = self.replicas[0].run_command(['ipa', 'topologysegment-find',
                                               DOMAIN_SUFFIX_NAME]).stdout_text
        assert(deleteme not in result3), "%s: segment still exists" % deleteme
        # Create test data on master and make sure it gets all the way down to
        # replica2 through replica1
        self.master.run_command(['ipa', 'user-add', 'someuser',
                                 '--first', 'test',
                                 '--last', 'user'])
        dest_ldap = self.replicas[1].ldap_connect()
        tasks.wait_for_replication(dest_ldap)
        result4 = self.replicas[1].run_command(['ipa', 'user-find'])
        assert('someuser' in result4.stdout_text), 'User not found: someuser'
        # We end up having a line topology: master <-> replica1 <-> replica2

    def test_remove_the_only_connection(self):
        """
        Testcase: http://www.freeipa.org/page/V4/Manage_replication_topology/
        Test_plan#Test_case:
        _Removal_of_a_topology_segment_is_allowed_only_if_there_is_at_least_one_more_segment_connecting_the_given_replica
        """
        text = "Removal of Segment disconnects topology"
        error1 = "The system should not have let you remove the segment"
        error2 = "Wrong error message thrown during segment removal: \"%s\""
        replicas = (self.replicas[0].hostname, self.replicas[1].hostname)

        returncode, error = tasks.destroy_segment(self.master, "%s-to-%s" % replicas)
        assert returncode != 0, error1
        assert error.count(text) == 1, error2 % error
        _newseg, err = tasks.create_segment(
            self.master, self.master, self.replicas[1])
        assert err == "", err
        returncode, error = tasks.destroy_segment(self.master, "%s-to-%s" % replicas)
        assert returncode == 0, error
