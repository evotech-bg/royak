"""Pure census protocol tests; no Docker, network, processes or root required."""
import unittest
from pod_access_e2e import inspected_containers,removable_fixture_network,tcp_listener_present


class ContainerCensus(unittest.TestCase):
    def test_full_exact_container_identity_is_required(self):
        cid='a'*64
        self.assertEqual(inspected_containers([cid],lambda _: (200,{'Id':cid}),lambda _:self.fail('not vanished')),[{'Id':cid}])

    def test_list_then_exact_404_is_recorded_not_an_unknown_zero(self):
        first,last='a'*64,'b'*64
        vanished=[]
        result=inspected_containers([first,last],lambda cid:(404,{}) if cid==first else (200,{'Id':last}),vanished.append)
        self.assertEqual(vanished,[first])
        self.assertEqual(result,[{'Id':last}])

    def test_other_status_or_retargeted_identity_is_not_omitted(self):
        cid='a'*64
        for status,value in [(0,{}),(403,{}),(500,{}),(200,{}),(200,{'Id':'b'*64})]:
            with self.assertRaises(AssertionError):
                inspected_containers([cid],lambda _:(status,value),lambda _:self.fail('not a404'))

    def test_short_or_duplicate_ids_refuse_before_inspection(self):
        for ids in [['abc'],['a'*64,'a'*64]]:
            with self.assertRaises(AssertionError):
                inspected_containers(ids,lambda _:self.fail('invalid id'),lambda _:self.fail('invalid id'))

    def test_network_cleanup_requires_exact_run_label_and_empty_known_network(self):
        owned=dict(Id='a'*64,Name='rk-our-ns',Labels={'royak.qualification':'run'},Containers={})
        self.assertTrue(removable_fixture_network(owned,'run',('rk-our-ns',)))
        for bad in (dict(owned,Labels={}),dict(owned,Labels={'royak.managed':'true'}),
                    dict(owned,Labels={'royak.qualification':'other-run'}),
                    dict(owned,Name='foreign'),dict(owned,Containers={'foreign-container':{}}),
                    dict(owned,Id='a'*12),dict(owned,Containers=None)):
            self.assertFalse(removable_fixture_network(bad,'run',('rk-our-ns',)))

    def test_listener_census_accepts_ipv4_or_ipv6_without_connecting(self):
        ipv4='header\n0: 00000000:1F90 00000000:0000 0A other\n'
        ipv6='header\n0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A other\n'
        self.assertTrue(tcp_listener_present([ipv4,'header\n'],8080))
        self.assertTrue(tcp_listener_present(['header\n',ipv6],8080))
        for tables in (['header\n'],[ipv6.replace('1F90','1F91')],[ipv4.replace(' 0A ',' 01 ')],['header\nshort\n']):
            self.assertFalse(tcp_listener_present(tables,8080))


if __name__=='__main__':
    unittest.main()
