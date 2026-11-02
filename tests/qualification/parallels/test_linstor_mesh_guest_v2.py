"""Pure fail-closed scope/cleanup regressions; no VM or network operations."""
import copy
import unittest
import linstor_mesh_guest_v2 as m


class MeshScopeTests(unittest.TestCase):
    def config(self):
        return dict(run=m.RUN,node=copy.deepcopy(m.NODES[0]),password='a'*64,stage_sha256='b'*64)
    def test_exact_owned_node_is_accepted(self):
        m.validate(self.config(),1)
    def test_foreign_underlay_address_is_rejected(self):
        c=self.config();c['node']['ip']='192.0.2.1'
        with self.assertRaises(AssertionError):m.validate(c,1)
    def test_broad_allowed_address_is_rejected(self):
        c=self.config();c['node']['wg_ip']='0.0.0.0/0'
        with self.assertRaises(AssertionError):m.validate(c,1)
    def test_other_run_and_extra_config_are_rejected(self):
        for key,value in [('run','other-run'),('extra','permission')]:
            c=self.config();c[key]=value
            with self.assertRaises(AssertionError):m.validate(c,1)
    def owner(self,value):
        o=object.__new__(m.Owner);o.cfg=self.config();o.created_link=99;o.alias_applied=True;o.key_applied=False;o.peer_keys=set()
        o.link=lambda:value;o.actions=[]
        def command(tag,argv,*args,**kwargs):
            o.actions.append(argv);return '[]'
        o.command=command
        return o
    def test_changed_interface_identity_never_deletes(self):
        correct=dict(ifindex=99,ifalias=m.RUN+':n1',linkinfo=dict(info_kind='wireguard'))
        for change in [dict(ifindex=98),dict(ifalias='another-owner'),dict(ifalias=''),dict(linkinfo=dict(info_kind='dummy'))]:
            value=copy.deepcopy(correct);value.update(change);o=self.owner(value)
            with self.assertRaises(AssertionError):o.network_down()
            self.assertEqual(o.actions,[])
    def test_exact_original_interface_can_be_removed(self):
        o=self.owner(dict(ifindex=99,ifalias=m.RUN+':n1',linkinfo=dict(info_kind='wireguard')))
        self.assertEqual(o.network_down(),dict(exact_owned_interface_removed=True))
        self.assertIn(['ip','link','delete','dev',m.IFACE],o.actions)
        self.assertIsNone(o.created_link)


if __name__=='__main__':unittest.main()
