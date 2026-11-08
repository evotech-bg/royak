"""Pure data-fixture scope guards, not a replacement for real VM e2e."""
import copy
import json
import unittest
import linstor_data_actions_v1 as d


class FakeOwner:
    def __init__(self):
        x=d.IDENTITIES[1];vg=d.vg_name(1);self.calls=[]
        self.blocks=[dict(path='/dev/sdd',serial=x['serial'],size=2*1024**3,type='disk')]
        self.pvs=[dict(pv_name='/dev/sdd',pv_uuid=x['pv'],vg_name=vg,vg_uuid=x['vg'],pv_tags=vg)]
        self.vgs=[dict(vg_name=vg,vg_uuid=x['vg'],vg_tags=vg)];self.lvs=[];self.resources=[]
    def command(self,tag,args,**kw):
        self.calls.append(args)
        if args[0]=='lsblk':return json.dumps(dict(blockdevices=self.blocks))
        if args[0]=='pvs':return json.dumps(dict(report=[dict(pv=self.pvs)]))
        if args[0]=='vgs':return json.dumps(dict(report=[dict(vg=self.vgs)]))
        if args[0]=='lvs':return json.dumps(dict(report=[dict(lv=self.lvs)]))
        if args[:2]==['drbdsetup','status']:return json.dumps(self.resources)
        raise AssertionError('unexpected mutating command in guard test')


class DataScope(unittest.TestCase):
    def test_exact_empty_new_pool(self):
        o=FakeOwner();d.pool_guard(None,o,dict(node=dict(id=1)),empty=True)
        self.assertEqual(len(o.calls),4)
    def test_wrong_disk_or_pv_vg_identity_refused(self):
        for field,change in [('blocks',dict(path='/dev/sda')),('blocks',dict(serial='OLD')),('pvs',dict(pv_uuid='foreign')),('pvs',dict(vg_uuid='foreign')),('vgs',dict(vg_uuid='foreign'))]:
            o=FakeOwner();getattr(o,field)[0].update(change)
            with self.assertRaises(AssertionError):d.pool_guard(None,o,dict(node=dict(id=1)),empty=True)
    def test_old_or_unexpected_lv_never_adopted(self):
        for name in ['prior-data','foreign',d.LV]:
            o=FakeOwner();o.lvs=[dict(vg_name=d.vg_name(1),lv_name=name)]
            with self.assertRaises(AssertionError):d.pool_guard(None,o,dict(node=dict(id=1)),empty=True)
            if name!=d.LV:
                with self.assertRaises(AssertionError):d.pool_guard(None,o,dict(node=dict(id=1)))
    def test_foreign_resource_or_minor_rejected(self):
        for resource,minor in [('old',d.MINOR),(d.RESOURCE,1)]:
            o=FakeOwner();o.resources=[dict(name=resource,devices=[dict(minor=minor)])]
            with self.assertRaises(AssertionError):d.kernel(o)
    def test_health_requires_three_current_diskful_votes(self):
        value=dict(devices=[{'disk-state':'UpToDate','quorum':True}],connections=[{'connection-state':'Connected','peer_devices':[{'peer-disk-state':'UpToDate','out-of-sync':0}]} for _ in range(2)])
        self.assertTrue(d.healthy(value))
        for change in ['quorum','peer','backlog','missing_peer']:
            x=copy.deepcopy(value)
            if change=='quorum':x['devices'][0]['quorum']=False
            elif change=='peer':x['connections'][0]['peer_devices'][0]['peer-disk-state']='Inconsistent'
            elif change=='backlog':x['connections'][0]['peer_devices'][0]['out-of-sync']=1
            else:x['connections'].pop()
            self.assertFalse(d.healthy(x))
    def test_pg_expected_payloads_are_exact_and_ordered(self):
        lines=d.expected_rows(2).splitlines();self.assertEqual(len(lines),2)
        self.assertEqual(lines[0],'1\t'+('c4ca4238a0b923820dcc509a6f75849b'*32).encode().hex())
        self.assertTrue(lines[1].startswith('2\t'))


if __name__=='__main__':unittest.main()
