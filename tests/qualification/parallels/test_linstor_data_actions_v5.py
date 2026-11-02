"""Offline candidate guards. No VM, Docker, network or native replica test."""
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import linstor_data_actions_v5 as d


class FakeOwner:
    def __init__(self, node=1):
        self.node=node
        identity=d.IDENTITIES[node];vg=d.vg_name(node)
        self.calls=[]
        self.blocks=[dict(path='/dev/sdd',serial=identity['serial'],size=2*1024**3,type='disk')]
        self.pvs=[dict(pv_name='/dev/sdd',pv_uuid=identity['pv'],vg_name=vg,vg_uuid=identity['vg'],pv_tags=vg)]
        self.vgs=[dict(vg_name=vg,vg_uuid=identity['vg'],vg_tags=vg,vg_extent_size='4194304')]
        self.retained=dict(vg_name=vg,lv_name=d.RETAINED_NAME,lv_uuid=d.RETAINED_A4[node],lv_size='541065216')
        self.lvs=[self.retained]

    def command(self, tag, args, **kwargs):
        self.calls.append(args)
        if args[0]=='lsblk':return json.dumps(dict(blockdevices=self.blocks))
        if args[0]=='pvs':return json.dumps(dict(report=[dict(pv=self.pvs)]))
        if args[0]=='vgs':return json.dumps(dict(report=[dict(vg=self.vgs)]))
        if args[0]=='lvs':return json.dumps(dict(report=[dict(lv=self.lvs)]))
        raise AssertionError('a mutating or otherwise unexpected command was attempted')


class PreservedResources(unittest.TestCase):
    def test_all_three_exact_retained_incarnations_are_readonly(self):
        for node in [1,2,3]:
            owner=FakeOwner(node)
            result=d.pool_guard(None,owner,dict(node=dict(id=node)),empty=True)
            self.assertEqual(result['lvs'],[])
            self.assertEqual(result['retained_lvs'],[owner.retained])
            self.assertEqual(result['extent_bytes'],4194304)
            self.assertEqual([x[0] for x in owner.calls],['lsblk','pvs','vgs','lvs'])

    def test_retained_uuid_name_size_or_absence_is_not_adopted(self):
        for changed in [dict(lv_uuid='replacement'),dict(lv_name='other'),dict(lv_size='536870912'),None]:
            owner=FakeOwner()
            if changed is None:owner.lvs=[]
            else:owner.retained.update(changed)
            with self.assertRaises(AssertionError):
                d.pool_guard(None,owner,dict(node=dict(id=1)),empty=True)

    def test_extra_foreign_or_duplicate_retained_lv_is_refused(self):
        for extra in [dict(vg_name=d.vg_name(1),lv_name='foreign',lv_uuid='x',lv_size='1'),
                      dict(vg_name=d.vg_name(1),lv_name=d.RETAINED_NAME,lv_uuid=d.RETAINED_A4[1],lv_size='541065216')]:
            owner=FakeOwner();owner.lvs.append(extra)
            with self.assertRaises(AssertionError):
                d.pool_guard(None,owner,dict(node=dict(id=1)))

    def test_current_resource_cannot_exist_before_fresh_creation(self):
        owner=FakeOwner()
        owner.lvs.append(dict(vg_name=d.vg_name(1),lv_name=d.LV,lv_uuid='new-only',lv_size='541065216'))
        with self.assertRaises(AssertionError):
            d.pool_guard(None,owner,dict(node=dict(id=1)),empty=True)
        result=d.pool_guard(None,owner,dict(node=dict(id=1)))
        self.assertEqual([x['lv_uuid'] for x in result['lvs']],['new-only'])
        self.assertEqual([x['lv_uuid'] for x in result['retained_lvs']],[d.RETAINED_A4[1]])

    def test_noncanonical_or_missing_extent_is_refused(self):
        for bad in ['4194304.0','4m',' 4194304','0',None]:
            owner=FakeOwner();owner.vgs[0]['vg_extent_size']=bad
            with self.assertRaises((AssertionError,ValueError)):
                d.pool_guard(None,owner,dict(node=dict(id=1)))

    def test_physical_identity_guards_remain(self):
        for field,change in [('blocks',dict(path='/dev/sda')),('blocks',dict(serial='old')),
                             ('pvs',dict(pv_uuid='foreign')),('pvs',dict(vg_uuid='foreign')),
                             ('vgs',dict(vg_uuid='foreign'))]:
            owner=FakeOwner();getattr(owner,field)[0].update(change)
            with self.assertRaises(AssertionError):
                d.pool_guard(None,owner,dict(node=dict(id=1)))


class CapacityIdentity(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.module=SimpleNamespace(CASE=Path(self.directory.name),put=self.put)
        self.pool=dict(lvs=[dict(lv_uuid='new-volume',lv_size='541065216')],extent_bytes=4194304)
        self.kernel=dict(role='Secondary',devices=[{'minor':d.MINOR,'size':528232,'disk-state':'UpToDate','quorum':True}],
                         connections=[{'connection-state':'Connected','peer_devices':[{'peer-disk-state':'UpToDate','out-of-sync':0}]} for _ in range(2)])
        self.profile=dict(resource=d.RESOURCE,minor=d.MINOR,lv_uuid='new-volume',source='exact native metadata observation',profile=dict(d.capacity.PROFILE))
        self.put(self.module.CASE/'drbd-metadata-profile.json',self.profile)
        self.addCleanup(patch.stopall)
        patch.object(d,'pool_guard',return_value=self.pool).start()
        patch.object(d,'kernel',side_effect=lambda owner:[self.kernel]).start()
        self.observation=patch.object(d,'exposed_block_observation',return_value=(Path('/dev/drbd'+str(d.MINOR)),1056464)).start()

    def put(self,path,value):
        path.write_text(json.dumps(value))

    def inspect(self):
        return d.inspect(self.module,None,dict(node=dict(id=1)))

    def test_recorded_rounding_creates_exact_persistent_capacity_identity(self):
        result=self.inspect()
        self.assertTrue(result['healthy'] and result['capacity_ready'])
        self.assertEqual(result['identity']['bytes'],540909568)
        self.assertEqual(result['identity']['capacity']['allocated_bytes'],541065216)
        self.assertEqual(result['identity'],self.inspect()['identity'])

    def test_pending_kernel_capacity_never_writes_identity_or_health(self):
        self.observation.return_value=None
        result=self.inspect()
        self.assertFalse(result['healthy'] or result['capacity_ready'])
        self.assertNotIn('identity',result)
        self.assertFalse((self.module.CASE/'volume-identity.json').exists())

    def test_missing_profile_is_not_invented_from_number_of_nodes(self):
        (self.module.CASE/'drbd-metadata-profile.json').unlink()
        with self.assertRaises(FileNotFoundError):self.inspect()
        self.assertFalse((self.module.CASE/'volume-identity.json').exists())

    def test_wrong_resource_minor_or_lv_profile_is_refused(self):
        for change in [dict(resource='old'),dict(minor=d.MINOR-1),dict(lv_uuid=d.RETAINED_A4[1]),dict(source='assumed')]:
            self.put(self.module.CASE/'drbd-metadata-profile.json',dict(self.profile,**change))
            with self.assertRaises(AssertionError):self.inspect()
            self.assertFalse((self.module.CASE/'volume-identity.json').exists())

    def test_profile_drift_does_not_rebaseline_identity(self):
        before=self.inspect()['identity']
        self.profile['profile']['peer_slots']=6
        self.put(self.module.CASE/'drbd-metadata-profile.json',self.profile)
        with self.assertRaises(ValueError):self.inspect()
        self.assertEqual(json.loads((self.module.CASE/'volume-identity.json').read_bytes()),before)

    def test_positive_size_or_sysfs_mismatch_fails_not_pending(self):
        for observation in [(Path('/dev/drbd'+str(d.MINOR)),1056463)]:
            self.observation.return_value=observation
            with self.assertRaises(ValueError):self.inspect()
        self.observation.return_value=(Path('/dev/drbd'+str(d.MINOR)),1056464)
        self.kernel['devices'][0]['size']-=4
        with self.assertRaises(ValueError):self.inspect()

    def test_healthy_size_does_not_override_missing_quorum_or_peer_sync(self):
        self.kernel['devices'][0]['quorum']=False
        result=self.inspect()
        self.assertTrue(result['capacity_ready'])
        self.assertFalse(result['healthy'])

    def test_changed_lv_incarnation_does_not_overwrite_recorded_identity(self):
        before=self.inspect()['identity']
        self.pool['lvs'][0]['lv_uuid']='replacement'
        self.profile['lv_uuid']='replacement'
        self.put(self.module.CASE/'drbd-metadata-profile.json',self.profile)
        with self.assertRaisesRegex(AssertionError,'identity or capacity drift'):self.inspect()
        self.assertEqual(json.loads((self.module.CASE/'volume-identity.json').read_bytes()),before)


class RawExtentUse(unittest.TestCase):
    def test_raw_ack_trailer_and_hash_use_actual_exposed_end(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'generated-local-data'
            actual=9*1024**2
            with path.open('wb') as stream:stream.truncate(actual)
            state=dict(identity=dict(bytes=actual))
            module=SimpleNamespace(CASE=Path(directory),put=lambda p,v:p.write_text(json.dumps(v)))
            with patch.object(d,'device',return_value=(path,state)):
                result=d.raw_write(module,None,dict(node=dict(id=1)))
            self.assertEqual(result['whole_device']['bytes'],actual)
            self.assertEqual(result['acknowledged_records'][-1]['offset'],actual-4096)
            self.assertEqual(len(result['acknowledged_records']),129)
            self.assertEqual(result['whole_device']['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(result['acknowledged_records'][-1]['sha256'],hashlib.sha256(path.read_bytes()[-4096:]).hexdigest())


if __name__=='__main__':unittest.main()
