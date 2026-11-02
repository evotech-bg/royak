"""Local producer/consumer integration; Linux block reads are mocked explicitly."""
import base64
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import linstor_data_actions_v6 as d
from test_linstor_native_metadata import synthetic_superblock

LV='Ab12Cd-Ef34-Gh56-Ij78-Kl90-Mn12-Op34Qr'


def receipt(binding):
    raw=synthetic_superblock()
    geometry=d.native_metadata.parse_superblock(raw,binding['allocated_bytes'])
    return dict(binding,kind='owned-v09-direct-geometry',source='exact native metadata observation',
                backing_device='/dev/dm-'+str(binding['device_minor']),
                geometry=geometry,profile=geometry['profile'],
                raw_superblock_base64=[base64.b64encode(raw).decode()]*2,
                raw_superblock_sha256=[hashlib.sha256(raw).hexdigest()]*2,
                header_commit=d.native_metadata.HEADER_COMMIT,utils_commit=d.native_metadata.UTILS_COMMIT)


class LiveReceiptCandidate(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.module=SimpleNamespace(CASE=Path(folder.name),put=self.put)
        self.config=dict(node=dict(id=1))
        self.pool=dict(lvs=[dict(lv_uuid=LV,lv_size='541065216',lv_kernel_major='252',lv_kernel_minor='4')],extent_bytes=4194304)
        self.status=dict(role='Secondary',devices=[{'minor':d.MINOR,'size':528232,'disk-state':'UpToDate','quorum':True}],
            connections=[{'connection-state':'Connected','peer_devices':[{'peer-disk-state':'UpToDate','out-of-sync':0}]} for _ in range(2)])
        self.addCleanup(patch.stopall)
        patch.object(d,'pool_guard',return_value=self.pool).start()
        patch.object(d,'kernel',return_value=[self.status]).start()
        self.exposed=patch.object(d,'exposed_block_observation',return_value=(Path('/dev/drbd'+str(d.MINOR)),1056464)).start()
        self.reader=patch.object(d.native_metadata,'read_owned_superblock',side_effect=lambda **kw:receipt(kw)).start()
        # Local regular files model the isolated guest's UID1000. Keep the
        # runtime root/UID1000/mode0600 guard unchanged on macOS as on Linux.
        real_fstat=os.fstat
        def guest_fstat(fd):
            value=real_fstat(fd)
            return SimpleNamespace(st_mode=value.st_mode,st_uid=1000,
                                   st_nlink=value.st_nlink,st_size=value.st_size)
        self.guest_fstat=patch.object(d.os,'fstat',side_effect=guest_fstat).start()

    def put(self,path,value):
        with path.open('x') as stream:json.dump(value,stream)
        path.chmod(0o600)

    def inspect(self):return d.inspect(self.module,None,self.config)

    def test_missing_profile_is_collected_from_exact_new_lv_and_persisted(self):
        got=self.inspect()
        self.assertTrue(got['healthy'] and got['capacity_ready'])
        binding=self.reader.call_args.kwargs
        self.assertEqual(binding,dict(resource=d.RESOURCE,minor=d.MINOR,node_id=0,
            vg_uuid=d.IDENTITIES[1]['vg'],lv_uuid=LV,major=252,device_minor=4,allocated_bytes=541065216))
        self.assertNotEqual(binding['lv_uuid'],d.RETAINED_A4[1])
        self.assertTrue((self.module.CASE/'drbd-metadata-profile.json').is_file())
        self.assertEqual(len(list(self.module.CASE.glob('drbd-metadata-observation-*.json'))),1)

    def test_existing_receipt_is_reparsed_and_reobserved_not_just_trusted(self):
        first=self.inspect()['identity']
        self.assertEqual(self.inspect()['identity'],first)
        self.assertEqual(self.reader.call_count,2)
        self.assertEqual(len(list(self.module.CASE.glob('drbd-metadata-observation-*.json'))),2)

    def test_forged_profile_labels_do_not_substitute_for_raw_metadata(self):
        def forged(**kw):
            result=receipt(kw);result['profile']['peer_slots']=2
            return result
        self.reader.side_effect=forged
        with self.assertRaises(ValueError):self.inspect()
        self.assertFalse((self.module.CASE/'volume-identity.json').exists())

    def test_bad_raw_hash_is_rejected_before_cache_or_volume_identity(self):
        def forged(**kw):
            result=receipt(kw);result['raw_superblock_sha256'][0]='0'*64
            return result
        self.reader.side_effect=forged
        with self.assertRaises(ValueError):self.inspect()
        self.assertFalse((self.module.CASE/'drbd-metadata-profile.json').exists())

    def test_unready_block_does_not_invoke_metadata_reader(self):
        self.exposed.return_value=None
        got=self.inspect()
        self.assertFalse(got['healthy'] or got['capacity_ready'])
        self.reader.assert_not_called()
        self.assertFalse(list(self.module.CASE.iterdir()))

    def test_foreign_binding_returned_by_reader_is_refused(self):
        def wrong(**kw):
            result=receipt(kw);result['lv_uuid']=d.RETAINED_A4[1]
            return result
        self.reader.side_effect=wrong
        with self.assertRaises(ValueError):self.inspect()
        self.assertFalse((self.module.CASE/'volume-identity.json').exists())

    def test_reader_failure_does_not_invent_a_profile(self):
        self.reader.side_effect=OSError('native direct read refused')
        with self.assertRaises(OSError):self.inspect()
        self.assertFalse(list(self.module.CASE.iterdir()))

    def test_symlink_or_insecure_cached_receipt_is_not_followed(self):
        self.inspect()
        path=self.module.CASE/'drbd-metadata-profile.json'
        target=self.module.CASE/'retained-original-profile'
        path.rename(target);path.symlink_to(target)
        with self.assertRaises(OSError):self.inspect()
        self.assertFalse((self.module.CASE/'volume-identity.json').is_symlink())
        path.unlink();target.rename(path);path.chmod(0o644)
        with self.assertRaises(AssertionError):self.inspect()

    def test_cached_raw_proof_tamper_does_not_overwrite_original_volume_identity(self):
        first=self.inspect()['identity'];path=self.module.CASE/'drbd-metadata-profile.json'
        old=json.loads(path.read_bytes());old['raw_superblock_sha256'][1]='0'*64
        path.write_text(json.dumps(old))
        with self.assertRaises(ValueError):self.inspect()
        self.assertEqual(json.loads((self.module.CASE/'volume-identity.json').read_bytes()),first)

    def test_foreign_owner_cached_receipt_is_refused(self):
        self.inspect()
        self.guest_fstat.side_effect=None
        self.guest_fstat.return_value=SimpleNamespace(st_mode=0o100600,st_uid=999,st_nlink=1,st_size=100)
        with self.assertRaises(AssertionError):self.inspect()

    def test_capacity_and_quorum_still_both_required(self):
        self.status['devices'][0]['quorum']=False
        got=self.inspect();self.assertFalse(got['healthy']);self.assertTrue(got['capacity_ready'])
        self.pool['lvs'][0]['lv_size']='536870912'
        with self.assertRaises(ValueError):self.inspect()


if __name__=='__main__':unittest.main()
