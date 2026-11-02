"""No live device is opened: golden native captures + isolated local/mock I/O."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

import linstor_native_metadata as m

VG='ckC6sy-iVAt-xG8b-MXwA-Sndr-0OTb-ZdfJod'
LV='Ab12Cd-Ef34-Gh56-Ij78-Kl90-Mn12-Op34Qr'


def synthetic_superblock():
    raw=bytearray(4096)
    for offset,value in [(48,123456789)]:struct.pack_into('>Q',raw,offset,value)
    for offset,value in [(60,m.MAGIC),(64,304),(68,(-64)&0xffffffff),(76,(-296)&0xffffffff),
                         (80,4096),(88,7),(92,0),(96,1),(100,8)]:
        struct.pack_into('>I',raw,offset,value)
    return bytes(raw)


class NativeGolden(unittest.TestCase):
    def test_three_retained_raw_captures_match_actual_native_dump_geometry(self):
        fixture=json.loads((Path(__file__).parent/'fixtures/drbd-v09-native-geometry.json').read_bytes())
        self.assertEqual([x['node'] for x in fixture['nodes']],[1,2,3])
        for node in fixture['nodes']:
            with self.subTest(node=node['node']):
                raw=base64.b64decode(node['superblock_base64'],validate=True)
                self.assertEqual(hashlib.sha256(raw).hexdigest(),node['superblock_sha256'])
                got=m.parse_superblock(raw,node['allocated_bytes'])
                expected=node['expected_from_native_dump']
                for key in ['node_id','device_uuid','metadata_bytes','superblock_offset','profile']:
                    self.assertEqual(got[key],expected[key])
                self.assertEqual(got['superblock_offset']+got['al_offset_sectors']*512,expected['al_offset_absolute'])
                self.assertEqual(got['superblock_offset']+got['bitmap_offset_sectors']*512,expected['bitmap_offset_absolute'])

    def test_synthetic_seven_slot_profile_has_exact_current_accounting(self):
        got=m.parse_superblock(synthetic_superblock(),541065216)
        self.assertEqual(got['metadata_bytes'],155648)
        self.assertEqual(got['profile'],dict(peer_slots=7,al_stripes=1,al_stripe_size_kib=32,bitmap_block_kib=4))

    def test_bad_length_magic_or_byte_order_is_rejected(self):
        raw=synthetic_superblock()
        bad=bytearray(raw);struct.pack_into('<I',bad,60,m.MAGIC)
        for value in [b'',raw[:-1],raw+b'x',bytes(bad),b'\0'*4096]:
            with self.assertRaises(ValueError):m.parse_superblock(value,541065216)

    def test_bad_geometry_fields_do_not_default_to_expected_profile(self):
        for offset,value in [(64,303),(68,0),(76,0),(80,0),(80,8191),(88,0),(88,32),
                             (92,32),(96,0),(100,0),(100,1000000)]:
            with self.subTest(offset=offset,value=value):
                raw=bytearray(synthetic_superblock());struct.pack_into('>I',raw,offset,value)
                with self.assertRaises(ValueError):m.parse_superblock(bytes(raw),541065216)

    def test_missing_device_uuid_and_data_overlap_fail(self):
        for offset,value in [(48,0),(0,541065216//512)]:
            raw=bytearray(synthetic_superblock());struct.pack_into('>Q',raw,offset,value)
            with self.assertRaises(ValueError):m.parse_superblock(bytes(raw),541065216)

    def test_raw_geometry_change_is_not_a_retry_or_rebaseline(self):
        raw=synthetic_superblock();changed=bytearray(raw);struct.pack_into('>Q',changed,48,98765)
        with self.assertRaisesRegex(ValueError,'changed between'):
            m.stable_geometry(raw,bytes(changed),541065216)

    def test_mutable_flags_can_change_without_inventing_stable_geometry(self):
        raw=synthetic_superblock();changed=bytearray(raw);struct.pack_into('>I',changed,56,0x91)
        self.assertEqual(m.stable_geometry(raw,bytes(changed),541065216),m.parse_superblock(raw,541065216))

    def test_bad_allocation_and_noninteger_values_fail(self):
        for size in [0,True,None,541065216.0,541065215,4096]:
            with self.assertRaises(ValueError):m.parse_superblock(synthetic_superblock(),size)


class DirectReader(unittest.TestCase):
    def test_aligned_reader_reads_exact_block_from_private_generated_file(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'local-only'
            p.write_bytes(b'p'*4096+synthetic_superblock())
            fd=os.open(p,os.O_RDONLY)
            try:self.assertEqual(m.read_direct_block(fd,4096),synthetic_superblock())
            finally:os.close(fd)

    def test_short_read_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'local-only';p.write_bytes(b'x'*2048)
            fd=os.open(p,os.O_RDONLY)
            try:
                with self.assertRaisesRegex(ValueError,'short direct'):
                    m.read_direct_block(fd,0)
            finally:os.close(fd)

    def native_mock(self):
        self.addCleanup(patch.stopall)
        patch.object(m.sys,'platform','linux').start()
        patch.object(m.os,'O_DIRECT',0x4000,create=True).start()
        patch.object(m.os,'geteuid',return_value=0).start()
        self.uuid=patch.object(m.Path,'read_text',return_value=m.mapper_uuid(VG,LV)).start()
        self.open=patch.object(m.os,'open',return_value=42).start()
        self.close=patch.object(m.os,'close').start()
        # Model Linux dev_t independently of the macOS test host's signed dev_t.
        patch.object(m.os,'major',side_effect=lambda value:(value>>8)&0xff).start()
        patch.object(m.os,'minor',side_effect=lambda value:value&0xff).start()
        self.state=SimpleNamespace(st_mode=stat.S_IFBLK|0o600,st_uid=0,st_rdev=(252<<8)|4,st_ino=1,st_dev=2)
        self.fstat=patch.object(m.os,'fstat',return_value=self.state).start()
        def size(fd,request,buffer,mutate):
            self.assertEqual((fd,request,mutate),(42,m.BLKGETSIZE64,True))
            buffer[:]=struct.pack('=Q',541065216)
        self.ioctl=patch.object(m.fcntl,'ioctl',side_effect=size).start()
        self.raw=patch.object(m,'read_direct_block',return_value=synthetic_superblock()).start()
        patch.object(m.os,'write',side_effect=AssertionError('write forbidden')).start()
        patch.object(m.os,'pwrite',side_effect=AssertionError('pwrite forbidden')).start()
        return dict(resource='rkls_data_20261102_a6',minor=436,node_id=0,vg_uuid=VG,lv_uuid=LV,
                    major=252,device_minor=4,allocated_bytes=541065216)

    def test_live_path_contract_is_readonly_direct_and_exact_mapper_bound(self):
        expected=self.native_mock();got=m.read_owned_superblock(**expected)
        args=self.open.call_args.args
        self.assertEqual(str(args[0]),'/dev/dm-4')
        self.assertEqual(args[1]&os.O_ACCMODE,os.O_RDONLY)
        self.assertTrue(args[1]&m.os.O_DIRECT and args[1]&os.O_NOFOLLOW)
        self.assertEqual(self.raw.call_count,2)
        self.assertEqual(self.ioctl.call_count,2)
        self.close.assert_called_once_with(42)
        self.assertFalse(got['data_consistency_proven'])
        m.validate_receipt(got,**expected)

    def test_uuid_mismatch_refuses_before_device_open(self):
        expected=self.native_mock();self.uuid.return_value='LVM-foreign'
        with self.assertRaises(ValueError):m.read_owned_superblock(**expected)
        self.open.assert_not_called();self.close.assert_not_called()

    def test_nonblock_or_wrong_major_minor_closes_exact_fd(self):
        for bad in [dict(st_mode=stat.S_IFREG|0o600),dict(st_uid=1000),dict(st_rdev=(252<<8)|5)]:
            expected=self.native_mock()
            for k,v in bad.items():setattr(self.state,k,v)
            with self.assertRaises(ValueError):m.read_owned_superblock(**expected)
            self.close.assert_called_once_with(42)
            patch.stopall()

    def test_capacity_change_or_node_mismatch_closes_exact_fd(self):
        for change in ['size','node']:
            expected=self.native_mock()
            if change=='node':expected['node_id']=1
            else:
                self.ioctl.side_effect=lambda fd,request,buffer,mutate:buffer.__setitem__(slice(None),struct.pack('=Q',123456))
            with self.assertRaises(ValueError):m.read_owned_superblock(**expected)
            self.close.assert_called_once_with(42);patch.stopall()

    def test_mapper_change_after_read_is_not_accepted(self):
        expected=self.native_mock();self.uuid.side_effect=[m.mapper_uuid(VG,LV),'LVM-foreign']
        with self.assertRaisesRegex(ValueError,'changed during'):
            m.read_owned_superblock(**expected)
        self.close.assert_called_once_with(42)

    def test_transport_reparses_raw_instead_of_trusting_profile_labels(self):
        expected=self.native_mock();got=m.read_owned_superblock(**expected)
        bad=copy.deepcopy(got);bad['profile']['peer_slots']=2
        with self.assertRaises(ValueError):m.validate_receipt(bad,**expected)
        bad=copy.deepcopy(got);bad['raw_superblock_sha256'][0]='0'*64
        with self.assertRaises(ValueError):m.validate_receipt(bad,**expected)
        bad=copy.deepcopy(got);bad['raw_superblock_base64'][0]='!invalid'
        with self.assertRaises(ValueError):m.validate_receipt(bad,**expected)
        bad=copy.deepcopy(got);bad['lv_uuid']='replacement'
        with self.assertRaises(ValueError):m.validate_receipt(bad,**expected)

    def test_scope_and_uuid_injection_fail_before_open(self):
        for change in [dict(resource='foreign'),dict(resource='rkls_data_20261102_a6;true'),
                       dict(lv_uuid='../../sda'),dict(vg_uuid='foreign'),dict(device_minor=True),dict(major=True)]:
            expected=self.native_mock();expected.update(change)
            with self.assertRaises(ValueError):m.read_owned_superblock(**expected)
            self.open.assert_not_called();patch.stopall()


if __name__=='__main__':unittest.main()
