import importlib.util
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('pool_prepare',Path(__file__).with_name('linstor_pool_prepare.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class PoolIdentityGuards(unittest.TestCase):
    def config(self):
        return dict(run=m.RUN,node=1,uuid=m.UUIDS[0],device='/dev/sdd',serial='NEW123',size=m.SIZE,major_minor='8:48',vg='rklsd_20261102_n1',tag='rklsd_20261102_n1')

    def test_exact_new_identity(self):m.validate_config(self.config())

    def test_tag_only_after_volume_group_and_never_pvcreate(self):
        plan=m.creation_commands(self.config())
        self.assertEqual([x[0] for x in plan],['pv-create','vg-create','pv-tag'])
        self.assertNotIn('--addtag',plan[0][1])
        self.assertTrue(all('--devices' in argv and '/dev/sdd' in argv for _,argv in plan))
        self.assertNotIn('--force',str(plan))

    def test_boot_or_old_disk_refused(self):
        for disk in ['/dev/sda','/dev/sdb','/dev/sdc','/dev/mapper/old']:
            c=self.config();c['device']=disk
            with self.assertRaises(AssertionError):m.validate_config(c)

    def test_descriptor_requires_exact_owned_backing_identity(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td).resolve();backing=p/'new.{11111111-1111-1111-1111-111111111111}.hds'
            backing.touch();s=backing.stat()
            ident=dict(host_disk=str(p),backing_name=backing.name,backing_inode=s.st_ino+1,backing_dev=s.st_dev,backing_size=m.SIZE,descriptor_sha256='x'*64)
            with self.assertRaises(AssertionError):m.descriptor_guard(p,ident)

    def test_real_new_descriptor_rejects_foreign_backing(self):
        # Pure guard validation on already-created local fixtures, no VM or I/O
        # operation: changing the inventory's backing name cannot grant access.
        with tempfile.TemporaryDirectory() as td:
            p=Path(td).resolve()
            with self.assertRaises(FileNotFoundError):m.descriptor_guard(p,dict(host_disk=str(p),backing_name='foreign',backing_inode=1,backing_dev=1,backing_size=m.SIZE,descriptor_sha256='x'*64))

    def test_positive_descriptor_and_exact_metadata_negatives(self):
        with tempfile.TemporaryDirectory() as td,patch.object(m,'SIZE',4096):
            p=Path(td).resolve();guid='{11111111-1111-1111-1111-111111111111}'
            backing=p/('new.'+guid+'.hds');backing.write_bytes(bytes(4096));s=backing.stat()
            old='<Parallels_disk_image><Disk_Parameters><Disk_size>8</Disk_size><Miscellaneous /></Disk_Parameters><StorageData><Storage><Start>0</Start><End>8</End><Image><GUID>'+guid+'</GUID><Type>Plain</Type><File>'+backing.name+'</File></Image></Storage></StorageData><Snapshots><Shot><GUID>'+guid+'</GUID><ParentGUID>{00000000-0000-0000-0000-000000000000}</ParentGUID></Shot></Snapshots></Parallels_disk_image>'
            new=old.replace('<Miscellaneous />','<Miscellaneous><Bootable>0</Bootable></Miscellaneous>')
            (p/'DiskDescriptor.xml.Backup').write_text(old);(p/'DiskDescriptor.xml').write_text(new)
            ident=dict(host_disk=str(p),backing_name=backing.name,backing_inode=s.st_ino,backing_dev=s.st_dev,backing_size=4096,descriptor_sha256='x'*64)
            result=m.descriptor_guard(p,ident)
            self.assertFalse(result['historical_creation_descriptor_equal'])
            for text in [new.replace('<Bootable>0','<Bootable>1'),new.replace('<End>8','<End>9'),new.replace(backing.name,'foreign.hds'),new.replace('<Type>Plain','<Type>Compressed')]:
                (p/'DiskDescriptor.xml').write_text(text)
                with self.assertRaises(AssertionError):m.descriptor_guard(p,ident)

    def test_foreign_identity_or_pool_refused(self):
        for k,v in [('uuid',m.UUIDS[1]),('vg','existing'),('run','other'),('size',1),('major_minor','8:48;bad')]:
            c=self.config();c[k]=v
            with self.assertRaises(AssertionError):m.validate_config(c)


if __name__=='__main__':unittest.main()
