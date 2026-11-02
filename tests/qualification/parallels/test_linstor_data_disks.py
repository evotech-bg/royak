import importlib.util
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('linstor_data_disks',Path(__file__).with_name('linstor_data_disks.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class BlankDiskGuards(unittest.TestCase):
    def test_event_cannot_collide_with_command_receipts(self):
        names={m.event_name(1,phase) for phase in ['shutdown-intent','disk-create-intent','disk-created','disk-attached','identified-blank']}
        receipts={'n1-'+tag+suffix+'.json' for tag in ['shutdown','create-disk','attach','start'] for suffix in ['-intent','-launched','-finished']}
        self.assertTrue(names.isdisjoint(receipts))

    def disk(self,serial='old',path='/dev/sda',**changes):
        return dict(serial=serial,path=path,type='disk',size=m.SIZE,mountpoints=[None],model='disk',uuid=None,**changes)

    def test_only_exact_new_blank_disk(self):
        old=self.disk();new=self.disk('new','/dev/sdd')
        self.assertEqual(m.validate_new_disk([old],[old,new]),new)

    def test_existing_or_multiple_disks_refused(self):
        old=self.disk()
        for after in [[old],[old,self.disk('new','/dev/sdd'),self.disk('other','/dev/sde')]]:
            with self.assertRaises(AssertionError):m.validate_new_disk([old],after)

    def test_wrong_size_mount_or_descendant_refused(self):
        old=self.disk()
        for changes in [dict(size=1),dict(mountpoints=['/data']),dict(children=[{}]),dict(path='/dev/sda')]:
            new=self.disk('new','/dev/sdd');new.update(changes)
            with self.assertRaises(AssertionError):m.validate_new_disk([old],[old,new])

    def test_old_disk_identity_change_refused(self):
        old=self.disk();changed=dict(old,size=1)
        with self.assertRaises(AssertionError):m.validate_new_disk([old],[changed,self.disk('new','/dev/sdd')])


if __name__=='__main__':unittest.main()
