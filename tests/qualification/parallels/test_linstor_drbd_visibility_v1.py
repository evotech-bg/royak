import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import linstor_drbd_visibility_v1 as v


class VisibilityGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.file = self.root / 'global'
        self.file.write_bytes(b'global { usage-count yes; }\ncommon {}\n')
        self.file.chmod(0o600)

    def test_exact_optout_preserves_other_bytes(self):
        raw = self.file.read_bytes()
        with patch.object(v, 'ORIGINAL', v.digest(raw)):
            self.assertEqual(v.opted_out(raw), b'global { usage-count no; }\ncommon {}\n')

    def test_wrong_original_refused(self):
        with self.assertRaises(AssertionError):
            v.opted_out(self.file.read_bytes())

    def test_duplicate_token_refused(self):
        raw = b'usage-count yes; usage-count yes;'
        with patch.object(v, 'ORIGINAL', v.digest(raw)), self.assertRaises(AssertionError):
            v.opted_out(raw)

    def test_already_opted_out_is_not_reapplied(self):
        raw = b'usage-count no;'
        with patch.object(v, 'ORIGINAL', v.digest(raw)), self.assertRaises(AssertionError):
            v.opted_out(raw)

    def test_regular_current_owner(self):
        raw, identity = v.regular(self.file, os.getuid(), 0o600)
        self.assertEqual(raw, self.file.read_bytes())
        self.assertEqual(identity['inode'], self.file.stat().st_ino)

    def test_symlink_refused(self):
        link = self.root / 'link'
        link.symlink_to(self.file)
        with self.assertRaises(OSError):
            v.regular(link, os.getuid())

    def test_hardlink_refused(self):
        os.link(self.file, self.root / 'hard')
        with self.assertRaises(AssertionError):
            v.regular(self.file, os.getuid())

    def test_wrong_owner_refused(self):
        with self.assertRaises(AssertionError):
            v.regular(self.file, os.getuid() + 1)

    def test_group_write_refused(self):
        self.file.chmod(0o620)
        with self.assertRaises(AssertionError):
            v.regular(self.file, os.getuid())

    def test_mode_mismatch_refused(self):
        with self.assertRaises(AssertionError):
            v.regular(self.file, os.getuid(), 0o400)

    def test_changed_bytes_refused(self):
        _, identity = v.regular(self.file, os.getuid(), 0o600)
        self.file.write_bytes(b'changed')
        with self.assertRaises(AssertionError):
            v.same_file(self.file, identity)

    def test_replacement_inode_refused(self):
        raw, identity = v.regular(self.file, os.getuid(), 0o600)
        new = self.root / 'new'
        new.write_bytes(raw)
        new.chmod(0o600)
        os.replace(new, self.file)
        with self.assertRaises(AssertionError):
            v.same_file(self.file, identity)

    def test_directory_symlink_refused(self):
        link = self.root / 'dirlink'
        link.symlink_to(self.root)
        with self.assertRaises(AssertionError):
            v.directory(link, os.getuid())

    def test_directory_writable_by_group_refused(self):
        folder = self.root / 'dir'
        folder.mkdir(mode=0o720)
        folder.chmod(0o720)
        with self.assertRaises(AssertionError):
            v.directory(folder, os.getuid())

    def test_optout_requires_quiescence_before_any_write(self):
        archive = self.root / 'archive'
        with patch.object(v, 'quiescent', side_effect=AssertionError('busy')), self.assertRaises(AssertionError):
            v.apply_optout(archive)
        self.assertFalse(archive.exists())

    def test_include_removal_requires_quiescence(self):
        before = self.file.read_bytes()
        with patch.object(v, 'quiescent', side_effect=AssertionError('busy')), self.assertRaises(AssertionError):
            v.include_remove(self.root)
        self.assertEqual(before, self.file.read_bytes())

    def test_include_is_literal_and_exact(self):
        self.assertEqual(v.BODY.count(b'include "'), 1)
        self.assertIn(str(v.TARGET).encode(), v.BODY)
        self.assertNotIn(b'*', v.BODY)
        self.assertNotIn(b'..', v.BODY)

    def test_all_generated_preflight_sources_compile(self):
        path = Path(__file__).parents[1] / '.runs/rkq-storage-20261030/root-linstor-data-v1/run_data_v6.py'
        spec = importlib.util.spec_from_file_location('v6_preflight_compile_only', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for node in [1, 2, 3]:
            for after in [False, True]:
                compile(module.probe_source(dict(id=node), after), '<probe>', 'exec')

    def test_runtime_bounds_and_TLS_unchanged(self):
        path = Path(__file__).with_name('linstor_data_guest_v6.py')
        source = path.read_text()
        for text in ['began<600', 'timeout=30', 'deadline=time.monotonic()+120', '1400*1024**2',
                     "'-Xms64M -Xmx512M", "ssl_protocol=\"TLSv1.2\"", 'ssl.create_default_context']:
            self.assertIn(text, source)
        self.assertNotIn('CERT_NONE', source)
        self.assertNotIn('check_hostname=False', source)


if __name__ == '__main__':
    unittest.main()
