"""Local exact-size/hash regressions; not native DRBD or replica acceptance."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import linstor_data_capacity as c


class ExactCapacity(unittest.TestCase):
    def actual_observations(self):
        return dict(requested_bytes=536870912, extent_bytes=4194304,
                    allocated_bytes=541065216, drbd_size_kib=528232,
                    sysfs_sectors=1056464, profile=dict(c.PROFILE))

    def test_recorded_native_capacity_is_exactly_explained(self):
        result = c.validate_capacity(**self.actual_observations())
        self.assertEqual(result['minimum_gross_bytes'], 537026560)
        self.assertEqual(result['metadata_bytes'], 155648)
        self.assertEqual(result['exposed_bytes'], 540909568)
        self.assertGreater(result['exposed_bytes'], result['requested_bytes'])

    def test_exact_requested_size_is_not_assumed_for_exposure(self):
        value = self.actual_observations()
        value['drbd_size_kib'] = value['requested_bytes']//1024
        with self.assertRaisesRegex(ValueError, 'DRBD size'):
            c.validate_capacity(**value)

    def test_one_extra_extent_is_not_a_permitted_margin(self):
        value = self.actual_observations()
        value['allocated_bytes'] += value['extent_bytes']
        with self.assertRaisesRegex(ValueError, 'LVM allocation'):
            c.validate_capacity(**value)

    def test_underallocation_is_rejected(self):
        value = self.actual_observations()
        value['allocated_bytes'] -= value['extent_bytes']
        with self.assertRaisesRegex(ValueError, 'LVM allocation'):
            c.validate_capacity(**value)

    def test_independent_sysfs_size_must_match(self):
        value = self.actual_observations()
        value['sysfs_sectors'] -= 8
        with self.assertRaisesRegex(ValueError, 'sysfs size'):
            c.validate_capacity(**value)

    def test_unready_or_missing_measurements_are_not_zero_capacity(self):
        for name in ['extent_bytes', 'allocated_bytes', 'drbd_size_kib', 'sysfs_sectors']:
            for bad in [0, -1, None, True, 1.0, '528232']:
                with self.subTest(name=name, bad=bad):
                    value = self.actual_observations()
                    value[name] = bad
                    with self.assertRaises(ValueError):
                        c.validate_capacity(**value)

    def test_metadata_profile_cannot_be_silently_changed(self):
        for key in c.PROFILE:
            value = self.actual_observations()
            value['profile'][key] += 1
            with self.assertRaisesRegex(ValueError, 'profile'):
                c.validate_capacity(**value)
        value = self.actual_observations()
        value['profile'] = {}
        with self.assertRaises(ValueError):
            c.validate_capacity(**value)

    def test_boolean_or_float_metadata_parameters_are_not_integers(self):
        for key, bad in [('al_stripes', True), ('peer_slots', 7.0)]:
            value = self.actual_observations()
            value['profile'][key] = bad
            with self.assertRaises(ValueError):
                c.validate_capacity(**value)

    def test_small_request_respects_metadata_minimum_gross_size(self):
        value = c.expected_capacity(4096, 4096)
        self.assertEqual(value['minimum_gross_bytes'], 68*1024)
        self.assertEqual(value['allocated_bytes'], 68*1024)
        self.assertEqual(value['exposed_bytes'], 28*1024)

    def test_alignment_and_lab_limits(self):
        for requested, extent in [(0,4194304), (True,4194304), (4097,4194304),
                                  (3*1024**3,4194304), (536870912,4097),
                                  (536870912,128*1024**2)]:
            with self.subTest(requested=requested, extent=extent):
                with self.assertRaises(ValueError):
                    c.expected_capacity(requested, extent)

    def test_all_supported_requests_cover_minimum_without_arbitrary_slack(self):
        for extent in [4096, 65536, 4194304]:
            for requested in [4096, 16384, 524288, 536870912, 1073741824]:
                with self.subTest(extent=extent, requested=requested):
                    v = c.expected_capacity(requested, extent)
                    self.assertGreaterEqual(v['exposed_bytes'], requested)
                    self.assertEqual(v['allocated_bytes'] % extent, 0)
                    self.assertLess(v['allocated_bytes']-v['minimum_gross_bytes'], extent)
                    self.assertEqual(v['exposed_bytes']+v['metadata_bytes'], v['allocated_bytes'])


class WholeExposedHash(unittest.TestCase):
    def test_tail_beyond_requested_prefix_changes_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'only-local-generated-data'
            prefix = b'p'*16384
            path.write_bytes(prefix+b'a'*4096)
            first = c.digest_exact_device(path, 20480)
            path.write_bytes(prefix+b'b'*4096)
            second = c.digest_exact_device(path, 20480)
            self.assertNotEqual(first, second)
            self.assertEqual(first['bytes'], 20480)
            self.assertEqual(first['sha256'], hashlib.sha256(prefix+b'a'*4096).hexdigest())

    def test_wrong_short_or_extra_file_size_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'only-local-generated-data'
            path.write_bytes(b'x'*4096)
            for size in [1, 4095, 4097, 8192]:
                with self.assertRaises(ValueError):
                    c.digest_exact_device(path, size)

    def test_symlink_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)/'data'
            target.write_bytes(b'x'*4096)
            link = Path(directory)/'link'
            link.symlink_to(target)
            with self.assertRaises(OSError):
                c.digest_exact_device(link, 4096)

    def test_short_read_is_a_failure_not_a_partial_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'data'
            path.write_bytes(b'x'*4096)
            with patch.object(c.os, 'read', return_value=b''):
                with self.assertRaisesRegex(ValueError, 'short read'):
                    c.digest_exact_device(path, 4096)

    def test_extra_kernel_tail_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'data'
            path.write_bytes(b'x'*4096)
            with patch.object(c.os, 'read', side_effect=[b'x'*4096, b'y']):
                with self.assertRaisesRegex(ValueError, 'unaccounted tail'):
                    c.digest_exact_device(path, 4096)

    def test_file_descriptor_closes_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'data'
            path.write_bytes(b'x'*4096)
            original = os.open
            observed = []
            def capture(*args, **kwargs):
                fd = original(*args, **kwargs)
                observed.append(fd)
                return fd
            with patch.object(c.os, 'open', side_effect=capture):
                with self.assertRaises(ValueError):
                    c.digest_exact_device(path, 8192)
            self.assertEqual(len(observed), 1)
            with self.assertRaises(OSError):
                os.fstat(observed[0])


if __name__ == '__main__':
    unittest.main()
