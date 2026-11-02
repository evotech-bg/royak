import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import subprocess

from host_capacity import GIB, MAX_BYTES, allocation_capacity, assess, measure


class CapacityTests(unittest.TestCase):
    def values(self, **changes):
        return dict(immediate=34 * GIB, important=223 * GIB,
                    opportunistic=206 * GIB, total=2000 * GIB, **changes)

    def test_foundation_totals_are_not_added_to_raw(self):
        value, basis = allocation_capacity(34 * GIB, 2000 * GIB, self.values())
        self.assertEqual(value, 206 * GIB)
        self.assertEqual(basis, "macOS-reclaimable-aware-estimate")

    def test_fallback_for_missing_malformed_or_inconsistent_foundation(self):
        for key in self.values():
            for bad in (None, True, -1, 1.5, "206", MAX_BYTES + 1):
                values = self.values()
                values[key] = bad
                self.assertEqual(allocation_capacity(34 * GIB, 2000 * GIB, values),
                                 (34 * GIB, "raw-free-fallback"))
        for values in (None, {}, [], dict(self.values(), total=1999 * GIB),
                       dict(self.values(), important=33 * GIB),
                       dict(self.values(), opportunistic=3000 * GIB)):
            self.assertEqual(allocation_capacity(34 * GIB, 2000 * GIB, values)[0], 34 * GIB)

    def test_equality_boundary_and_no_space_reservation_claim(self):
        report = assess([dict(allocation_available_bytes=40 * GIB)], 8 * GIB)
        self.assertTrue(report["admitted"])
        self.assertTrue(report["capacity_is_estimate_not_reservation"])
        self.assertFalse(report["raw_free_floor_verified"])
        self.assertFalse(assess([dict(allocation_available_bytes=40 * GIB - 1)], 8 * GIB)["admitted"])

    def test_shared_pool_or_different_volumes_are_not_summed(self):
        self.assertFalse(assess([dict(allocation_available_bytes=35 * GIB)] * 3, 8 * GIB)["admitted"])
        self.assertFalse(assess([dict(allocation_available_bytes=200 * GIB),
                                 dict(allocation_available_bytes=35 * GIB)], 8 * GIB)["admitted"])

    def test_bytes_are_binary_gib_not_decimal_gb(self):
        self.assertFalse(assess([dict(allocation_available_bytes=40_000_000_000)], 8 * GIB)["admitted"])

    def test_invalid_raw_and_planned_values_refuse(self):
        for raw, total in ((True, 100), (-1, 100), (101, 100), (0, None)):
            with self.assertRaises(ValueError):
                allocation_capacity(raw, total)
        for planned in (-1, True, MAX_BYTES + 1):
            with self.assertRaises(ValueError):
                assess([dict(allocation_available_bytes=100 * GIB)], planned)
        with self.assertRaises(ValueError):
            assess([], 0)
        for bad in (None, True, -1, MAX_BYTES + 1):
            with self.assertRaises(ValueError):
                assess([dict(allocation_available_bytes=40 * GIB),
                        dict(allocation_available_bytes=bad)], 0)

    def fake_location(self, second_device=11):
        location = Mock()
        location.resolve.return_value = location
        location.stat.side_effect = [SimpleNamespace(st_dev=11),
                                     SimpleNamespace(st_dev=second_device)]
        return location

    def test_non_macos_uses_raw_and_never_launches_foundation(self):
        with patch("host_capacity.Path", return_value=self.fake_location()), \
                patch("host_capacity.shutil.disk_usage", return_value=SimpleNamespace(free=40 * GIB, total=100 * GIB)), \
                patch("host_capacity.sys.platform", "linux"), \
                patch("host_capacity.subprocess.run") as run:
            report = measure("/exact/write/location")
        run.assert_not_called()
        self.assertEqual(report["allocation_available_bytes"], 40 * GIB)
        self.assertEqual(report["basis"], "raw-free-fallback")

    def test_foundation_timeout_or_malformed_output_falls_back_to_raw(self):
        for result in (subprocess.TimeoutExpired("osascript", 15),
                       SimpleNamespace(stdout="not-json")):
            with patch("host_capacity.Path", return_value=self.fake_location()), \
                    patch("host_capacity.shutil.disk_usage", return_value=SimpleNamespace(free=40 * GIB, total=100 * GIB)), \
                    patch("host_capacity.sys.platform", "darwin"), \
                    patch("host_capacity.subprocess.run") as run:
                if isinstance(result, Exception):
                    run.side_effect = result
                else:
                    run.return_value = result
                report = measure("/exact/write/location")
            self.assertEqual(report["allocation_available_bytes"], 40 * GIB)
            self.assertIsNotNone(report["observation_error"])

    def test_filesystem_change_during_observation_refuses(self):
        with patch("host_capacity.Path", return_value=self.fake_location(second_device=12)), \
                patch("host_capacity.shutil.disk_usage", return_value=SimpleNamespace(free=40 * GIB, total=100 * GIB)), \
                patch("host_capacity.sys.platform", "linux"):
            with self.assertRaisesRegex(RuntimeError, "filesystem changed"):
                measure("/exact/write/location")


if __name__ == "__main__":
    unittest.main()
