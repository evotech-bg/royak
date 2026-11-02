import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import verify_release as release


def elf(machine=183):
    return b"\x7fELF\x02\x01\x01" + bytes(11) + machine.to_bytes(2, "little") + bytes(12)


class ReleaseVerification(unittest.TestCase):
    def run_verification(self, data=None, results=None, limit=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "royak"
            if data is not None:
                binary.write_bytes(data)
            report_path = root / "report.json"
            results = results if results is not None else [
                subprocess.CompletedProcess([], 0, "OrinBrain", ""),
                subprocess.CompletedProcess([], 0, "SCHEDULE", "")]
            with patch.object(release.subprocess, "run", side_effect=results) as run, \
                    patch.object(release, "MAX_BYTES", limit or release.MAX_BYTES):
                report = release.verify(binary, report_path, system="Linux", machine="aarch64")
            self.assertEqual(json.loads(report_path.read_text()), report)
            # Test temporary working directories were cleaned, not the checkout.
            for call in run.call_args_list:
                self.assertFalse(Path(call.kwargs["cwd"]).exists())
                self.assertNotEqual(call.kwargs["cwd"], str(root))
                self.assertEqual(call.kwargs["timeout"], 90)
            return report, run.call_count

    def test_success_records_exact_hash_and_both_exit_codes(self):
        report, count = self.run_verification(elf())
        self.assertTrue(report["passed"])
        self.assertFalse(report["production_qualified"])
        self.assertEqual(count, 2)
        self.assertEqual(len(report["sha256"]), 64)

    def test_marker_cannot_hide_failed_exit(self):
        report, count = self.run_verification(elf(), [subprocess.CompletedProcess([], 7, "OrinBrain", "crash")])
        self.assertFalse(report["passed"])
        self.assertIn("exit code 7", report["failure"])
        self.assertEqual(count, 1)

    def test_demo_failed_exit_is_not_pass(self):
        report, _ = self.run_verification(elf(), [
            subprocess.CompletedProcess([], 0, "OrinBrain", ""),
            subprocess.CompletedProcess([], 1, "SCHEDULE", "crash")])
        self.assertFalse(report["passed"])

    def test_missing_marker_fails(self):
        report, _ = self.run_verification(elf(), [subprocess.CompletedProcess([], 0, "unrelated", "")])
        self.assertIn("no expected smoke marker", report["failure"])

    def test_timeout_writes_failure_report(self):
        report, _ = self.run_verification(elf(), [subprocess.TimeoutExpired(["royak"], 90)])
        self.assertFalse(report["passed"])
        self.assertIn("TimeoutExpired", report["failure"])

    def test_missing_binary_does_not_execute(self):
        report, count = self.run_verification()
        self.assertFalse(report["passed"])
        self.assertEqual(count, 0)

    def test_wrong_arch_does_not_execute(self):
        report, count = self.run_verification(elf(62))
        self.assertIn("architecture", report["failure"])
        self.assertEqual(count, 0)

    def test_wrong_format_does_not_execute(self):
        report, count = self.run_verification(b"not a release")
        self.assertFalse(report["passed"])
        self.assertEqual(count, 0)

    def test_oversized_binary_does_not_execute(self):
        report, count = self.run_verification(elf(), limit=16)
        self.assertIn("10 MiB", report["failure"])
        self.assertEqual(count, 0)

    def test_macho_arm64(self):
        self.assertEqual(release.binary_identity(b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01", "Darwin", "arm64"), "ARM64")

    def test_macho_wrong_arch(self):
        with self.assertRaisesRegex(ValueError, "architecture"):
            release.binary_identity(b"\xcf\xfa\xed\xfe\x0c\x00\x00\x01", "Darwin", "x86_64")

    def test_real_child_marker_followed_by_failure_is_rejected(self):
        real_run = subprocess.run
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "royak"
            binary.write_bytes(elf())
            def child(args, **kwargs):
                return real_run([sys.executable, "-B", "-c",
                                 "print('OrinBrain'); raise SystemExit(9)"], **kwargs)
            with patch.object(release.subprocess, "run", side_effect=child):
                report = release.verify(binary, root / "report.json",
                                        system="Linux", machine="aarch64")
            self.assertFalse(report["passed"])
            self.assertEqual(report["checks"][0]["exit_code"], 9)
            self.assertIn("OrinBrain", report["checks"][0]["stdout"])

    def test_binary_mutation_during_smoke_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "royak"
            binary.write_bytes(elf())
            def child(args, **kwargs):
                binary.write_bytes(elf() + b"changed")
                return subprocess.CompletedProcess(args, 0, "OrinBrain SCHEDULE", "")
            with patch.object(release.subprocess, "run", side_effect=child):
                report = release.verify(binary, root / "report.json",
                                        system="Linux", machine="aarch64")
            self.assertFalse(report["passed"])
            self.assertIn("changed during verification", report["failure"])


if __name__ == "__main__":
    unittest.main()
