"""Offline contract fixtures: no network, real GPG, binary execution or CI calls."""
import bz2
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("restic_setup_under_test", Path(__file__).with_name("get_restic.py"))
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)


def executable(selected):
    data = bytearray(128)
    if selected.startswith("linux"):
        data[:7] = b"\x7fELF\x02\x01\x01"
        data[18:20] = (183 if selected.endswith("arm64") else 62).to_bytes(2, "little")
    else:
        data[:4] = b"\xcf\xfa\xed\xfe"
        data[4:8] = (0x0100000C if selected.endswith("arm64") else 0x01000007).to_bytes(4, "little")
    return bytes(data)


class ResticSetup(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="royak-restic-setup-unit-")
        self.root = Path(self.temp.name).resolve()
        self.runs = self.root / ".runs"
        self.runs.mkdir(mode=0o700)
        self.output = self.runs / "fresh tools"
        self.requests, self.gpg = [], []
        self.archives = {f"restic_{tool.VERSION}_{p}.bz2": bz2.compress(executable(p)) for p in tool.SUPPORTED_PLATFORMS}
        self.payloads = {tool.KEY: b"fixture public key\n", tool.BASE + "SHA256SUMS.asc": b"fixture detached signature\n"}
        self.refresh_sums()
        self.run_patch = mock.patch.object(tool, "RUNS", self.runs)
        self.net_patch = mock.patch.object(tool.urllib.request, "urlopen", side_effect=self.urlopen)
        self.gpg_patch = mock.patch.object(tool.subprocess, "run", side_effect=self.verify)
        for patch in (self.run_patch, self.net_patch, self.gpg_patch): patch.start()
        self.addCleanup(self.temp.cleanup)
        for patch in (self.run_patch, self.net_patch, self.gpg_patch): self.addCleanup(patch.stop)

    def refresh_sums(self):
        self.payloads[tool.BASE + "SHA256SUMS"] = "".join(hashlib.sha256(v).hexdigest() + "  " + k + "\n" for k, v in sorted(self.archives.items())).encode()

    def urlopen(self, url, timeout):
        self.requests.append((url, timeout))
        if url in self.payloads: return io.BytesIO(self.payloads[url])
        if url.startswith(tool.BASE) and url[len(tool.BASE):] in self.archives: return io.BytesIO(self.archives[url[len(tool.BASE):]])
        raise AssertionError("unexpected/off-contract network request: " + url)

    def verify(self, args, **kwargs):
        self.gpg.append((args, kwargs))
        self.assertEqual(args[0], "gpg")
        for flag in ["--no-options", "--homedir", "--batch", "--no-autostart"]: self.assertIn(flag, args)
        self.assertTrue(kwargs["check"])
        self.assertEqual(kwargs["timeout"], 60)
        stdout = "[GNUPG:] VALIDSIG " + tool.FINGERPRINT + " 2026-01-01 1 0 4 0 1 10 00 " + tool.FINGERPRINT + "\n"
        return types.SimpleNamespace(stdout=stdout if "--verify" in args else b"")

    def tree(self):
        return {str(p.relative_to(self.output)): (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                for p in self.output.rglob("*") if p.is_file()}

    def test_legacy_default_keeps_exact_two_arm_platforms_and_manifest_schema(self):
        report = tool.fetch(self.output)
        self.assertEqual([b["platform"] for b in report["builds"]], ["darwin_arm64", "linux_arm64"])
        self.assertEqual(set(report), {"version", "signature_fingerprint", "checksums_sha256", "builds"})
        self.assertEqual(json.loads((self.output / "restic-build.json").read_text()), report)
        self.assertEqual(len(self.gpg), 2)
        for build in report["builds"]:
            path = Path(build["path"])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertEqual(build["sha256"], hashlib.sha256(executable(build["platform"])).hexdigest())

    def test_each_explicit_platform_is_available_without_other_archives(self):
        for platform in tool.SUPPORTED_PLATFORMS:
            self.requests.clear()
            report = tool.fetch(self.runs / platform, [platform])
            self.assertEqual([b["platform"] for b in report["builds"]], [platform])
            archives = [url for url, _ in self.requests if url.endswith(".bz2")]
            self.assertEqual(archives, [tool.BASE + f"restic_{tool.VERSION}_{platform}.bz2"])

    def test_host_mapping_covers_both_architectures_for_linux_and_darwin(self):
        for system, machine, selected in [("Linux", "x86_64", "linux_amd64"), ("Linux", "aarch64", "linux_arm64"),
                ("Linux", "AMD64", "linux_amd64"), ("Darwin", "x86_64", "darwin_amd64"), ("Darwin", "arm64", "darwin_arm64")]:
            self.assertEqual(tool.host_platform(system, machine), selected)

    def test_unknown_host_and_platform_fail_closed(self):
        for system, machine in [("Windows", "AMD64"), ("Linux", "armv7l"), ("Darwin", ""), ("", "arm64")]:
            with self.assertRaises(ValueError): tool.host_platform(system, machine)
        for selected in [[], ["linux_386"], ["linux_arm64", "linux_arm64"]]:
            with self.assertRaises(ValueError): tool.fetch(self.output, selected)
        self.assertFalse(self.requests)

    def test_cli_host_sets_only_the_verified_actual_platform(self):
        env_file = self.root / "github-env"; env_file.write_text("EXISTING=value\n"); env_file.chmod(0o600)
        with mock.patch.object(tool.host, "system", return_value="Linux"), mock.patch.object(tool.host, "machine", return_value="x86_64"), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(tool.main(["--root", str(self.output), "--host", "--github-env", str(env_file)]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual([b["platform"] for b in report["builds"]], ["linux_amd64"])
        self.assertEqual(env_file.read_text(), "EXISTING=value\nROYAK_STAGE_RESTIC=" + report["builds"][0]["path"] + "\n")
        self.assertNotIn("PATH=", env_file.read_text())

    def test_cli_host_and_explicit_selection_are_mutually_exclusive(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            tool.main(["--root", str(self.output), "--host", "--platform", "linux_arm64"])
        self.assertFalse(self.requests)

    def test_env_export_requires_host_mode_not_an_arbitrary_foreign_selection(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            tool.main(["--root", str(self.output), "--platform", "linux_arm64", "--github-env", str(self.root / "env")])
        self.assertFalse(self.requests)

    def test_missing_or_bad_signature_never_publishes_executable_or_env(self):
        for status in ["", "[GNUPG:] VALIDSIG " + "0" * 40, "[GNUPG:] VALIDSIG "]:
            with mock.patch.object(tool.subprocess, "run", return_value=types.SimpleNamespace(stdout=status)):
                with self.assertRaises(ValueError): tool.fetch(self.output, ["linux_amd64"])
            self.assertFalse((self.output / "restic-build.json").exists())
            self.assertFalse(list(self.output.glob("restic-0.19.1-*")))
        self.assertFalse(any(url.endswith(".bz2") for url, _ in self.requests))

    def test_cli_signature_failure_does_not_export_an_environment_value(self):
        env = self.root / "env"; env.write_text("unchanged\n"); env.chmod(0o600)
        with mock.patch.object(tool.host, "system", return_value="Linux"), mock.patch.object(tool.host, "machine", return_value="x86_64"), \
                mock.patch.object(tool.subprocess, "run", return_value=types.SimpleNamespace(stdout="")):
            with self.assertRaises(ValueError): tool.main(["--host", "--root", str(self.output), "--github-env", str(env)])
        self.assertEqual(env.read_text(), "unchanged\n")

    def test_gpg_nonzero_exit_is_not_accepted_from_status_text(self):
        with mock.patch.object(tool.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["gpg"])):
            with self.assertRaises(subprocess.CalledProcessError): tool.fetch(self.output)
        self.assertFalse((self.output / "restic-build.json").exists())

    def test_missing_gpg_is_an_error_not_a_skip_or_success(self):
        with mock.patch.object(tool.subprocess, "run", side_effect=FileNotFoundError("fixture gpg is absent")):
            with self.assertRaises(FileNotFoundError): tool.fetch(self.output)
        self.assertFalse((self.output / "restic-build.json").exists())
        self.assertFalse(list(self.output.glob("restic-0.19.1-*")))

    def test_archive_checksum_failure_cannot_publish_a_tool(self):
        self.archives[f"restic_{tool.VERSION}_linux_amd64.bz2"] = bz2.compress(b"not the signed payload")
        with self.assertRaisesRegex(ValueError, "checksum"): tool.fetch(self.output, ["linux_amd64"])
        self.assertFalse((self.output / "restic-build.json").exists())
        self.assertFalse(list(self.output.glob("restic-0.19.1-*")))

    def test_wrong_architecture_even_with_valid_signed_checksum_is_rejected(self):
        self.archives[f"restic_{tool.VERSION}_linux_amd64.bz2"] = bz2.compress(executable("linux_arm64")); self.refresh_sums()
        with self.assertRaisesRegex(ValueError, "architecture"): tool.fetch(self.output, ["linux_amd64"])
        self.assertFalse((self.output / "restic-build.json").exists())

    def test_existing_legacy_evidence_revalidates_without_download_or_modification(self):
        first = tool.fetch(self.output); before = self.tree(); self.requests.clear()
        second = tool.fetch(self.output)
        self.assertEqual(second, first); self.assertEqual(self.tree(), before); self.assertFalse(self.requests)

    def test_existing_selection_cannot_be_extended_or_replaced(self):
        tool.fetch(self.output); before = self.tree(); self.requests.clear(); self.gpg.clear()
        with self.assertRaisesRegex(ValueError, "different tools"): tool.fetch(self.output, ["linux_amd64"])
        self.assertEqual(self.tree(), before); self.assertFalse(self.requests); self.assertFalse(self.gpg)

    def test_existing_manifest_symlink_or_corruption_is_not_overwritten(self):
        self.output.mkdir(mode=0o700)
        target = self.root / "other"; target.write_text("forensics"); target.chmod(0o600)
        (self.output / "restic-build.json").symlink_to(target)
        with self.assertRaises(ValueError): tool.fetch(self.output)
        self.assertEqual(target.read_text(), "forensics"); self.assertFalse(self.requests)

    def test_malformed_existing_manifest_is_rejected_before_any_fetch(self):
        for index, content in enumerate(["null", "[]", "{", '{"builds":[1]}']):
            output = self.runs / ("malformed-" + str(index)); output.mkdir(mode=0o700)
            report = output / "restic-build.json"; report.write_text(content); report.chmod(0o600)
            with self.assertRaises(ValueError): tool.fetch(output)
            self.assertEqual(report.read_text(), content)
        self.assertFalse(self.requests); self.assertFalse(self.gpg)

    def test_existing_executable_tamper_is_rejected_without_repair(self):
        report = tool.fetch(self.output); target = Path(report["builds"][0]["path"]); target.write_bytes(b"changed forensics")
        before = self.tree(); self.requests.clear()
        with self.assertRaises(ValueError): tool.fetch(self.output)
        self.assertEqual(self.tree(), before); self.assertFalse(self.requests)

    def test_missing_file_in_completed_evidence_is_not_refetched(self):
        tool.fetch(self.output); (self.output / "key.asc").unlink(); self.requests.clear()
        with self.assertRaisesRegex(ValueError, "incomplete"): tool.fetch(self.output)
        self.assertFalse(self.requests)

    def test_symlink_and_hardlink_metadata_are_refused(self):
        for kind in ["symlink", "hardlink"]:
            output = self.runs / kind; output.mkdir(mode=0o700)
            other = self.root / (kind + "-outside"); other.write_bytes(b"other data"); other.chmod(0o600)
            if kind == "symlink": (output / "key.asc").symlink_to(other)
            else: os.link(other, output / "key.asc")
            with self.assertRaises((ValueError, OSError)): tool.fetch(output)
            self.assertEqual(other.read_bytes(), b"other data")

    def test_root_outside_runs_and_runs_itself_are_refused(self):
        for root in [self.root / "outside", self.runs]:
            with self.assertRaises(ValueError): tool.fetch(root)
        self.assertFalse(self.requests)

    def test_output_directory_symlink_and_nonprivate_mode_are_refused(self):
        target = self.runs / "target"; target.mkdir(mode=0o700); self.output.symlink_to(target)
        with self.assertRaises(ValueError): tool.fetch(self.output)
        self.output.unlink(); self.output.mkdir(mode=0o755); self.output.chmod(0o755)
        with self.assertRaises(ValueError): tool.fetch(self.output)

    def test_env_file_symlink_or_changed_binary_cannot_receive_output(self):
        report = tool.fetch(self.output, ["darwin_arm64"])
        env = self.root / "env"; env.write_text("unchanged\n"); env.chmod(0o600)
        link = self.root / "env-link"; link.symlink_to(env)
        with mock.patch.object(tool.host, "system", return_value="Darwin"), mock.patch.object(tool.host, "machine", return_value="arm64"):
            with self.assertRaises(OSError): tool.export_github_env(report, link)
            Path(report["builds"][0]["path"]).write_bytes(b"changed")
            with self.assertRaises(ValueError): tool.export_github_env(report, env)
        self.assertEqual(env.read_text(), "unchanged\n")

    def test_limits_duplicate_checksums_and_archive_trailing_data_fail(self):
        with mock.patch.object(tool, "MAX_ARCHIVE", 8):
            with self.assertRaisesRegex(ValueError, "size"): tool.fetch(self.output, ["linux_amd64"])
        with self.assertRaises(ValueError): tool.parse_checksums(("0" * 64 + "  same\n") .encode() * 2)
        with self.assertRaises(ValueError): tool.parse_checksums(b"bad checksum\n")
        with self.assertRaises(ValueError): tool.decompress(bz2.compress(b"one") + bz2.compress(b"two"))
        with mock.patch.object(tool, "MAX_EXECUTABLE", 8):
            with self.assertRaises(ValueError): tool.decompress(bz2.compress(b"x" * 9))


if __name__ == "__main__":
    unittest.main(verbosity=2)
