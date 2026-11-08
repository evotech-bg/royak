import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import royak_thread_census as subject

BOOT = "12345678-1234-1234-1234-123456789abc"
OTHER_BOOT = "abcdef01-1234-1234-1234-123456789abc"


def stat_data(tid=21, start="100", user=7, kernel=19, comm="royak ) (main)", state="S"):
    fields = [state, "1", "9", "9", *(["0"] * 7), str(user), str(kernel), *(["0"] * 6), start]
    return f"{tid} ({comm}) " + " ".join(fields)


def status_data(tid=21, pid=21, threads=2, voluntary=7, involuntary=19):
    return (f"Name:\tworker\nState:\tS (sleeping)\nPid:\t{tid}\nTgid:\t{pid}\nThreads:\t{threads}\n"
            f"voluntary_ctxt_switches:\t{voluntary}\nnonvoluntary_ctxt_switches:\t{involuntary}\n")


class RoyakThreadCensusTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="owned-thread-census-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.proc = self.root / "proc"
        self.boot = self.proc / "sys/kernel/random/boot_id"
        self.boot.parent.mkdir(parents=True)
        self.boot.write_text(BOOT + "\n")
        self.locator = self.root / "royak.pid"
        self.locator.write_text("21\n")
        self.image = self.root / "royak"
        self.image.write_bytes(b"owned fixture, never executed")
        self.process = self.proc / "21"
        (self.process / "task").mkdir(parents=True)
        (self.process / "stat").write_text(stat_data())
        (self.process / "exe").symlink_to(self.image)
        self.task(21, "100")
        self.task(22, "200")

    def task(self, tid, start):
        path = self.process / "task" / str(tid)
        path.mkdir()
        (path / "stat").write_text(stat_data(tid, start, user=100, kernel=200))
        (path / "status").write_text(status_data(tid))
        (path / "wchan").write_text("futex_wait_queue\n")
        return path

    def collect(self, clock_ticks=100):
        with mock.patch.object(subject, "_clock_ticks", return_value=clock_ticks):
            return subject._collect_paths(self.locator, self.proc, self.image,
                expected_pid=21, expected_start_ticks="100", expected_boot_id=BOOT)

    def row(self, value, tid=22):
        return next(row for row in value["threads"] if row["tid"] == tid)

    def errors(self, value):
        return [error["error"] for row in value["threads"] for error in row["errors"] + row["status_errors"]]

    def test_complete_nonatomic_sample_keeps_exact_cpu_status_and_identity_endpoints(self):
        value = self.collect()
        self.assertEqual(value["observation_status"], "OBSERVED_NONATOMIC")
        self.assertTrue(value["coverage"]["complete"])
        self.assertEqual(value["coverage"]["total_threads"], 2)
        self.assertEqual(value["leader_before"]["boot_id"], value["leader_after"]["boot_id"])
        self.assertEqual(value["leader_before"]["stat"]["start_ticks"], "100")
        row = self.row(value)
        self.assertEqual((row["utime_ticks"], row["stime_ticks"], row["cpu_ticks"]), (100, 200, 300))
        self.assertEqual(row["status_fields"]["voluntary_ctxt_switches"], 7)
        self.assertEqual(row["status_fields"]["nonvoluntary_ctxt_switches"], 19)
        self.assertEqual(value["leader_before"]["stat"]["cpu_ticks"], 26)  # not a task sum
        self.assertEqual(value["clock_ticks"], 100)
        self.assertFalse(value["atomic_continuous_coverage_proven"])
        self.assertFalse(value["owned_service_authority"])
        self.assertFalse(value["idle_retirement_or_stable_growth_or_leak_proven"])

    def test_public_entry_forwards_only_fixed_original_locator_proc_and_executable(self):
        sentinel = object()
        with mock.patch.object(subject, "_collect_paths", return_value=sentinel) as called:
            self.assertIs(subject.collect_royak_threads(expected_pid=21, expected_start_ticks="100", expected_boot_id=BOOT), sentinel)
        called.assert_called_once_with(Path("/lab/royak.pid"), Path("/proc"), Path("/opt/royak"),
                                      expected_pid=21, expected_start_ticks="100", expected_boot_id=BOOT)

    def test_invalid_expected_incarnation_refuses_before_any_metadata_read(self):
        values = [(True, "100", BOOT), (21, "-1", BOOT), (21, "１００", BOOT), (21, "0100", BOOT), (21, "100", "fixture-not-a-boot")]
        for pid, start, boot in values:
            with self.subTest(pid=pid, start=start, boot=boot), mock.patch.object(subject, "_leader") as read:
                with self.assertRaises(ValueError):
                    subject._collect_paths(self.locator, self.proc, self.image, expected_pid=pid,
                                           expected_start_ticks=start, expected_boot_id=boot)
                read.assert_not_called()

    def test_wrong_initial_pid_start_or_boot_never_adopts_another_process(self):
        for field in ("pid", "start", "boot"):
            with self.subTest(field=field):
                self.locator.write_text("99\n" if field == "pid" else "21\n")
                self.boot.write_text((OTHER_BOOT if field == "boot" else BOOT) + "\n")
                (self.process / "stat").write_text(stat_data(start="101" if field == "start" else "100"))
                with mock.patch.object(subject, "_scan_tasks") as scan:
                    value = self.collect()
                scan.assert_not_called()
                self.assertEqual(value["observation_status"], "UNKNOWN_IDENTITY")
                self.assertEqual(value["threads"], [])
                self.assertIsNone(value["coverage"]["total_threads"])

    def test_missing_locator_or_boot_is_unavailable_not_zero(self):
        for path in (self.locator, self.boot):
            original = path.read_bytes()
            path.unlink()
            with self.subTest(path=path.name):
                value = self.collect()
                self.assertEqual(value["observation_status"], "UNAVAILABLE")
                self.assertIsNone(value["coverage"]["total_threads"])
                self.assertIsNone(value["task_census_before"])
            path.write_bytes(original)

    def test_missing_or_wrong_executable_refuses_before_tasks_without_path_disclosure(self):
        target = self.process / "exe"
        target.unlink()
        missing = self.collect()
        self.assertEqual(missing["observation_status"], "UNAVAILABLE")
        other = self.root / "private-sensitive-binary-name"
        other.write_bytes(b"other fixture")
        target.symlink_to(other)
        value = self.collect()
        self.assertEqual(value["observation_status"], "UNKNOWN_IDENTITY")
        self.assertNotIn(other.name, json.dumps(value))
        self.assertIsNone(value["task_census_before"])

    def test_observed_after_leader_start_change_retains_rows_as_unknown(self):
        original = subject._bounded_text
        count = 0
        def read(path, maximum):
            nonlocal count
            if path == self.process / "stat":
                count += 1
                if count == 2:
                    return stat_data(start="101", user=13, kernel=23)
            return original(path, maximum)
        with mock.patch.object(subject, "_bounded_text", side_effect=read):
            value = self.collect()
        self.assertEqual(value["observation_status"], "UNKNOWN_IDENTITY")
        self.assertEqual(len(value["threads"]), 2)
        self.assertEqual(value["leader_before"]["stat"]["cpu_ticks"], 26)
        self.assertEqual(value["leader_after"]["stat"]["cpu_ticks"], 36)
        self.assertIsNone(value["coverage"]["total_threads"])

    def test_leader_task_start_conflict_is_unknown_even_when_outer_endpoints_match(self):
        (self.process / "task/21/stat").write_text(stat_data(21, "101"))
        value = self.collect()
        self.assertEqual(value["leader_before"]["stat"]["start_ticks"], "100")
        self.assertEqual(value["leader_after"]["stat"]["start_ticks"], "100")
        self.assertIn("LeaderTaskIncarnationMismatch", value["errors"])
        self.assertEqual(value["observation_status"], "UNKNOWN_IDENTITY")
        self.assertIsNone(value["coverage"]["total_threads"])

    def test_observed_after_boot_or_locator_change_is_unknown_not_an_adoption(self):
        original = subject._bounded_text
        for changed, replacement in ((self.boot, OTHER_BOOT), (self.locator, "99")):
            count = 0
            def read(path, maximum):
                nonlocal count
                if path == changed:
                    count += 1
                    if count == 2:
                        return replacement + "\n"
                return original(path, maximum)
            with self.subTest(metadata=changed.name), mock.patch.object(subject, "_bounded_text", side_effect=read):
                value = self.collect()
            self.assertEqual(value["observation_status"], "UNKNOWN_IDENTITY")
            self.assertEqual(len(value["threads"]), 2)
            self.assertIsNone(value["coverage"]["total_threads"])

    def test_same_path_executable_inode_replacement_is_observed_unknown(self):
        original = subject._executable
        calls = 0
        def observe(process, expected):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.image.rename(self.root / "old-owned-image")
                self.image.write_bytes(b"new owned inode")
            return original(process, expected)
        with mock.patch.object(subject, "_executable", side_effect=observe):
            value = self.collect()
        self.assertEqual(value["observation_status"], "UNKNOWN_IDENTITY")
        self.assertIn("ExecutableIdentityChanged", value["errors"])

    def test_comm_closing_parentheses_and_zero_wait_channel_are_actual_metadata(self):
        (self.process / "task/22/stat").write_text(stat_data(22, "200", comm="pool ) (worker)"))
        (self.process / "task/22/wchan").write_text("0\n")
        value = self.collect()
        self.assertEqual(self.row(value)["comm"], "pool ) (worker)")
        self.assertEqual(self.row(value)["wait_channel"], "0")
        self.assertFalse(value["idle_retirement_or_stable_growth_or_leak_proven"])

    def test_tid_reuse_keeps_first_actual_cpu_and_both_stats_but_is_partial(self):
        original = subject._bounded_text
        calls = 0
        def read(path, maximum):
            nonlocal calls
            if path == self.process / "task/22/stat":
                calls += 1
                if calls == 2:
                    return stat_data(22, "201", user=13, kernel=23)
            return original(path, maximum)
        with mock.patch.object(subject, "_bounded_text", side_effect=read):
            value = self.collect()
        row = self.row(value)
        self.assertEqual((row["start_ticks"], row["utime_ticks"], row["stime_ticks"]), ("200", 100, 200))
        self.assertEqual(row["stat_after"]["start_ticks"], "201")
        self.assertIn("ThreadIncarnationChanged", self.errors(value))
        self.assertEqual(value["churn"]["incarnation_changed_tids"], [22])
        self.assertEqual(value["observation_status"], "PARTIAL")

    def test_cpu_regression_is_not_clamped_or_mixed_with_first_stat(self):
        original = subject._bounded_text
        calls = 0
        def read(path, maximum):
            nonlocal calls
            if path == self.process / "task/22/stat":
                calls += 1
                if calls == 2:
                    return stat_data(22, "200", user=99, kernel=200)
            return original(path, maximum)
        with mock.patch.object(subject, "_bounded_text", side_effect=read):
            value = self.collect()
        self.assertEqual(self.row(value)["utime_ticks"], 100)
        self.assertIn("CpuCounterRegressed", self.errors(value))
        self.assertFalse(value["coverage"]["complete"])

    def test_missing_wait_channel_is_not_task_exit_and_other_fields_survive(self):
        (self.process / "task/22/wchan").unlink()
        value = self.collect()
        row = self.row(value)
        self.assertIsNone(row["wait_channel"])
        self.assertEqual(row["wait_channel_error"], "FileNotFoundError")
        self.assertEqual(row["missing_stat_metadata"], [])
        self.assertTrue(row["stat_identity_consistent"])
        self.assertEqual(row["status_fields"]["voluntary_ctxt_switches"], 7)
        self.assertNotIn("exited_during_sample", value)
        self.assertEqual(value["observation_status"], "PARTIAL")

    def test_missing_stat_retains_directory_tid_and_null_fields_not_zero(self):
        (self.process / "task/22/stat").unlink()
        value = self.collect()
        row = self.row(value)
        self.assertEqual(row["tid"], 22)
        self.assertIsNone(row["cpu_ticks"])
        self.assertIsNone(row["stat_before"])
        self.assertEqual(row["missing_stat_metadata"], ["stat_before", "stat_after"])
        self.assertEqual(value["coverage"]["recorded_rows"], 2)
        self.assertEqual(value["coverage"]["valid_first_stat_rows"], 1)
        self.assertIsNone(value["coverage"]["total_threads"])

    def test_stat_missing_only_after_metadata_keeps_first_incarnation_without_exit_claim(self):
        original = subject._bounded_text
        calls = 0
        def read(path, maximum):
            nonlocal calls
            if path == self.process / "task/22/stat":
                calls += 1
                if calls == 2:
                    raise FileNotFoundError("owned fixture metadata vanished")
            return original(path, maximum)
        with mock.patch.object(subject, "_bounded_text", side_effect=read):
            value = self.collect()
        row = self.row(value)
        self.assertEqual(row["start_ticks"], "200")
        self.assertEqual(row["cpu_ticks"], 300)
        self.assertIsNone(row["stat_after"])
        self.assertEqual(row["missing_stat_metadata"], ["stat_after"])
        self.assertEqual(value["observation_status"], "PARTIAL")
        self.assertNotIn("exited_during_sample", value)

    def test_unavailable_clock_frequency_is_not_zero_or_complete(self):
        for ticks in (None, 0, True, 2**64):
            with self.subTest(ticks=ticks):
                value = self.collect(clock_ticks=ticks)
                self.assertIsNone(value["clock_ticks"])
                self.assertIn("ClockTicks:ValueError", value["errors"])
                self.assertFalse(value["coverage"]["complete"])
                self.assertIsNone(value["coverage"]["total_threads"])

    def test_status_missing_field_preserves_available_context_and_is_partial(self):
        path = self.process / "task/22/status"
        path.write_text(status_data(22).replace("voluntary_ctxt_switches:\t7\n", ""))
        value = self.collect()
        row = self.row(value)
        self.assertIsNone(row["status_fields"]["voluntary_ctxt_switches"])
        self.assertEqual(row["status_fields"]["nonvoluntary_ctxt_switches"], 19)
        self.assertIn("voluntary_ctxt_switches", row["status_missing_fields"])
        self.assertFalse(value["coverage"]["complete"])

    def test_duplicate_status_field_never_chooses_one_context_counter(self):
        path = self.process / "task/22/status"
        path.write_text(status_data(22) + "voluntary_ctxt_switches:\t99\n")
        value = self.collect()
        row = self.row(value)
        self.assertIsNone(row["status_fields"]["voluntary_ctxt_switches"])
        self.assertEqual(row["status_duplicate_counts"]["voluntary_ctxt_switches"], 1)
        self.assertIn("DuplicateStatusField", self.errors(value))
        self.assertEqual(row["status_fields"]["nonvoluntary_ctxt_switches"], 19)

    def test_repeated_status_duplicates_keep_exact_count_without_error_list_growth(self):
        raw = status_data(22) + "Pid:\t22\n" * 1000
        parsed = subject.parse_task_status(raw, 22, 21)
        self.assertIsNone(parsed["fields"]["Pid"])
        self.assertEqual(parsed["duplicate_counts"]["Pid"], 1000)
        self.assertEqual(parsed["errors"], [dict(field="Pid", error="DuplicateStatusField")])

    def test_status_pid_or_tgid_mismatch_stays_actual_but_refuses_complete(self):
        for raw in (status_data(999), status_data(22, pid=999)):
            with self.subTest(raw=raw):
                (self.process / "task/22/status").write_text(raw)
                value = self.collect()
                self.assertIn("StatusIdentityMismatch", self.errors(value))
                self.assertFalse(value["coverage"]["complete"])

    def test_context_counter_negative_unicode_overflow_and_zero_are_not_defaults(self):
        for value in (-1, "１２", 2**64):
            with self.subTest(value=value):
                parsed = subject.parse_task_status(status_data(22, voluntary=value), 22, 21)
                self.assertIsNone(parsed["fields"]["voluntary_ctxt_switches"])
                self.assertTrue(parsed["errors"])
                self.assertEqual(parsed["fields"]["nonvoluntary_ctxt_switches"], 19)
        parsed = subject.parse_task_status(status_data(22, voluntary=0), 22, 21)
        self.assertEqual(parsed["fields"]["voluntary_ctxt_switches"], 0)
        self.assertEqual(parsed["errors"], [])

    def test_status_zero_or_changed_thread_quantity_is_explicit_partial(self):
        for threads in (0, 3):
            with self.subTest(threads=threads):
                (self.process / "task/22/status").write_text(status_data(22, threads=threads))
                value = self.collect()
                self.assertFalse(value["coverage"]["complete"])
                self.assertIsNone(value["coverage"]["total_threads"])

    def test_task_set_change_retains_both_observed_sets_without_sampling_new_tid_as_old(self):
        original = subject._scan_tasks
        calls = 0
        def scan(process):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.task(23, "300")
            return original(process)
        with mock.patch.object(subject, "_scan_tasks", side_effect=scan):
            value = self.collect()
        self.assertEqual(value["churn"]["after_only_observed_tids"], [23])
        self.assertEqual([row["tid"] for row in value["threads"]], [21, 22])
        self.assertIn("TaskSetChanged", value["errors"])
        self.assertIsNone(value["coverage"]["total_threads"])

    def test_census_cap_retains_only_an_explicit_truncated_prefix_not_success(self):
        with mock.patch.object(subject, "MAX_TASKS", 1):
            value = self.collect()
        self.assertTrue(value["coverage"]["truncated"])
        self.assertLessEqual(value["coverage"]["recorded_rows"], 1)
        self.assertFalse(value["coverage"]["complete"])
        self.assertIsNone(value["coverage"]["total_threads"])
        self.assertFalse(value["task_census_before"]["complete"])
        self.assertEqual(value["task_census_before"]["directory_entries_observed"], 2)

    def test_unexpected_task_entry_is_not_ignored_as_complete(self):
        (self.process / "task/private-sensitive-entry").mkdir()
        value = self.collect()
        self.assertIn("UnexpectedTaskDirectoryEntry", value["task_census_before"]["errors"])
        self.assertEqual(len(value["threads"]), 2)
        self.assertFalse(value["coverage"]["complete"])
        self.assertNotIn("private-sensitive-entry", json.dumps(value))

    def test_duplicate_observed_directory_tid_cannot_count_as_two_threads(self):
        entries = []
        for name in ("21", "22", "22"):
            entry = mock.Mock()
            entry.name = name
            entry.is_dir.return_value = True
            entries.append(entry)
        def scan(_):
            context = mock.MagicMock()
            context.__enter__.return_value = iter(entries)
            return context
        with mock.patch.object(subject.os, "scandir", side_effect=scan):
            value = self.collect()
        self.assertEqual(value["task_census_before"]["ids"], [21, 22])
        self.assertIn("DuplicateTaskDirectoryEntry", value["task_census_before"]["errors"])
        self.assertFalse(value["coverage"]["complete"])
        self.assertIsNone(value["coverage"]["total_threads"])

    def test_task_stat_symlink_is_not_followed_or_zero_filled(self):
        path = self.process / "task/22/stat"
        path.unlink()
        path.symlink_to(self.process / "stat")
        value = self.collect()
        self.assertIsNone(self.row(value)["stat_before"])
        self.assertIsNone(self.row(value)["utime_ticks"])
        self.assertFalse(value["coverage"]["complete"])

    def test_symlink_task_directory_is_not_followed(self):
        path = self.process / "task"
        path.rename(self.root / "original-owned-tasks")
        path.symlink_to(self.root / "original-owned-tasks")
        value = self.collect()
        self.assertFalse(value["task_census_before"]["complete"])
        self.assertIsNone(value["coverage"]["total_threads"])

    def test_all_file_bounds_refuse_with_actual_other_observations_retained(self):
        cases = [(self.process / "task/22/stat", subject.MAX_STAT_BYTES),
                 (self.process / "task/22/status", subject.MAX_STATUS_BYTES),
                 (self.process / "task/22/wchan", subject.MAX_WCHAN_BYTES),
                 (self.locator, subject.MAX_PID_BYTES), (self.boot, subject.MAX_BOOT_BYTES)]
        for path, maximum in cases:
            old = path.read_bytes()
            path.write_bytes(b"x" * (maximum + 1))
            with self.subTest(file=path.name):
                value = self.collect()
                self.assertFalse(value["coverage"]["complete"])
                self.assertIsNone(value["coverage"]["total_threads"])
                self.assertIn("CensusBoundExceeded", json.dumps(value))
            path.write_bytes(old)

    def test_metadata_errors_do_not_emit_exception_paths_or_secret_values(self):
        with mock.patch.object(subject, "_bounded_text", side_effect=PermissionError("/private/secret-token-value")):
            value = self.collect()
        raw = json.dumps(value)
        self.assertIn("PermissionError", raw)
        self.assertNotIn("secret-token-value", raw)
        self.assertIsNone(value["coverage"]["total_threads"])


if __name__ == "__main__":
    unittest.main()
