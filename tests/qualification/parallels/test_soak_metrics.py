"""Owned-filesystem/mocked integration units; not actual Royak/idle evidence.

No process, Docker, environment, HOME or host /proc operation is performed at
import/test construction. Root alone runs these against NEW TemporaryDirectory
fixtures. The unchanged 22 held collector cases remain in test_pid_census.py.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import pid_census as collector
import soak_metrics as subject


def stat_data(tid=21, start="100", user=2, kernel=1, comm="fixture (worker)"):
    fields = ["S", "1", "9", "9", *(["0"] * 7), str(user), str(kernel), *(["0"] * 6), start]
    return f"{tid} ({comm}) " + " ".join(fields)


class MetricsContextTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.proc = self.root / "owned-proc-fixture"
        self.process = self.proc / "21"
        (self.process / "task").mkdir(parents=True)
        (self.process / "fd").mkdir()
        for fd in (3, 4):
            (self.process / "fd" / str(fd)).write_bytes(b"")
        self.executable = self.root / "owned-fixture-binary-not-royak"
        self.executable.write_bytes(b"fixture metadata only")
        (self.process / "exe").symlink_to(self.executable)
        self.pid_file = self.root / "owned-pid-locator"
        self.pid_file.write_text("21\n")
        (self.process / "stat").write_text(stat_data())
        (self.process / "status").write_text("Name:\tfixture\nVmRSS:\t12 kB\nThreads:\t2\n")
        for tid, start in ((21, "100"), (22, "200")):
            task = self.process / "task" / str(tid)
            task.mkdir()
            (task / "stat").write_text(stat_data(tid, start))
            (task / "wchan").write_text("futex_wait_queue")

    def observe(self):
        return subject.observe_process(self.pid_file, self.proc, self.executable)

    def errors(self, observation):
        return {(item["stage"], item["error"]) for item in observation["errors"]}

    def assert_unavailable(self, value, observation):
        self.assertIsNone(value)
        self.assertEqual(observation["status"], "UNAVAILABLE")
        self.assertFalse(observation["atomic_continuous_coverage_proven"])
        self.assertFalse(observation["owned_unit_continuity_proven"])
        self.assertFalse(observation["idle_or_retirement_authority"])

    def reviewer(self):
        path = Path(__file__).resolve().with_name("thread_review.py")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),
                         "5e0c627caceb8c9e1a08c0209173120081b97f4641a240bea7c2bb30b84257fa")
        spec = importlib.util.spec_from_file_location("held_metrics_join_reviewer_v3", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def review(self, process):
        return self.reviewer().review_samples([dict(node=1, elapsed_s=1.0, phase="steady", metrics=dict(
            schema_version=2, boot_id="fixture-boot", clock_ticks=100, process=process))])

    def test_actual_fixture_pid_and_same_start_are_passed_as_exact_census_kwargs(self):
        with mock.patch.object(subject, "thread_census", wraps=collector.thread_census) as called:
            value, observation = self.observe()
        called.assert_called_once_with(self.process, expected_pid=21, expected_start_ticks="100")
        self.assertEqual({key: value[key] for key in ("pid", "start_ticks", "cpu_ticks", "rss_bytes", "fds", "threads")},
                         dict(pid=21, start_ticks="100", cpu_ticks=3, rss_bytes=12288, fds=2, threads=2))
        self.assertTrue(value["thread_census"]["process_identity_pinned"])
        self.assertTrue(value["thread_census"]["process_identity_consistent"])
        self.assertEqual(observation["status"], "OBSERVED_NONATOMIC")
        self.assertEqual(observation["executable_before"], observation["executable_after"])
        self.assertEqual(observation["errors"], [])
        self.assertIsNone(observation["thread_census"])
        self.assertEqual(observation["census_location"], "process.thread_census")
        encoded = json.dumps(dict(process=value, process_observation=observation))
        self.assertEqual(encoded.count('"observed_is_recorded_rows_not_total"'), 1)
        self.assertNotIn(str(self.root), encoded)

    def test_public_stat_parser_preserves_comm_with_spaces_and_closing_parentheses(self):
        (self.process / "stat").write_text(stat_data(comm="main ) (worker)"))
        with mock.patch.object(subject, "parse_task_stat", wraps=collector.parse_task_stat) as called:
            value, observation = self.observe()
        self.assertEqual(called.call_count, 2)
        self.assertEqual(observation["stat_before"]["comm"], "main ) (worker)")
        self.assertEqual(value["cpu_ticks"], 3)

    def test_process_cpu_split_uses_actual_process_stat_not_sum_of_sampled_tasks(self):
        (self.process / "stat").write_text(stat_data(user=7, kernel=19))
        (self.process / "task/22/stat").write_text(stat_data(22, "200", user=100, kernel=200))
        value, observation = self.observe()
        self.assertEqual((value["utime_ticks"], value["stime_ticks"], value["cpu_ticks"]), (7, 19, 26))
        self.assertEqual(value["utime_ticks"], observation["stat_before"]["utime_ticks"])
        self.assertEqual(value["stime_ticks"], observation["stat_before"]["stime_ticks"])
        task = value["thread_census"]["threads"][1]
        self.assertEqual((task["utime_ticks"], task["stime_ticks"], task["cpu_ticks"]), (100, 200, 300))
        self.assertEqual(observation["status"], "OBSERVED_NONATOMIC")

    def test_later_process_cpu_stat_does_not_mix_or_overwrite_before_counters(self):
        (self.process / "stat").write_text(stat_data(user=7, kernel=19))
        original = subject._read_stat
        reads = 0
        def read(process, pid):
            nonlocal reads
            reads += 1
            if reads == 2:
                (self.process / "stat").write_text(stat_data(user=13, kernel=23))
            return original(process, pid)
        with mock.patch.object(subject, "_read_stat", side_effect=read):
            value, observation = self.observe()
        self.assertEqual((value["utime_ticks"], value["stime_ticks"], value["cpu_ticks"]), (7, 19, 26))
        after = observation["stat_after"]
        self.assertEqual((after["utime_ticks"], after["stime_ticks"], after["cpu_ticks"]), (13, 23, 36))
        self.assertEqual(observation["status"], "OBSERVED_NONATOMIC")

    def test_wrong_executable_refuses_before_census_without_reporting_its_path(self):
        other = self.root / "private-other-binary-name"
        other.write_bytes(b"other")
        (self.process / "exe").unlink()
        (self.process / "exe").symlink_to(other)
        with mock.patch.object(subject, "thread_census") as called:
            value, observation = self.observe()
        self.assert_unavailable(value, observation)
        called.assert_not_called()
        self.assertIn(("exe_before", "ExecutableMismatch"), self.errors(observation))
        self.assertNotIn(str(other), json.dumps(observation))

    def test_missing_executable_is_unavailable_without_census_or_path_error(self):
        (self.process / "exe").unlink()
        with mock.patch.object(subject, "thread_census") as called:
            value, observation = self.observe()
        self.assert_unavailable(value, observation)
        called.assert_not_called()
        self.assertIn(("exe_before", "FileNotFoundError"), self.errors(observation))
        self.assertNotIn(str(self.root), json.dumps(observation))

    def test_missing_stat_has_no_zero_or_guessed_identity_fallback(self):
        (self.process / "stat").unlink()
        with mock.patch.object(subject, "thread_census") as called:
            value, observation = self.observe()
        self.assert_unavailable(value, observation)
        called.assert_not_called()
        self.assertIsNone(observation["stat_before"])
        self.assertIn(("stat_before", "FileNotFoundError"), self.errors(observation))

    def test_wrong_pid_short_unicode_or_negative_stat_refuses(self):
        for raw in (stat_data(22), "21 (x) S 1", stat_data(start="-1"), stat_data(start="１２")):
            with self.subTest(raw=raw):
                (self.process / "stat").write_text(raw)
                value, observation = self.observe()
                self.assert_unavailable(value, observation)
                self.assertIn(("stat_before", "ValueError"), self.errors(observation))

    def test_stat_bound_refuses_oversize_not_truncated_success(self):
        (self.process / "stat").write_bytes(b"x" * (subject.MAX_STAT_BYTES + 1))
        value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertIn(("stat_before", "ObservationBoundExceeded"), self.errors(observation))

    def test_stat_symlink_refuses_before_reading_foreign_metadata(self):
        source = self.process / "stat"
        source.unlink()
        source.symlink_to(self.process / "task/21/stat")
        value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertTrue(any(stage == "stat_before" for stage, _ in self.errors(observation)))

    def test_invalid_missing_or_oversize_locator_never_guesses_another_pid(self):
        for raw in ("", "0", "-21", "２１", "2147483648", "21\n22", "9" * 65):
            with self.subTest(raw=raw):
                self.pid_file.write_text(raw)
                with mock.patch.object(subject, "thread_census") as called:
                    value, observation = self.observe()
                self.assert_unavailable(value, observation)
                self.assertIsNone(observation["pid"])
                called.assert_not_called()
        self.pid_file.unlink()
        value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertIn(("pid_locator", "FileNotFoundError"), self.errors(observation))

    def test_missing_malformed_or_duplicate_status_retains_actual_census_not_zero_fields(self):
        status = self.process / "status"
        for raw in ("Threads: 2\n", "VmRSS: 12 MB\nThreads: 2\n", "VmRSS: -1 kB\nThreads: 2\n",
                    "VmRSS: 12 kB\nThreads: 0\n", "VmRSS: 12 kB\nThreads: 2\nThreads: 2\n"):
            with self.subTest(raw=raw):
                status.write_text(raw)
                value, observation = self.observe()
                self.assert_unavailable(value, observation)
                self.assertIsNone(observation["status_fields"])
                self.assertEqual(observation["thread_census"]["observed"], 2)
                self.assertEqual(observation["census_location"], "process_observation.thread_census")
        status.unlink()
        value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertIn(("status", "FileNotFoundError"), self.errors(observation))
        self.assertEqual(observation["thread_census"]["observed"], 2)

    def test_oversize_status_refuses_and_keeps_census_and_after_context(self):
        (self.process / "status").write_bytes(b"x" * (subject.MAX_STATUS_BYTES + 1))
        value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertIn(("status", "ObservationBoundExceeded"), self.errors(observation))
        self.assertEqual(observation["thread_census"]["observed"], 2)
        self.assertEqual(observation["stat_after"]["start_ticks"], "100")
        self.assertTrue(observation["exe_after"])

    def test_missing_fd_directory_is_unavailable_not_zero_open_files(self):
        for entry in (self.process / "fd").iterdir():
            entry.unlink()
        (self.process / "fd").rmdir()
        value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertIsNone(observation["fd_count"])
        self.assertEqual(observation["thread_census"]["observed"], 2)
        self.assertIn(("fd_count", "FileNotFoundError"), self.errors(observation))

    def test_observed_outer_pid_reuse_retains_both_stats_and_actual_census(self):
        original = subject._read_stat
        reads = 0
        def read(process, pid):
            nonlocal reads
            reads += 1
            if reads == 2:
                (self.process / "stat").write_text(stat_data(start="300"))
            return original(process, pid)
        with mock.patch.object(subject, "_read_stat", side_effect=read):
            value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertEqual(observation["stat_before"]["start_ticks"], "100")
        self.assertEqual(observation["stat_after"]["start_ticks"], "300")
        self.assertEqual(observation["thread_census"]["observed"], 2)
        self.assertIn(("stat_after", "ProcessIncarnationChanged"), self.errors(observation))

    def test_missing_or_wrong_pid_after_stat_keeps_actual_prior_rows_unavailable(self):
        original = subject._read_stat
        for replacement in (None, stat_data(22)):
            with self.subTest(replacement=replacement):
                (self.process / "stat").write_text(stat_data())
                reads = 0
                def read(process, pid):
                    nonlocal reads
                    reads += 1
                    if reads == 2:
                        if replacement is None:
                            (self.process / "stat").unlink()
                        else:
                            (self.process / "stat").write_text(replacement)
                    return original(process, pid)
                with mock.patch.object(subject, "_read_stat", side_effect=read):
                    value, observation = self.observe()
                self.assert_unavailable(value, observation)
                self.assertIsNone(observation["stat_after"])
                self.assertEqual(observation["thread_census"]["observed"], 2)
                self.assertTrue(any(stage == "stat_after" for stage, _ in self.errors(observation)))

    def test_observed_executable_path_change_is_unavailable_with_actual_census(self):
        other = self.root / "replacement-binary"
        other.write_bytes(b"other")
        original = subject._read_executable
        reads = 0
        def read(process, expected):
            nonlocal reads
            reads += 1
            if reads == 2:
                (self.process / "exe").unlink()
                (self.process / "exe").symlink_to(other)
            return original(process, expected)
        with mock.patch.object(subject, "_read_executable", side_effect=read):
            value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertIn(("exe_after", "ExecutableMismatch"), self.errors(observation))
        self.assertEqual(observation["thread_census"]["observed"], 2)

    def test_same_path_executable_inode_replacement_is_observed_not_claimed_continuous(self):
        replacement = self.root / "new-executable-inode"
        replacement.write_bytes(b"replacement")
        original = subject._read_executable
        reads = 0
        def read(process, expected):
            nonlocal reads
            reads += 1
            if reads == 2:
                replacement.replace(self.executable)
            return original(process, expected)
        with mock.patch.object(subject, "_read_executable", side_effect=read):
            value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertTrue(observation["exe_before"])
        self.assertTrue(observation["exe_after"])
        self.assertNotEqual(observation["executable_before"]["inode"], observation["executable_after"]["inode"])
        self.assertIn(("exe_after", "ExecutableIdentityChanged"), self.errors(observation))

    def test_collector_process_reuse_is_not_hidden_by_matching_outer_stat_endpoints(self):
        original = collector._bounded_text
        reads = 0
        def read(path, maximum):
            nonlocal reads
            if path == self.process / "stat":
                reads += 1
                if reads == 2:
                    return stat_data(start="300")
            return original(path, maximum)
        with mock.patch.object(collector, "_bounded_text", side_effect=read):
            value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertEqual(observation["stat_before"], observation["stat_after"])
        self.assertFalse(observation["thread_census"]["process_identity_consistent"])
        self.assertIn(("thread_census", "PinnedProcessIdentityUnavailable"), self.errors(observation))
        self.assertIn("ProcessIncarnationChanged", {row["error"] for row in observation["thread_census"]["errors"]})

    def test_actual_tid_reuse_preserves_first_stat_and_partial_census_for_offline_v3(self):
        original = collector._bounded_text
        reads = 0
        def read(path, maximum):
            nonlocal reads
            if path == self.process / "task/22/stat":
                reads += 1
                if reads == 2:
                    return stat_data(22, "201")
            return original(path, maximum)
        with mock.patch.object(collector, "_bounded_text", side_effect=read):
            value, observation = self.observe()
        self.assertEqual(observation["status"], "PARTIAL")
        self.assertEqual(value["thread_census"]["threads"][1]["start_ticks"], "200")
        self.assertIn("ThreadIncarnationChanged", {row["error"] for row in value["thread_census"]["errors"]})
        result = self.review(value)
        self.assertEqual(result["review_state"], "INCOMPLETE_OBSERVATIONS")
        self.assertIn("CENSUS_ERRORS", result["overlapping_category_counts"])

    def test_missing_wchan_is_partial_not_exited_and_joins_old_reviewer(self):
        (self.process / "task/22/wchan").unlink()
        value, observation = self.observe()
        self.assertEqual(observation["status"], "PARTIAL")
        self.assertEqual(value["thread_census"]["exited_during_sample"], [])
        self.assertEqual(value["thread_census"]["observed"], 2)
        row = value["thread_census"]["threads"][1]
        self.assertIsNone(row["wait_channel"])
        self.assertEqual(row["wait_channel_error"], "FileNotFoundError")
        result = self.review(value)
        self.assertEqual(result["review_state"], "INCOMPLETE_OBSERVATIONS")
        self.assertIn("WAIT_CHANNEL_UNKNOWN", result["overlapping_category_counts"])

    def test_changed_task_set_keeps_actual_rows_and_errors_as_partial(self):
        with mock.patch.object(collector, "_task_ids", side_effect=[[21, 22], [21]]):
            value, observation = self.observe()
        self.assertEqual(observation["status"], "PARTIAL")
        self.assertEqual(value["thread_census"]["observed"], 2)
        self.assertFalse(value["thread_census"]["task_set_consistent"])
        self.assertIn("TaskSetChanged", {row["error"] for row in value["thread_census"]["errors"]})

    def test_census_error_is_safe_class_only_never_sensitive_exception_path(self):
        with mock.patch.object(subject, "thread_census", side_effect=OSError("/secret/payload/never-report")):
            value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertIn(("thread_census", "OSError"), self.errors(observation))
        self.assertNotIn("/secret/", json.dumps(observation))
        self.assertIsNone(observation["thread_census"])

    def test_malformed_returned_census_is_retained_not_rebuilt_as_empty_success(self):
        returned = {"diagnostic": "owned mocked malformed shape"}
        with mock.patch.object(subject, "thread_census", return_value=returned):
            value, observation = self.observe()
        self.assert_unavailable(value, observation)
        self.assertIs(observation["thread_census"], returned)
        self.assertIn(("thread_census", "PinnedProcessIdentityUnavailable"), self.errors(observation))

    def test_actual_complete_metrics_shape_joins_unchanged_offline_v3(self):
        value, observation = self.observe()
        result = self.review(value)
        self.assertEqual(result["review_state"], "OBSERVATIONS_REVIEWED")
        self.assertEqual(result["observed_thread_identity_count"], 2)
        self.assertEqual(observation["status"], "OBSERVED_NONATOMIC")
        self.assertIn("leak-free", result["claims_excluded"])

    def test_sample_preserves_schema2_and_uses_context_without_real_proc_docker_or_ss(self):
        original_observe_process = subject.observe_process
        def observe_owned_fixture():
            return original_observe_process(self.pid_file, self.proc, self.executable)
        real_path = Path
        boot = mock.Mock()
        boot.read_text.return_value = "owned-fixture-boot\n"
        def path(value):
            return boot if value == "/proc/sys/kernel/random/boot_id" else real_path(value)
        def output(*args):
            self.assertIn(args, (("ss", "-tanH"), ("docker", "ps", "-aq"),
                                 ("docker", "stats", "--no-stream", "--format", "{{json .}}")))
            return ""
        with mock.patch.object(subject, "Path", side_effect=path), \
             mock.patch.object(subject, "observe_process", side_effect=observe_owned_fixture) as observed, \
             mock.patch.object(subject.os, "sysconf", return_value=100), \
             mock.patch.object(subject.shutil, "disk_usage", return_value=mock.Mock(free=1234)), \
             mock.patch.object(subject, "output", side_effect=output), \
             mock.patch.object(subject, "path_usage", return_value=dict(bytes=None)) as usage:
            value = subject.sample()
        observed.assert_called_once_with()
        self.assertEqual(value["schema_version"], 2)
        self.assertEqual(value["boot_id"], "owned-fixture-boot")
        self.assertEqual(value["process"]["start_ticks"], "100")
        self.assertEqual(value["process_observation"]["status"], "OBSERVED_NONATOMIC")
        self.assertEqual(value["containers"], [])
        self.assertEqual(usage.call_count, 4)


if __name__ == "__main__":
    unittest.main()
