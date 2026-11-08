"""Authored v3 / UNRUN pure DATA; 27 v2 bodies preserved, no kernel proof."""
import copy
import unittest
from unittest.mock import patch

import thread_review as review


def thread(tid=21, start=100, cpu=0, comm="tokio-rt-worker", state="S", wait="futex_wait_queue"):
    return dict(tid=tid, start_ticks=str(start), cpu_ticks=cpu, comm=comm, state=state, wait_channel=wait)


def sample(at, values=None, node=1, boot="boot-a", pid=10, process_start=5, phase="baseline", count=None, hz=100, include_main=True):
    workers = [thread()] if values is None else values
    values = ([thread(tid=pid, start=process_start, comm="royak")] if include_main else []) + workers
    process = dict(pid=pid, start_ticks=str(process_start), cpu_ticks=0, rss_bytes=1024, fds=3,
                   threads=len(values) if count is None else count,
                   thread_census=dict(threads=values, observed=len(values), exited_during_sample=[], errors=[]))
    return dict(node=node, elapsed_s=at, phase=phase, metrics=dict(schema_version=2, boot_id=boot, clock_ticks=hz, process=process))


def idle(phase="idle-retirement", start=0, end=10, minimum=10):
    return dict(phase=phase, start_s=start, end_s=end, minimum_span_s=minimum, declaration_sha256="ab" * 32)


def worker(report, tid=21, start=None):
    rows = [r for r in report["thread_identities"] if r["identity"]["tid"] == tid
            and (start is None or r["identity"]["thread_start_ticks"] == start)]
    if len(rows) != 1:
        raise AssertionError("one exact synthetic worker observation expected")
    return rows[0]


class ThreadReviewDataTests(unittest.TestCase):
    def test_full_identity_separates_tid_reuse_and_never_joins_cpu(self):
        result = review.review_samples([sample(0, [thread(start=100, cpu=90)]),
                                        sample(1, [thread(start=200, cpu=1)])])
        a, b = [r for r in result["thread_identities"] if r["identity"]["tid"] == 21]
        self.assertEqual(a["identity"]["tid"], b["identity"]["tid"])
        self.assertNotEqual(a["identity"]["thread_start_ticks"], b["identity"]["thread_start_ticks"])
        self.assertEqual(a["cpu_intervals"], [])
        self.assertEqual(b["cpu_intervals"], [])
        self.assertEqual(a["disappearance_observation_bounds"]["by_full_census_omission_s"], 1)
        self.assertFalse(a["disappearance_observation_bounds"]["exact_exit_proven"])

    def test_process_restart_and_node_boot_reuse_keep_all_six_identity_fields(self):
        rows = [sample(0), sample(1, process_start=6), sample(2, boot="boot-b", process_start=6),
                sample(0, node=2, boot="boot-b", process_start=6)]
        result = review.review_samples(rows)
        self.assertEqual(len(result["incarnations"]), 4)
        self.assertEqual(len(result["thread_identities"]), 8)
        for item in result["thread_identities"]:
            self.assertEqual(set(item["identity"]), {"node", "boot_id", "pid", "process_start_ticks", "tid", "thread_start_ticks"})
            self.assertIsNone(item["disappearance_observation_bounds"])

    def test_missing_old_census_is_unknown_not_zero_or_pass(self):
        row = sample(0)
        del row["metrics"]["process"]["thread_census"]
        result = review.review_samples([row])
        self.assertEqual(result["review_state"], "INCOMPLETE_OBSERVATIONS")
        self.assertIsNone(result["observed_thread_identity_count"])
        self.assertIsNone(result["thread_identities"])
        self.assertEqual(result["overlapping_category_counts"], {"THREAD_CENSUS_MISSING": 1})
        self.assertEqual(result["incarnations"][0]["idle_window"]["status"], "UNKNOWN_NO_PREDECLARED_IDLE_WINDOW")
        self.assertNotIn("passed", result)

    def test_cpu_monotonic_deltas_use_actual_user_hz_without_pool_attribution(self):
        result = review.review_samples([sample(0, [thread(cpu=10)]), sample(2, [thread(cpu=60, state="R", wait="0")])])
        item = worker(result)
        self.assertEqual(item["cpu_intervals"], [dict(from_s=0, to_s=2, delta_ticks=50, cpu_seconds=.5,
                                                   one_core_percent=25, intervening_node_samples=0)])
        self.assertEqual([v["wait_channel"] for v in item["observations"]], ["futex_wait_queue", "0"])
        self.assertTrue(item["worker_name_or_wait_channel_is_not_harmlessness_or_exit_proof"])

    def test_counter_decrease_is_explicit_and_not_clamped_to_zero(self):
        result = review.review_samples([sample(0, [thread(cpu=10)]), sample(1, [thread(cpu=5)])])
        item = worker(result)
        self.assertEqual(item["cpu_intervals"], [])
        self.assertEqual(item["activity_issues"], [dict(at_s=1, category="CPU_COUNTER_DECREASE")])
        self.assertEqual(result["review_state"], "INCOMPLETE_OBSERVATIONS")

    def test_clock_change_and_missing_wait_channel_are_unknown(self):
        first, second = sample(0, [thread(cpu=10)]), sample(1, [thread(cpu=30)], hz=250)
        second["metrics"]["process"]["thread_census"]["threads"][-1]["wait_channel"] = None
        second["metrics"]["process"]["thread_census"]["threads"][-1]["wait_channel_error"] = "PermissionError"
        result = review.review_samples([first, second])
        item = worker(result)
        self.assertEqual(item["cpu_intervals"], [])
        self.assertEqual(item["activity_issues"], [dict(at_s=1, category="CLOCK_TICKS_CHANGED")])
        self.assertIn("WAIT_CHANNEL_UNKNOWN", result["sample_issues"][0]["categories"])
        self.assertIn("WAIT_CHANNEL_ERROR", result["sample_issues"][0]["categories"])

    def test_nonatomic_overlap_categories_are_retained_not_disjoint_totals(self):
        row = sample(0, count=3)
        census = row["metrics"]["process"]["thread_census"]
        census.update(observed=1, exited_during_sample=[22], errors=[dict(tid=23, error="OSError")])
        result = review.review_samples([row])
        self.assertEqual(result["samples_with_issues"], 1)
        self.assertEqual(result["samples_in_multiple_categories"], 1)
        self.assertEqual(set(result["sample_issues"][0]["categories"]), {
            "CENSUS_OBSERVED_COUNT_MISMATCH", "STATUS_CENSUS_NONATOMIC_MISMATCH",
            "TASK_VANISHED_DURING_SAMPLE", "CENSUS_ERRORS"})
        self.assertEqual(sum(result["overlapping_category_counts"].values()), 4)
        self.assertTrue(result["categories_are_not_disjoint"])

    def test_vanish_gap_does_not_become_exit_or_zero_during_the_race(self):
        gap = sample(1, [], count=1)
        gap["metrics"]["process"]["thread_census"]["exited_during_sample"] = [21]
        result = review.review_samples([sample(0), gap, sample(2, [])])
        bounds = worker(result)["disappearance_observation_bounds"]
        self.assertEqual(bounds, dict(after_last_observation_s=0, by_full_census_omission_s=2,
                                     exact_exit_proven=False, intervening_node_samples=1))
        self.assertFalse(result["sample_observations"][1]["census_complete"])

    def test_true_complete_census_omission_is_an_interval_not_exact_kernel_exit(self):
        result = review.review_samples([sample(0), sample(2, [])])
        item = worker(result)
        self.assertEqual(item["disappearance_observation_bounds"], dict(after_last_observation_s=0,
            by_full_census_omission_s=2, exact_exit_proven=False, intervening_node_samples=0))
        self.assertFalse(item["observed_present_in_last_incarnation_census"])
        self.assertEqual(result["review_state"], "OBSERVATIONS_REVIEWED")
        for key in ("passed", "leak_free", "retirement_qualified"):
            self.assertNotIn(key, result)

    def test_reappearance_after_omission_preserves_conflicting_evidence(self):
        result = review.review_samples([sample(0), sample(1, []), sample(2, [thread(cpu=2)])])
        item = worker(result)
        self.assertEqual(item["omission_reobservations"], [dict(omitted_at_s=1, reobserved_at_s=2,
            category="REOBSERVED_AFTER_FULL_CENSUS_OMISSION")])
        self.assertIsNone(item["disappearance_observation_bounds"])
        self.assertEqual(result["review_state"], "INCOMPLETE_OBSERVATIONS")

    def test_birth_bounds_and_baseline_load_phase_coverage_do_not_claim_exact_birth(self):
        result = review.review_samples([sample(0, [], phase="baseline"), sample(1, phase="steady"),
                                        sample(2, phase="drain")])
        item = worker(result)
        self.assertEqual(item["birth_observation_bounds"], dict(after_full_census_omission_s=0,
            by_first_observation_s=1, exact_birth_proven=False, intervening_node_samples=0))
        inc = result["incarnations"][0]
        self.assertEqual(inc["baseline_phases_observed"], ["baseline"])
        self.assertEqual(inc["load_phases_observed"], ["steady"])
        self.assertEqual(inc["idle_window"]["status"], "UNKNOWN_NO_PREDECLARED_IDLE_WINDOW")

    def test_final_traffic_is_not_an_idle_window_even_with_a_declaration_hash(self):
        result = review.review_samples([sample(0, phase="final"), sample(10, phase="final")], idle("final"))
        self.assertEqual(result["incarnations"][0]["idle_window"]["status"], "TRAFFIC_PHASE_IS_NOT_IDLE")
        self.assertFalse(result["incarnations"][0]["idle_window"]["causal_retirement_proven"])

    def test_coherent_predeclared_window_is_coverage_not_retirement_authority(self):
        rows = [sample(0, phase="idle-retirement"), sample(10, phase="idle-retirement")]
        report = review.review_samples(rows, idle())
        coverage = report["incarnations"][0]["idle_window"]
        self.assertEqual(coverage["status"], "COHERENT_DECLARED_WINDOW_OBSERVED")
        self.assertEqual(coverage["observed_span_s"], 10)
        self.assertFalse(coverage["declaration_chronology_verified"])
        self.assertFalse(coverage["causal_retirement_proven"])
        self.assertFalse(coverage["continuous_unsampled_coverage_proven"])

    def test_missing_process_inside_idle_window_denies_complete_coverage(self):
        middle = sample(5, phase="idle-retirement")
        middle["metrics"]["process"] = None
        report = review.review_samples([sample(0, phase="idle-retirement"), middle,
                                        sample(10, phase="idle-retirement")], idle())
        self.assertEqual(report["incarnations"][0]["idle_window"]["status"], "UNKNOWN_INCOMPLETE_IDLE_COVERAGE")
        self.assertEqual(report["incarnations"][0]["idle_window"]["unrepresented_node_samples"], 1)

    def test_raw_decoder_refuses_duplicates_nonfinite_and_trailing_data(self):
        for raw in ('{"node":1,"node":2}', '{"elapsed_s":NaN}', '{} {}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                review._json(raw)

    def test_future_metric_schema_never_imports_thread_units_or_identity(self):
        row = sample(0)
        row["metrics"]["schema_version"] = 3
        result = review.review_samples([row])
        self.assertEqual(result["overlapping_category_counts"], {"METRICS_SCHEMA_UNKNOWN": 1})
        self.assertIsNone(result["thread_identities"])
        self.assertEqual(result["incarnations"], [])

    def test_malformed_identity_bool_cpu_and_time_never_become_valid_zero_data(self):
        for field, value in (("pid", True), ("start_ticks", "-1")):
            row = sample(0)
            row["metrics"]["process"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                review.review_samples([row])
        row = sample(0)
        row["metrics"]["process"]["thread_census"]["threads"][0]["cpu_ticks"] = True
        result = review.review_samples([row])
        self.assertIn("THREAD_CPU_COUNTER_UNKNOWN", result["sample_issues"][0]["categories"])
        with self.assertRaises(ValueError):
            review.review_samples([sample(float("nan"))])

    def test_refusal_bounds_do_not_truncate_input_or_create_partial_analysis(self):
        with patch.object(review, "MAX_ROWS", 1), self.assertRaisesRegex(ValueError, "row bound"):
            review.review_samples([sample(0), sample(1)])
        with patch.object(review, "MAX_IDENTITIES", 1), self.assertRaisesRegex(ValueError, "identity bound"):
            review.review_samples([sample(0, [thread(21), thread(22)])])
        with patch.object(review, "MAX_OBSERVATIONS", 1), self.assertRaisesRegex(ValueError, "observation bound"):
            review.review_samples([sample(0), sample(1)])

    def test_input_is_unchanged_and_payload_fields_are_never_copied(self):
        rows = [sample(0)]
        rows[0]["metrics"]["process"]["argv"] = "PAYLOAD-NOT-FOR-REPORT"
        rows[0]["environment"] = dict(secret="PAYLOAD-NOT-FOR-REPORT")
        before = copy.deepcopy(rows)
        result = review.review_samples(rows)
        self.assertEqual(rows, before)
        self.assertNotIn("PAYLOAD-NOT-FOR-REPORT", repr(result))
        self.assertFalse(result["aggregate_thresholds_evaluated"])


    def test_zero_status_and_empty_census_never_support_coherent_disappearance(self):
        zero = sample(2, [], count=0, include_main=False)
        result = review.review_samples([sample(0), zero])
        self.assertEqual(set(result["sample_issues"][0]["categories"]),
                         {"THREAD_STATUS_NOT_POSITIVE", "MAIN_TID_MISSING"})
        self.assertFalse(result["sample_observations"][1]["census_complete"])
        self.assertIsNone(worker(result)["disappearance_observation_bounds"])
        self.assertEqual(result["review_state"], "INCOMPLETE_OBSERVATIONS")

    def test_positive_count_missing_main_is_incomplete_even_when_counts_match(self):
        row = sample(1, [thread()], include_main=False)
        result = review.review_samples([sample(0), row])
        self.assertEqual(result["sample_issues"][0]["categories"], ["MAIN_TID_MISSING"])
        self.assertFalse(result["sample_observations"][1]["census_complete"])
        self.assertEqual(result["sample_observations"][1]["observed_main_tid_rows"], 0)

    def test_main_start_must_match_same_original_process_start(self):
        row = sample(1)
        row["metrics"]["process"]["thread_census"]["threads"][0]["start_ticks"] = "6"
        result = review.review_samples([row])
        self.assertIn("MAIN_TID_START_MISMATCH", result["sample_issues"][0]["categories"])
        self.assertFalse(result["sample_observations"][0]["census_complete"])

    def test_duplicate_main_rows_are_not_complete_main_presence(self):
        row = sample(0, [thread(tid=10, start=5), thread()])
        result = review.review_samples([row])
        self.assertIn("DUPLICATE_TID_IN_CENSUS", result["sample_issues"][0]["categories"])
        self.assertIn("MAIN_TID_NOT_UNIQUE", result["sample_issues"][0]["categories"])
        self.assertFalse(result["sample_observations"][0]["census_complete"])

    def test_worker_start_before_process_is_retained_but_not_coherent(self):
        row = sample(0, [thread(start=4)])
        result = review.review_samples([row])
        self.assertIn("THREAD_START_PRECEDES_PROCESS_START", result["sample_issues"][0]["categories"])
        self.assertEqual(worker(result)["identity"]["thread_start_ticks"], 4)
        self.assertFalse(result["sample_observations"][0]["census_complete"])
        self.assertFalse(result["absolute_boot_age_or_wallclock_start_join_verified"])

    def test_process_start_rewind_within_same_boot_pid_is_explicit_incomplete(self):
        result = review.review_samples([sample(0, process_start=6), sample(1, process_start=5)])
        self.assertEqual(len(result["incarnations"]), 2)
        self.assertIn("PROCESS_START_REWIND_WITHIN_BOOT_PID", result["sample_issues"][0]["categories"])
        self.assertEqual(result["sample_observations"][1]["previous_process_start_max_ticks"], 6)
        self.assertFalse(result["sample_observations"][1]["census_complete"])

    def test_tid_start_rewind_is_not_accepted_as_normal_reuse(self):
        result = review.review_samples([sample(0, [thread(start=200)]), sample(1, [thread(start=100)])])
        self.assertIn("THREAD_START_REWIND_WITHIN_PROCESS_TID", result["sample_issues"][0]["categories"])
        self.assertFalse(result["sample_observations"][1]["census_complete"])
        self.assertEqual({r["identity"]["thread_start_ticks"] for r in result["thread_identities"]
                          if r["identity"]["tid"] == 21}, {100, 200})

    def test_flat_schema7_is_unrepresentable_without_original_identity_clock_and_phase(self):
        row = dict(at=1793372803.5701191, incarnation=2775, threads=1, observed_threads=1,
                   vanished_tasks=[], tasks=[dict(tid=2122, starttime=2775, comm="royak",
                                                 state="S", utime=0, stime=1, wchan="hrtimer_nanosleep")])
        before = copy.deepcopy(row)
        with self.assertRaisesRegex(ValueError, "UNREPRESENTABLE_FLAT_SCHEMA7"):
            review.review_samples([row])
        self.assertEqual(row, before)

    def test_original_eight_traffic_exclusions_stay_nonidle(self):
        original = ("warmup", "baseline", "steady", "soak", "load", "fault", "recovery", "final")
        for phase in original:
            with self.subTest(phase=phase):
                rows = [sample(0, phase=phase), sample(10, phase=phase)]
                before = copy.deepcopy(rows)
                result = review.review_samples(rows, idle(phase))
                coverage = result["incarnations"][0]["idle_window"]
                self.assertEqual(coverage["status"], "TRAFFIC_PHASE_IS_NOT_IDLE")
                self.assertFalse(coverage["causal_retirement_proven"])
                self.assertEqual(rows, before)

    def test_exact_actual_fault_and_recovery_aliases_are_load_not_idle(self):
        faults = ("pod-kill", "leader-sigkill", "control-partition", "node-restart", "wireguard-down")
        aliases = faults + tuple("recovery-" + phase for phase in faults)
        self.assertEqual(review.TRAFFIC_PHASES,
                         frozenset(("warmup", "baseline", "steady", "soak", "load", "fault", "recovery", "final") + aliases))
        for phase in aliases:
            with self.subTest(phase=phase):
                rows = [sample(0, phase=phase), sample(10, phase=phase)]
                before = copy.deepcopy(rows)
                result = review.review_samples(rows, idle(phase))
                incarnation = result["incarnations"][0]
                self.assertEqual(incarnation["load_phases_observed"], [phase])
                self.assertEqual(set(incarnation["phase_coverage"]), {phase})
                self.assertEqual(incarnation["idle_window"]["status"], "TRAFFIC_PHASE_IS_NOT_IDLE")
                self.assertFalse(incarnation["idle_window"]["declaration_chronology_verified"])
                self.assertFalse(incarnation["idle_window"]["causal_retirement_proven"])
                self.assertEqual([s["phase"] for s in result["sample_observations"]], [phase, phase])
                self.assertEqual(rows, before)

    def test_unknown_arbitrary_and_near_miss_phase_names_never_gain_idle_meaning(self):
        for phase in ("idle", "Idle-retirement", "idle_retirement", "idle-retirement ",
                      "idle-retirement-extra", "arbitrary-phase", "recovery-unreviewed"):
            with self.subTest(phase=phase):
                rows = [sample(0, phase=phase), sample(10, phase=phase)]
                before = copy.deepcopy(rows)
                result = review.review_samples(rows, idle(phase))
                incarnation = result["incarnations"][0]
                self.assertEqual(incarnation["idle_window"]["status"], "UNKNOWN_UNSUPPORTED_IDLE_PHASE")
                self.assertEqual(incarnation["idle_window"]["declaration"]["phase"], phase)
                self.assertEqual(set(incarnation["phase_coverage"]), {phase})
                self.assertEqual(incarnation["load_phases_observed"], [])
                self.assertFalse(incarnation["idle_window"]["causal_retirement_proven"])
                self.assertEqual(rows, before)

    def test_short_drain_is_not_the_supported_idle_retirement_phase(self):
        rows = [sample(0, phase="drain"), sample(10, phase="drain")]
        result = review.review_samples(rows, idle("drain"))
        incarnation = result["incarnations"][0]
        self.assertEqual(incarnation["idle_window"]["status"], "UNKNOWN_UNSUPPORTED_IDLE_PHASE")
        self.assertEqual(set(incarnation["phase_coverage"]), {"drain"})
        declared_supported = review.review_samples(rows, idle())["incarnations"][0]["idle_window"]
        self.assertEqual(declared_supported["status"], "UNKNOWN_INCOMPLETE_IDLE_COVERAGE")
        self.assertEqual(declared_supported["samples"], 0)
        self.assertFalse(declared_supported["continuous_unsampled_coverage_proven"])
        self.assertFalse(declared_supported["causal_retirement_proven"])

    def test_interleaved_actual_traffic_denies_supported_idle_window_coverage(self):
        for phase in sorted(review.TRAFFIC_PHASES):
            with self.subTest(phase=phase):
                rows = [sample(0, phase="idle-retirement"), sample(5, phase=phase),
                        sample(10, phase="idle-retirement")]
                result = review.review_samples(rows, idle())
                incarnation = result["incarnations"][0]
                coverage = incarnation["idle_window"]
                self.assertEqual(coverage["status"], "UNKNOWN_INCOMPLETE_IDLE_COVERAGE")
                self.assertEqual(coverage["unrepresented_node_samples"], 1)
                self.assertEqual(coverage["samples"], 2)
                self.assertIn(phase, incarnation["phase_coverage"])
                self.assertFalse(coverage["declaration_chronology_verified"])
                self.assertFalse(coverage["continuous_unsampled_coverage_proven"])
                self.assertFalse(coverage["causal_retirement_proven"])

    def test_interleaved_unknown_or_drain_samples_are_not_erased_from_idle_coverage(self):
        for phase in ("arbitrary-phase", "drain", "idle_retirement", "recovery-unreviewed"):
            with self.subTest(phase=phase):
                rows = [sample(0, phase="idle-retirement"), sample(5, phase=phase),
                        sample(10, phase="idle-retirement")]
                result = review.review_samples(rows, idle())
                incarnation = result["incarnations"][0]
                self.assertEqual(set(incarnation["phase_coverage"]), {"idle-retirement", phase})
                self.assertEqual(incarnation["idle_window"]["status"], "UNKNOWN_INCOMPLETE_IDLE_COVERAGE")
                self.assertEqual(incarnation["idle_window"]["unrepresented_node_samples"], 1)
                self.assertEqual(result["sample_observations"][1]["phase"], phase)
                self.assertFalse(incarnation["idle_window"]["causal_retirement_proven"])

if __name__ == "__main__":
    unittest.main()
