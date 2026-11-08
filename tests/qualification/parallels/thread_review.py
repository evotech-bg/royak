"""Offline thread-attribution v3 DATA, never a leak/retirement gate.

No procfs, subprocess, network, environment, argv or stack collection. Existing
aggregate thresholds are neither evaluated nor changed here. All observation
bounds describe samples, not exact kernel birth/exit times or harmless workers.
"""
import argparse
import bisect
import hashlib
import json
import math
import os
from pathlib import Path
import stat

# Offline analysis refusal limits, NOT product, collector or kernel allowances.
MAX_INPUT_BYTES = 64 * 1024**2
MAX_REPORT_BYTES = 32 * 1024**2
MAX_ROWS = 10_000
MAX_THREADS_PER_SAMPLE = 4_096
MAX_OBSERVATIONS = 200_000
MAX_IDENTITIES = 50_000
# Exact aliases emitted by soak.FAULTS and the inherited fault() phase setter.
FAULT_TRAFFIC_PHASES = frozenset(("pod-kill", "leader-sigkill", "control-partition", "node-restart", "wireguard-down"))
RECOVERY_TRAFFIC_PHASES = frozenset("recovery-" + phase for phase in FAULT_TRAFFIC_PHASES)
TRAFFIC_PHASES = (frozenset(("warmup", "baseline", "steady", "soak", "load", "fault", "recovery", "final"))
                  | FAULT_TRAFFIC_PHASES | RECOVERY_TRAFFIC_PHASES)
IDLE_RETIREMENT_PHASE = "idle-retirement"
BASELINE_PHASES = frozenset(("warmup", "baseline"))
LOAD_PHASES = TRAFFIC_PHASES - BASELINE_PHASES


def _integer(value, label, minimum=0, maximum=2**64 - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("invalid " + label)
    return value


def _ticks(value, label):
    if type(value) is str and value.isascii() and value.isdecimal() and len(value) <= 20:
        value = int(value)
    return _integer(value, label)


def _number(value, label, minimum=0):
    if type(value) not in (int, float) or not minimum <= value <= 10**12 or not math.isfinite(value):
        raise ValueError("invalid " + label)
    return value


def _text(value, label, maximum=128):
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError("invalid " + label)
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("control character in " + label)
    return value


def _idle_policy(value):
    if value is None:
        return None
    if type(value) is not dict or set(value) != {"phase", "start_s", "end_s", "minimum_span_s", "declaration_sha256"}:
        raise ValueError("invalid idle declaration fields")
    phase = _text(value["phase"], "idle phase", 64)
    start = _number(value["start_s"], "idle start")
    end = _number(value["end_s"], "idle end")
    span = _number(value["minimum_span_s"], "idle minimum span")
    pin = value["declaration_sha256"]
    if not end > start or not 0 < span <= end - start:
        raise ValueError("invalid idle declaration interval")
    if type(pin) is not str or len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        raise ValueError("invalid external idle declaration hash")
    return dict(phase=phase, start_s=start, end_s=end, minimum_span_s=span, declaration_sha256=pin)


def _identity(key):
    node, boot, pid, process_start, tid, thread_start = key
    return dict(node=node, boot_id=boot, pid=pid, process_start_ticks=process_start,
                tid=tid, thread_start_ticks=thread_start)


def _incarnation(key):
    return dict(node=key[0], boot_id=key[1], pid=key[2], process_start_ticks=key[3])


def _idle_coverage(samples, policy):
    base = dict(declaration_chronology_verified=False, causal_retirement_proven=False)
    if policy is None:
        return dict(base, status="UNKNOWN_NO_PREDECLARED_IDLE_WINDOW")
    if policy["phase"] in TRAFFIC_PHASES:
        return dict(base, status="TRAFFIC_PHASE_IS_NOT_IDLE", declaration=policy)
    if policy["phase"] != IDLE_RETIREMENT_PHASE:
        return dict(base, status="UNKNOWN_UNSUPPORTED_IDLE_PHASE", declaration=policy)
    selected = [s for s in samples if s["phase"] == policy["phase"]
                and policy["start_s"] <= s["at_s"] <= policy["end_s"]]
    complete = [s for s in selected if s["census_complete"]]
    span = complete[-1]["at_s"] - complete[0]["at_s"] if len(complete) >= 2 else None
    unrepresented_node_samples = sum(max(0, b["node_sample_ordinal"] - a["node_sample_ordinal"] - 1)
                                     for a, b in zip(selected, selected[1:]))
    covered = (bool(selected) and len(complete) == len(selected) and not unrepresented_node_samples
               and span is not None and span >= policy["minimum_span_s"])
    return dict(base, status="COHERENT_DECLARED_WINDOW_OBSERVED" if covered else "UNKNOWN_INCOMPLETE_IDLE_COVERAGE",
                declaration=policy, samples=len(selected), complete_samples=len(complete), observed_span_s=span,
                unrepresented_node_samples=unrepresented_node_samples,
                maximum_observed_sample_gap_s=max((b["at_s"] - a["at_s"] for a, b in zip(selected, selected[1:])), default=None),
                continuous_unsampled_coverage_proven=False,
                external_declaration_is_a_reference_not_verified_pre_run_authority=True)


def review_samples(rows, idle_window=None):
    """Pure canonical soak-row review; old missing thread_census stays UNKNOWN.

    The caller retains original raw backing. Returned metadata omits arbitrary
    row fields and error messages. Incomplete categories intentionally overlap.
    """
    policy = _idle_policy(idle_window)
    summaries, issues, incarnations, threads, last_node_time, node_ordinals = [], [], {}, {}, {}, {}
    process_start_maxima, thread_start_maxima = {}, {}
    observations = 0
    any_census = False
    for index, row in enumerate(rows):
        if index >= MAX_ROWS:
            raise ValueError("offline row bound exceeded; no truncation")
        if type(row) is not dict:
            raise ValueError("row must be an object")
        if "metrics" not in row and {"at", "incarnation", "tasks"} <= set(row):
            raise ValueError("UNREPRESENTABLE_FLAT_SCHEMA7: missing original node/boot_id/pid/clock_ticks/elapsed_s/phase; no synthetic adapter")
        node = _integer(row.get("node"), "node", 1, 2**31 - 1)
        at = _number(row.get("elapsed_s"), "sample elapsed time")
        phase = _text(row.get("phase"), "sample phase", 64)
        if node in last_node_time and at <= last_node_time[node]:
            raise ValueError("node sample times must increase; no sorting/rewrite")
        last_node_time[node] = at
        ordinal = node_ordinals.get(node, 0)
        node_ordinals[node] = ordinal + 1
        categories = []
        sample = dict(index=index, node=node, at_s=at, phase=phase, node_sample_ordinal=ordinal,
                      census_complete=False, categories=categories)
        summaries.append(sample)
        metric = row.get("metrics")
        if row.get("error") or type(metric) is not dict:
            categories.append("SAMPLE_UNAVAILABLE")
            continue
        if type(metric.get("schema_version")) is not int or metric["schema_version"] != 2:
            categories.append("METRICS_SCHEMA_UNKNOWN")
            continue
        boot = _text(metric.get("boot_id"), "boot identity")
        process = metric.get("process")
        if process is None:
            categories.append("PROCESS_ABSENT_NOT_THREAD_ABSENCE")
            continue
        if type(process) is not dict:
            raise ValueError("invalid process object")
        pid = _integer(process.get("pid"), "process PID", 1, 2**31 - 1)
        process_start = _ticks(process.get("start_ticks"), "process start")
        process_key = (node, boot, pid)
        previous_process_start = process_start_maxima.get(process_key)
        if previous_process_start is not None and process_start < previous_process_start:
            categories.append("PROCESS_START_REWIND_WITHIN_BOOT_PID")
            sample["previous_process_start_max_ticks"] = previous_process_start
        process_start_maxima[process_key] = max(process_start, previous_process_start if previous_process_start is not None else process_start)
        ikey = (node, boot, pid, process_start)
        inc = incarnations.setdefault(ikey, [])
        inc.append(sample)
        sample["incarnation"] = _incarnation(ikey)
        count = process.get("threads")
        if type(count) is not int or count < 0:
            categories.append("THREAD_STATUS_COUNT_UNKNOWN")
            count = None
        elif count == 0:
            categories.append("THREAD_STATUS_NOT_POSITIVE")
        sample["status_threads"] = count
        hz = metric.get("clock_ticks")
        if type(hz) is not int or not 0 < hz <= 2**32 - 1:
            categories.append("CLOCK_TICKS_UNKNOWN")
            hz = None
        census = process.get("thread_census")
        if census is None:
            categories.append("THREAD_CENSUS_MISSING")
            continue
        if type(census) is not dict:
            raise ValueError("invalid thread census")
        any_census = True
        values = census.get("threads")
        if type(values) is not list or len(values) > MAX_THREADS_PER_SAMPLE:
            raise ValueError("invalid or oversized offline thread census")
        reported_observed = census.get("observed")
        if type(reported_observed) is not int or reported_observed != len(values):
            categories.append("CENSUS_OBSERVED_COUNT_MISMATCH")
        if count is not None and count != len(values):
            categories.append("STATUS_CENSUS_NONATOMIC_MISMATCH")
        vanished, errors = census.get("exited_during_sample"), census.get("errors")
        if type(vanished) is not list or type(errors) is not list:
            raise ValueError("missing census race/error arrays")
        if len(vanished) > MAX_THREADS_PER_SAMPLE or len(errors) > MAX_THREADS_PER_SAMPLE:
            raise ValueError("offline race/error bound exceeded")
        sample["vanished_tids"] = [_integer(v, "vanished TID", 1, 2**31 - 1) for v in vanished]
        if vanished:
            categories.append("TASK_VANISHED_DURING_SAMPLE")
        sample["census_errors"] = []
        for error in errors:
            if type(error) is not dict:
                raise ValueError("invalid census error")
            sample["census_errors"].append(dict(tid=_integer(error.get("tid"), "error TID", 1, 2**31 - 1),
                                                error_class=_text(error.get("error"), "error class")))
        if errors:
            categories.append("CENSUS_ERRORS")
        seen, main_count = set(), 0
        for value in values:
            observations += 1
            if observations > MAX_OBSERVATIONS:
                raise ValueError("offline observation bound exceeded; no truncation")
            if type(value) is not dict:
                raise ValueError("invalid thread observation")
            tid = _integer(value.get("tid"), "TID", 1, 2**31 - 1)
            start = _ticks(value.get("start_ticks"), "thread start")
            if start < process_start:
                categories.append("THREAD_START_PRECEDES_PROCESS_START")
            if tid == pid:
                main_count += 1
                if start != process_start:
                    categories.append("MAIN_TID_START_MISMATCH")
            tid_key = ikey + (tid,)
            previous_thread_start = thread_start_maxima.get(tid_key)
            if previous_thread_start is not None and start < previous_thread_start:
                categories.append("THREAD_START_REWIND_WITHIN_PROCESS_TID")
            thread_start_maxima[tid_key] = max(start, previous_thread_start if previous_thread_start is not None else start)
            key = ikey + (tid, start)
            if tid in seen:
                categories.append("DUPLICATE_TID_IN_CENSUS")
            seen.add(tid)
            if key not in threads and len(threads) >= MAX_IDENTITIES:
                raise ValueError("offline identity bound exceeded; no truncation")
            cpu = value.get("cpu_ticks")
            if type(cpu) is not int or not 0 <= cpu <= 2**64 - 1:
                categories.append("THREAD_CPU_COUNTER_UNKNOWN")
                cpu = None
            wait = value.get("wait_channel")
            if wait is not None:
                wait = _text(wait, "wait channel")
            else:
                categories.append("WAIT_CHANNEL_UNKNOWN")
            if value.get("wait_channel_error") is not None:
                categories.append("WAIT_CHANNEL_ERROR")
            observation = dict(sample_index=index, node_sample_ordinal=ordinal, at_s=at, phase=phase,
                               cpu_ticks=cpu, clock_ticks=hz, comm=_text(value.get("comm"), "thread comm"),
                               state=_text(value.get("state"), "thread state", 8), wait_channel=wait)
            threads.setdefault(key, []).append(observation)
        if main_count != 1:
            categories.append("MAIN_TID_MISSING" if main_count == 0 else "MAIN_TID_NOT_UNIQUE")
        sample["observed_main_tid_rows"] = main_count
        sample["census_observed_threads"] = len(values)
        categories[:] = sorted(set(categories))
        sample["census_complete"] = not categories
    for sample in summaries:
        if sample["categories"]:
            issues.append(dict(sample_index=sample["index"], node=sample["node"], at_s=sample["at_s"],
                               categories=list(sample["categories"])))
    groups, thread_rows, census_indexes = [], [], {}
    for ikey, samples in sorted(incarnations.items()):
        complete = [s for s in samples if s["census_complete"]]
        census_indexes[ikey] = (complete, [s["at_s"] for s in complete])
        phases = {}
        for sample in samples:
            p = phases.setdefault(sample["phase"], dict(samples=0, complete_samples=0, first_s=sample["at_s"], last_s=sample["at_s"]))
            p["samples"] += 1
            p["complete_samples"] += int(sample["census_complete"])
            p["last_s"] = sample["at_s"]
        groups.append(dict(identity=_incarnation(ikey), first_observed_s=samples[0]["at_s"],
                           last_observed_s=samples[-1]["at_s"], phase_coverage=phases,
                           baseline_phases_observed=sorted(set(phases) & BASELINE_PHASES),
                           load_phases_observed=sorted(set(phases) & LOAD_PHASES), idle_window=_idle_coverage(samples, policy)))
    for key, values in sorted(threads.items()):
        samples = incarnations[key[:4]]
        complete, times = census_indexes[key[:4]]
        first, last = values[0], values[-1]
        before = bisect.bisect_left(times, first["at_s"]) - 1
        after = bisect.bisect_right(times, last["at_s"])
        birth = None if before < 0 else dict(after_full_census_omission_s=times[before],
            by_first_observation_s=first["at_s"], exact_birth_proven=False,
            intervening_node_samples=first["node_sample_ordinal"] - complete[before]["node_sample_ordinal"] - 1)
        disappearance = None if after == len(complete) else dict(after_last_observation_s=last["at_s"],
            by_full_census_omission_s=times[after], exact_exit_proven=False,
            intervening_node_samples=complete[after]["node_sample_ordinal"] - last["node_sample_ordinal"] - 1)
        intervals, counter_issues, reobserved = [], [], []
        for previous, current in zip(values, values[1:]):
            if current["at_s"] <= previous["at_s"]:
                counter_issues.append(dict(at_s=current["at_s"], category="NONINCREASING_THREAD_OBSERVATION_TIME"))
                continue
            p, c = previous["cpu_ticks"], current["cpu_ticks"]
            if p is None or c is None or previous["clock_ticks"] is None or current["clock_ticks"] is None:
                counter_issues.append(dict(at_s=current["at_s"], category="CPU_INTERVAL_UNKNOWN"))
            elif c < p:
                counter_issues.append(dict(at_s=current["at_s"], category="CPU_COUNTER_DECREASE"))
            elif current["clock_ticks"] != previous["clock_ticks"]:
                counter_issues.append(dict(at_s=current["at_s"], category="CLOCK_TICKS_CHANGED"))
            else:
                seconds = (c - p) / current["clock_ticks"]
                percent = seconds / (current["at_s"] - previous["at_s"]) * 100
                if not math.isfinite(percent):
                    counter_issues.append(dict(at_s=current["at_s"], category="DERIVED_CPU_INTERVAL_NONFINITE"))
                else:
                    intervals.append(dict(from_s=previous["at_s"], to_s=current["at_s"], delta_ticks=c - p,
                        cpu_seconds=seconds, one_core_percent=percent,
                        intervening_node_samples=current["node_sample_ordinal"] - previous["node_sample_ordinal"] - 1))
            omitted = bisect.bisect_right(times, previous["at_s"])
            if omitted < len(times) and times[omitted] < current["at_s"]:
                reobserved.append(dict(omitted_at_s=times[omitted], reobserved_at_s=current["at_s"],
                                       category="REOBSERVED_AFTER_FULL_CENSUS_OMISSION"))
        thread_rows.append(dict(identity=_identity(key), first_observed_s=first["at_s"], last_observed_s=last["at_s"],
            observed_span_s=last["at_s"] - first["at_s"], observations=values, birth_observation_bounds=birth,
            disappearance_observation_bounds=disappearance,
            observed_present_in_last_incarnation_census=last["at_s"] == samples[-1]["at_s"],
            not_observed_absent_after_last_seen=disappearance is None, cpu_intervals=intervals,
            activity_issues=counter_issues, omission_reobservations=reobserved,
            worker_name_or_wait_channel_is_not_harmlessness_or_exit_proof=True))
    category_counts = {}
    for issue in issues:
        for category in issue["categories"]:
            category_counts[category] = category_counts.get(category, 0) + 1
    activity_issue_count = sum(len(t["activity_issues"]) for t in thread_rows)
    omission_reobservation_count = sum(len(t["omission_reobservations"]) for t in thread_rows)
    return dict(schema_version=1, review_algorithm_version=3, kind="offline-thread-observation-attribution-data",
                review_state="UNKNOWN_NO_ROWS" if not summaries else "INCOMPLETE_OBSERVATIONS" if issues or activity_issue_count or omission_reobservation_count else "OBSERVATIONS_REVIEWED",
                samples=len(summaries), samples_with_issues=len(issues), overlapping_category_counts=category_counts,
                activity_issue_count=activity_issue_count, omission_reobservation_count=omission_reobservation_count,
                samples_in_multiple_categories=sum(len(s["categories"]) > 1 for s in summaries),
                categories_are_not_disjoint=True, sample_issues=issues, sample_observations=summaries,
                observed_thread_identity_count=len(thread_rows) if any_census else None,
                thread_identities=thread_rows if any_census else None, incarnations=groups,
                idle_declaration=policy, aggregate_thresholds_evaluated=False,
                positive_status_and_matching_main_required_for_complete_census=True,
                relative_start_order_checked=True, absolute_boot_age_or_wallclock_start_join_verified=False,
                claims_excluded=["leak-free", "exact kernel birth or exit", "harmless pool attribution",
                    "late pool retirement", "verified pre-run declaration chronology", "production qualification"],
                scope="Recorded sampled metadata only; no stacks/argv/environment; absence is not exact exit. Existing +8 aggregate gate remains separate.")


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _json(raw):
    return json.loads(raw, object_pairs_hook=_no_duplicates,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON number")))


def _read_original(path, limit):
    if not path.is_absolute() or path.resolve(strict=True) != path or path.is_symlink():
        raise ValueError("input must be an exact nonsymlink absolute path")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_size > limit:
            raise ValueError("input is not bounded original owned regular data")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        named = path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or len(raw) > limit or any(getattr(before, k) != getattr(after, k) or getattr(after, k) != getattr(named, k) for k in fields):
            raise ValueError("original input changed during bounded read")
        return raw, {k: getattr(after, k) for k in fields}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="one NEW report in an existing private owned directory")
    parser.add_argument("--idle-declaration", type=Path)
    args = parser.parse_args()
    raw, metadata = _read_original(args.input, MAX_INPUT_BYTES)
    lines = raw.decode("utf-8", errors="strict").splitlines()
    if len(lines) > MAX_ROWS or any(not line for line in lines):
        raise ValueError("invalid/oversized JSONL framing; no skipping")
    declaration, declaration_record = None, None
    if args.idle_declaration is not None:
        policy_raw, policy_meta = _read_original(args.idle_declaration, 4096)
        declaration = _json(policy_raw)
        declaration_record = dict(raw_sha256=hashlib.sha256(policy_raw).hexdigest(), metadata=policy_meta,
                                  chronology_verified=False)
    result = review_samples((_json(line) for line in lines), declaration)
    result["original_input"] = dict(path=str(args.input), bytes=len(raw), raw_sha256=hashlib.sha256(raw).hexdigest(), metadata=metadata)
    result["idle_declaration_input"] = declaration_record
    encoded = json.dumps(result, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n"
    if len(encoded) > MAX_REPORT_BYTES:
        raise ValueError("offline report bound exceeded; no truncation/output")
    output = args.output
    if not output.is_absolute() or output.parent.resolve(strict=True) != output.parent or output.parent.is_symlink():
        raise ValueError("output requires an exact existing parent")
    parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        owner = os.fstat(parent_fd)
        if not stat.S_ISDIR(owner.st_mode) or owner.st_uid != os.getuid() or stat.S_IMODE(owner.st_mode) != 0o700:
            raise ValueError("output parent must be private and owned")
        parent_named = output.parent.lstat()
        parent_fields = ("st_dev", "st_ino", "st_mode", "st_uid")
        if any(getattr(owner, k) != getattr(parent_named, k) for k in parent_fields):
            raise ValueError("output parent replaced before report creation")
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            if stream.write(encoded) != len(encoded):
                raise OSError("short report write; partial evidence retained")
            stream.flush()
            os.fsync(stream.fileno())
            actual, named = os.fstat(stream.fileno()), os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            if (not stat.S_ISREG(actual.st_mode) or actual.st_uid != os.getuid() or actual.st_nlink != 1
                or stat.S_IMODE(actual.st_mode) != 0o600 or actual.st_size != len(encoded)
                or any(getattr(actual, k) != getattr(named, k) for k in fields)):
                raise ValueError("new report identity changed; evidence retained")
        os.fsync(parent_fd)
        if any(getattr(owner, k) != getattr(output.parent.lstat(), k) for k in parent_fields):
            raise ValueError("output parent replaced after report creation; evidence retained")
    finally:
        os.close(parent_fd)
    print(json.dumps(dict(report=str(output), bytes=len(encoded), report_sha256=hashlib.sha256(encoded).hexdigest(),
                          input_raw_sha256=hashlib.sha256(raw).hexdigest(), kind="DATA_REVIEW_ONLY"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
