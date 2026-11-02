"""Pinned Royak thread metadata, not process ownership, idle or leak authority.

Production reads ONLY the explicit expected incarnation through the original
/lab/royak.pid locator and /proc. Alternate roots belong to the private test
adapter, never a fallback. No filesystem or process observation occurs at import.
"""
import json
import os
from pathlib import Path
import re
import stat
import time

# Observation-refusal bounds, never product/soak/thread-growth thresholds.
MAX_TASKS = 4096
MAX_STAT_BYTES = 16 * 1024
MAX_WCHAN_BYTES = 1024
MAX_STATUS_BYTES = 64 * 1024
MAX_PID_BYTES = 64
MAX_BOOT_BYTES = 64

class CensusBoundExceeded(ValueError):
    pass


def _bounded_text(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('not regular proc metadata')
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise CensusBoundExceeded('proc metadata exceeds observation bound')
        return raw.decode('utf-8', errors='strict')


def _natural(value):
    if not value.isascii() or not value.isdecimal() or len(value) > 20:
        raise ValueError('invalid proc counter')
    number = int(value)
    if number > 2**64 - 1:
        raise ValueError('proc counter overflow')
    return number


def _safe_text(value):
    if not value or len(value.encode('utf-8')) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('unrepresentable proc text')
    return value


def parse_task_stat(raw, expected_tid):
    """Linux stat fields 14/15 and 22; comm can contain spaces/parentheses."""
    left, suffix = raw.rsplit(') ', 1)
    identity, comm = left.split(' (', 1)
    fields = suffix.split()
    if (_natural(identity) != expected_tid or len(fields) < 20 or len(fields[0]) != 1
            or not fields[0].isascii() or not fields[0].isalpha()):
        raise ValueError('proc stat identity or field framing differs')
    start = fields[19]
    _natural(start)
    utime, stime = _natural(fields[11]), _natural(fields[12])
    cpu = utime + stime
    if cpu > 2**64 - 1:
        raise ValueError('combined proc CPU counter overflow')
    return dict(tid=expected_tid, comm=_safe_text(comm), state=_safe_text(fields[0]),
                start_ticks=start, cpu_ticks=cpu, utime_ticks=utime, stime_ticks=stime)


_STATUS_KEYS = ("Name", "State", "Pid", "Tgid", "Threads",
                "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches")
_BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _expected(pid, start, boot):
    if type(pid) is not int or not 0 < pid < 2**31 or type(start) is not str:
        raise ValueError("explicit original PID/start/boot required")
    _natural(start)
    if str(int(start)) != start or type(boot) is not str or not _BOOT.fullmatch(boot):
        raise ValueError("canonical original start/boot required")
    return dict(pid=pid, start_ticks=start, boot_id=boot)


def _boot(path):
    value = _bounded_text(path, MAX_BOOT_BYTES).strip()
    if not _BOOT.fullmatch(value):
        raise ValueError("invalid boot metadata")
    return value


def _pid(path):
    value = _natural(_bounded_text(path, MAX_PID_BYTES).strip())
    if not 0 < value < 2**31:
        raise ValueError("invalid PID locator metadata")
    return value


def _executable(process, expected):
    # Match actual resolved name AND inode at both endpoints. This is not
    # atomic, and cannot rule out intervening same-path exec or hostile races.
    target = process / "exe"
    same_name = target.resolve(strict=True) == expected
    actual, named = target.stat(), expected.stat()
    if not stat.S_ISREG(actual.st_mode) or not stat.S_ISREG(named.st_mode):
        raise ValueError("not regular executable metadata")
    return dict(matches_expected=same_name and (actual.st_dev, actual.st_ino) == (named.st_dev, named.st_ino),
                device=actual.st_dev, inode=actual.st_ino)


def _clock_ticks():
    return os.sysconf("SC_CLK_TCK")


def _leader(paths, expected):
    locator, proc, executable = paths
    value = dict(boot_id=None, locator_pid=None, executable=None, stat=None,
                 matched_expected=None, errors=[])
    stage = "boot"
    try:
        value["boot_id"] = _boot(proc / "sys/kernel/random/boot_id")
        if value["boot_id"] != expected["boot_id"]:
            value["matched_expected"] = False
            value["errors"].append(dict(stage=stage, error="BootIdentityMismatch"))
            return value
        stage = "pid_locator"
        value["locator_pid"] = _pid(locator)
        if value["locator_pid"] != expected["pid"]:
            value["matched_expected"] = False
            value["errors"].append(dict(stage=stage, error="LocatorPidMismatch"))
            return value  # never adopt a replacement locator PID
        process = proc / str(expected["pid"])
        stage = "executable"
        value["executable"] = _executable(process, executable)
        if not value["executable"]["matches_expected"]:
            value["matched_expected"] = False
            value["errors"].append(dict(stage=stage, error="ExecutableMismatch"))
            return value
        stage = "leader_stat"
        value["stat"] = parse_task_stat(_bounded_text(process / "stat", MAX_STAT_BYTES), expected["pid"])
        value["matched_expected"] = value["stat"]["start_ticks"] == expected["start_ticks"]
        if not value["matched_expected"]:
            value["errors"].append(dict(stage=stage, error="ProcessStartMismatch"))
    except (OSError, ValueError, RuntimeError) as error:
        # Do not leak raw paths/exception text, argv, environment or payload.
        value["errors"].append(dict(stage=stage, error=type(error).__name__))
    return value


def _scan_tasks(process):
    value = dict(ids=[], directory_entries_observed=0, complete=False,
                 truncated=False, errors=[])
    seen = set()
    try:
        if (process / "task").is_symlink():
            raise ValueError("task directory is a symlink")
        with os.scandir(process / "task") as entries:
            for entry in entries:
                value["directory_entries_observed"] += 1
                if value["directory_entries_observed"] > MAX_TASKS:
                    value["truncated"] = True
                    value["errors"].append("CensusBoundExceeded")
                    break  # observed prefix only; never claim this is a total
                name = entry.name
                if (not name.isascii() or not name.isdecimal() or len(name) > 10
                        or str(int(name)) != name or not 0 < int(name) < 2**31
                        or not entry.is_dir(follow_symlinks=False)):
                    value["errors"].append("UnexpectedTaskDirectoryEntry")
                    continue
                tid = int(name)
                if tid in seen:
                    value["errors"].append("DuplicateTaskDirectoryEntry")
                    continue
                seen.add(tid)
                value["ids"].append(tid)
        value["ids"].sort()
        value["complete"] = not value["truncated"] and not value["errors"]
    except (OSError, ValueError) as error:
        value["errors"].append(type(error).__name__)
    return value


def parse_task_status(raw, tid, leader_pid):
    """Selected bounded metadata only; malformed/missing never becomes zero."""
    if type(raw) is not str or len(raw.encode("utf-8")) > MAX_STATUS_BYTES:
        raise CensusBoundExceeded("status DATA exceeds observation bound")
    fields = dict.fromkeys(_STATUS_KEYS)
    duplicates = dict.fromkeys(_STATUS_KEYS, 0)
    seen, invalid, errors = set(), set(), []
    for line in raw.splitlines():
        key, separator, text = line.partition(":")
        if not separator or key not in fields:
            continue
        if key in seen:
            fields[key] = None
            invalid.add(key)
            duplicates[key] += 1
            if duplicates[key] == 1:
                errors.append(dict(field=key, error="DuplicateStatusField"))
            continue
        seen.add(key)
        try:
            text = text.strip()
            if key == "Name":
                fields[key] = _safe_text(text)
            elif key == "State":
                tokens = text.split()
                if not tokens or len(tokens[0]) != 1 or not tokens[0].isascii() or not tokens[0].isalpha():
                    raise ValueError("invalid status state")
                fields[key] = tokens[0]
            else:
                fields[key] = _natural(text)
                if key in ("Pid", "Tgid") and not 0 < fields[key] < 2**31:
                    raise ValueError("invalid status identity")
                if key == "Threads" and fields[key] == 0:
                    raise ValueError("invalid status thread quantity")
        except ValueError as error:
            fields[key] = None
            invalid.add(key)
            errors.append(dict(field=key, error=type(error).__name__))
    missing = [key for key in _STATUS_KEYS if key not in seen]
    for key in missing:
        errors.append(dict(field=key, error="StatusFieldUnavailable"))
    for key, expected in (("Pid", tid), ("Tgid", leader_pid)):
        if fields[key] is not None and fields[key] != expected:
            errors.append(dict(field=key, error="StatusIdentityMismatch"))
    return dict(fields=fields, missing_fields=missing, duplicate_counts=duplicates,
                invalid_fields=sorted(invalid), errors=errors)


def _thread(process, tid, pid):
    task = process / "task" / str(tid)
    row = dict(tid=tid, comm=None, state=None, start_ticks=None, utime_ticks=None,
               stime_ticks=None, cpu_ticks=None, stat_before=None, stat_after=None,
               stat_identity_consistent=None, wait_channel=None, wait_channel_error=None,
               status_fields=None, status_missing_fields=None, status_duplicate_counts=None, status_errors=[],
               missing_stat_metadata=[], errors=[])
    for stage in ("stat_before", "status", "wchan", "stat_after"):
        try:
            if stage.startswith("stat_"):
                value = parse_task_stat(_bounded_text(task / "stat", MAX_STAT_BYTES), tid)
                row[stage] = value
                if stage == "stat_before":
                    for key in ("comm", "state", "start_ticks", "utime_ticks", "stime_ticks", "cpu_ticks"):
                        row[key] = value[key]  # SAME first stat, never later counters
            elif stage == "status":
                value = parse_task_status(_bounded_text(task / "status", MAX_STATUS_BYTES), tid, pid)
                row["status_fields"] = value["fields"]
                row["status_missing_fields"] = value["missing_fields"]
                row["status_duplicate_counts"] = value["duplicate_counts"]
                row["status_errors"] = value["errors"]
            else:
                row["wait_channel"] = _safe_text(_bounded_text(task / "wchan", MAX_WCHAN_BYTES).strip())
        except (OSError, ValueError) as error:
            category = type(error).__name__
            row["errors"].append(dict(stage=stage, error=category))
            if stage.startswith("stat_") and isinstance(error, FileNotFoundError):
                row["missing_stat_metadata"].append(stage)
            if stage == "wchan":
                row["wait_channel_error"] = category  # missing wchan is NOT exit
    before, after = row["stat_before"], row["stat_after"]
    if before is not None and after is not None:
        row["stat_identity_consistent"] = before["start_ticks"] == after["start_ticks"]
        if not row["stat_identity_consistent"]:
            row["errors"].append(dict(stage="stat_after", error="ThreadIncarnationChanged"))
        elif any(after[key] < before[key] for key in ("utime_ticks", "stime_ticks")):
            row["errors"].append(dict(stage="stat_after", error="CpuCounterRegressed"))
    row["complete"] = (row["stat_identity_consistent"] is True and row["wait_channel"] is not None
                       and row["status_fields"] is not None and not row["status_errors"] and not row["errors"])
    return row


def _collect_paths(locator, proc_root, expected_executable, *, expected_pid, expected_start_ticks, expected_boot_id):
    """Private adapter for Root-owned fixture roots, never automatic fallback."""
    expected = _expected(expected_pid, expected_start_ticks, expected_boot_id)
    paths = (Path(locator), Path(proc_root), Path(expected_executable))
    began = time.monotonic()
    before = _leader(paths, expected)
    result = dict(schema="royak-pinned-thread-census-v1", metadata_only=True,
                  expected=expected, leader_before=before, leader_after=None,
                  leader_identity_consistent=None, task_census_before=None, task_census_after=None,
                  threads=[], errors=[], churn=None, clock_ticks=None, observation_status="UNAVAILABLE",
                  coverage=dict(complete=False, truncated=False, recorded_rows=0,
                                valid_first_stat_rows=0, complete_rows=0, total_threads=None),
                  bounds=dict(max_tasks=MAX_TASKS, max_stat_bytes=MAX_STAT_BYTES,
                              max_status_bytes=MAX_STATUS_BYTES, max_wchan_bytes=MAX_WCHAN_BYTES,
                              max_pid_bytes=MAX_PID_BYTES, max_boot_bytes=MAX_BOOT_BYTES),
                  atomic_continuous_coverage_proven=False, owned_service_authority=False,
                  idle_retirement_or_stable_growth_or_leak_proven=False)
    try:
        ticks = _clock_ticks()
        if type(ticks) is not int or not 0 < ticks < 2**64:
            raise ValueError("invalid observed clock frequency")
        result["clock_ticks"] = ticks
    except (OSError, ValueError, AttributeError) as error:
        result["errors"].append("ClockTicks:" + type(error).__name__)
    process = paths[1] / str(expected_pid)
    if before["matched_expected"] is True:
        first = _scan_tasks(process)
        result["task_census_before"] = first
        if expected_pid not in first["ids"]:
            result["errors"].append("MainTaskMissingFromObservedDirectory")
        for tid in first["ids"]:
            result["threads"].append(_thread(process, tid, expected_pid))
        result["task_census_after"] = _scan_tasks(process)
    # Actual endpoints are attempted even after a partial census, never filled
    # from an earlier sample or inferred from a pid locator or missing metadata.
    after = _leader(paths, expected)
    result["leader_after"] = after
    matched = (before["matched_expected"], after["matched_expected"])
    if False in matched:
        result["leader_identity_consistent"] = False
    elif matched == (True, True):
        result["leader_identity_consistent"] = before["executable"] == after["executable"]
        if not result["leader_identity_consistent"]:
            result["errors"].append("ExecutableIdentityChanged")
    for row in result["threads"]:
        if row["tid"] == expected_pid and any(observed is not None and observed["start_ticks"] != expected_start_ticks
                                               for observed in (row["stat_before"], row["stat_after"])):
            result["leader_identity_consistent"] = False
            result["errors"].append("LeaderTaskIncarnationMismatch")
            row["complete"] = False
    first, last = result["task_census_before"], result["task_census_after"]
    if first is not None and last is not None:
        same = first["complete"] and last["complete"] and first["ids"] == last["ids"]
        result["churn"] = dict(endpoint_comparison_complete=first["complete"] and last["complete"],
                               same_observed_tid_set=same,
                               before_only_observed_tids=sorted(set(first["ids"]) - set(last["ids"])),
                               after_only_observed_tids=sorted(set(last["ids"]) - set(first["ids"])),
                               incarnation_changed_tids=[row["tid"] for row in result["threads"] if row["stat_identity_consistent"] is False])
        if first["complete"] and last["complete"] and first["ids"] != last["ids"]:
            result["errors"].append("TaskSetChanged")
        if same:
            for row in result["threads"]:
                fields = row["status_fields"]
                if fields is not None and fields["Threads"] is not None and fields["Threads"] != len(first["ids"]):
                    row["errors"].append(dict(stage="status", error="ThreadQuantityChanged"))
                    row["complete"] = False
    rows = result["threads"]
    coverage = result["coverage"]
    coverage.update(recorded_rows=len(rows),
                    valid_first_stat_rows=sum(row["stat_before"] is not None for row in rows),
                    complete_rows=sum(row["complete"] for row in rows),
                    truncated=any(value is not None and value["truncated"] for value in (first, last)))
    coverage["complete"] = (result["leader_identity_consistent"] is True and first is not None and last is not None
                            and first["complete"] and last["complete"] and first["ids"] == last["ids"]
                            and expected_pid in first["ids"] and bool(rows)
                            and all(row["complete"] for row in rows) and not result["errors"])
    if result["leader_identity_consistent"] is not True:
        result["observation_status"] = "UNKNOWN_IDENTITY" if result["leader_identity_consistent"] is False else "UNAVAILABLE"
    else:
        result["observation_status"] = "OBSERVED_NONATOMIC" if coverage["complete"] else "PARTIAL"
    if coverage["complete"]:
        coverage["total_threads"] = len(rows)  # non-atomic endpoint census only
    result["elapsed_observer_seconds"] = time.monotonic() - began
    return result


def collect_royak_threads(*, expected_pid, expected_start_ticks, expected_boot_id):
    """One Root-authorized expected incarnation; no PID discovery/adoption."""
    return _collect_paths(Path("/lab/royak.pid"), Path("/proc"), Path("/opt/royak"),
                          expected_pid=expected_pid, expected_start_ticks=expected_start_ticks,
                          expected_boot_id=expected_boot_id)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-pid", type=int, required=True)
    parser.add_argument("--expected-start-ticks", required=True)
    parser.add_argument("--expected-boot-id", required=True)
    args = parser.parse_args()
    value = collect_royak_threads(expected_pid=args.expected_pid,
                                  expected_start_ticks=args.expected_start_ticks,
                                  expected_boot_id=args.expected_boot_id)
    print(json.dumps(value, sort_keys=True))
    return int(not value["coverage"]["complete"])


if __name__ == "__main__":
    raise SystemExit(main())

