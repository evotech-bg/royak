"""Guest-local, metadata-only resource sample; no environment/key/payload capture."""
import collections
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time

from pid_census import census, thread_census, parse_task_stat


def output(*args):
    return subprocess.check_output(args, text=True, timeout=8).strip()


def path_usage(path):
    """Apparent and allocated bytes, without following links outside the lab."""
    path=Path(path)
    try: info=path.lstat()
    except FileNotFoundError:return dict(present=False,kind=None,bytes=None,allocated_bytes=None,files=None)
    kind='directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'other'
    if kind=='other':raise RuntimeError('unexpected telemetry path type: '+str(path))
    entries=[path] if kind=='file' else [path,*path.rglob('*')]
    size=allocated=count=0
    for entry in entries:
        try: value=entry.lstat()
        except FileNotFoundError:continue  # atomic replacement during sampling
        if stat.S_ISREG(value.st_mode):size+=value.st_size;count+=1
        allocated+=value.st_blocks*512
    return dict(present=True,kind=kind,bytes=size,allocated_bytes=allocated,files=count)


# Observation-refusal bounds only, not Royak acceptance/resource thresholds.
MAX_STAT_BYTES = 16 * 1024
MAX_STATUS_BYTES = 64 * 1024
MAX_PID_BYTES = 64


class ObservationBoundExceeded(ValueError):
    pass


def _metadata_text(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("not regular process metadata")
        raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ObservationBoundExceeded("process metadata exceeds observation bound")
        return raw.decode("utf-8", errors="strict")


def _counter(value):
    if not value.isascii() or not value.isdecimal() or len(value) > 20:
        raise ValueError("invalid process counter")
    result = int(value)
    if result > 2**64 - 1:
        raise ValueError("process counter overflow")
    return result


def _read_pid(path):
    value = _counter(_metadata_text(path, MAX_PID_BYTES).strip())
    if not 0 < value < 2**31:
        raise ValueError("invalid locator PID")
    return value


def _read_stat(process, pid):
    return parse_task_stat(_metadata_text(process / "stat", MAX_STAT_BYTES), pid)


def _read_status(process):
    selected = {}
    for line in _metadata_text(process / "status", MAX_STATUS_BYTES).splitlines():
        key, separator, value = line.partition(":")
        if separator and key in ("VmRSS", "Threads"):
            if key in selected:
                raise ValueError("duplicate required status field")
            selected[key] = value.split()
    if set(selected) != {"VmRSS", "Threads"}:
        raise ValueError("required status metadata unavailable")
    rss, threads = selected["VmRSS"], selected["Threads"]
    if len(rss) != 2 or rss[1] != "kB" or len(threads) != 1:
        raise ValueError("invalid required status field")
    rss_bytes, count = _counter(rss[0]) * 1024, _counter(threads[0])
    if rss_bytes > 2**64 - 1 or count == 0:
        raise ValueError("invalid required process quantity")
    return dict(rss_bytes=rss_bytes, threads=count)


def _read_executable(process, expected):
    # Keep only metadata, never another process's path/argv. These separate
    # reads are not atomic and cannot rule out intervening same-path exec.
    target = process / "exe"
    matches = target.resolve(strict=True) == expected
    actual, named = target.stat(), expected.stat()
    if not stat.S_ISREG(actual.st_mode) or not stat.S_ISREG(named.st_mode):
        raise ValueError("not regular executable metadata")
    return dict(matches_expected=matches and (actual.st_dev, actual.st_ino) == (named.st_dev, named.st_ino),
                device=actual.st_dev, inode=actual.st_ino)


def _census_partial(value, status_threads):
    if type(value) is not dict:
        raise ValueError("invalid returned census shape")
    rows, errors, vanished = value.get("threads"), value.get("errors"), value.get("exited_during_sample")
    if type(rows) is not list or type(errors) is not list or type(vanished) is not list:
        raise ValueError("invalid returned census fields")
    if any(type(row) is not dict for row in rows):
        raise ValueError("invalid returned thread row")
    return (bool(errors or vanished) or value.get("task_set_consistent") is not True
            or value.get("observed") != len(rows) or status_threads != len(rows)
            or any(row.get("wait_channel") is None or row.get("wait_channel_error") is not None for row in rows))


def observe_process(pid_file=Path("/lab/royak.pid"), proc_root=Path("/proc"),
                    expected_executable=Path("/opt/royak")):
    """Metadata context around one actual locator PID, never service authority.

    Unavailable context returns process=None, not zero, retaining actual parsed
    observations/census where available. Matching endpoints cannot rule out
    intervening churn, same-path exec or hostile replacement between reads.
    Tests pass only their NEW owned fixture roots; defaults do no import IO.
    """
    observation = dict(schema_version=1, status="UNAVAILABLE", pid=None,
        exe_before=None, executable_before=None, stat_before=None, status_fields=None, fd_count=None,
        thread_census=None, stat_after=None, exe_after=None, executable_after=None, errors=[],
        census_location=None, atomic_continuous_coverage_proven=False,
        owned_unit_continuity_proven=False, idle_or_retirement_authority=False)

    def error(stage, category):
        # Fixed stages/error classes only; never str(exc), raw paths or payload.
        observation["errors"].append(dict(stage=stage, error=category))

    try:
        pid = _read_pid(pid_file)
        observation["pid"] = pid
    except (OSError, ValueError) as exc:
        error("pid_locator", type(exc).__name__)
        return None, observation
    process = Path(proc_root) / str(pid)
    try:
        observation["executable_before"] = _read_executable(process, expected_executable)
        observation["exe_before"] = observation["executable_before"]["matches_expected"]
        if not observation["exe_before"]:
            error("exe_before", "ExecutableMismatch")
            return None, observation
    except (OSError, ValueError, RuntimeError) as exc:
        error("exe_before", type(exc).__name__)
        return None, observation
    try:
        before = _read_stat(process, pid)
        observation["stat_before"] = before
    except (OSError, ValueError) as exc:
        error("stat_before", type(exc).__name__)
        return None, observation
    try:
        observation["status_fields"] = _read_status(process)
    except (OSError, ValueError) as exc:
        error("status", type(exc).__name__)
    try:
        observation["fd_count"] = sum(1 for _ in (process / "fd").iterdir())
    except OSError as exc:
        error("fd_count", type(exc).__name__)
    try:
        # This pair comes from the SAME actual stat above, not a guessed PID,
        # PID filename alone, receipt, earlier incarnation or fallback.
        observation["thread_census"] = thread_census(
            process, expected_pid=pid, expected_start_ticks=before["start_ticks"])
        observation["census_location"] = "process_observation.thread_census"
    except (OSError, ValueError) as exc:
        error("thread_census", type(exc).__name__)
    try:
        observation["stat_after"] = _read_stat(process, pid)
        if observation["stat_after"]["start_ticks"] != before["start_ticks"]:
            error("stat_after", "ProcessIncarnationChanged")
    except (OSError, ValueError) as exc:
        error("stat_after", type(exc).__name__)
    try:
        observation["executable_after"] = _read_executable(process, expected_executable)
        observation["exe_after"] = observation["executable_after"]["matches_expected"]
        if not observation["exe_after"]:
            error("exe_after", "ExecutableMismatch")
        elif observation["executable_after"] != observation["executable_before"]:
            error("exe_after", "ExecutableIdentityChanged")
    except (OSError, ValueError, RuntimeError) as exc:
        error("exe_after", type(exc).__name__)
    census = observation["thread_census"]
    if type(census) is dict and (census.get("process_identity_pinned") is not True
                                or census.get("process_identity_consistent") is not True):
        error("thread_census", "PinnedProcessIdentityUnavailable")
    if observation["errors"]:
        return None, observation
    try:
        partial = _census_partial(census, observation["status_fields"]["threads"])
    except (ValueError, KeyError, TypeError) as exc:
        error("thread_census", type(exc).__name__)
        return None, observation
    fields = observation["status_fields"]
    value = dict(pid=pid, start_ticks=before["start_ticks"], cpu_ticks=before["cpu_ticks"],
        utime_ticks=before["utime_ticks"], stime_ticks=before["stime_ticks"],
        rss_bytes=fields["rss_bytes"], fds=observation["fd_count"], threads=fields["threads"],
        thread_census=census)
    # Move the SAME returned census into its schema2 location, not a copy or
    # reconstructed complete row. Unavailable samples retain it above instead.
    observation["thread_census"] = None
    observation["census_location"] = "process.thread_census"
    observation["status"] = "PARTIAL" if partial else "OBSERVED_NONATOMIC"
    return value, observation


def sample():
    result = {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
              "schema_version":2,"monotonic_s":time.monotonic(),"clock_ticks":os.sysconf('SC_CLK_TCK'),
              "root_free_bytes": shutil.disk_usage("/").free}
    result["process"], result["process_observation"] = observe_process()
    result["tcp_states"] = dict(collections.Counter(line.split()[0] for line in output("ss", "-tanH").splitlines()))
    ids = output("docker", "ps", "-aq").split()
    containers = json.loads(output("docker", "inspect", *ids)) if ids else []
    result["containers"]=[]
    for c in containers:
        row=dict(id=c['Id'],started_at=c['State']['StartedAt'],running=c['State']['Running'],oom=c['State']['OOMKilled'],
                 init=c['HostConfig'].get('Init') is True,namespace=c['Config'].get('Labels',{}).get('royak.namespace'))
        if row['running']:
            try:
                # Read the container's already-mounted procfs from the guest.
                # No docker exec: the collector creates no workload processes.
                row['census']=census(Path('/proc')/str(c['State']['Pid'])/'root/proc')
            except (OSError,ValueError) as error:row['census_error']=type(error).__name__
        result['containers'].append(row)
    result["docker_stats"] = [json.loads(line) for line in output("docker", "stats", "--no-stream", "--format", "{{json .}}").splitlines()]
    result['paths']={name:path_usage(name) for name in
                    ('/lab/state.json','/lab/state.json.raft','/lab/royak.log','/lab/data/connect-audit.jsonl')}
    result['files_bytes']={name:value['bytes'] for name,value in result['paths'].items()}
    return result


if __name__ == "__main__":
    print(json.dumps(sample()))
