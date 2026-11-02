"""Container-local process/task state; no argv, environment or payload capture."""
import collections
import json
import os
from pathlib import Path
import stat

# Collector refusal bounds only, not product/thread/leak acceptance limits.
MAX_TASKS = 4096
MAX_STAT_BYTES = 16 * 1024
MAX_WCHAN_BYTES = 1024


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


def _task_ids(process):
    values = []
    with os.scandir(process / 'task') as entries:
        for entry in entries:
            if (not entry.name.isascii() or not entry.name.isdecimal()
                    or str(int(entry.name)) != entry.name or not entry.is_dir(follow_symlinks=False)):
                raise ValueError('unexpected task directory entry')
            tid = int(entry.name)
            if not 0 < tid < 2**31:
                raise ValueError('invalid task directory TID')
            values.append(tid)
            if len(values) > MAX_TASKS:
                raise CensusBoundExceeded('too many tasks; no truncated census')
    return sorted(values)


def thread_census(process, *, expected_pid=None, expected_start_ticks=None):
    """Sample identities, with explicit races/errors, never a leak-free claim.

    The production sampler supplies both expected identity fields. Unpinned
    calls remain diagnostic-only for old fixtures; no liveness is inferred.
    observed counts recorded rows, NOT a missing/failed total thread count.
    Even matching pre/post reads do not prove continuous atomic coverage.
    """
    process = Path(process)
    pinned = expected_pid is not None or expected_start_ticks is not None
    if pinned:
        if type(expected_pid) is not int or not 0 < expected_pid < 2**31 or type(expected_start_ticks) is not str:
            raise ValueError('both original process identity fields required')
        _natural(expected_start_ticks)
    threads, exited, errors = [], [], []
    before = after = ids_before = ids_after = None

    def error(tid, category):
        errors.append(dict(tid=tid, error=category))

    def process_identity():
        row = parse_task_stat(_bounded_text(process / 'stat', MAX_STAT_BYTES), expected_pid)
        return dict(pid=row['tid'], start_ticks=row['start_ticks'])

    def finish():
        return dict(threads=threads, observed=len(threads), exited_during_sample=sorted(set(exited)), errors=errors,
                    process_identity_pinned=pinned, process_before=before, process_after=after,
                    process_identity_consistent=(before == after == dict(pid=expected_pid, start_ticks=expected_start_ticks)) if pinned else None,
                    task_ids_before=ids_before, task_ids_after=ids_after,
                    task_set_consistent=ids_before == ids_after if ids_before is not None and ids_after is not None else None,
                    observed_is_recorded_rows_not_total=True, atomic_continuous_coverage_proven=False)

    if pinned:
        try:
            before = process_identity()
            if before != dict(pid=expected_pid, start_ticks=expected_start_ticks):
                error(expected_pid, 'ProcessIdentityBeforeMismatch')
                return finish()
        except (OSError, ValueError) as exc:
            error(expected_pid, type(exc).__name__)
            return finish()
    try:
        ids_before = _task_ids(process)
    except (OSError, ValueError) as exc:
        if not pinned:
            raise
        error(expected_pid, type(exc).__name__)
        return finish()
    if pinned and expected_pid not in ids_before:
        error(expected_pid, 'MainTaskMissingFromDirectory')
    for tid in ids_before:
        task = process / 'task' / str(tid)
        try:
            row = parse_task_stat(_bounded_text(task / 'stat', MAX_STAT_BYTES), tid)
        except FileNotFoundError:
            exited.append(tid)
            continue
        except (OSError, ValueError) as exc:
            error(tid, type(exc).__name__)
            continue
        try:
            row['wait_channel'] = _safe_text(_bounded_text(task / 'wchan', MAX_WCHAN_BYTES).strip())
        except OSError as exc:
            row['wait_channel'] = None
            row['wait_channel_error'] = type(exc).__name__
        except ValueError as exc:
            row['wait_channel'] = None
            row['wait_channel_error'] = type(exc).__name__
        threads.append(row)  # retain actual first stat even if later metadata races
        if pinned:
            try:
                returned = parse_task_stat(_bounded_text(task / 'stat', MAX_STAT_BYTES), tid)
                if returned['start_ticks'] != row['start_ticks']:
                    error(tid, 'ThreadIncarnationChanged')
            except FileNotFoundError:
                exited.append(tid)
            except (OSError, ValueError) as exc:
                error(tid, type(exc).__name__)
    try:
        ids_after = _task_ids(process)
        if ids_after != ids_before:
            error(expected_pid if pinned else ids_before[0] if ids_before else 1, 'TaskSetChanged')
    except (OSError, ValueError) as exc:
        error(expected_pid if pinned else ids_before[0] if ids_before else 1, type(exc).__name__)
    if pinned:
        try:
            after = process_identity()
            if after != before:
                error(expected_pid, 'ProcessIncarnationChanged')
        except (OSError, ValueError) as exc:
            error(expected_pid, type(exc).__name__)
    return finish()


def census(proc_root=Path('/proc'), exclude_pid=None):
    processes=[]
    for path in proc_root.iterdir():
        if not path.name.isdigit() or int(path.name)==exclude_pid: continue
        try:
            raw=(path/'stat').read_text()
            left,fields=raw.rsplit(') ',1)
            fields=fields.split()
            processes.append(dict(pid=int(path.name),comm=left.split('(',1)[1],state=fields[0],
                                  ppid=int(fields[1]),pgrp=int(fields[2]),session=int(fields[3]),
                                  start_ticks=fields[19],
                                  threads=len(list((path/'task').iterdir()))))
        except (OSError,ValueError):
            continue  # a task may exit while sampling
    return dict(processes=sorted(processes,key=lambda p:p['pid']),
                states=dict(collections.Counter(p['state'] for p in processes)),
                tasks=sum(p['threads'] for p in processes),
                zombies=[p for p in processes if p['state']=='Z'])


if __name__=='__main__': print(json.dumps(census(exclude_pid=os.getpid())))
