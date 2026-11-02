"""Explicitly approved, exact-three-guest DRBD visibility adjustment.

Initial mount namespace only. Keep original bytes and receipts. The survey
opt-out persists; only the exact temporary resource include is removed.
No DRBD CLI, network, TLS, quorum, timeout, package or service changes here.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

ROOT = Path('/home/royak/.local/share/royak-qualification/linstor-footprint-20261102-v1')
CASE = ROOT / 'data-attempt6'
GLOBAL = Path('/etc/drbd.d/global_common.conf')
MAIN = Path('/etc/drbd.conf')
INCLUDE = Path('/etc/drbd.d/rkq-linstor-data-a6.res')
TARGET = CASE / 'owned-var-lib/linstor.d/rkls_data_20261102_a6.res'
ARCHIVES = Path('/var/lib/royak-storage-qualification')
ORIGINAL = 'b5da1949687e64e2b8e0473d25ada00c84be856cde5b84e427a02dbcab589082'
MAIN_SHA = '90e150d20287caa62650e0d5be648eaa3fe4b48ed1b0ea0f3e66c42f37527314'
BODY = ('# Owned Royak qualification a6; remove after exact-run shutdown.\n'
        'include "' + str(TARGET) + '";\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def directory(path, uid=0):
    s = path.lstat()
    assert stat.S_ISDIR(s.st_mode) and s.st_uid == uid and s.st_mode & 0o022 == 0, str(path)
    assert path.resolve() == path, 'symlinked directory: ' + str(path)
    return s


def regular(path, uid=0, mode=None):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        assert stat.S_ISREG(s.st_mode) and s.st_uid == uid and s.st_nlink == 1
        assert s.st_mode & 0o022 == 0 and s.st_size <= 65536
        if mode is not None:
            assert stat.S_IMODE(s.st_mode) == mode
        raw = os.read(fd, 65537)
        assert len(raw) == s.st_size
        identity = dict(dev=s.st_dev, inode=s.st_ino, uid=s.st_uid, gid=s.st_gid,
                        mode=stat.S_IMODE(s.st_mode), size=s.st_size, sha256=digest(raw),
                        mtime_ns=str(s.st_mtime_ns), ctime_ns=str(s.st_ctime_ns))
        return raw, identity
    finally:
        os.close(fd)


def same_file(path, expected):
    raw, actual = regular(path, expected['uid'], expected['mode'])
    assert actual == expected, 'exact original file changed: ' + str(path)
    return raw


def fresh(path, raw, mode):
    directory(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
        os.fchmod(fd, mode)
        s = os.fstat(fd)
        assert stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1
    finally:
        os.close(fd)
    fsync_dir(path.parent)


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def record(path, value):
    fresh(path, (json.dumps(value, indent=2) + '\n').encode(), 0o400)


def opted_out(raw):
    assert digest(raw) == ORIGINAL and raw.count(b'usage-count yes;') == 1
    result = raw.replace(b'usage-count yes;', b'usage-count no;', 1)
    assert result != raw
    return result


def guard(node):
    assert os.getuid() == 0 and node in [1, 2, 3]
    assert Path('/etc/royak-lab-owner').read_text().strip() == 'rkq-vm-20261028-royak'
    assert os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'), 'not initial mount namespace'
    assert subprocess.check_output(['hostname'], text=True).strip() == 'rkq-vm-20261028-royak-n' + str(node)
    assert os.path.realpath('/lab') == '/var/lib/royak-qualification/rkq-soak-20261029-175129-343525'
    for parent in [Path('/etc'), GLOBAL.parent, Path('/var'), Path('/var/lib')]:
        directory(parent)
    assert digest(regular(MAIN)[0]) == MAIN_SHA
    return ARCHIVES / ('drbd-visibility-20261102-v1-n' + str(node))


def quiescent():
    assert subprocess.check_output(['docker', 'ps', '-aq'], text=True).strip() == ''
    assert json.loads(subprocess.check_output(['drbdsetup', 'status', '--json'], text=True)) == []
    assert subprocess.check_output(['wg', 'show', 'interfaces'], text=True).strip() == ''
    for p in Path('/proc').iterdir():
        if p.name.isdigit():
            try:
                comm = (p / 'comm').read_text().strip()
                assert comm not in ['java', 'postgres', 'restic'] and 'royak' not in comm
                if comm.startswith('python'):
                    assert int(p.name) == os.getpid(), 'another Python owner remains'
            except (FileNotFoundError, ProcessLookupError):
                pass


def archive_state(archive):
    directory(ARCHIVES)
    directory(archive)
    original, _ = regular(archive / 'global_common.conf.original', mode=0o400)
    assert digest(original) == ORIGINAL
    receipt = json.loads(regular(archive / 'optout-applied.json', mode=0o400)[0])
    assert same_file(GLOBAL, receipt['after']) == opted_out(original)
    return receipt


def apply_optout(archive):
    quiescent()
    assert not archive.exists() and not archive.is_symlink()
    original, before = regular(GLOBAL)
    replacement = opted_out(original)
    if not ARCHIVES.exists():
        ARCHIVES.mkdir(mode=0o700)
        fsync_dir(ARCHIVES.parent)
    directory(ARCHIVES)
    archive.mkdir(mode=0o700)
    fsync_dir(ARCHIVES)
    fresh(archive / 'global_common.conf.original', original, 0o400)
    record(archive / 'optout-intent.json', dict(before=before, replacement_sha256=digest(replacement)))
    same_file(GLOBAL, before)
    temporary = GLOBAL.parent / '.rkq-a6-global-optout.tmp'
    fresh(temporary, replacement, before['mode'])
    os.chown(temporary, before['uid'], before['gid'])
    same_file(GLOBAL, before)
    os.replace(temporary, GLOBAL)
    fsync_dir(GLOBAL.parent)
    actual, after = regular(GLOBAL)
    assert actual == replacement and after['uid'] == before['uid'] and after['gid'] == before['gid']
    result = dict(before=before, after=after, backup_sha256=digest(regular(archive / 'global_common.conf.original', mode=0o400)[0]),
                  only_semantic_change='usage-count yes -> no', archive=str(archive), survey_optout_persists=True)
    record(archive / 'optout-applied.json', result)
    return result


def target_probe():
    for path in [ROOT, CASE, CASE / 'owned-var-lib', TARGET.parent]:
        directory(path, 1000)
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    raw, identity = regular(TARGET, mode=0o600)
    assert raw == b'', 'target must be a fresh, empty root-owned placeholder'
    assert not INCLUDE.exists() and not INCLUDE.is_symlink()
    return identity


def include_install(archive):
    quiescent()
    archive_state(archive)
    target = target_probe()
    record(archive / 'include-intent.json', dict(path=str(INCLUDE), sha256=digest(BODY), target=str(TARGET), placeholder=target))
    fresh(INCLUDE, BODY, 0o600)
    raw, identity = regular(INCLUDE, mode=0o600)
    assert raw == BODY
    result = dict(include=identity, target=str(TARGET), placeholder=target)
    record(archive / 'include-installed.json', result)
    return result


def include_remove(archive):
    quiescent()
    archive_state(archive)
    installed = json.loads(regular(archive / 'include-installed.json', mode=0o400)[0])
    assert same_file(INCLUDE, installed['include']) == BODY
    # Revalidate after acquiring a no-follow directory fd; remove just this leaf.
    directory(INCLUDE.parent)
    fd = os.open(INCLUDE.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        same_file(INCLUDE, installed['include'])
        os.unlink(INCLUDE.name, dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)
    assert not INCLUDE.exists() and not INCLUDE.is_symlink()
    result = dict(removed=True, exact_include=installed['include'], survey_optout_persists=True,
                  original_archived=True, target_and_old_evidence_not_deleted=True)
    record(archive / 'include-removed.json', result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--node', type=int, choices=[1, 2, 3], required=True)
    p.add_argument('--action', choices=['probe-original', 'optout', 'include-probe', 'include-install', 'include-remove'], required=True)
    a = p.parse_args()
    os.umask(0o077)
    archive = guard(a.node)
    if a.action == 'probe-original':
        quiescent()
        original, identity = regular(GLOBAL)
        opted_out(original)
        assert not archive.exists() and not archive.is_symlink()
        assert not INCLUDE.exists() and not INCLUDE.is_symlink()
        result = dict(original=identity, archive_absent=True, include_absent=True)
    elif a.action == 'optout':
        result = apply_optout(archive)
    elif a.action == 'include-probe':
        archive_state(archive)
        quiescent()
        result = dict(target=target_probe())
    elif a.action == 'include-install':
        result = include_install(archive)
    else:
        result = include_remove(archive)
    print(json.dumps(dict(passed=True, action=a.action, node=a.node, result=result)), flush=True)


if __name__ == '__main__':
    main()
