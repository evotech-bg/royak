"""Real pinned-restic component checks. Not Royak backup/auth integration."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree(root):
    rows = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        row = dict(mode=stat.S_IMODE(info.st_mode))
        if path.is_symlink(): row.update(kind="symlink", target=os.readlink(path))
        elif path.is_dir(): row.update(kind="directory")
        elif path.is_file(): row.update(kind="file", sha256=sha(path), bytes=info.st_size)
        else: raise RuntimeError("unexpected source file type")
        rows[str(path.relative_to(root))] = row
    return rows


def collect(binary, build, checks):
    expected = next(v for v in build["builds"] if v["platform"] == "darwin_arm64")
    assert sha(binary) == expected["sha256"] and build["version"] == "0.19.1"
    with tempfile.TemporaryDirectory(prefix="rkq-restic-") as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir(); (source / "nested").mkdir()
        (source / "nested" / "данни.bin").write_bytes(os.urandom(2 * 1024**2))
        (source / "empty").write_bytes(b"")
        (source / "private").write_bytes(b"owned-cold-backup-fixture\n")
        (source / "private").chmod(0o600)
        (root / "not-source").write_bytes(b"must-not-follow-symlink")
        (source / "link").symlink_to(root / "not-source")
        original = tree(source)
        key = root / "key"
        key.write_text(os.urandom(32).hex()); key.chmod(0o600)
        wrong = root / "wrong"
        wrong.write_text(os.urandom(32).hex()); wrong.chmod(0o600)
        env = dict(PATH=os.environ.get("PATH", ""), HOME=str(root), RESTIC_PASSWORD_FILE=str(key),
                   RESTIC_CACHE_DIR=str(root / "cache"))
        repo = root / "repository"

        def run(*args, password=key):
            return subprocess.run([str(binary.resolve()), "--repo", str(repo), "--no-cache", *args],
                                  env=dict(env, RESTIC_PASSWORD_FILE=str(password)),
                                  capture_output=True, text=True, timeout=120)

        def check(name, passed, **details):
            checks.append(dict(name=name, passed=bool(passed), **details))

        result = run("init", "--repository-version", "2")
        check("fresh encrypted owned repository initialized", result.returncode == 0)
        result = run("backup", "--json", "--one-file-system", str(source))
        summary = next(json.loads(line) for line in result.stdout.splitlines()
                       if json.loads(line).get("message_type") == "summary")
        snapshot = summary.get("snapshot_id", "")
        check("cold capture returns exact full snapshot ID", result.returncode == 0 and len(snapshot) == 64)
        snapshots = run("snapshots", "--json")
        check("snapshot is independently listed in repository", snapshots.returncode == 0
              and snapshot in {v["id"] for v in json.loads(snapshots.stdout)})
        result = run("check", "--read-data")
        check("full data check succeeds before restore", result.returncode == 0)
        destination = root / "restore-one"
        assert not destination.exists()
        result = run("restore", snapshot, "--target", str(destination))
        restored = destination / str(source).lstrip("/")
        check("isolated restore matches exact bytes modes and symlinks", result.returncode == 0 and tree(restored) == original)
        (source / "private").write_bytes(b"changed-later")
        increment = run("backup", "--json", str(source))
        later = next(json.loads(line)["snapshot_id"] for line in increment.stdout.splitlines()
                     if json.loads(line).get("message_type") == "summary")
        check("second incremental recovery point has a distinct identity", increment.returncode == 0 and len(later) == 64 and later != snapshot)
        # Exit 3 is a real partial backup, not a valid complete capture.
        unreadable = source / "unreadable"
        unreadable.write_bytes(b"incomplete-input")
        unreadable.chmod(0)
        try: incomplete = run("backup", "--json", str(source))
        finally: unreadable.chmod(0o600)
        check("unreadable source returns incomplete exit 3", incomplete.returncode == 3, exit_code=incomplete.returncode)
        # Delete only this fixture's source, retaining the independent expected
        # content digest in memory. The earlier point must remain restorable.
        import shutil
        shutil.rmtree(source)
        destination = root / "restore-after-source-loss"
        assert not destination.exists()
        result = run("restore", snapshot, "--target", str(destination))
        restored = destination / str(source).lstrip("/")
        check("old snapshot restores after source loss and later modifications", result.returncode == 0 and tree(restored) == original)
        result = run("check", "--read-data", password=wrong)
        check("wrong recovery key is rejected", result.returncode != 0)
        result = run("restore", "0"*64, "--target", str(root / "missing-snapshot"))
        check("unknown exact snapshot cannot be restored", result.returncode != 0)
        packs = sorted(p for p in (repo / "data").rglob("*") if p.is_file())
        assert packs
        pack = max(packs, key=lambda p:p.stat().st_size)
        pack.chmod(0o600)  # Deliberate corruption of this disposable fixture only.
        with pack.open("r+b") as stream:
            stream.seek(pack.stat().st_size // 2)
            value = stream.read(1); stream.seek(-1, 1); stream.write(bytes([value[0] ^ 0xff]))
        result = run("check", "--read-data")
        check("corrupt pack is rejected by full data check", result.returncode != 0)
        result = run("restore", snapshot, "--target", str(root / "corrupt-restore"))
        check("corrupt data cannot yield a successful restore", result.returncode != 0)
        quarantine = root / "missing-pack"
        pack.rename(quarantine)
        result = run("check", "--read-data")
        check("missing pack fails repository verification", result.returncode != 0)
    return checks


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.output.exists(): p.error("refusing to overwrite prior evidence")
    checks, error = [], None
    try: collect(a.binary, json.loads(a.build.read_text()), checks)
    except Exception as e: error = f"{type(e).__name__}: {e}"
    report = dict(passed=bool(checks) and error is None and all(r["passed"] for r in checks), checks=checks, error=error,
                  binary_sha256=sha(a.binary), fixture_sha256=sha(Path(__file__)),
                  build_manifest_sha256=sha(a.build),
                  scope="restic dependency component only; no Royak auth, job lifecycle, live-DB or disaster-recovery qualification")
    with a.output.open("x") as stream:
        json.dump(report, stream, indent=2); stream.write("\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__": main()
