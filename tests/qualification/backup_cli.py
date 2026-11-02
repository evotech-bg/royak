"""Actual offline metadata-backup safety checks; private files, no daemon/network."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


SEED = dict(schemaVersion=1, namespaces=["default", "team-a"],
            configmaps=[dict(name="settings", namespace="team-a", data={"K": "V"})])


def collect(binary):
    rows = []
    for case in ("missing source", "valid existing source", "existing destination",
                 "live owner", "Raft authority", "corrupt source", "source symlink",
                 "destination symlink", "source as destination", "no Docker dependency"):
        with tempfile.TemporaryDirectory(prefix="rkq-backup-cli-") as directory:
            root = Path(directory)
            source, target = root / "state.json", root / "backup.json"
            source.write_text(json.dumps(SEED))
            before = source.read_bytes()
            env = dict(HOME=directory, PATH=os.environ.get("PATH", ""),
                       ROYAK_STATE=str(source), ROYAK_DATA_DIR=str(root / "data"),
                       ROYAK_NO_DOCKER="1", DOCKER_HOST="unix://" + str(root / "missing.sock"))
            owner = None
            if case == "missing source":
                source.unlink()
            elif case == "existing destination":
                target.write_bytes(b"earlier recovery point")
            elif case == "live owner":
                owner = (root / "state.json.lock").open("w")
                fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
            elif case == "Raft authority":
                raft = root / "state.json.raft"
                raft.mkdir()
                (raft / "snapshot.json").write_bytes(b"owned authoritative fixture")
            elif case == "corrupt source":
                source.write_bytes(b"{bad json")
                before = source.read_bytes()
            elif case == "source symlink":
                source.rename(root / "real-state.json")
                source.symlink_to(root / "real-state.json")
            elif case == "destination symlink":
                (root / "retained").write_bytes(b"earlier recovery point")
                target.symlink_to(root / "retained")
            elif case == "source as destination":
                target = source
            elif case == "no Docker dependency":
                env.pop("ROYAK_NO_DOCKER")
            try:
                result = subprocess.run([str(binary.resolve()), "backup", str(target)],
                                        env=env, capture_output=True, text=True, timeout=10)
            finally:
                if owner:
                    owner.close()
            success = case in ("valid existing source", "no Docker dependency")
            if success:
                try:
                    backup = json.loads(target.read_text())
                    good = (result.returncode == 0 and backup["state"]["configmaps"]["team-a/settings"]["data"]["K"] == "V"
                            and target.stat().st_mode & 0o777 == 0o600)
                except (OSError, ValueError, KeyError, TypeError):
                    good = False
            else:
                good = result.returncode != 0 and "backed up" not in result.stdout
                if case == "existing destination":
                    good = good and target.read_bytes() == b"earlier recovery point"
                elif case == "destination symlink":
                    good = good and target.is_symlink() and (root / "retained").read_bytes() == b"earlier recovery point"
                elif case != "source as destination":
                    good = good and not target.exists()
            if source.exists():
                good = good and source.read_bytes() == before
            rows.append(dict(name=case, passed=bool(good), exit_code=result.returncode))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("refusing to overwrite earlier evidence")
    rows = collect(args.binary)
    report = dict(passed=all(r["passed"] for r in rows), checks=rows,
                  binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  scope="actual offline metadata CLI; not volume backup or live Raft export")
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return int(not report["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
