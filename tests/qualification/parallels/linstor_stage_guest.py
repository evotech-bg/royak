#!/usr/bin/env python3
"""Unprivileged, pinned private extraction only; no package scripts or service.

Does not start a controller/satellite, touch block devices or change networking.
The caller owns the original SSH and this script owns every original child.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def put(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    root = args.root
    assert os.getuid() == 1000 and root.resolve() == root
    assert root.parent == Path.home() / ".local/share/royak-qualification"
    assert root.name == "linstor-footprint-20261102-v1"
    assert root.stat().st_uid == os.getuid() and stat.S_IMODE(root.stat().st_mode) == 0o700
    assert sha(root / "package-plan.json") == args.plan_sha256
    plan = json.loads((root / "package-plan.json").read_bytes())
    assert not plan["package_installation"] and len(plan["packages"]) == 4
    assert not (root / "stage-report.json").exists() and not (root / "downloads").exists()
    os.umask(0o077)
    (root / "downloads").mkdir(mode=0o700)
    (root / "payloads").mkdir(mode=0o700)
    (root / "logs").mkdir(mode=0o700)
    home = root / "child-home"
    home.mkdir(mode=0o700)
    env = dict(PATH="/usr/bin:/bin", HOME=str(home), LANG="C.UTF-8", LC_ALL="C.UTF-8")
    children = []
    report = dict(kind="linstor-private-package-staging", passed=False, packages=[], children=[],
        package_installation=False, package_scripts_executed=False, runtime_started=False,
        backend_selected=False, storage_or_network_mutation=False)

    def run(tag, argv, seconds):
        put(root / (tag + "-intent.json"), dict(argv=argv, budget_seconds=seconds))
        log = (root / "logs" / (tag + ".log")).open("xb")
        child = subprocess.Popen(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
            stdout=log, stderr=subprocess.STDOUT, close_fds=True, start_new_session=True)
        children.append((child, log))
        put(root / (tag + "-launched.json"), dict(pid=child.pid, argv=argv))
        try:
            code = child.wait(timeout=seconds)
        except BaseException as error:
            put(root / (tag + "-UNKNOWN.json"), dict(pid=child.pid, error=type(error).__name__, retained=True, no_signal=True))
            while child.poll() is None:
                time.sleep(1)
            # Natural completion never turns UNKNOWN into normal success.
            log.flush()
            os.fsync(log.fileno())
            log.close()
            raise
        log.flush()
        os.fsync(log.fileno())
        log.close()
        put(root / (tag + "-finished.json"), dict(pid=child.pid, exit_code=code, log_sha256=sha(root / "logs" / (tag + ".log"))))
        report["children"].append(dict(tag=tag, pid=child.pid, exit_code=code))
        assert code == 0, "known terminal staging command failed: " + tag
        return (root / "logs" / (tag + ".log")).read_text()

    try:
        for row in plan["packages"]:
            name = row["package"]
            assert name in {"linstor-common", "linstor-controller", "linstor-satellite", "openjdk-21-jre-headless"}
            target = root / "downloads" / row["filename"]
            assert target.parent == root / "downloads" and not target.exists()
            run("download-" + name, ["curl", "--fail", "--location", "--silent", "--show-error",
                "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "10", "--max-time", "90",
                "--output", str(target), row["url"]], 100)
            assert target.stat().st_size == row["bytes"] and sha(target) == row["sha256"], "pinned package bytes differ"
            metadata = run("metadata-" + name, ["dpkg-deb", "--field", str(target), "Package", "Version", "Architecture"], 20)
            fields = dict(line.split(": ", 1) for line in metadata.splitlines())
            assert fields == {"Package":name, "Version":row["version"], "Architecture":row["architecture"]}
            payload = root / "payloads" / name
            assert not payload.exists()
            run("extract-" + name, ["dpkg-deb", "--extract", str(target), str(payload)], 60)
            report["packages"].append(dict(package=name, sha256=row["sha256"], bytes=row["bytes"], payload=str(payload)))
        java = root / "payloads/openjdk-21-jre-headless/usr/lib/jvm/java-21-openjdk-arm64/bin/java"
        report["java_version"] = run("java-version", [str(java), "--version"], 30)
        launchers = []
        for name in ["linstor-common", "linstor-controller", "linstor-satellite"]:
            for file in (root / "payloads" / name / "usr/share/linstor-server/bin").glob("*"):
                if file.is_file() and file.stat().st_size <= 32 * 1024:
                    launchers.append(dict(path=str(file.relative_to(root)), sha256=sha(file), bytes=file.stat().st_size, text=file.read_text()))
        report["launchers"] = launchers
        report["passed"] = True
    except BaseException as error:
        report["failure"] = type(error).__name__ + ": " + str(error)
    report["all_original_children_reaped"] = all(child.poll() is not None for child, _ in children)
    put(root / "stage-report.json", report)
    print(json.dumps(dict(passed=report["passed"], failure=report.get("failure"), java_version=report.get("java_version"),
        packages=len(report["packages"]), all_original_children_reaped=report["all_original_children_reaped"])), flush=True)
    return int(not report["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
