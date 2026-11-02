#!/usr/bin/env python3
"""Run legacy integration suites only inside a disposable nested Docker daemon.

The legacy suites contain broad cleanup commands. This driver never executes
them on the host and never mounts the host Docker socket into the test node.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import time

from run import ROOT, HERE, LABEL, docker, digest, wait_for, source_inventory

SUITES = ["test-auth-http.sh", "test-servicelb-probes.sh", "test-http-probe-address.sh", "test-multinode.sh",
          "test-raft-cluster.sh", "test-ha-lease.sh", "test-mesh.sh", "test-ingress.sh",
          "test-load.sh", "test-build.sh", "test-neuropod.sh", "test-demo.sh", "test-k8s-negative-contract.sh", "test-http-protocol.sh", "test-beta-lifecycle-topology.sh"]


def run_suites(binary, suites, timeout, storage_driver="vfs"):
    if binary.read_bytes()[:4] != b"\x7fELF":
        raise ValueError("a Linux ELF binary is required")
    run_id = "rkq-suites-" + time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    out = HERE / ".runs" / run_id
    out.mkdir(parents=True, mode=0o700)
    node = run_id + "-node"
    volume = run_id + "-disk"
    network = run_id + "-net"
    started = time.monotonic()
    results, cleanup_errors = [], []
    failure = None
    process = None
    created_node = created_network = created_volume = False
    print("Evidence: " + str(out), flush=True)
    try:
        build_path = binary.with_name(binary.name + ".build.json")
        if build_path.exists():
            build = json.loads(build_path.read_text())
            current = {str(p.relative_to(ROOT)): digest(p) for p in source_inventory()}
            if build.get("binary_sha256") != digest(binary) or build.get("source_sha256") != current:
                raise RuntimeError("build manifest does not match binary/current embedded sources")
            (out / "build-manifest.json").write_text(json.dumps(build, indent=2))
        if shutil.disk_usage(ROOT).free < 3 * 1024**3:
            raise RuntimeError("less than 3 GiB host space; no workloads started")
        ids = docker("network", "ls", "-q").split()
        networks = json.loads(docker("network", "inspect", *ids)) if ids else []
        used = [ipaddress.ip_network(c["Subnet"]) for n in networks for c in (n["IPAM"].get("Config") or []) if c.get("Subnet")]
        subnet = next((ipaddress.ip_network(f"10.232.{i}.0/24") for i in range(1, 255)
                       if not any(ipaddress.ip_network(f"10.232.{i}.0/24").overlaps(old) for old in used)), None)
        if subnet is None:
            raise RuntimeError("no non-overlapping lab subnet")
        docker("network", "create", "--label", LABEL + "=" + run_id, "--subnet", str(subnet), network)
        created_network = True
        docker("volume", "create", "--label", LABEL + "=" + run_id, volume)
        created_volume = True
        docker("run", "-d", "--name", node, "--label", LABEL + "=" + run_id, "--privileged",
               "--memory", "3g", "--cpus", "3", "--tmpfs", "/run", "--network", network,
               "-e", "DOCKER_TLS_CERTDIR=", "-v", str(binary.resolve()) + ":/opt/royak:ro",
               "-e", "ROYAK_QUALIFICATION_NODE="+run_id,
               "-v", volume + ":/var/lib/docker", "docker:28-dind", "--tls=false", "--storage-driver=" + storage_driver,
               "--default-address-pool=base=172.30.0.0/16,size=24")
        created_node = True
        wait_for(lambda: subprocess.run(["docker", "exec", node, "docker", "info"], capture_output=True).returncode == 0,
                 "isolated suite daemon")
        actual_driver = docker("exec", node, "docker", "info", "--format", "{{.Driver}}").strip()
        if actual_driver != storage_driver:
            raise RuntimeError("unexpected nested Docker storage driver: " + actual_driver)
        print("Preparing isolated test tools…", flush=True)
        docker("exec", node, "apk", "add", "--no-cache", "bash", "curl", "python3", "lsof", "git",
               "coreutils", "util-linux", "e2fsprogs", "openssl", "iproute2", "kubectl", "tar", timeout=300)
        docker("exec", node, "git", "config", "--global", "init.defaultBranch", "main")
        # Snapshot only Git-visible working files, including dirty/untracked
        # changes. Ignored caches, .runs, .git and host credentials are excluded.
        names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT).decode().split("\0")
        names = [name for name in names if name and (ROOT / name).is_file()]
        archive = out / "source.tar"
        with tarfile.open(archive, "w") as tar:
            for name in names:
                tar.add(ROOT / name, arcname=name, recursive=False)
        docker("exec", node, "mkdir", "-p", "/snapshot", "/work")
        with archive.open("rb") as stream:
            docker("exec", "-i", node, "tar", "-xf", "-", "-C", "/snapshot", stdin=stream)
        archive.unlink()
        # Seed exact cached base images instead of repeatedly downloading them.
        images = ["alpine:3.22", "alpine:latest", "nginx:1.28-alpine", "nginx:1.29-alpine"]
        image_archive = out / "images.tar"
        docker("save", "-o", image_archive, *images)
        with image_archive.open("rb") as stream:
            docker("exec", "-i", node, "docker", "load", stdin=stream)
        image_archive.unlink()
        docker("exec", node, "docker", "tag", "nginx:1.29-alpine", "nginx:alpine")
        manifest = dict(schema_version=1, run_id=run_id, binary_sha256=digest(binary), suites=suites,
                        storage_driver=actual_driver,
                        source_sha256={name: digest(ROOT / name) for name in names},
                        tracked_diff_sha256=hashlib.sha256(subprocess.check_output(["git", "diff", "--binary"], cwd=ROOT)).hexdigest(),
                        topology="one isolated Docker daemon; legacy multi-node suites use multiple processes",
                        host_socket_mounted=False, kubectl=docker("exec", node, "kubectl", "version", "--client", "-o", "json"),
                        tar_version=docker("exec", node, "tar", "--version").splitlines()[0],
                        image_aliases={"nginx:alpine": "nginx:1.29-alpine"},
                        base_images={i: json.loads(docker("image", "inspect", i))[0]["Id"] for i in images})
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
        for suite in suites:
            if shutil.disk_usage(ROOT).free < 2 * 1024**3:
                raise RuntimeError("host space fell below 2 GiB; remaining suites not run")
            name = Path(suite).stem
            directory = "/work/" + name
            docker("exec", node, "sh", "-ec", 'mkdir -p "$1/target/release"; cp -a /snapshot/. "$1/"; cp /opt/royak "$1/target/release/royak"', "sh", directory)
            print("START " + suite, flush=True)
            (out / "progress.json").write_text(json.dumps(dict(suite=suite, started_at=time.time())))
            suite_start = time.monotonic()
            with (out / (name + ".log")).open("w") as log:
                process = subprocess.Popen(["docker", "exec", "-w", directory, node, "bash", suite], stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + timeout
                    while process.poll() is None and time.monotonic() < deadline:
                        if shutil.disk_usage(ROOT).free < 1024**3:
                            raise RuntimeError("host space below 1 GiB during suite; stopping this isolated lab")
                        time.sleep(2)
                    if process.poll() is None:
                        raise subprocess.TimeoutExpired(suite, timeout)
                    code = process.returncode
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=10)
                    code = 124
            text = (out / (name + ".log")).read_text(errors="replace")
            result = dict(suite=suite, exit_code=code, passed=code == 0, duration_s=round(time.monotonic() - suite_start, 3),
                          success_lines=len(re.findall(r"^\s*✓", text, re.M)), failure_lines=len(re.findall(r"^\s*✗", text, re.M)),
                          skip_lines=[line.strip() for line in text.splitlines() if "⊘" in line or "(skipped:" in line])
            if result["skip_lines"]:
                result["passed"]=False
            results.append(result)
            if code != 0:
                # A negative code belongs to the host docker-exec client, not
                # necessarily to Royak or bash in the node. Preserve that
                # distinction and inspect only this run's owned container.
                try:
                    state = json.loads(docker("inspect", "-f", "{{json .State}}", node))
                    safe_state = {k: state.get(k) for k in ("Running", "OOMKilled", "ExitCode", "StartedAt", "FinishedAt")}
                    (out / (name + "-failure-state.json")).write_text(json.dumps(
                        dict(host_exec_exit_code=code, container=safe_state), indent=2))
                except Exception:
                    pass
            print(("PASS " if result["passed"] else "FAIL ") + suite + " " + str(result["duration_s"]) + "s", flush=True)
            # Broad cleanup is safe ONLY here, inside this run's isolated daemon.
            docker("exec", node, "sh", "-ec",
                   'for p in /proc/[0-9]*; do case "$(readlink "$p/exe" 2>/dev/null || true)" in /work/*/target/release/royak) kill -KILL "${p##*/}" 2>/dev/null || true;; esac; done; '
                   'docker ps -aq | xargs -r docker rm -f >/dev/null; rm -rf "$1"', "sh", directory)
    except BaseException as error:
        failure = type(error).__name__ + ": " + str(error)
        print(failure, file=sys.stderr, flush=True)
    finally:
        if process and process.poll() is None:
            process.terminate()
        if created_node:
            try:
                owned = docker("inspect", "-f", '{{index .Config.Labels "' + LABEL + '"}}', node).strip()
                if owned == run_id:
                    docker("rm", "-f", node)
            except Exception as error:
                cleanup_errors.append(str(error))
        for kind, name, created in [("volume", volume, created_volume), ("network", network, created_network)]:
            if created:
                try:
                    owned = docker(kind, "inspect", "-f", '{{index .Labels "' + LABEL + '"}}', name).strip()
                    if owned == run_id:
                        docker(kind, "rm", name)
                except Exception as error:
                    cleanup_errors.append(str(error))
        passed = not failure and not cleanup_errors and len(results) == len(suites) and all(r["passed"] for r in results)
        report = dict(schema_version=1, run_id=run_id, passed=passed, failure=failure, cleanup_errors=cleanup_errors,
                      suites=results, duration_s=round(time.monotonic() - started, 3), production_ready=False)
        (out / "report.json").write_text(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--suite", choices=SUITES, action="append")
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--storage-driver", choices=["vfs", "overlay2"], default="vfs")
    args = parser.parse_args()
    sys.exit(run_suites(args.binary, args.suite or SUITES, args.timeout, args.storage_driver))
