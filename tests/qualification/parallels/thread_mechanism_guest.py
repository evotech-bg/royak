#!/usr/bin/env python3
"""Focused real Royak thread observations; never endurance/release acceptance.

One unprivileged, fresh owned directory. No Docker, mount, service, /lab,
WireGuard, routes, package, model or external-endpoint operation. Historical
artifacts differ beyond Connect, so this is NOT a single-change causal A/B.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request

import royak_thread_census as census

PLAN = dict(kind="focused-real-control-API-thread-lifetime-diagnostic-v1",
            warmup_seconds=15, baseline_seconds=15, idle_seconds=45,
            sample_seconds=1, write_count=128, concurrent_workers=16,
            value_bytes=1024, request_timeout_seconds=8, case_budget_seconds=180,
            idle_api_requests=0, product_settings_changed=False,
            endurance_or_release_qualified=False)


def digest(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1
        value = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
        assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        return value


def put(path, value):
    with path.open("x", encoding="utf8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def run_case(root, name, binary, expected_sha):
    assert digest(binary) == expected_sha
    directory = root / name
    directory.mkdir(mode=0o700)
    home = directory / "home"
    home.mkdir(mode=0o700)
    state = directory / "state.json"
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    token = secrets.token_hex(32)
    env = dict(PATH="/usr/bin:/bin", HOME=str(home), ROYAK_STATE=str(state),
               ROYAK_DATA_DIR=str(directory / "data"), ROYAK_NO_DOCKER="1",
               DOCKER_HOST="unix://" + str(directory / "missing-docker.sock"),
               ROYAK_TOKEN=token, ROYAK_SECRET_KEY=secrets.token_hex(32))
    argv = [str(binary), "watch", "--tls", "--port", str(port),
            "--ingress-port", "0", "--interval", "1"]
    result = dict(name=name, artifact_sha256=expected_sha, argv=argv, plan=PLAN,
                  acknowledged_control_writes=[], verified_control_reads=0,
                  write_failures_or_ambiguities=[], samples=0, metadata_errors=[],
                  artifact_current_full_source=False, creator_callsite_proven=False,
                  historical_SOAK004_cause_proven=False, qualified=False)
    log = (directory / "server.log").open("xb")
    child = None
    stopped, sampling = threading.Event(), None
    phase, phase_lock = "startup", threading.Lock()
    began = time.monotonic()
    budget = began + PLAN["case_budget_seconds"]
    locator = directory / "original.pid"
    expected = None

    def transition(value):
        nonlocal phase
        with phase_lock:
            phase = value
        with (directory / "phases.jsonl").open("a") as stream:
            stream.write(json.dumps(dict(phase=value, monotonic=time.monotonic(), elapsed=time.monotonic()-began)) + "\n")

    def observe():
        try:
            value = census._collect_paths(locator, Path("/proc"), binary,
                expected_pid=expected["pid"], expected_start_ticks=expected["start_ticks"], expected_boot_id=expected["boot_id"])
            with phase_lock:
                current = phase
            row = dict(phase=current, monotonic=time.monotonic(), elapsed=time.monotonic()-began, census=value)
            with (directory / "samples.jsonl").open("a") as stream:
                stream.write(json.dumps(row) + "\n")
            result["samples"] += 1
        except Exception as error:
            result["metadata_errors"].append(type(error).__name__)

    def sample_loop():
        while not stopped.is_set():
            observe()
            stopped.wait(PLAN["sample_seconds"])

    def idle_for(seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            assert child.poll() is None, "exact Royak child exited"
            assert time.monotonic() < budget, "fixed diagnostic budget exceeded"
            time.sleep(min(.2, max(0, deadline-time.monotonic())))

    try:
        # Intent and original Popen are retained before any PID-locator/sample.
        put(directory / "launch-intent.json", dict(argv=argv, binary_sha256=expected_sha, plan=PLAN))
        child = subprocess.Popen(argv, env=env, cwd=directory, stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT, close_fds=True, start_new_session=True)
        original = census.parse_task_stat(Path("/proc", str(child.pid), "stat").read_text(), child.pid)
        expected = dict(pid=child.pid, start_ticks=original["start_ticks"],
                        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        put(directory / "original-child.json", expected)
        locator.write_text(str(child.pid) + "\n")
        ca = home / ".kube/royak-ca.pem"
        startup_deadline = time.monotonic() + 15
        while not ca.exists():
            assert child.poll() is None and time.monotonic() < startup_deadline, "no original Royak TLS identity"
            time.sleep(.1)
        context = ssl.create_default_context(cafile=str(ca))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        base = "https://localhost:" + str(port)

        def api(path, method="GET", body=None):
            assert child.poll() is None and time.monotonic() < budget
            raw = None if body is None else json.dumps(body).encode()
            request = urllib.request.Request(base+path, raw, {"Authorization":"Bearer "+token, "Content-Type":"application/json"}, method=method)
            try:
                response = opener.open(request, timeout=PLAN["request_timeout_seconds"])
            except urllib.error.HTTPError as error:
                response = error
            with response:
                return response.status, json.loads(response.read())

        while True:
            try:
                status, payload = api("/api/v1/namespaces")
                assert status == 200, "unexpected authenticated startup response"
                break
            except (OSError, urllib.error.URLError):
                assert child.poll() is None and time.monotonic() < startup_deadline, "original TLS listener unavailable"
                time.sleep(.1)  # read-only startup observation; no write replay
        # This genuine TLS-authenticated route starts Connect's actual sweeper
        # without a Service, target socket or fabricated native capability.
        status, payload = api("/royak/v1/connect/namespaces/default/sessions")
        assert status == 200 and payload == {"items":[]}, "actual empty Connect registry unavailable"
        sampling = threading.Thread(target=sample_loop)
        sampling.start()
        transition("warmup")
        idle_for(PLAN["warmup_seconds"])
        transition("baseline")
        idle_for(PLAN["baseline_seconds"])
        transition("control-write-burst")
        def write(index):
            name = "thread-diag-"+str(index)
            value = hashlib.sha256((name+expected_sha).encode()).hexdigest() * (PLAN["value_bytes"]//64)
            body = dict(apiVersion="v1",kind="ConfigMap",metadata=dict(name=name,namespace="default"),data=dict(value=value))
            status, data = api("/api/v1/namespaces/default/configmaps", "POST", body)
            if status not in (200,201):
                raise ValueError("control write HTTP "+str(status))
            return dict(name=name,value_sha256=hashlib.sha256(value.encode()).hexdigest())
        # Executor exit joins every original request worker. No write retries.
        with concurrent.futures.ThreadPoolExecutor(max_workers=PLAN["concurrent_workers"]) as workers:
            pending = [workers.submit(write,index) for index in range(PLAN["write_count"])]
            for index,future in enumerate(pending):
                try:
                    result["acknowledged_control_writes"].append(future.result())
                except Exception as error:
                    result["write_failures_or_ambiguities"].append(dict(index=index,error=type(error).__name__))
        transition("verify-control-data")
        for row in result["acknowledged_control_writes"]:
            status, value = api("/api/v1/namespaces/default/configmaps/"+row["name"])
            assert status == 200 and hashlib.sha256(value["data"]["value"].encode()).hexdigest() == row["value_sha256"], "acknowledged control data changed"
            result["verified_control_reads"] += 1
        # API/load workers have joined and all response bodies are closed before
        # this fixed additional observation. No API polling during idle.
        result["idle_began_after_request_workers_joined"] = True
        result["idle_began_monotonic"] = time.monotonic()
        transition("focused-idle-observation")
        idle_for(PLAN["idle_seconds"])
        result["idle_observed_seconds"] = time.monotonic()-result["idle_began_monotonic"]
        observe()
        result["diagnostic_work_completed"] = not result["write_failures_or_ambiguities"]
    except Exception as error:
        result["failure"] = type(error).__name__ + ": " + str(error).replace(token,"[REDACTED]")
    finally:
        stopped.set()
        if sampling is not None:
            sampling.join()
        if child is not None:
            # Original child handle only. Never signal a discovered/adopted PID.
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
            try:
                result["original_exit"] = child.wait(timeout=15)
                result["original_reaped"] = True
            except subprocess.TimeoutExpired:
                result["cleanup_unknown"] = True
                put(directory / "UNKNOWN.json", result)
                print(json.dumps(dict(holding_original_owner=True,pid=child.pid,directory=str(directory))),flush=True)
                while True:
                    signal.pause()  # retain original Popen/log; no forced kill/retry
            residual=[]
            for process in Path("/proc").iterdir():
                if not process.name.isdigit():
                    continue
                try:
                    fields=(process/"stat").read_text().rsplit(") ",1)[1].split()
                    if int(fields[3])==child.pid:
                        residual.append(int(process.name))
                except (FileNotFoundError,ProcessLookupError):
                    pass
            result["residual_original_session_pids"] = residual
            result["diagnostic_work_completed"] = result.get("diagnostic_work_completed",False) and not residual
        log.close()
        result["elapsed_seconds"] = time.monotonic()-began
        result["artifact_unchanged"] = digest(binary) == expected_sha
        put(directory / "case-report.json", result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--old",type=Path,required=True)
    parser.add_argument("--new",type=Path,required=True)
    args=parser.parse_args()
    assert os.geteuid()!=0, "unprivileged diagnostic only"
    root=args.root.resolve(strict=True)
    assert root.name.startswith("thread-mechanism-") and root.parent==Path.home()/".local/share/royak-qualification"
    assert root.stat().st_uid==os.getuid() and stat.S_IMODE(root.stat().st_mode)==0o700
    assert not (root/"plan.json").exists()
    put(root/"plan.json", PLAN)
    values=[]
    for name,binary,sha in [("historical-quorum",args.old,"22297fd61a5b954d0d5fafebcba6c03dc24ca114b9d6d8cdd93dbae9cd9183ec"),
        ("same-current-connect",args.new,"6d73c112a881e2de42ab1023ab0c9e625e45f9ec39ec8714aae4253d57ba82fb")]:
        values.append(run_case(root,name,binary.resolve(strict=True),sha))
    put(root/"diagnostic-report.json",dict(plan=PLAN,cases=values,artifact_single_change_AB=False,
        current_full_build_or_7200s_endurance=False,production_qualified=False))
    print(json.dumps(dict(completed=all(v.get("diagnostic_work_completed") for v in values),
        root=str(root),cases=[{k:v.get(k) for k in ("name","samples","verified_control_reads","original_reaped","failure")}for v in values])),flush=True)


if __name__=="__main__":
    main()
