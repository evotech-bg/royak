#!/usr/bin/env python3
"""One bounded512MiB controller baseline in a NEW guest-only network namespace.

Unpacked artifacts, no package/service/block/host-network mutation. Real mTLS
GETs and procfs observations are not replication, HA or production acceptance.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import resource
import secrets
import shutil
import socket
import ssl
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


def bootstrap_namespace():
    assert os.getuid() == 0
    assert Path("/etc/royak-lab-owner").read_text().strip() == "rkq-vm-20261028-royak"
    own, initial = os.readlink("/proc/self/ns/net"), os.readlink("/proc/1/ns/net")
    assert own != initial, "refuse to configure the guest's existing network namespace"
    child = subprocess.Popen(["/usr/sbin/ip", "link", "set", "lo", "up"], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    try:
        stdout, stderr = child.communicate(timeout=10)
    except BaseException:
        while child.poll() is None:
            time.sleep(1)
        raise
    assert child.returncode == 0 and not stdout and not stderr
    # Create ONLY a previously absent backend metadata directory on this
    # dedicated guest. Existing paths are never adopted, changed or deleted.
    parent = Path("/var/lib")
    backend = parent / "linstor"
    assert parent.resolve() == parent and parent.stat().st_uid == 0
    assert not backend.exists() and not backend.is_symlink(), "existing backend state is out of scope"
    backend.mkdir(mode=0o700)
    identity = backend.stat()
    marker = backend / ".royak-qualification-owner"
    marker.write_text(json.dumps(dict(run="linstor-footprint-20261102-v1-controller2", device=identity.st_dev, inode=identity.st_ino)) + "\n")
    marker.chmod(0o600)
    marker_sha = sha(marker)
    os.chown(backend, 1000, 1000)
    os.setgroups([])
    os.setgid(1000)
    os.setuid(1000)
    assert os.geteuid() == 1000
    caps = next(line.split()[1] for line in Path("/proc/self/status").read_text().splitlines() if line.startswith("CapEff:"))
    assert int(caps, 16) == 0
    return dict(initial=initial, owned=own, bootstrap_pid=child.pid, bootstrap_exit=child.returncode, new_owned_backend_state=dict(path=str(backend),device=identity.st_dev,inode=identity.st_ino,marker_sha256=marker_sha))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--stage-sha256", required=True)
    args = parser.parse_args()
    netns = bootstrap_namespace()
    root = args.root
    assert root == Path("/home/royak/.local/share/royak-qualification/linstor-footprint-20261102-v1") and root.resolve() == root
    assert root.stat().st_uid == 1000 and stat.S_IMODE(root.stat().st_mode) == 0o700
    assert sha(root / "stage-report.json") == args.stage_sha256
    staged = json.loads((root / "stage-report.json").read_bytes())
    assert staged["passed"] and staged["all_original_children_reaped"]
    os.umask(0o077)
    case = root / "controller-attempt2"
    assert not case.exists()
    case.mkdir(mode=0o700)
    for name in ["logs", "private", "config", "db", "tmp", "home", "app"]:
        (case / name).mkdir(mode=0o700)
    env = dict(PATH="/usr/bin:/bin", HOME=str(case / "home"), LANG="C.UTF-8", LC_ALL="C.UTF-8", TMPDIR=str(case / "tmp"))
    password = secrets.token_hex(32)
    env["RKQ_STORE_PASSWORD"] = password
    report = dict(kind="one-real-LINSTOR-controller512MiB-mTLS-baseline", passed=False, netns=netns,
        packages_installed=False, system_service_started=False, storage_block_or_host_network_changed=False, new_backend_metadata_directory_created=True,
        heap_profile=dict(initial_mib=64, maximum_mib=512, vendor_default_initial_mib=256, vendor_default_maximum_mib=8192),
        default_vendor_footprint=False, backend_selected=False, production_or_replication_or_endurance_qualified=False,
        children=[], requests=0, negatives={}, samples=0)
    original = None
    original_log = None
    owned_children = []

    def run(tag, argv, seconds=30):
        log = (case / "logs" / (tag + ".log")).open("xb")
        child = subprocess.Popen(argv, cwd=case, env=env, stdin=subprocess.DEVNULL, stdout=log,
            stderr=subprocess.STDOUT, close_fds=True, start_new_session=True)
        owned_children.append((child, log))
        put(case / (tag + "-launched.json"), dict(pid=child.pid, argv=argv))
        try:
            code = child.wait(timeout=seconds)
        except BaseException as error:
            put(case / (tag + "-UNKNOWN.json"), dict(pid=child.pid, error=type(error).__name__, no_signal=True))
            while child.poll() is None:
                time.sleep(1)
            raise
        log.flush()
        os.fsync(log.fileno())
        log.close()
        report["children"].append(dict(tag=tag, pid=child.pid, exit=code))
        assert code == 0, "known terminal prerequisite failed: " + tag

    try:
        # Preserve staged payloads; only this new private portable JRE copy has
        # absolute packaging symlinks redirected to its own extracted tree.
        portable = case / "jre"
        shutil.copytree(root / "payloads/openjdk-21-jre-headless", portable, symlinks=True)
        remapped = []
        for path in portable.rglob("*"):
            if path.is_symlink() and os.readlink(path).startswith("/"):
                old = os.readlink(path)
                target = portable / old.lstrip("/")
                path.unlink()
                path.symlink_to(os.path.relpath(target, path.parent))
                remapped.append(dict(path=str(path.relative_to(portable)), original=old))
        report["portable_JRE_link_remaps"] = remapped
        java_home = portable / "usr/lib/jvm/java-21-openjdk-arm64"
        env["JAVA_HOME"] = str(java_home)
        app = case / "app"
        for package in ["linstor-common", "linstor-controller", "linstor-satellite"]:
            source = root / "payloads" / package / "usr/share/linstor-server"
            for path in source.rglob("*"):
                destination = app / path.relative_to(source)
                if path.is_dir():
                    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
                elif path.is_file():
                    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    if destination.exists():
                        assert sha(destination) == sha(path), "package projection file conflict"
                    elif path.name == "Controller":
                        assert sha(path) == "8309d34cdf86d91e14805a7cd39617ff385a8a1ed365c0b270ce76a81ea92ec4"
                        shutil.copy2(path, destination)
                    else:
                        destination.symlink_to(path)
        private = case / "private"
        run("ca", ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=Royak-private-LINSTOR-test-CA",
            "-keyout", str(private / "ca.key"), "-out", str(private / "ca.pem")])
        for name, usage in [("server", "serverAuth"), ("client", "clientAuth")]:
            run(name + "-csr", ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + ("localhost" if name == "server" else "Royak-test-client"),
                "-keyout", str(private / (name + ".key")), "-out", str(private / (name + ".csr"))])
            ext = private / (name + ".ext")
            ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=" + usage + "\n" + ("subjectAltName=DNS:localhost,IP:127.0.0.1\n" if name == "server" else ""))
            run(name + "-sign", ["openssl", "x509", "-req", "-in", str(private / (name + ".csr")), "-CA", str(private / "ca.pem"),
                "-CAkey", str(private / "ca.key"), "-set_serial", "1" if name == "server" else "2", "-days", "1", "-sha256", "-extfile", str(ext), "-out", str(private / (name + ".pem"))])
        run("keystore", ["openssl", "pkcs12", "-export", "-in", str(private / "server.pem"), "-inkey", str(private / "server.key"),
            "-certfile", str(private / "ca.pem"), "-name", "controller", "-out", str(private / "server.p12"), "-passout", "env:RKQ_STORE_PASSWORD"])
        run("truststore", [str(java_home / "bin/keytool"), "-importcert", "-noprompt", "-alias", "test-ca", "-file", str(private / "ca.pem"),
            "-storetype", "PKCS12", "-keystore", str(private / "trusted.p12"), "-storepass:env", "RKQ_STORE_PASSWORD"])
        with socket.socket() as reservation, socket.socket() as redirect_reservation:
            reservation.bind(("127.0.0.1", 0))
            redirect_reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
            redirect_port = redirect_reservation.getsockname()[1]
        config = case / "config/linstor.toml"
        config.write_text('[db]\nuser="linstor"\npassword="' + password + '"\nconnection_url="jdbc:h2:' + str(case / "db/linstordb") + '"\n'
            '[http]\nenabled=true\nlisten_addr="127.0.0.1"\nport=' + str(redirect_port) + '\n[https]\nenabled=true\nlisten_addr="127.0.0.1"\nport=' + str(port) + '\n'
            'keystore="' + str(private / "server.p12") + '"\nkeystore_password="' + password + '"\n'
            'truststore="' + str(private / "trusted.p12") + '"\ntruststore_password="' + password + '"\n')
        report["private_config_sha256"] = sha(config)
        env["JAVA_OPTS"] = "-Xms64M -Xmx512M -Djava.io.tmpdir=" + str(case / "tmp")
        argv = [str(app / "bin/Controller"), "--config-directory=" + str(case / "config"), "--logs=" + str(case / "logs")]
        original_log = (case / "controller.log").open("xb")
        def no_core():
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        original = subprocess.Popen(argv, cwd=case, env=env, stdin=subprocess.DEVNULL, stdout=original_log,
            stderr=subprocess.STDOUT, close_fds=True, start_new_session=True, preexec_fn=no_core)
        put(case / "controller-launched.json", dict(pid=original.pid, argv=argv, heap_profile=report["heap_profile"], netns=netns))
        good = ssl.create_default_context(cafile=str(private / "ca.pem"))
        good.load_cert_chain(str(private / "client.pem"), str(private / "client.key"))
        no_client = ssl.create_default_context(cafile=str(private / "ca.pem"))

        def get(context):
            connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
            try:
                connection.request("GET", "/v1/controller/version")
                response = connection.getresponse()
                body = response.read(32 * 1024 + 1)
                assert len(body) <= 32 * 1024 and response.status == 200
                return json.loads(body)
            finally:
                connection.close()

        deadline = time.monotonic() + 120
        while True:
            assert original.poll() is None, "controller exited during startup"
            try:
                version = get(good)
                break
            except (OSError, ssl.SSLError):
                assert time.monotonic() < deadline, "controller startup deadline exceeded"
                time.sleep(0.2)
        assert "1.35.3" in json.dumps(version)
        report["version"] = version
        redirect = http.client.HTTPConnection("127.0.0.1", redirect_port, timeout=5)
        try:
            redirect.request("GET", "/v1/controller/version")
            response = redirect.getresponse()
            assert response.status in (301,302,303,307,308) and response.getheader("Location") == "https://127.0.0.1:" + str(port) + "/v1/controller/version"
            response.read(32768)
            report["negatives"]["plain_HTTP_has_only_HTTPS_redirect"] = response.status
        finally:
            redirect.close()
        for name, context in [("no_client_certificate", no_client), ("untrusted_server_CA", ssl.create_default_context())]:
            try:
                get(context)
            except (OSError, ssl.SSLError) as error:
                report["negatives"][name] = type(error).__name__
            else:
                raise AssertionError("mTLS boundary accepted " + name)
        stats = Path("/proc") / str(original.pid)
        identity = (stats / "stat").read_text().rsplit(") ", 1)[1].split()[19]
        phase = "warmup"
        began = time.monotonic()
        report["requested_phase_seconds"] = dict(warmup=30, workload=120, idle=30)
        report["phase_observations"] = [dict(phase="warmup", elapsed_s=0.0)]
        warm_end, work_end, idle_end = began + 30, began + 150, began + 180
        next_sample, next_request = began, warm_end
        with (case / "resources.jsonl").open("x") as samples:
            while time.monotonic() < idle_end:
                assert original.poll() is None, "original controller exited"
                now = time.monotonic()
                actual_phase = "warmup" if now < warm_end else "workload" if now < work_end else "idle"
                if actual_phase != phase:
                    report["phase_observations"].append(dict(phase=actual_phase, elapsed_s=now-began))
                    phase = actual_phase
                if now >= next_sample:
                    fields = (stats / "stat").read_text().rsplit(") ", 1)[1].split()
                    assert fields[19] == identity
                    status = dict(line.split(":", 1) for line in (stats / "status").read_text().splitlines() if ":" in line)
                    rss = int(status["VmRSS"].split()[0]) * 1024
                    row = dict(elapsed_s=now-began, phase=phase, pid=original.pid, start_ticks=identity, rss_bytes=rss,
                        fd=len(list((stats / "fd").iterdir())), threads=int(status["Threads"]), task_count=len(list((stats / "task").iterdir())),
                        utime_ticks=int(fields[11]), stime_ticks=int(fields[12]), clock_ticks_per_second=os.sysconf("SC_CLK_TCK"))
                    samples.write(json.dumps(row) + "\n")
                    samples.flush()
                    report["samples"] += 1
                    assert rss < 1200 * 1024**2, "controller safety RSS ceiling exceeded"
                    next_sample = now + 2
                if phase == "workload" and now >= next_request:
                    assert get(good) == version
                    report["requests"] += 1
                    next_request = now + 0.2
                time.sleep(0.02)
            samples.flush()
            os.fsync(samples.fileno())
        report["phase_observations"].append(dict(phase="complete", elapsed_s=time.monotonic()-began))
        report["observed_runtime_seconds"] = time.monotonic()-began
        report["actual_java_executable"] = os.readlink(stats / "exe")
        assert Path(report["actual_java_executable"]) == java_home / "bin/java"
        report["actual_java_executable_sha256"] = sha(java_home / "bin/java")
        report["actual_java_cmdline"] = (stats / "cmdline").read_bytes().decode().split("\0")[:-1]
        assert report["actual_java_cmdline"].count("-Xmx512M") == 1
        report["passed"] = True
    except BaseException as error:
        report["failure"] = (type(error).__name__ + ": " + str(error)).replace(password, "[REDACTED]")
    finally:
        if original is not None:
            if original.poll() is None:
                original.terminate()  # only the SAME original owned Popen
                try:
                    original.wait(timeout=30)
                except BaseException as error:
                    put(case / "controller-UNKNOWN.json", dict(pid=original.pid, error=type(error).__name__, no_force_kill=True))
                    while original.poll() is None:
                        time.sleep(1)
                    report["passed"] = False
            report["original_reaped"] = original.poll() is not None
            report["controller_exit"] = original.returncode
        if original_log is not None:
            original_log.flush()
            os.fsync(original_log.fileno())
            original_log.close()
        report["all_prerequisite_children_reaped"] = all(child.poll() is not None for child, _ in owned_children)
        if (case / "controller.log").exists():
            tail = (case / "controller.log").read_text(errors="replace")[-12000:].replace(password, "[REDACTED]")
            (case / "controller-redacted-tail.txt").write_text(tail)
        report["private_credentials_retained_pending_exact_cleanup"] = True
        put(case / "controller-report.json", report)
    print(json.dumps({key:report.get(key) for key in ("passed", "failure", "requests", "samples", "negatives", "original_reaped", "controller_exit")}), flush=True)
    return int(not report["passed"])


if __name__ == "__main__":
    raise SystemExit(main())

