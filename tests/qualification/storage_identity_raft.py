"""Real three-process Raft/TLS identity durability and old-envelope refusal.

No Docker, VMs, route changes or public endpoints. This is not a cross-kernel
storage test. Every exact child is reaped; original failed evidence is retained.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect(binary, old_binary):
    checks, launches, snapshots = [], [], []
    with tempfile.TemporaryDirectory(prefix="rkq-storage-raft-") as directory:
        root = Path(directory)
        token, secret = secrets.token_hex(24), secrets.token_hex(32)
        reserved = [socket.socket() for _ in range(4)]
        for sock in reserved:
            sock.bind(("127.0.0.1", 0))
        ports = [s.getsockname()[1] for s in reserved]
        for sock in reserved:
            sock.close()
        nodes = []
        for i, port in enumerate(ports[:3], 1):
            home = root / str(i)
            home.mkdir(mode=0o700)
            env = dict(PATH=os.environ.get("PATH", ""), HOME=str(home),
                ROYAK_STATE=str(home / "state.json"), ROYAK_DATA_DIR=str(home / "data"),
                ROYAK_NODE_NAME=f"identity-raft-{i}", ROYAK_NO_DOCKER="1",
                DOCKER_HOST="unix://" + str(home / "missing.sock"), ROYAK_TOKEN=token,
                ROYAK_CLUSTER_SECRET=secret)
            nodes.append(dict(id=i, port=port, home=home, env=env, process=None, log=None))

        def check(name, value, **details):
            checks.append(dict(name=name, passed=bool(value), **details))
            assert value, name

        def api(n, path, method="GET", body=None):
            ca = n["home"] / ".kube" / "royak-ca.pem"
            if not ca.exists() or not n["process"] or n["process"].poll() is not None:
                return 0, {}
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))
            request = urllib.request.Request(f"https://localhost:{n['port']}" + path,
                None if body is None else json.dumps(body).encode(),
                {"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method=method)
            try:
                with opener.open(request, timeout=5) as response:
                    return response.status, json.loads(response.read())
            except urllib.error.HTTPError as error:
                with error:
                    return error.code, json.loads(error.read())
            except OSError:
                return 0, {}

        def wait(fn, name, seconds=45):
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                value = fn()
                if value:
                    return value
                time.sleep(.15)
            raise AssertionError("timeout: " + name)

        def start(n, bootstrap=False):
            peers = ",".join(f"{p['id']}@127.0.0.1:{p['port']}" for p in nodes if p is not n)
            args = [str(binary), "watch", "--tls", "--port", str(n["port"]), "--ingress-port", "0",
                    "--interval", "1", "--node-id", str(n["id"]), "--peers", peers]
            if bootstrap:
                args.append("--bootstrap")
            n["log"] = (n["home"] / "server.log").open("ab")
            n["process"] = subprocess.Popen(args, env=n["env"], cwd=n["home"],
                stdout=n["log"], stderr=subprocess.STDOUT)
            n["launch"] = dict(node=n["id"], pid=n["process"].pid, started=time.time(), reaped=False)
            launches.append(n["launch"])

        def stop(n, hard=False):
            process = n["process"]
            if process:
                process.kill() if hard else process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                n["launch"]["reaped"] = process.poll() is not None
                n["process"] = None
            if n["log"]:
                n["log"].close()
                n["log"] = None

        def leader():
            for n in nodes:
                code, value = api(n, "/royak/v1/raft/status")
                if code == 200 and value.get("leaderConfirmed") and value.get("generation", 0) >= 1:
                    return n
            return None

        def post(path, kind, name, ns=None, spec=None, data=None):
            body = dict(apiVersion="v1", kind=kind, metadata=dict(name=name, uid="untrusted"))
            if ns:
                body["metadata"]["namespace"] = ns
            if spec is not None:
                body["spec"] = spec
            if data is not None:
                body["data"] = data
            n = wait(leader, "confirmed leader")
            code, value = api(n, path, "POST", body)
            assert code == 201, f"{kind} commit returned {code}"
            return value["metadata"]["uid"]

        def all_uid(path, uid, subset=None):
            return all(api(n, path)[1].get("metadata", {}).get("uid") == uid for n in (subset or nodes))

        try:
            start(nodes[1])
            start(nodes[2])
            start(nodes[0], bootstrap=True)
            first = wait(leader, "initial seeded leader")
            check("real encrypted Raft cluster reaches committed generation", first is not None)
            ns_uid = post("/api/v1/namespaces", "Namespace", "team")
            pv_uid = post("/api/v1/persistentvolumes", "PersistentVolume", "disk", spec=dict(
                capacity=dict(storage="32Mi"), hostPath=dict(path=str(root / "no-workload-data"))))
            claim_uid = post("/api/v1/namespaces/team/persistentvolumeclaims", "PersistentVolumeClaim", "data", "team",
                dict(resources=dict(requests=dict(storage="16Mi")), accessModes=["ReadWriteOnce"]))
            ns_path, pv_path = "/api/v1/namespaces/team", "/api/v1/persistentvolumes/disk"
            claim_path = "/api/v1/namespaces/team/persistentvolumeclaims/data"
            post("/apis/storage.k8s.io/v1/storageclasses", "StorageClass", "replicated", spec=dict(
                provisioner="royak/drbd-lvm", reclaimPolicy="Delete"))
            managed_uid = post("/api/v1/namespaces/team/persistentvolumeclaims", "PersistentVolumeClaim", "replicated", "team",
                dict(storageClassName="replicated", resources=dict(requests=dict(storage="16Mi")), accessModes=["ReadWriteOnce"]))
            managed_path = "/api/v1/namespaces/team/persistentvolumeclaims/replicated"
            wait(lambda: all_uid(ns_path, ns_uid) and all_uid(pv_path, pv_uid) and all_uid(claim_path, claim_uid), "identity convergence")
            check("all peers preserve exact server-owned namespace/PV/claim identities", True,
                  namespace_uid=ns_uid, volume_uid=pv_uid, claim_uid=claim_uid)
            check("all replicated claim bindings remain reciprocal", all(api(n, claim_path)[1]["spec"]["volumeName"] == "disk"
                  and api(n, pv_path)[1]["spec"]["claimRef"]["namespace"] == "team"
                  and api(n, pv_path)[1]["spec"]["claimRef"]["uid"] == claim_uid for n in nodes))
            wait(lambda: all_uid(managed_path, managed_uid), "managed-intent identity convergence")
            managed_volume = api(first, managed_path)[1]["status"]["royakStorage"]["volumeUID"]
            check("managed intent replicates without fabricating a ready backend", all(
                api(n, managed_path)[1]["status"]["phase"] == "Pending"
                and api(n, managed_path)[1]["status"]["royakStorage"]["volumeUID"] == managed_volume
                and api(n, managed_path)[1]["status"]["royakStorage"]["attachmentEpoch"] == 0 for n in nodes))
            old_leader = wait(leader, "leader before SIGKILL")
            stop(old_leader, hard=True)
            second = wait(leader, "new leader after exact old process kill")
            check("majority elects another confirmed leader", second["id"] != old_leader["id"])
            survivors = [n for n in nodes if n is not old_leader]
            check("acknowledged identities survive leader process loss", all_uid(ns_path, ns_uid, survivors)
                  and all_uid(pv_path, pv_uid, survivors) and all_uid(claim_path, claim_uid, survivors))
            check("acknowledged managed intent survives leader process loss", all_uid(managed_path, managed_uid, survivors)
                  and all(api(n, managed_path)[1]["status"]["royakStorage"]["volumeUID"] == managed_volume for n in survivors))
            after_uid = post("/api/v1/namespaces", "Namespace", "after-loss")
            start(old_leader)
            wait(lambda: all_uid("/api/v1/namespaces/after-loss", after_uid) and all_uid(claim_path, claim_uid), "rejoined peer catches up")
            check("restarted peer catches up without rotating old identities", True)
            # Cross the real configured snapshot policy (64 entries), not a
            # handcrafted snapshot pretending to be a runtime artifact.
            for i in range(70):
                post("/api/v1/namespaces/team/configmaps", "ConfigMap", f"snapshot-{i}", "team", data=dict(k=str(i)))
            snapshot = old_leader["home"] / "state.json.raft" / "snapshot.json"
            wait(lambda: snapshot.is_file(), "runtime snapshot on restarted peer")
            stop(old_leader)
            snapshots.append(dict(node=old_leader["id"], sha256=digest(snapshot), bytes=snapshot.stat().st_size))
            # A separate old process has no peer addresses and only a private
            # COPY of that snapshot. It must refuse the new AEAD domain before
            # starting its API; no original Raft evidence is rewritten.
            probe = root / "old-reader"
            probe.mkdir()
            target = probe / "state.json.raft"
            target.mkdir()
            shutil.copy2(snapshot, target / "snapshot.json")
            before = digest(target / "snapshot.json")
            env = dict(old_leader["env"], HOME=str(probe), ROYAK_STATE=str(probe / "state.json"),
                ROYAK_DATA_DIR=str(probe / "data"), ROYAK_NODE_NAME="old-snapshot-reader")
            result = subprocess.run([str(old_binary), "watch", "--tls", "--port", str(ports[3]),
                "--ingress-port", "0", "--node-id", "99"], env=env, cwd=probe,
                capture_output=True, timeout=12)
            check("actual previous binary refuses new protected Raft snapshot", result.returncode != 0
                  and b"snapshot.json" in result.stderr and b"API server listening" not in result.stdout
                  and digest(target / "snapshot.json") == before, exit_code=result.returncode)
            start(old_leader)
            wait(lambda: all_uid(claim_path, claim_uid), "snapshot-backed restart preserves identity")
            check("new binary can restart from its protected snapshot", True)
            check("snapshot restart preserves managed intent and zero grants", all_uid(managed_path, managed_uid)
                  and all(api(n, managed_path)[1]["status"]["royakStorage"]["assignment"] is None for n in nodes))
            check("bound PV deletion is refused by actual quorum commit path", api(wait(leader, "leader for delete"), pv_path, "DELETE")[0] == 409
                  and all_uid(pv_path, pv_uid))
        except Exception as error:
            checks.append(dict(name="fixture completion", passed=False, error=f"{type(error).__name__}: {error}"))
        finally:
            for n in nodes:
                stop(n)
        checks.append(dict(name="all exact Raft child processes reaped", passed=all(p["reaped"] for p in launches)))
        available = True
        for port in ports:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    available = False
            except OSError:
                pass
        checks.append(dict(name="all exact API listeners released", passed=available))
    return checks, launches, snapshots


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--old-binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    os.umask(0o077)
    if a.output.exists():
        p.error("never overwrite earlier evidence")
    checks, launches, snapshots = collect(a.binary.resolve(), a.old_binary.resolve())
    src = Path(__file__).resolve().parents[2] / "src"
    report = dict(passed=all(c["passed"] for c in checks), checks=checks, launches=launches, snapshots=snapshots,
        binary_sha256=digest(a.binary), old_binary_sha256=digest(a.old_binary), fixture_sha256=digest(Path(__file__)),
        source_sha256={str(path.relative_to(src)): digest(path) for path in sorted(src.rglob("*")) if path.is_file()},
        scope="three native processes, same kernel; actual Raft/TLS/state identity, not cross-host durability or physical HA")
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(dict(passed=report["passed"], checks=checks, binary_sha256=report["binary_sha256"]), indent=2))
    raise SystemExit(not report["passed"])


if __name__ == "__main__":
    main()
