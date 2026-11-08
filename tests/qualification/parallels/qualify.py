#!/usr/bin/env python3
"""Real three-kernel Parallels qualification using existing Connect/fault assertions.

Only the transport changes: docker exec into DIND becomes authenticated SSH
into exact owned VMs. Actual Docker, WireGuard, API, socket and ledger checks
are reused unchanged. No public endpoints or host Docker operations exist here.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import run as original
import connect_e2e as connect
from bootstrap import run, save, ssh, verify_owner
from workload import Handler
from http.server import ThreadingHTTPServer


def local_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class VMMixin:
    def __init__(self, args):
        super().__init__(args)
        self.vmroot = args.inventory.resolve().parent
        self.inventory = json.loads(args.inventory.read_text())
        if self.inventory.get("kind") != "royak-parallels-lab-v1" or len(self.inventory["nodes"]) != 3:
            raise ValueError("Need an owned three-VM inventory")
        self.vm_by_name = {n["name"]: n for n in self.inventory["nodes"]}
        self.tunnels = {}
        self.rollback_nodes = set()
        self.wg_nodes = set()
        self.ledger_server = None
        self.iface = "rkconn"
        self.prepared_nodes = []
        # The old suites remain untouched; adapt only explicit host operations.
        original.docker = self.transport
        connect.docker = self.transport

    def remote(self, node, args, timeout=120, input=None, stdin=None):
        values = [str(a) for a in args]
        command = "sudo -- " + shlex.join(values)
        if input is None and stdin is None:
            return ssh(self.vmroot, node, command, timeout=timeout)
        return run("ssh", *self.ssh_options(), "royak@" + node["ip"], command,
                   timeout=timeout, input=input, stdin=stdin)

    def ssh_options(self):
        return ["-i", str(self.vmroot / "operator"), "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", "UserKnownHostsFile=" + str(self.vmroot / "known_hosts"),
                "-o", "ConnectTimeout=3", "-o", "ServerAliveInterval=3",
                "-o", "ServerAliveCountMax=2"]

    def write_remote(self, node, path, data, mode="600"):
        # Streaming through stdin prevents credentials appearing in process argv.
        self.remote(node, ["sh", "-ec", "umask 077; tee " + shlex.quote(path) +
                          " >/dev/null; chmod " + mode + " " + shlex.quote(path)],
                    input=data if isinstance(data, bytes) else data.encode())

    def transport(self, *args, **kwargs):
        args = list(args)
        if args[0] == "exec":
            args.pop(0)
            while args and args[0] in ("-i",):
                args.pop(0)
            node = self.vm_by_name[args.pop(0)]
            # A timed, guest-local rollback survives runner failure and leaves
            # management SSH unaffected; only the exact commented rules expire.
            if args[:2] == ["iptables", "-I"] and "--comment" in args:
                if node["id"] not in self.rollback_nodes:
                    self.write_remote(node, "/lab/fault-rollback.sh", "#!/bin/sh\n", "700")
                    self.remote(node, ["systemd-run", "--quiet", "--on-active=90s",
                                      "--unit=" + self.run + "-rollback", "/bin/sh", "/lab/fault-rollback.sh"])
                    self.rollback_nodes.add(node["id"])
                undo = shlex.join(["iptables", "-D", *args[2:]]) + " 2>/dev/null || true\n"
                self.remote(node, ["sh", "-ec", "tee -a /lab/fault-rollback.sh >/dev/null"], input=undo.encode())
            return self.remote(node, args, **kwargs)
        if args[0] == "cp" and ":" in args[1]:
            name, path = args[1].split(":", 1)
            data = self.remote(self.vm_by_name[name], ["cat", path])
            save(Path(args[2]), data)
            return ""
        raise RuntimeError("Unsupported host Docker operation refused: " + str(args[:2]))

    def forward(self, node):
        old = self.tunnels.pop(node["id"], None)
        if old:
            old.terminate()
            old.wait(timeout=5)
        api = node.setdefault("api_port", local_port())
        ingress = node.setdefault("ingress_port", local_port())
        process = subprocess.Popen(["ssh", *self.ssh_options(), "-N", "-o", "ExitOnForwardFailure=yes",
                                    "-L", f"127.0.0.1:{api}:127.0.0.1:6443",
                                    "-L", f"127.0.0.1:{ingress}:127.0.0.1:8080", "royak@" + node["ip"]],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.tunnels[node["id"]] = process
        node["api"] = f"https://127.0.0.1:{api}"
        node["ingress"] = f"https://127.0.0.1:{ingress}"
        time.sleep(.3)
        if process.poll() is not None:
            raise RuntimeError("SSH management forwarding failed")

    def start_node(self, node):
        self.remote(node, ["systemctl", "start", "royak-qualification.service"])

    def certificate_fingerprint(self, node, port):
        return self.remote(node, ["sh", "-ec", f"openssl s_client -connect 127.0.0.1:{port} -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256"]).strip()

    def prepare(self, node):
        verify_owner(self.vmroot, node)
        owner = self.remote(node, ["cat", "/etc/royak-lab-owner"]).strip()
        if owner != self.inventory["run_id"]:
            raise RuntimeError("Guest ownership marker mismatch")
        active = self.remote(node, ["sh", "-ec", "systemctl is-active royak-qualification.service || true"]).strip()
        if active == "active":
            raise RuntimeError("Owned guest already has an active qualification; refusing replacement")
        directory = "/var/lib/royak-qualification/" + self.run
        self.remote(node, ["install", "-d", "-m", "700", directory])
        self.remote(node, ["sh", "-ec", "test ! -e /lab || test -L /lab; ln -sfn " + directory + " /lab"])
        self.prepared_nodes.append(node)
        with self.binary.open("rb") as stream:
            self.remote(node, ["sh", "-ec", "umask 077; tee /opt/royak >/dev/null; chmod 755 /opt/royak"], stdin=stream)
        remote_hash = self.remote(node, ["sha256sum", "/opt/royak"]).split()[0]
        if remote_hash != original.digest(self.binary):
            raise RuntimeError("Binary transport hash mismatch")
        self.remote(node, ["install", "-d", "-m", "700", "/lab/build"])
        for file in ("Dockerfile.workload", "workload.py"):
            self.write_remote(node, "/lab/build/" + file, (original.HERE / file).read_bytes(), "644")
        self.remote(node, ["docker", "build", "--label", "royak.qualification=" + self.run,
                           "-t", self.image, "-f", "/lab/build/Dockerfile.workload", "/lab/build"], timeout=300)
        self.remote(node, ["docker", "run", "--rm", "--network", "none", "--user", "10001:10001",
                           "--read-only", "--label", "royak.qualification=" + self.run, self.image,
                           "python3", "-c", "compile(open('/app.py').read(), '/app.py', 'exec')"])
        self.remote(node, ["docker", "pull", "alpine:3.21"], timeout=180)
        peer_map = {"q-n" + str(n["id"]): n["wg_ip"] + ":6443" for n in self.inventory["nodes"]}
        environment = dict(HOME="/root", ROYAK_TOKEN=self.token, ROYAK_CLUSTER_SECRET=self.cluster_secret,
                           ROYAK_SECRET_KEY=self.seal, ROYAK_NODE_NAME="q-n" + str(node["id"]),
                           ROYAK_STATE="/lab/state.json", ROYAK_DATA_DIR="/lab/data",
                           ROYAK_ADVERTISE_ADDR=node["ip"] + ":6443",
                           ROYAK_CONNECT_WG_INTERFACE=self.iface, ROYAK_CONNECT_WG_PEERS=json.dumps(peer_map))
        if isinstance(self, connect.ConnectLab):
            environment["ROYAK_TOKEN_FILE"] = "/lab/connect-tokens.csv"
            self.write_remote(node, "/lab/connect-tokens.csv",
                              f'{self.user},alice,u1,"connect-users"\n{self.other},mallory,u2,"connect-users"\n{self.viewer},vera,u3,"viewers"\n')
        self.write_remote(node, "/lab/environment", "\n".join(k + "=" + json.dumps(v) for k, v in environment.items()) + "\n")
        peers = ",".join(f"{n['id']}@{n['ip']}:6443" for n in self.inventory["nodes"] if n["id"] != node["id"])
        self.write_remote(node, "/lab/start.sh", "#!/bin/sh\nset -eu\ncd /lab\necho $$ > /lab/royak.pid\nexec /opt/royak watch --tls --port 6443 --ingress-port 8080 --interval 2 --node-id " + str(node["id"]) + " --peers " + shlex.quote(peers) + (" --bootstrap" if node["id"] == 1 else "") + " >> /lab/royak.log 2>&1\n", "700")
        unit = "[Unit]\nAfter=network-online.target docker.service\nWants=network-online.target\nRequires=docker.service\n[Service]\nType=simple\nEnvironmentFile=/lab/environment\nExecStart=/lab/start.sh\nKillMode=process\nRestart=no\n[Install]\nWantedBy=multi-user.target\n"
        self.write_remote(node, "/etc/systemd/system/royak-qualification.service", unit)
        self.remote(node, ["systemctl", "daemon-reload"])
        self.remote(node, ["systemctl", "enable", "royak-qualification.service"])
        self.start_node(node)
        self.forward(node)
        return dict(node=node["id"], uuid=node["uuid"],
                    boot_id=self.remote(node, ["cat", "/proc/sys/kernel/random/boot_id"]).strip(),
                    machine_id=self.remote(node, ["cat", "/etc/machine-id"]).strip(),
                    kernel=self.remote(node, ["uname", "-r"]).strip(),
                    docker=json.loads(self.remote(node, ["docker", "info", "--format", "{{json .}}"]))["ID"],
                    resources=self.remote(node, ["sh", "-ec", "nproc; grep MemTotal /proc/meminfo; df -h /"]).strip(),
                    binary_sha256=remote_hash)

    def preflight_idle(self):
        # Refuse all writes before parallel preparation can partially move /lab
        # pointers on idle nodes while another node still belongs to an old run.
        for node in self.inventory['nodes']:
            verify_owner(self.vmroot,node)
            active=self.remote(node,['sh','-ec','systemctl is-active royak-qualification.service || true']).strip()
            if active=='active':
                raise RuntimeError('Owned guest '+str(node['id'])+' has an active qualification; exact recovery is required before any preparation')
        for node in self.inventory['nodes']:
            if self.remote(node,['docker','ps','-aq']).strip():
                raise RuntimeError('Owned guest '+str(node['id'])+' has residual containers; exact recovery is required before any preparation')

    def provision(self):
        build = json.loads(self.binary.with_name(self.binary.name + ".build.json").read_text())
        self.check("Linux artifact matches unchanged current working sources",
                   build["binary_sha256"] == original.digest(self.binary) and build["source_unchanged_during_build"] and
                   build["source_sha256"] == {str(p.relative_to(original.ROOT)): original.digest(p) for p in original.source_inventory()})
        self.nodes = [dict(n) for n in self.inventory["nodes"]]
        self.preflight_idle()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            identities = list(pool.map(self.prepare, self.nodes))
        self.check("three distinct VM kernels, machine identities and Docker daemons",
                   all(len({i[key] for i in identities}) == 3 for key in ("uuid", "boot_id", "machine_id", "docker")), identities=identities)
        save(self.out / "vm-manifest.json", json.dumps(dict(
            topology="three-parallels-linux-kernels-one-physical-mac", production_ready=False,
            inventory_run=self.inventory["run_id"], nodes=identities, binary_sha256=original.digest(self.binary),
            source_sha256=build["source_sha256"], fixture_sha256=original.digest(Path(__file__)),
            connect_fixture_sha256=original.digest(Path(connect.__file__)),
            fault_fixture_sha256=original.digest(Path(original.__file__))), indent=2))
        self.wg_setup()
        for node in self.nodes:
            api_cert = self.certificate_fingerprint(node, 6443)
            ingress_cert = self.certificate_fingerprint(node, 8080)
            self.check("API and ingress share one persisted TLS identity on VM " + str(node["id"]),
                       api_cert == ingress_cert, fingerprint=api_cert)
        if not isinstance(self, connect.ConnectLab):
            self.ledger_ip = "10.37.129.2"
            self.ledger_url = "http://" + self.ledger_ip + ":8000"
            os.environ.update(MODE="ledger", DB=str(self.out / "ledger.db"))
            import sqlite3
            with sqlite3.connect(os.environ["DB"]) as db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute("CREATE TABLE entries(id TEXT PRIMARY KEY,value TEXT NOT NULL)")
            self.ledger_server = ThreadingHTTPServer((self.ledger_ip, 8000), Handler)
            threading.Thread(target=self.ledger_server.serve_forever, daemon=True).start()
            self.check("application ledger is external to all three VMs", original.request(self.ledger_url + "/health")[0] == 200)

    def wg_setup(self):
        if self.wg_nodes:
            return
        public = {}
        for node in self.nodes:
            public[node["id"]] = self.remote(node, ["sh", "-ec", "umask 077; wg genkey > /lab/wg.key; wg pubkey < /lab/wg.key"]).strip()
            self.remote(node, ["ip", "link", "add", self.iface, "type", "wireguard"])
            self.wg_nodes.add(node["id"])
            self.remote(node, ["ip", "address", "add", node["wg_ip"] + "/24", "dev", self.iface])
            self.remote(node, ["wg", "set", self.iface, "listen-port", "51821", "private-key", "/lab/wg.key"])
        for node in self.nodes:
            for peer in self.nodes:
                if peer == node:
                    continue
                self.remote(node, ["wg", "set", self.iface, "peer", public[peer["id"]], "allowed-ips", peer["wg_ip"] + "/32",
                                   "endpoint", peer["ip"] + ":51821", "persistent-keepalive", "1"])
            self.remote(node, ["ip", "link", "set", self.iface, "up"])
        for node in self.nodes:
            for peer in self.nodes:
                if peer != node:
                    self.remote(node, ["ping", "-c", "1", "-W", "3", peer["wg_ip"]], timeout=8)
        self.check("real kernel WireGuard reaches every other VM", True)

    def select_vm_outage_target(self, candidates):
        return self.random.choice(candidates)

    def restart_node(self):
        def occupied_nodes():
            placement = [(n, self.remote(n, ["docker", "ps", "-q", "--filter", "label=royak.namespace=qualification"]).split()) for n in self.nodes]
            return [(n, ids) for n, ids in placement if ids] if sum(len(ids) for _, ids in placement) == 3 else None
        candidates = original.wait_for(occupied_nodes, "three real application replicas before VM fault", timeout=45)
        node, lost_containers = self.select_vm_outage_target(candidates)
        self.check("hard-stopped VM actually hosts a live application replica", bool(lost_containers),
                   node=node["id"], running_container_ids=lost_containers)
        old_boot = self.remote(node, ["cat", "/proc/sys/kernel/random/boot_id"]).strip()
        old_certificate = self.certificate_fingerprint(node, 8080)
        verify_owner(self.vmroot, node)
        self.event("faults.jsonl", kind="target", node=node["id"], scope="real Parallels VM hard stop; disk preserved", old_boot_id=old_boot)
        run("prlctl", "stop", node["uuid"], "--kill", timeout=60)
        try:
            self.observe(self.args.node_outage)
            survivors = [n for n in self.nodes if n != node]
            counts = [len(self.remote(n, ["docker", "ps", "-q", "--filter", "label=royak.namespace=qualification"]).split()) for n in survivors]
            self.check("other VMs replace lost VM replicas before it returns", sum(counts) == 3, counts=counts)
        finally:
            run("prlctl", "start", node["uuid"], timeout=90)
            def ready():
                try:
                    return self.remote(node, ["docker", "info", "--format", "{{.ID}}"], timeout=5).strip()
                except (RuntimeError, subprocess.TimeoutExpired):
                    return None
            original.wait_for(ready, "VM boot and Docker recovery", timeout=120)
            new_boot = self.remote(node, ["cat", "/proc/sys/kernel/random/boot_id"]).strip()
            self.check("restarted VM has a genuinely new kernel boot identity", new_boot != old_boot, old=old_boot, new=new_boot)
            # WireGuard is ephemeral in this lab; restore its exact saved peer
            # config after reboot, without changing other VMs' live interfaces.
            self.remote(node, ["ip", "link", "add", self.iface, "type", "wireguard"])
            self.remote(node, ["ip", "address", "add", node["wg_ip"] + "/24", "dev", self.iface])
            self.remote(node, ["wg", "setconf", self.iface, "/lab/wg.conf"])
            self.remote(node, ["ip", "link", "set", self.iface, "up"])
            self.start_node(node)
            self.forward(node)
            original.wait_for(lambda: self.api(node, "GET", "/royak/v1/raft/status")[0] == 200, "restarted TLS API")
            self.check("whole-VM restart preserves the exact trusted TLS identity",
                       self.certificate_fingerprint(node, 8080) == old_certificate and
                       self.certificate_fingerprint(node, 6443) == old_certificate)

    def diagnostics(self):
        evidence = []
        secrets_to_hide = (self.token, self.cluster_secret, self.seal,
                           getattr(self, "user", "-no-user-"), getattr(self, "other", "-no-other-"),
                           getattr(self, "viewer", "-no-viewer-"))
        for node in self.prepared_nodes:
            row = dict(node=node["id"])
            try:
                row["resources"] = self.remote(node, ["sh", "-ec", "free -b; cat /proc/loadavg; docker stats --no-stream --format '{{json .}}'"])
                ids = self.remote(node, ["docker", "ps", "-aq", "--filter", "ancestor=" + self.image]).split()
                row["containers"] = []
                for ident in ids:
                    row["containers"].append(dict(id=ident,
                        state=self.remote(node, ["docker", "inspect", "-f", "{{json .State}}", ident]),
                        logs=self.remote(node, ["sh", "-ec", "docker logs --tail 40 " + shlex.quote(ident) + " 2>&1"])))
            except Exception as error:
                row["error"] = type(error).__name__
            evidence.append(row)
        text = json.dumps(evidence, indent=2)
        for secret in secrets_to_hide:
            text = text.replace(secret, "[REDACTED]")
        save(self.out / "vm-failure-diagnostics.json", text)

    def cleanup(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=10)
        for node in self.prepared_nodes:
            try:
                if node["id"] in self.rollback_nodes:
                    self.remote(node, ["sh", "/lab/fault-rollback.sh"])
                    self.remote(node, ["sh", "-ec", "systemctl stop " + self.run + "-rollback.timer 2>/dev/null || true"])
                self.remote(node, ["systemctl", "disable", "--now", "royak-qualification.service"])
                log = self.remote(node, ["tail", "-c", "150000", "/lab/royak.log"])
                for secret in (self.token, self.cluster_secret, self.seal, getattr(self, "user", "-no-user-"), getattr(self, "other", "-no-other-"), getattr(self, "viewer", "-no-viewer-")):
                    log = log.replace(secret, "[REDACTED]")
                save(self.out / f"node-{node['id']}.log", log)
                ids = self.remote(node, ["docker", "ps", "-aq", "--filter", "ancestor=" + self.image]).split()
                if ids:
                    self.remote(node, ["docker", "rm", "-f", *ids])
                self.remote(node, ["docker", "image", "rm", self.image])
                if node["id"] in self.wg_nodes:
                    self.remote(node, ["ip", "link", "delete", self.iface])
                self.remote(node, ["sh", "-ec", "test -z \"$(iptables-save | grep -- " + shlex.quote(self.run) + ")\""])
            except Exception as error:
                self.event("cleanup.jsonl", node=node["id"], error=str(error))
        for process in self.tunnels.values():
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if self.ledger_server:
            self.ledger_server.shutdown()
            self.ledger_server.server_close()


class VMConnectLab(VMMixin, connect.ConnectLab):
    def scenarios(self):
        super().scenarios()
        client = subprocess.run([str(self.args.client), "connect", "list", "--server", self.gateway["api"],
                                 "--ca-cert", str(self.ca), "--token-file", str(self.out / "client.token"),
                                 "--namespace", "team-a"], capture_output=True, timeout=10)
        self.check("laptop retains trusted TLS after issuer process restart without replacing its CA",
                   client.returncode == 0)
        pair = None
        for node in self.nodes:
            groups = {}
            for namespace in ("team-a", "team-b"):
                ids = self.remote(node, ["docker", "ps", "-q", "--filter", "label=royak.namespace=" + namespace,
                                         "--filter", "label=royak.role=main"]).split()
                if ids:
                    ident = ids[0]
                    networks = json.loads(self.remote(node, ["docker", "inspect", "-f", "{{json .NetworkSettings.Networks}}", ident]))
                    groups[namespace] = dict(id=ident, networks=networks)
            if len(groups) == 2:
                pair = node, groups
                break
        self.check("direct network isolation fixtures occupy the same real VM", pair is not None)
        node, groups = pair
        networks_a, networks_b = (set(groups[n]["networks"]) for n in ("team-a", "team-b"))
        self.check("same-host namespaces retain their separately named Docker networks",
                   "rk-team-a" in networks_a and "rk-team-b" in networks_b and
                   "rk-team-a" not in networks_b and "rk-team-b" not in networks_a,
                   node=node["id"], team_a=sorted(networks_a), team_b=sorted(networks_b))
        probe = """import socket,sys
try:
 s=socket.create_connection((sys.argv[1],9090),timeout=2)
 s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n'); data=s.recv(4096);s.close()
 print('CONNECTED' if b'HTTP/1.1 200' in data else 'BAD_RESPONSE')
except OSError: print('DENIED')
"""
        addresses = {}
        for source, target in (("team-a", "team-b"), ("team-b", "team-a")):
            own_ip = next(n["IPAddress"] for n in groups[source]["networks"].values() if n.get("IPAddress"))
            foreign_ip = groups[target]["networks"]["bridge"]["IPAddress"]
            addresses[source] = own_ip, foreign_ip
            positive = self.remote(node, ["docker", "exec", groups[source]["id"], "python3", "-c", probe, own_ip]).strip()
            baseline = self.remote(node, ["docker", "exec", groups[source]["id"], "python3", "-c", probe, foreign_ip]).strip()
            self.check(source + " unpoliced baseline is measured before applying denyAll",
                       positive == "CONNECTED" and baseline == "CONNECTED", own_pod=positive, foreign_pod=baseline,
                       meaning="namespace/API identity alone is not a default-deny network boundary")
        for namespace in ("team-a", "team-b"):
            self.apply("/apis/networking.k8s.io/v1/namespaces/" + namespace + "/networkpolicies",
                       dict(apiVersion="networking.k8s.io/v1", kind="NetworkPolicy",
                            metadata=dict(name="vm-deny-egress", namespace=namespace),
                            spec=dict(podSelector={}, denyAll=True)))
        def denied(source):
            foreign_ip = addresses[source][1]
            return self.remote(node, ["docker", "exec", groups[source]["id"], "python3", "-c", probe, foreign_ip]).strip() == "DENIED"
        # The existing contract declares asynchronous helper installation, not
        # instantaneous default-deny. Require actual TCP denial, not an API ack.
        for source, target in (("team-a", "team-b"), ("team-b", "team-a")):
            original.wait_for(lambda: denied(source), "explicit denyAll enforced in " + source, timeout=60)
            positive = self.remote(node, ["docker", "exec", groups[source]["id"], "python3", "-c", probe, addresses[source][0]]).strip()
            self.check(source + " explicit denyAll blocks direct TCP into " + target,
                       positive == "CONNECTED" and denied(source), local_positive_control=positive,
                       scope="Royak denyAll egress subset after activation, not Kubernetes policy equivalence")


class VMFaultLab(VMMixin, original.Lab):
    def wg_setup(self):
        super().wg_setup()
        for node in self.nodes:
            # Keep private config inside the owned guest only, never in reports.
            self.remote(node, ["sh", "-ec", "umask 077; wg showconf rkconn > /lab/wg.conf"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["connect", "fault"])
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()
    args.client = args.client.resolve()
    for key, value in dict(seed=42, probe_mode="http", ui_check=False, rate=5, settle=20,
                           node_outage=45, baseline_availability=.99).items():
        setattr(args, key, value)
    lab = (VMConnectLab if args.mode == "connect" else VMFaultLab)(args)
    fixture_before = original.digest(Path(__file__))
    source_before = {str(p.relative_to(original.ROOT)): original.digest(p) for p in original.source_inventory()}
    result = lab.execute_connect() if args.mode == "connect" else lab.execute()
    report = lab.out / ("connect-report.json" if args.mode == "connect" else "report.json")
    data = json.loads(report.read_text())
    data.update(topology="three-parallels-linux-kernels-one-physical-mac", production_ready=False,
                qualification="bounded multi-VM qualification; not independent physical hosts",
                vm_fixture_sha256=original.digest(Path(__file__)))
    if fixture_before != original.digest(Path(__file__)) or source_before != {
            str(p.relative_to(original.ROOT)): original.digest(p) for p in original.source_inventory()}:
        data["passed"] = False
        data["failure"] = data.get("failure") or "source or VM fixture changed during qualification"
        result = 1
    if (lab.out / "cleanup.jsonl").exists():
        data["passed"] = False
        data["failure"] = data.get("failure") or "owned cleanup failed"
        result = 1
    save(report, json.dumps(data, indent=2))
    print(report, flush=True)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
