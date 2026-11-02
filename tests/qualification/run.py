#!/usr/bin/env python3
"""Isolated three-daemon qualification lab; Docker CLI + Python stdlib only."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from checker import check_history, read_jsonl, summarize

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
LABEL = "royak.qualification"
TLS = ssl._create_unverified_context()  # ephemeral lab certificates, loopback published ports only


def command(args, timeout=120, **kwargs):
    result = subprocess.run([str(a) for a in args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, **kwargs)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {args[:4]}\n{result.stderr.decode()[-3000:]}")
    return result.stdout.decode()


def docker(*args, **kwargs):
    return command(["docker", *args], **kwargs)


def request(url, method="GET", body=None, token=None, host=None, timeout=8):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if host:
        headers["Host"] = host
    req = urllib.request.Request(url, None if body is None else json.dumps(body).encode(), headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=TLS) as response:
            raw, status = response.read(), response.status
    except urllib.error.HTTPError as error:
        with error:
            raw, status = error.read(), error.code
    except (OSError, TimeoutError):
        return 0, None
    try:
        return status, json.loads(raw)
    except ValueError:
        return status, raw.decode(errors="replace")[:500]


def wait_for(predicate, description, timeout=90):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(1)
    raise RuntimeError("timeout: " + description)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_inventory():
    """Include embedded assets too: changing a watchdog/UI changes the binary."""
    return [ROOT / "Cargo.toml", ROOT / "Cargo.lock", *sorted(
        p for p in (ROOT / "src").rglob("*") if p.is_file() and p.suffix in {".rs", ".html", ".js", ".css", ".sh"})]


def cleanup_build_resources(run, volumes, completed):
    """Delete only label-bound build resources, never a colliding foreign name."""
    failures=[]
    for kind,name in [('container',run),*(('volume',v) for v in volumes)]:
        field='.Config.Labels' if kind=='container' else '.Labels'
        inspected=subprocess.run(['docker',kind,'inspect','-f','{{index '+field+' "'+LABEL+'"}}',name],capture_output=True,text=True)
        if inspected.returncode!=0:
            if completed:failures.append(kind+' cleanup observation unavailable')
            continue
        if inspected.stdout.strip()!=run:
            failures.append('refused non-owned '+kind)
            continue
        removed=subprocess.run(['docker',kind,'rm',*(['-f'] if kind=='container' else []),name],capture_output=True)
        if removed.returncode!=0:failures.append('owned '+kind+' cleanup failed')
    if failures:raise RuntimeError('; '.join(failures))


def build(binary, debug_symbols=False, symbols_only=False):
    """Compile exactly the working sources; never writes to the user's target/cache."""
    binary = binary.resolve()
    build_log=binary.with_name(binary.name+'.build.log')
    if binary.exists() or binary.with_name(binary.name + '.build.json').exists() or build_log.exists():
        raise ValueError('never overwrite an earlier binary/build evidence')
    binary.parent.mkdir(parents=True, exist_ok=True)
    sources = {str(p.relative_to(ROOT)): digest(p) for p in source_inventory()}
    run = "rkq-build-" + secrets.token_hex(4)
    volumes = [run + "-target", run + "-cargo"]
    built = None
    try:
        for volume in volumes:
            docker("volume", "create", "--label", LABEL + "=" + run, volume)
            if docker('volume','inspect','-f','{{index .Labels "'+LABEL+'"}}',volume).strip()!=run:
                raise RuntimeError('refusing a non-owned build volume')
        print("Building Linux binary from current working sources…", flush=True)
        debug_env = (["-e", "CARGO_PROFILE_RELEASE_STRIP=none"] if symbols_only else
                     ["-e", "CARGO_PROFILE_RELEASE_DEBUG=1", "-e", "CARGO_PROFILE_RELEASE_STRIP=none",
                      "-e", "RUSTFLAGS=-C force-frame-pointers=yes"] if debug_symbols else [])
        build_args=["docker","run", "--name", run, "--label", LABEL + "=" + run,
               "--cpus","3","--memory","6g","--memory-swap","6g",*debug_env,
               "-v", str(ROOT) + ":/work:ro", "-v", volumes[0] + ":/target",
               "-v", volumes[1] + ":/usr/local/cargo", "-w", "/work",
               "-e", "CARGO_TARGET_DIR=/target","-e","CARGO_BUILD_JOBS=3", "rust:1.90-alpine", "sh", "-ec",
               "rustc -Vv\ncargo -V\napk add --no-cache musl-dev build-base cmake perl linux-headers >/dev/null\ncargo build --locked --release"]
        with build_log.open('x') as log:
            compiled=subprocess.run(build_args,stdout=log,stderr=subprocess.STDOUT,timeout=1800)
        if compiled.returncode:
            raise RuntimeError('Linux build failed; preserved raw log: '+str(build_log))
        after = {str(p.relative_to(ROOT)): digest(p) for p in source_inventory()}
        if after != sources:
            raise RuntimeError("source changed during the Linux build; binary is not qualified")
        if docker('container','inspect','-f','{{index .Config.Labels "'+LABEL+'"}}',run).strip()!=run:
            raise RuntimeError('build container ownership changed')
        state=json.loads(docker('container','inspect','-f','{{json .State}}',run))
        limits=json.loads(docker('container','inspect','-f','{{json .HostConfig}}',run))
        if (state['Running'] or state['Restarting'] or state['Dead'] or state['OOMKilled'] or state['ExitCode']!=0
            or limits['Memory']!=6*1024**3 or limits['MemorySwap']!=6*1024**3 or limits['NanoCpus']!=3*10**9):
            raise RuntimeError('compiler terminal/resource validation failed')
        image=docker('container','inspect','-f','{{.Image}}',run).strip()
        if len(image)!=71 or not image.startswith('sha256:') or any(c not in '0123456789abcdef' for c in image[7:]):
            raise RuntimeError('actual build image identity unavailable')
        docker("cp", run + ":/target/release/royak", str(binary))
        binary.chmod(0o755)
        built=dict(
            binary_sha256=digest(binary), source_sha256=sources,
            source_unchanged_during_build=True, debug_symbols=debug_symbols or symbols_only,
            symbols_only=symbols_only,build_fixture_sha256=digest(Path(__file__)),
            builder_image_id=image,build_command=build_args,
            build_resource_limits=dict(memory_bytes=limits['Memory'],memory_swap_bytes=limits['MemorySwap'],nano_cpus=limits['NanoCpus']),
            compiler_terminal_state=state,
            raw_build_log_sha256=digest(build_log),raw_build_log=str(build_log))
    finally:
        # A random name is not ownership. Never remove or mount a colliding
        # foreign resource, and never publish a qualified build before cleanup.
        cleanup_build_resources(run,volumes,built is not None)
    if built is not None:
        built['owned_build_cleanup_verified']=True
        binary.with_name(binary.name+'.build.json').write_text(json.dumps(built,indent=2))
        print(str(binary),flush=True)


class Lab:
    def __init__(self, args):
        self.args = args
        self.run = "rkq-" + time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
        self.out = HERE / ".runs" / self.run
        self.out.mkdir(parents=True, mode=0o700)
        self.token = secrets.token_hex(24)
        self.cluster_secret = secrets.token_hex(24)
        self.seal = secrets.token_hex(16)
        self.nodes = []
        self.containers, self.volumes = [], []
        self.network = None
        self.image = self.run + ":workload"
        self.phase = "setup"
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.thread = None
        self.client_error = None
        self.checks = []
        self.control_writes = {}
        self.started = time.monotonic()
        self.binary = args.binary.resolve()
        self.random = random.Random(args.seed)

    def event(self, filename, **event):
        event = dict(time_ns=time.time_ns(), elapsed_s=round(time.monotonic() - self.started, 6),
                     phase=self.phase, **event)
        with self.lock:
            with (self.out / filename).open("a") as stream:
                stream.write(json.dumps(event, sort_keys=True) + "\n")
                stream.flush()

    def check(self, name, passed, **details):
        self.checks.append(dict(name=name, passed=bool(passed), **details))
        print(("PASS " if passed else "FAIL ") + name, flush=True)
        if not passed:
            raise AssertionError(name + ": " + json.dumps(details))

    def volume(self, suffix):
        name = self.run + "-" + suffix
        docker("volume", "create", "--label", LABEL + "=" + self.run, name)
        self.volumes.append(name)
        return name

    def container(self, name, *args):
        self.containers.append(name)  # include partially created containers in cleanup
        return docker("run", "-d", "--name", name, "--label", LABEL + "=" + self.run, *args).strip()

    def port(self, name, internal):
        return docker("port", name, str(internal) + "/tcp").strip().split(":")[-1]

    def provision(self):
        if self.binary.read_bytes()[:4] != b"\x7fELF":
            raise ValueError("--binary must be a Linux ELF binary; use the build command first")
        info = json.loads(docker("info", "--format", "{{json .}}"))
        if info["MemTotal"] < 5 * 1024**3 or info["NCPU"] < 4:
            raise RuntimeError("Lab requires at least 5 GiB Docker memory and 4 CPUs")
        ids = docker("network", "ls", "-q").split()
        networks = json.loads(docker("network", "inspect", *ids)) if ids else []
        used = [ipaddress.ip_network(c["Subnet"]) for n in networks for c in (n["IPAM"].get("Config") or []) if c.get("Subnet")]
        subnet = next((ipaddress.ip_network(f"10.231.{i}.0/24") for i in range(1, 255)
                       if not any(ipaddress.ip_network(f"10.231.{i}.0/24").overlaps(old) for old in used)), None)
        if subnet is None:
            raise RuntimeError("No non-overlapping test subnet; no existing networks were changed")
        self.network = self.run
        docker("network", "create", "--label", LABEL + "=" + self.run, "--subnet", str(subnet), self.network)
        docker("build", "-f", HERE / "Dockerfile.workload", "--label", LABEL + "=" + self.run,
               "-t", self.image, HERE, timeout=300)
        archive = self.out / "workload.tar"
        docker("save", "-o", archive, self.image)
        ledger = self.run + "-ledger"
        self.container(ledger, "--network", self.network, "--network-alias", "ledger", "-p", "127.0.0.1::8000",
                       "-e", "MODE=ledger", "-e", "DB=/data/ledger.db", "-v", self.volume("ledger") + ":/data", self.image)
        self.ledger_url = "http://127.0.0.1:" + self.port(ledger, 8000)
        self.ledger_ip = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", ledger).strip()
        wait_for(lambda: request(self.ledger_url + "/health")[0] == 200, "ledger")
        for i in range(1, 4):
            name = self.run + "-n" + str(i)
            self.container(name, "--privileged", "--memory", "1536m", "--cpus", "2", "--network", self.network,
                           "--tmpfs", "/run",
                           "-p", "127.0.0.1::6443", "-p", "127.0.0.1::8080", "-e", "DOCKER_TLS_CERTDIR=",
                           "-e", "ROYAK_TOKEN=" + self.token, "-e", "ROYAK_CLUSTER_SECRET=" + self.cluster_secret,
                           "-e", "ROYAK_SECRET_KEY=" + self.seal, "-e", "ROYAK_NODE_NAME=q-n" + str(i),
                           "-e", "ROYAK_STATE=/lab/state.json", "-e", "ROYAK_DATA_DIR=/lab/data",
                           "-v", str(self.binary) + ":/opt/royak:ro", "-v", self.volume("n" + str(i) + "-docker") + ":/var/lib/docker",
                           "-v", self.volume("n" + str(i) + "-state") + ":/lab", "docker:28-dind", "--storage-driver=vfs", "--tls=false")
            wait_for(lambda: subprocess.run(["docker", "exec", name, "docker", "info"], capture_output=True).returncode == 0,
                     "inner Docker " + name)
            ip = docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).strip()
            node = dict(id=i, name=name, ip=ip, api="https://127.0.0.1:" + self.port(name, 6443),
                        ingress="https://127.0.0.1:" + self.port(name, 8080))
            self.nodes.append(node)
            with archive.open("rb") as stream:
                docker("exec", "-i", name, "docker", "load", stdin=stream)
        archive.unlink()
        for node in self.nodes:
            self.start_node(node)
        source_files = source_inventory()
        manifest = dict(schema_version=1, run_id=self.run, seed=self.args.seed, topology="single-host-three-independent-docker-daemons",
                        production_ready=False, started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        head=command(["git", "rev-parse", "HEAD"], cwd=ROOT).strip(),
                        tracked_diff_sha256=hashlib.sha256(subprocess.check_output(["git", "diff", "--binary"], cwd=ROOT)).hexdigest(),
                        source_sha256={str(p.relative_to(ROOT)): digest(p) for p in source_files}, binary_sha256=digest(self.binary),
                        probe_mode=self.args.probe_mode,
                        driver_pid=os.getpid(),
                        harness_sha256={p.name: digest(p) for p in sorted(HERE.glob("*.py"))},
                        ui_fixture_sha256=digest(HERE / "topology_live.cjs") if self.args.ui_check else None,
                        contract=dict(rate=self.args.rate, settle_seconds=self.args.settle, soak_seconds=self.args.duration,
                                      node_outage_seconds=self.args.node_outage, baseline_availability=self.args.baseline_availability),
                        docker=dict(version=info["ServerVersion"], memory=info["MemTotal"], cpus=info["NCPU"]),
                        images={image: json.loads(docker("image", "inspect", image))[0]["Id"] for image in [self.image, "docker:28-dind"]},
                        nodes=[{k: v for k, v in n.items() if k != "name"} for n in self.nodes],
                        non_claims=["cross-host qualification", "distributed volume durability", "linearizability proof", "72h soak", "ML predictive quality"])
        (self.out / "manifest.json").write_text(json.dumps(manifest, indent=2))

    def start_node(self, node):
        peers = ",".join(f"{n['id']}@{n['ip']}:6443" for n in self.nodes if n != node)
        docker("exec", "-d", "-e", "ROYAK_ADVERTISE_ADDR=" + node["ip"] + ":6443", node["name"], "sh", "-ec",
               f"cd /lab; echo $$ > /lab/royak.pid; exec /opt/royak watch --tls --port 6443 --ingress-port 8080 --interval 2 --node-id {node['id']} --peers '{peers}' "
               + ("--bootstrap " if node["id"] == 1 else "") + ">> /lab/royak.log 2>&1")

    def api(self, node, method, path, body=None, timeout=8):
        return request(node["api"] + path, method, body, self.token, timeout=timeout)

    def leader(self, exclude=None):
        for node in self.nodes:
            if node == exclude:
                continue
            code, value = self.api(node, "GET", "/royak/v1/raft/status", timeout=2)
            if code == 200 and value.get("leaderConfirmed"):
                return node
        return None

    def apply(self, path, body):
        for _ in range(5):
            leader = wait_for(self.leader, "confirmed leader", timeout=45)
            code, value = self.api(leader, "POST", path, body, timeout=12)
            if 200 <= code < 300:
                return value
            if code != 421:
                raise RuntimeError(f"apply failed: {code} {value}")
        raise RuntimeError("leader kept changing")

    def control_write(self, name):
        value = secrets.token_hex(8)
        body = dict(apiVersion="v1", kind="ConfigMap", metadata=dict(name=name, namespace="qualification"), data=dict(value=value))
        self.apply("/api/v1/namespaces/qualification/configmaps", body)
        self.control_writes[name] = value
        self.event("history.jsonl", kind="control_ack", id=name, value=value)

    def deploy(self):
        self.apply("/api/v1/namespaces", dict(apiVersion="v1", kind="Namespace", metadata=dict(name="qualification")))
        probe = (dict(httpGet=dict(path="/health", port=8000)) if self.args.probe_mode == "http" else
                 {"exec": {"command": ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=1).close()"]}})
        container = dict(name="web", image=self.image, ports=[dict(containerPort=8000)],
                         env=[dict(name="LEDGER_URL", value="http://" + self.ledger_ip + ":8000"), dict(name="PYTHONDONTWRITEBYTECODE", value="1")],
                         securityContext=dict(runAsUser=10001, runAsGroup=10001, runAsNonRoot=True,
                                              readOnlyRootFilesystem=True, allowPrivilegeEscalation=False,
                                              capabilities=dict(drop=["ALL"])),
                         readinessProbe=probe,
                         resources=dict(limits=dict(cpu="250m", memory="64Mi")))
        self.apply("/apis/apps/v1/namespaces/qualification/deployments", dict(apiVersion="apps/v1", kind="Deployment",
                   metadata=dict(name="web", namespace="qualification"), spec=dict(replicas=3,
                   selector=dict(matchLabels=dict(app="web")), template=dict(metadata=dict(labels=dict(app="web")), spec=dict(containers=[container])))))
        self.apply("/api/v1/namespaces/qualification/services", dict(apiVersion="v1", kind="Service", metadata=dict(name="web", namespace="qualification"),
                   spec=dict(selector=dict(app="web"), ports=[dict(port=80, targetPort=8000)])))
        self.apply("/apis/networking.k8s.io/v1/namespaces/qualification/ingresses", dict(apiVersion="networking.k8s.io/v1", kind="Ingress",
                   metadata=dict(name="web", namespace="qualification"), spec=dict(rules=[dict(host="qualification.test", http=dict(paths=[dict(path="/", pathType="Prefix",
                   backend=dict(service=dict(name="web", port=dict(number=80))))]))])))
        wait_for(lambda: all(request(n["ingress"] + "/health", host="qualification.test", timeout=2)[0] == 200 for n in self.nodes),
                 "ingress ready on all three daemons", timeout=120)
        ids = [docker("exec", n["name"], "docker", "info", "--format", "{{.ID}}").strip() for n in self.nodes]
        self.check("three distinct Docker daemons", len(set(ids)) == 3)
        self.control_write("baseline")

    def client(self):
        try:
            self.client_loop()
        except BaseException as error:
            self.client_error = repr(error)
            self.stop.set()

    def client_loop(self):
        sequence = 0
        while not self.stop.is_set():
            node = self.nodes[sequence % len(self.nodes)]
            ident = self.run + "-" + str(sequence)
            value = hashlib.sha256(ident.encode()).hexdigest()
            start = time.monotonic()
            self.event("history.jsonl", kind="app_invoke", id=ident, value=value, node=node["id"])
            code, body = request(node["ingress"] + "/write", "POST", dict(id=ident, value=value), host="qualification.test", timeout=3)
            body = body if isinstance(body, dict) else {}
            self.event("history.jsonl", kind="app_complete", id=ident, value=value, node=node["id"], status=code,
                       returned_id=body.get("id"), returned_value=body.get("value"), instance=body.get("instance"),
                       latency_ms=round((time.monotonic() - start) * 1000, 3))
            sequence += 1
            self.stop.wait(max(0, 1 / self.args.rate - (time.monotonic() - start)))

    def observe(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self.client_error:
                raise RuntimeError("external client failed: " + self.client_error)
            statuses = []
            for node in self.nodes:
                code, body = self.api(node, "GET", "/royak/v1/raft/status", timeout=1)
                statuses.append(dict(node=node["id"], http_status=code, raft=body if code == 200 else None))
            self.event("telemetry.jsonl", kind="sample", fault_label=self.phase, nodes=statuses,
                       cpu_percent=None, memory_bytes=None, note="missing measurements are null, not zero; labels are injector ground truth")
            self.stop.wait(min(2, max(0, end - time.monotonic())))

    def fault(self, name, action):
        self.phase = name
        self.event("faults.jsonl", kind="fault_start", fault=name)
        try:
            action()
        finally:
            self.event("faults.jsonl", kind="fault_end", fault=name)
        self.phase = "recovery-" + name
        self.observe(self.args.settle)
        self.control_write(name)

    def kill_pod(self):
        candidates = []
        for node in self.nodes:
            for ident in docker("exec", node["name"], "docker", "ps", "-q", "--filter", "label=royak.namespace=qualification").split():
                candidates.append((node, ident))
        if not candidates:
            raise RuntimeError("no workload pod to kill")
        node, ident = self.random.choice(candidates)
        self.event("faults.jsonl", kind="target", node=node["id"], container=ident)
        docker("exec", node["name"], "docker", "rm", "-f", ident)
        self.observe(10)

    def kill_leader(self):
        old = wait_for(self.leader, "leader before kill")
        self.event("faults.jsonl", kind="target", node=old["id"])
        docker("exec", old["name"], "sh", "-ec",
               'pid=$(cat /lab/royak.pid); [ "$(readlink /proc/$pid/exe)" = /opt/royak ]; kill -KILL "$pid"')
        try:
            wait_for(lambda: self.leader(exclude=old), "new leader after SIGKILL", timeout=50)
            self.control_write("while-leader-down")
            self.observe(8)
        finally:
            self.start_node(old)

    def partition(self):
        old = wait_for(self.leader, "leader before partition")
        installed = []
        try:
            for peer in self.nodes:
                if peer == old:
                    continue
                for chain, direction in [("INPUT", "-s"), ("OUTPUT", "-d")]:
                    rule = [chain, direction, peer["ip"], "-p", "tcp", "--dport", "6443", "-m", "comment", "--comment", self.run, "-j", "DROP"]
                    docker("exec", old["name"], "iptables", "-I", *rule)
                    installed.append(rule)
            self.event("faults.jsonl", kind="target", node=old["id"], scope="peer control-plane TCP/6443 only")
            wait_for(lambda: self.leader(exclude=old), "majority elects during partition", timeout=50)
            body = dict(apiVersion="v1", kind="ConfigMap", metadata=dict(name="minority-write", namespace="qualification"), data=dict(value="unconfirmed"))
            code, _ = self.api(old, "POST", "/api/v1/namespaces/qualification/configmaps", body, timeout=12)
            self.event("history.jsonl", kind="minority_write_complete", status=code, outcome="unknown" if code in (0, 504) else "response")
            reachable, _ = self.api(old, "GET", "/royak/v1/raft/status")
            self.check("minority API remains reachable from the external client", reachable == 200, status=reachable)
            self.check("isolated minority explicitly does not acknowledge a state write", code in (421, 503, 504), status=code)
            self.control_write("majority-during-partition")
            self.observe(8)
        finally:
            for rule in reversed(installed):
                docker("exec", old["name"], "iptables", "-D", *rule)

    def restart_node(self):
        node = self.random.choice(self.nodes)
        self.event("faults.jsonl", kind="target", node=node["id"], scope="outer container and inner daemon, disk preserved")
        docker("stop", "-t", "1", node["name"])
        try:
            self.observe(self.args.node_outage)
            survivors = [n for n in self.nodes if n != node]
            counts = [len(docker("exec", n["name"], "docker", "ps", "-q", "--filter", "label=royak.namespace=qualification").split()) for n in survivors]
            self.check("surviving daemons replace the lost node's replicas", sum(counts) == 3,
                       counts_per_survivor=counts, outage_seconds=self.args.node_outage)
        finally:
            docker("start", node["name"])
            wait_for(lambda: subprocess.run(["docker", "exec", node["name"], "docker", "info"], capture_output=True).returncode == 0, "Docker after restart")
            # Docker reallocates ephemeral published ports on stop/start. The
            # internal peer IP is stable; external client endpoints must refresh.
            node["api"] = "https://127.0.0.1:" + self.port(node["name"], 6443)
            node["ingress"] = "https://127.0.0.1:" + self.port(node["name"], 8080)
            self.event("faults.jsonl", kind="external_endpoint_refresh", node=node["id"], api=node["api"], ingress=node["ingress"])
            self.start_node(node)

    def verify(self):
        self.phase = "verification"
        wait_for(lambda: all(request(n["ingress"] + "/health", host="qualification.test", timeout=2)[0] == 200 for n in self.nodes), "all ingress recovered", timeout=90)
        self.stop.set()
        self.thread.join(timeout=10)
        code, ledger = request(self.ledger_url + "/entries")
        if code != 200:
            raise RuntimeError("external ledger unavailable at verification")
        (self.out / "ledger.json").write_text(json.dumps(ledger, sort_keys=True))
        events = read_jsonl(self.out / "history.jsonl")
        result = check_history(events, ledger)
        performance = summarize(events)
        (self.out / "performance.json").write_text(json.dumps(performance, indent=2))
        self.check("external client completed without an internal error", not self.client_error, error=self.client_error)
        self.check("acknowledged application writes retained without corruption", result["passed"], **{k:v for k,v in result.items() if k != "passed"})
        baseline = performance.get("baseline", {})
        self.check("baseline meets declared availability and covers every ingress",
                   baseline.get("availability", 0) >= self.args.baseline_availability and baseline.get("successful_ingress_nodes") == [1, 2, 3],
                   threshold=self.args.baseline_availability, observed=baseline)
        self.check("application served requests during every injected fault",
                   all(performance.get(p, {}).get("successes", 0) > 0 for p in ("pod-kill", "leader-sigkill", "control-partition", "node-restart")),
                   scope="at least one success per fault window; NOT an availability SLO", observed=performance)
        def converged():
            for node in self.nodes:
                for name, value in self.control_writes.items():
                    status, body = self.api(node, "GET", "/api/v1/namespaces/qualification/configmaps/" + name, timeout=2)
                    if status != 200 or body.get("data", {}).get("value") != value:
                        return False
            return True
        wait_for(converged, "acknowledged control writes converge on every node", timeout=45)
        self.check("acknowledged control writes survive faults and converge", True, writes=len(self.control_writes))
        counts = [len(docker("exec", n["name"], "docker", "ps", "-q", "--filter", "label=royak.namespace=qualification").split()) for n in self.nodes]
        self.check("replica count settles to exactly three", sum(counts) == 3, counts_per_daemon=counts)
        self.check("application actually placed on multiple daemons", sum(c > 0 for c in counts) >= 2, counts_per_daemon=counts)
        constraints = []
        for node in self.nodes:
            ids = docker("exec", node["name"], "docker", "ps", "-q", "--filter", "label=royak.namespace=qualification").split()
            for ident in ids:
                fields = docker("exec", node["name"], "docker", "inspect", "-f",
                                '{{json .Config.User}}|{{json .HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapDrop}}|{{json .HostConfig.SecurityOpt}}', ident).strip().split("|")
                user, readonly, dropped, options = [json.loads(field) for field in fields]
                status = docker("exec", node["name"], "docker", "exec", ident, "cat", "/proc/1/status")
                kernel = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
                constraints.append(dict(node=node["id"], container=ident, user=user, readonly=readonly, cap_drop=dropped,
                                        security_opt=options, uid=kernel.get("Uid", "").split(), gid=kernel.get("Gid", "").split(), cap_eff=kernel.get("CapEff", "").strip(),
                                        cap_bnd=kernel.get("CapBnd", "").strip(),
                                        no_new_privs=kernel.get("NoNewPrivs", "").strip()))
        (self.out / "security.json").write_text(json.dumps(constraints, indent=2))
        self.check("all surviving/replacement pods retain enforced security constraints", len(constraints) == 3 and all(
            c["user"] == "10001:10001" and c["readonly"] and "ALL" in (c["cap_drop"] or []) and
            c["uid"] == ["10001"] * 4 and c["gid"] == ["10001"] * 4 and c["cap_eff"] == "0000000000000000" and c["cap_bnd"] == "0000000000000000" and c["no_new_privs"] == "1"
            for c in constraints), observed=constraints)

        if self.args.ui_check:
            environment = dict(os.environ, ROYAK_UI_URL=self.nodes[0]["api"], ROYAK_UI_TOKEN=self.token,
                               ROYAK_UI_EVIDENCE=str(self.out))
            if self.args.playwright_module:
                environment["ROYAK_PLAYWRIGHT"] = self.args.playwright_module
            output = command([self.args.node, HERE / "topology_live.cjs"], env=environment, timeout=120)
            (self.out / "ui.log").write_text(output.replace(self.token, "[REDACTED]"))
            ui = json.loads((self.out / "ui-report.json").read_text())
            self.check("live browser topology and read-only interactions", ui.get("passed") is True and ui.get("synthetic") is False)

    def cleanup(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=10)
        for node in self.nodes:
            try:
                log = docker("exec", node["name"], "tail", "-c", "200000", "/lab/royak.log")
                for secret in (self.token, self.cluster_secret, self.seal):
                    log = log.replace(secret, "[REDACTED]")
                (self.out / f"node-{node['id']}.log").write_text(log)
            except Exception:
                pass
        # Exact names AND ownership labels required; no global prune or broad kill.
        for name in reversed(self.containers):
            try:
                owned = docker("inspect", "-f", '{{index .Config.Labels "' + LABEL + '"}}', name).strip()
                if owned == self.run:
                    docker("rm", "-f", name)
            except Exception as error:
                self.event("cleanup.jsonl", resource=name, error=str(error))
        for volume in self.volumes:
            try:
                if docker("volume", "inspect", "-f", '{{index .Labels "' + LABEL + '"}}', volume).strip() == self.run:
                    docker("volume", "rm", volume)
            except Exception as error:
                self.event("cleanup.jsonl", resource=volume, error=str(error))
        if self.network:
            try:
                if docker("network", "inspect", "-f", '{{index .Labels "' + LABEL + '"}}', self.network).strip() == self.run:
                    docker("network", "rm", self.network)
            except Exception as error:
                self.event("cleanup.jsonl", resource=self.network, error=str(error))
        subprocess.run(["docker", "image", "rm", self.image], capture_output=True)

    def execute(self):
        print("Evidence: " + str(self.out), flush=True)
        failure = None
        try:
            self.provision()
            self.deploy()
            self.phase = "baseline"
            self.thread = threading.Thread(target=self.client, daemon=True)
            self.thread.start()
            self.observe(self.args.settle)
            for name, action in [("pod-kill", self.kill_pod), ("leader-sigkill", self.kill_leader),
                                 ("control-partition", self.partition), ("node-restart", self.restart_node)]:
                self.fault(name, action)
            self.phase = "soak"
            self.observe(self.args.duration)
            self.verify()
        except BaseException as error:
            failure = type(error).__name__ + ": " + str(error)
            print(failure, file=sys.stderr, flush=True)
        finally:
            self.cleanup()
            report = dict(schema_version=1, run_id=self.run, passed=failure is None, failure=failure,
                          checks=self.checks, duration_s=round(time.monotonic() - self.started, 3),
                          qualification="single-host experimental lab; not production certification")
            (self.out / "report.json").write_text(json.dumps(report, indent=2))
        return 1 if failure else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["build", "run"])
    parser.add_argument("--binary", type=Path, default=HERE / ".runs" / "linux-royak")
    parser.add_argument("--debug-symbols", action="store_true", help="retain Linux diagnostic symbols/frame pointers; build action only")
    parser.add_argument("--symbols-only", action="store_true", help="retain symbol table without changing release optimization/frame pointers")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--rate", type=float, default=5)
    parser.add_argument("--settle", type=int, default=20)
    parser.add_argument("--duration", type=int, default=30, help="additional soak seconds, after the fault matrix")
    parser.add_argument("--baseline-availability", type=float, default=0.99)
    parser.add_argument("--node-outage", type=int, default=45, help="seconds a daemon stays down before checking replacement replicas")
    parser.add_argument("--probe-mode", choices=["http", "exec-ipv4"], default="http",
                        help="exec-ipv4 is an explicit workaround for the tracked localhost/IPv6 HTTP probe issue")
    parser.add_argument("--ui-check", action="store_true", help="verify/capture the actual recovered topology in Chromium")
    parser.add_argument("--node", default="node", help="Node runtime for optional UI check")
    parser.add_argument("--playwright-module", help="explicit bundled Playwright module path")
    args = parser.parse_args()
    if args.rate <= 0 or args.settle < 1 or args.duration < 0 or args.node_outage < 1:
        parser.error("positive rate/settle and nonnegative duration required")
    if not 0 <= args.baseline_availability <= 1:
        parser.error("baseline availability must be between zero and one")
    if args.action == "build":
        build(args.binary, args.debug_symbols, args.symbols_only)
        return 0
    return Lab(args).execute()


if __name__ == "__main__":
    sys.exit(main())
