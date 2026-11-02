#!/usr/bin/env python3
"""Bounded real-VM endurance run. Separate evidence, no product-code changes.

Only the exact owned Parallels inventory is touched. Application writes are never
replayed. Fresh Connect sessions may select another explicitly pre-trusted issuer.
"""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import selectors
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from bootstrap import run, save, ssh, verify_owner
from load_balancer import LBVMFaultLab
from qualify import original
from checker import read_jsonl, check_history, summarize
from soak_checks import resource_report, traffic_gate, continuity, guest_cleanup_passed

HERE = Path(__file__).resolve().parent
FAULTS = ("pod-kill", "leader-sigkill", "control-partition", "node-restart", "wireguard-down")


def fixtures():
    paths = [HERE / p for p in ("soak.py", "soak_checks.py", "soak_metrics.py", "pid_census.py", "qualify.py", "load_balancer.py", "bootstrap.py", "launch_soak.py", "recover.py")]
    paths += [original.HERE / p for p in ("run.py", "workload.py", "checker.py", "Dockerfile.workload")]
    return {str(p): original.digest(p) for p in paths}


class SoakLab(LBVMFaultLab):
    def __init__(self, args):
        super().__init__(args)
        old = self.out
        self.run = self.run.replace("rkq-", "rkq-soak-", 1)
        self.out = old.with_name(self.run)
        old.rename(self.out)
        self.image = self.run + ":workload"
        self.user = secrets.token_hex(24)
        self.other, self.viewer = "-unused-other-", "-unused-viewer-"
        self.connect_stop = threading.Event()
        self.metrics_stop = threading.Event()
        self.connect_threads, self.metrics_thread = [], None
        self.children = {}
        self.child_lock = threading.Lock()
        self.status_lock = threading.Lock()
        self.metrics = []
        self.heartbeat_at = 0
        self.workload_started = None
        self.ca_paths = {}
        self.cli_forced_kills = 0
        self.fault_count = 0

    def check(self, name, passed, **details):
        # Provisioning/fault actions still fail immediately. Final verification
        # records failed assertions but must continue to collect independent
        # drain/resource evidence; none of these failures is converted to PASS.
        try:
            super().check(name, passed, **details)
        except AssertionError:
            if not getattr(self, "collecting_closeout", False):
                raise

    def status(self, state="running", **extra):
        value = json.dumps(dict(
            schema_version=1, run=self.run, pid=os.getpid(), state=state, phase=self.phase,
            updated_at=time.time(), evidence=str(self.out), profile=self.args.profile,
            requested_seconds=self.args.duration, faults_completed=self.fault_count,
            workload_elapsed_s=None if self.workload_started is None else round(time.monotonic()-self.workload_started, 2),
            **extra), indent=2)
        with self.status_lock:
            temporary = self.out / ".soak-status.tmp"
            save(temporary, value)
            temporary.replace(self.out / "soak-status.json")

    def write_remote(self, node, path, data, mode="600"):
        if path == "/lab/environment":
            super().write_remote(node, "/lab/connect-tokens.csv", f'{self.user},soak-user,soak-user,"soak-connectors"\n')
            data = data + 'ROYAK_TOKEN_FILE="/lab/connect-tokens.csv"\n'
        if path == "/lab/build/workload.py":
            data = data.decode() if isinstance(data, bytes) else data
            needle = "class Handler(BaseHTTPRequestHandler):"
            if data.count(needle) != 1:
                raise RuntimeError("workload fixture shape changed")
            # Same durable external ledger/application, but actual persistent
            # HTTP/1.1 TCP connections for the Connect endurance workload.
            data = data.replace(needle, needle + '\n    protocol_version = "HTTP/1.1"')
        super().write_remote(node, path, data, mode)

    def provision(self):
        super().provision()
        # A soak attempt is never substituted for the canonical short fault gate.
        (self.out / "vm-manifest.json").rename(self.out / "soak-vm-manifest.json")
        for node in self.nodes:
            self.write_remote(node, "/lab/soak_metrics.py", (HERE / "soak_metrics.py").read_bytes())
            self.write_remote(node, "/lab/pid_census.py", (HERE / "pid_census.py").read_bytes())
            path = self.out / ("node-" + str(node["id"]) + "-ca.pem")
            save(path, self.remote(node, ["cat", "/root/.kube/royak-ca.pem"]))
            self.ca_paths[node["id"]] = path
        save(self.out / "client.token", self.user)

    def deploy(self):
        super().deploy()
        ns = "soak-connect"
        self.apply("/api/v1/namespaces", dict(apiVersion="v1", kind="Namespace", metadata=dict(name=ns)))
        for i in range(3):
            name = "c" + str(i)
            container = dict(name="app", image=self.image, ports=[dict(containerPort=8000)],
                env=[dict(name="LEDGER_URL", value=self.ledger_url), dict(name="PYTHONDONTWRITEBYTECODE", value="1")],
                resources=dict(limits=dict(cpu="250m", memory="64Mi")),
                securityContext=dict(runAsUser=10001, runAsGroup=10001, runAsNonRoot=True, readOnlyRootFilesystem=True,
                                     allowPrivilegeEscalation=False, capabilities=dict(drop=["ALL"])),
                readinessProbe=dict(tcpSocket=dict(port=8000), periodSeconds=1))
            self.apply("/apis/apps/v1/namespaces/"+ns+"/deployments", dict(apiVersion="apps/v1", kind="Deployment",
                metadata=dict(name=name, namespace=ns), spec=dict(replicas=1, selector=dict(matchLabels=dict(app=name)),
                template=dict(metadata=dict(labels=dict(app=name)), spec=dict(containers=[container])))))
            self.apply("/api/v1/namespaces/"+ns+"/services", dict(apiVersion="v1", kind="Service", metadata=dict(name=name, namespace=ns),
                spec=dict(selector=dict(app=name), ports=[dict(port=80, targetPort=8000)])))
        base = "/apis/rbac.authorization.k8s.io/v1/namespaces/"+ns
        self.apply(base+"/roles", dict(apiVersion="rbac.authorization.k8s.io/v1", kind="Role", metadata=dict(name="connector", namespace=ns),
            rules=[dict(apiGroups=[""], resources=["services/connect"], resourceNames=["c0:80","c1:80","c2:80"], verbs=["create"])]))
        self.apply(base+"/rolebindings", dict(apiVersion="rbac.authorization.k8s.io/v1", kind="RoleBinding", metadata=dict(name="connector", namespace=ns),
            roleRef=dict(kind="Role", name="connector"), subjects=[dict(kind="Group", name="soak-connectors")]))
        original.wait_for(lambda: self.remote_target(self.leader(), 0), "Ready remote Connect soak backend", timeout=90)

    def control_write(self, name):
        # Preserve every acknowledged control object through later faults,
        # rather than overwriting the same name on each cycle.
        super().control_write("cycle-"+str(self.fault_count)+"-"+name)

    def remote_target(self, issuer, worker):
        if not issuer:
            return None
        code, body = self.api(issuer, "GET", "/api/v1/namespaces/soak-connect/pods", timeout=2)
        if code != 200:
            return None
        choices = []
        for p in body.get("items", []):
            statuses = p.get("status", {}).get("containerStatuses", [])
            node = p.get("spec", {}).get("nodeName")
            if node != "q-n"+str(issuer["id"]) and any(s.get("ready") for s in statuses):
                ids = [s.get("containerID", "").split("://")[-1][:12] for s in statuses if s.get("ready")]
                choices.append((p["metadata"]["labels"]["app"], node, ids))
        return choices[worker % len(choices)] if choices else None

    def cli(self, issuer, service, worker):
        command = [str(self.args.client), "connect", "open", "--server", issuer["api"], "--ca-cert", str(self.ca_paths[issuer["id"]]),
            "--token-file", str(self.out / "client.token"), "--namespace", "soak-connect", "--service", service, "--port", "80", "--ttl-seconds", "120"]
        env = dict(os.environ, DOCKER_HOST="unix:///does-not-exist-soak", ROYAK_STATE="/does-not-exist-soak/state.json")
        error_log = (self.out / ("connect-client-"+str(worker)+".log")).open("a")
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=error_log, text=True, env=env)
        error_log.close()
        with self.child_lock:
            self.children[proc.pid] = proc
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(proc.stdout, selectors.EVENT_READ)
                if not ready.select(15):
                    raise TimeoutError("bounded native CLI startup")
            line = proc.stdout.readline()
            opened = json.loads(line)
            if not opened["local_address"].startswith("127.0.0.1:"):
                raise RuntimeError("Connect listener is not loopback")
            return proc, opened
        except BaseException:
            self.close_cli(proc)
            raise

    def close_cli(self, proc):
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)
                self.cli_forced_kills += 1
        if proc.stdout:
            proc.stdout.close()
        with self.child_lock:
            self.children.pop(proc.pid, None)

    def connect_worker(self, worker):
        sequence = 0
        while not self.connect_stop.is_set() and not self.stop.is_set():
            proc = conn = None
            try:
                issuer = self.leader()
                target = self.remote_target(issuer, worker)
                if not target:
                    raise ConnectionError("no confirmed issuer/Ready remote backend")
                service, backend, instances = target
                backend_node = next(n for n in self.nodes if "q-n"+str(n["id"])==backend)
                instances = self.remote(backend_node, ["docker", "ps", "-q", "--filter", "label=royak.namespace=soak-connect",
                    "--filter", "label=royak.deployment="+service, "--filter", "label=royak.role=main"], timeout=8).split()
                proc, opened = self.cli(issuer, service, worker)
                self.event("connect-access.jsonl", kind="session-open", worker=worker, issuer=issuer["id"], backend=backend,
                           session=opened["session"], local_address=opened["local_address"])
                host, port = opened["local_address"].split(":")
                conn = http.client.HTTPConnection(host, int(port), timeout=3)
                renew_at = time.monotonic()+90
                while time.monotonic()<renew_at and not self.connect_stop.is_set() and not self.stop.is_set():
                    ident = f"{self.run}-connect-{worker}-{sequence}"
                    sequence += 1  # never reuse an ID, including an ambiguous write
                    value = hashlib.sha256(ident.encode()).hexdigest()
                    start = time.monotonic()
                    self.event("connect-history.jsonl", kind="app_invoke", id=ident, value=value, node=issuer["id"], worker=worker)
                    code, body, error = 0, {}, None
                    try:
                        conn.request("POST", "/write", json.dumps(dict(id=ident, value=value)), {"Content-Type":"application/json"})
                        response = conn.getresponse()
                        code, body = response.status, json.loads(response.read(8192))
                    except (OSError, ValueError, http.client.HTTPException) as exc:
                        error = type(exc).__name__
                    self.event("connect-history.jsonl", kind="app_complete", id=ident, value=value, node=issuer["id"], worker=worker,
                        status=code, returned_id=body.get("id"), returned_value=body.get("value"), instance=body.get("instance"),
                        remote_proven=body.get("instance") in instances, expected_backend=backend,
                        error=error, latency_ms=round((time.monotonic()-start)*1000,3))
                    if code != 200:
                        break
                    self.connect_stop.wait(max(0, 1/self.args.connect_rate-(time.monotonic()-start)))
            except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
                self.event("connect-access.jsonl", kind="session-open-failed", worker=worker, error=type(exc).__name__)
                self.connect_stop.wait(1)
            finally:
                if conn:
                    conn.close()
                if proc:
                    self.close_cli(proc)

    def sample_resources(self):
        def one(node):
            sample_started=time.monotonic()-self.started
            try:
                metrics = json.loads(self.remote(node, ["python3", "/lab/soak_metrics.py"], timeout=15))
                return dict(node=node["id"], metrics=metrics,sample_started_s=sample_started)
            except (RuntimeError, subprocess.SubprocessError, ValueError) as exc:
                return dict(node=node["id"], error=type(exc).__name__)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            for row in pool.map(one, self.nodes):
                event = dict(elapsed_s=time.monotonic()-self.started, phase=self.phase, **row)
                self.metrics.append(event)
                self.event("resources.jsonl", kind="resources", **row)
        self.status()

    def metrics_loop(self):
        while not self.metrics_stop.is_set():
            started=time.monotonic()
            try:
                self.sample_resources()
            except BaseException as exc:
                self.event("resource-errors.jsonl", error=type(exc).__name__)
            # The declared cadence includes collection time. Sleeping another
            # full interval systematically undersamples, especially in smoke.
            self.metrics_stop.wait(max(0,self.args.sample_interval-(time.monotonic()-started)))

    def observe(self, seconds):
        if shutil.disk_usage(original.ROOT).free < 20 * 1024**3:
            raise RuntimeError("host free space below 20 GiB reserve")
        if self.connect_threads and any(not t.is_alive() for t in self.connect_threads) and not self.connect_stop.is_set():
            raise RuntimeError("Connect workload worker stopped unexpectedly")
        super().observe(seconds)

    def wireguard_down(self):
        issuer = original.wait_for(self.leader, "issuer before WireGuard fault")
        self.event("faults.jsonl", kind="target", node=issuer["id"], scope="guest rkconn only, no ordinary-route fallback")
        # Guest-local rollback also covers an abruptly interrupted runner.
        self.remote(issuer, ["systemd-run", "--quiet", "--on-active=60s", "--unit="+self.run+"-wg-up", "/usr/sbin/ip", "link", "set", "rkconn", "up"])
        self.remote(issuer, ["ip", "link", "set", "rkconn", "down"])
        down_at=time.monotonic()-self.started
        try:
            self.observe(15)
            with self.lock:
                events=read_jsonl(self.out/"connect-history.jsonl")
                attempts=read_jsonl(self.out/"connect-access.jsonl")
            leaked=[e for e in events if e.get("kind")=="app_complete" and e.get("phase")=="wireguard-down" and e["elapsed_s"]>down_at+5 and e.get("status")==200]
            failures=[e for e in attempts if e.get("kind")=="session-open-failed" and e.get("phase")=="wireguard-down"]
            failures += [e for e in events if e.get("kind")=="app_complete" and e.get("phase")=="wireguard-down" and e.get("status")!=200]
            self.check("WireGuard-only outage fails closed during active Connect traffic", not leaked and bool(failures), unexpected_successes=len(leaked))
        finally:
            self.remote(issuer, ["ip", "link", "set", "rkconn", "up"])
            self.remote(issuer, ["sh", "-ec", "systemctl stop "+self.run+"-wg-up.timer 2>/dev/null || true"])

    def partition(self):
        # Every repeated partition needs a fresh rollback, not an already-fired
        # transient timer retained by the short one-shot fixture.
        for node in self.nodes:
            if node["id"] in self.rollback_nodes:
                self.remote(node,["sh","-ec","systemctl stop "+self.run+"-rollback.timer 2>/dev/null || true"])
                self.remote(node,["sh","/lab/fault-rollback.sh"])
                self.rollback_nodes.discard(node["id"])
        super().partition()

    def verify(self):
        errors = []
        self.collecting_closeout = True
        try:
            for stage, action in (("traffic", self.verify_traffic),
                                  ("drain", self.verify_drain),
                                  ("resources", self.verify_resources)):
                try:
                    action()
                except Exception as error:
                    errors.append(error)
                    self.check("closeout stage collected: " + stage, False, error=type(error).__name__)
        finally:
            self.collecting_closeout = False
        if errors:
            raise errors[0]
        failed = [c["name"] for c in self.checks if not c["passed"]]
        if failed:
            raise AssertionError("final verification failed: " + "; ".join(failed))

    def verify_traffic(self):
        traffic_ended=time.monotonic()-self.started
        self.check("requested workload duration actually completed", time.monotonic()-self.workload_started>=self.args.duration,
                   requested_seconds=self.args.duration, observed_seconds=time.monotonic()-self.workload_started)
        self.connect_stop.set()
        for thread in self.connect_threads:
            thread.join(timeout=25)
        self.check("all Connect workers stop without abandoned native clients", not any(t.is_alive() for t in self.connect_threads) and not self.children and self.cli_forced_kills==0)
        super().verify()
        events = read_jsonl(self.out / "connect-history.jsonl")
        ledger = json.loads((self.out / "ledger.json").read_text())
        data = check_history(events, ledger)
        self.check("all acknowledged Connect writes retained without corruption", data["passed"], **{k:v for k,v in data.items() if k!="passed"})
        healthy = traffic_gate(events, self.args.connect_rate, self.args.connect_workers, minimum_window=15 if self.args.profile=="smoke" else 45)
        self.check("Connect healthy baseline/final windows have traffic and meet declared bounds", healthy["passed"], observed=healthy)
        ack = [e for e in events if e.get("kind")=="app_complete" and e.get("status")==200]
        remote = sum(e.get("remote_proven") is True for e in ack)
        self.check("actual acknowledged Connect traffic reaches distinct remote VM backends", bool(ack) and remote/len(ack)>=.95, remote_proven=remote, acknowledgements=len(ack))
        save(self.out / "connect-performance.json", json.dumps(summarize(events), indent=2))
        if self.args.profile=="full":
            faults=read_jsonl(self.out/"faults.jsonl")
            start=self.workload_started-self.started+self.args.warmup
            continuous={}
            for name,rate in (("connect",self.args.connect_workers*self.args.connect_rate),("lb",self.args.rate),("direct",self.args.rate)):
                file={"connect":"connect-history.jsonl","lb":"lb-history.jsonl","direct":"history.jsonl"}[name]
                continuous[name]=continuity(read_jsonl(self.out/file),faults,start,traffic_ended,rate,recovery=self.args.settle)
            save(self.out/"traffic-continuity.json",json.dumps(continuous,indent=2))
            self.check("constant traffic has no hidden empty healthy minute windows", all(r["passed"] for r in continuous.values()) and
                       all(len(r["windows"])>=60 for r in continuous.values()), report="traffic-continuity.json")
        if self.args.negative_closeout_control:
            self.check("intentional closeout negative control remains FAILED", False,
                       scope="smoke-only evidence collection regression, never qualification")

    def verify_drain(self):
        # Also runs if traffic reconciliation raises before its normal stop.
        self.connect_stop.set()
        for thread in self.connect_threads:
            thread.join(timeout=25)
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=8)
        self.check("closeout traffic workers stopped before drain",
                   not any(t.is_alive() for t in self.connect_threads) and
                   not (self.thread and self.thread.is_alive()) and not self.children)
        self.phase = "drain"
        time.sleep(10)
        self.metrics_stop.set()
        if self.metrics_thread:
            self.metrics_thread.join(timeout=20)
        for _ in range(3):
            self.sample_resources()
            time.sleep(2)
        sessions = []
        for node in self.nodes:
            code, body = self.api(node, "GET", "/royak/v1/connect/namespaces/soak-connect/sessions", timeout=3)
            sessions.append(dict(node=node["id"], status=code, retained=len(body.get("items",[])),
                                 active=sum(s.get("active_connections",0) for s in body.get("items",[])),
                                 open=sum(not s.get("closed",True) for s in body.get("items",[]))))
        save(self.out / "connect-drain.json", json.dumps(sessions, indent=2))
        self.check("all Connect sessions/sockets drain and retained cache stays bounded",
            all(s["status"]==200 and s["active"]==0 and s["open"]==0 and s["retained"]<=256 for s in sessions), observed=sessions)

    def verify_resources(self):
        # A failed drain query must not suppress already-collected raw metrics.
        self.metrics_stop.set()
        if self.metrics_thread:
            self.metrics_thread.join(timeout=20)
        audit_first={}
        for event in read_jsonl(self.out/'connect-access.jsonl'):
            if event.get('kind')=='session-open':audit_first.setdefault(event['issuer'],event['elapsed_s'])
        resources = resource_report(self.metrics, minimum_span=60 if self.args.profile=="smoke" else 300,audit_first_use=audit_first)
        resources['audit_history_sha256']=original.digest(self.out/'connect-access.jsonl')
        final = [r for r in self.metrics if r.get("phase")=="drain" and "metrics" in r][-9:]
        resources['drain_samples_per_node']={node:sum(r['node']==node for r in final) for node in (1,2,3)}
        resources['drain_complete']=(all(n==3 for n in resources['drain_samples_per_node'].values()) and
                                     not (self.metrics_thread and self.metrics_thread.is_alive()))
        resources['passed']=resources['passed'] and resources['drain_complete']
        save(self.out / "resource-report.json", json.dumps(resources, indent=2))
        self.check("observed same-incarnation resource growth stays within declared bounds", resources["passed"], report="resource-report.json")
        good={node:sum(r["node"]==node and r.get("metrics",{}).get("process") is not None for r in self.metrics) for node in (1,2,3)}
        self.check("resource telemetry covers at least 80 percent of each VM workload", all(count>=.8*self.args.duration/self.args.sample_interval for count in good.values()), samples=good)
        self.check("final resource census covers all three VMs without OOM or container accumulation",
            {r["node"] for r in final}=={1,2,3} and all(not c["oom"] for r in final for c in r["metrics"]["containers"]) and
            all(sum(len(r["metrics"]["containers"]) for r in final[i:i+3])==6 for i in range(0,len(final),3)))
        expected = len(FAULTS) if self.args.profile=="smoke" else 10
        faults=read_jsonl(self.out/"faults.jsonl")
        counts={name:sum(e.get("kind")=="fault_end" and e.get("fault")==name for e in faults) for name in FAULTS}
        self.check("declared periodic fault coverage completed", self.fault_count>=expected and all(n>=(1 if self.args.profile=="smoke" else 2) for n in counts.values()), completed=self.fault_count, minimum=expected, counts=counts)

    def cleanup(self):
        self.connect_stop.set()
        for thread in self.connect_threads:
            thread.join(timeout=25)
        with self.child_lock:
            children = list(self.children.values())
        for child in children:
            self.close_cli(child)
        self.metrics_stop.set()
        if self.metrics_thread:
            self.metrics_thread.join(timeout=20)
        for node in self.prepared_nodes:
            try:
                self.remote(node,["sh","-ec","systemctl stop "+self.run+"-wg-up.timer 2>/dev/null || true"])
            except (RuntimeError,subprocess.SubprocessError):
                pass
        super().cleanup()
        # Powering a guest off can conceal an enabled service or surviving
        # container. Verify while it is still reachable, before shutdown.
        script='''import json,subprocess,sys
from pathlib import Path
def run(*args,allowed=(0,)):
 result=subprocess.run(args,capture_output=True,text=True,timeout=8)
 if result.returncode not in allowed:raise RuntimeError('cleanup observation unavailable: '+args[0])
 return result
pid=Path('/lab/royak.pid').read_text().strip()
print(json.dumps(dict(service_active=run('systemctl','is-active','royak-qualification.service',allowed=(0,3)).stdout.strip(),
 service_enabled=run('systemctl','is-enabled','royak-qualification.service',allowed=(0,1)).stdout.strip(),
 royak_process_alive=(Path('/proc')/pid/'exe').resolve()==Path('/opt/royak'),
 containers=run('docker','ps','-aq','--filter','ancestor='+sys.argv[1]).stdout.split(),
 all_container_count=len(run('docker','ps','-aq').stdout.split()),
 wireguard_present=run('ip','link','show','rkconn',allowed=(0,1)).returncode==0,
 owned_firewall_rules=run('iptables-save').stdout.count(sys.argv[2]))))
'''
        rows=[]
        for node in self.prepared_nodes:
            try:
                value=json.loads(self.remote(node,['python3','-c',script,self.image,self.run],timeout=45))
                rows.append(dict(node=node['id'],passed=guest_cleanup_passed(value),**value))
            except Exception as error:rows.append(dict(node=node['id'],passed=False,error=type(error).__name__))
        save(self.out/'cleanup-verification.json',json.dumps(rows,indent=2))
        ok=len(rows)==3 and all(r['passed'] for r in rows)
        self.check('guest cleanup verified before poweroff: disabled service, no exact process/container/WireGuard/fault rules',ok)
        if not ok:self.event('cleanup.jsonl',error='post-cleanup guest verification failed; see cleanup-verification.json')

    def poweroff(self):
        results = []
        for node in self.prepared_nodes:
            try:
                verify_owner(self.vmroot,node)
                try:
                    ssh(self.vmroot,node,"sudo systemctl poweroff",timeout=15)
                except RuntimeError:
                    pass  # verify actual power state below, never infer from SSH
                deadline=time.monotonic()+30
                while time.monotonic()<deadline:
                    if verify_owner(self.vmroot,node).get("State")=="stopped":
                        break
                    time.sleep(1)
                stopped=verify_owner(self.vmroot,node).get("State")=="stopped"
                results.append(dict(node=node["id"], stopped=stopped))
            except BaseException as exc:
                results.append(dict(node=node["id"], stopped=False, error=type(exc).__name__))
        save(self.out/"power-state.json",json.dumps(results,indent=2))
        return len(results)==3 and all(r["stopped"] for r in results)

    def execute_soak(self):
        print("Evidence: "+str(self.out),flush=True)
        before=fixtures()
        sources={str(p.relative_to(original.ROOT)):original.digest(p) for p in original.source_inventory()}
        manifest=dict(profile=self.args.profile, requested_seconds=self.args.duration, warmup_seconds=self.args.warmup,
            baseline_seconds=self.args.baseline, final_seconds=self.args.final, fault_interval_seconds=self.args.fault_interval,
            faults=list(FAULTS), connect_workers=self.args.connect_workers, connect_rate_per_worker=self.args.connect_rate,
            lb_rate=self.args.rate, direct_rate=self.args.rate, resource_sample_interval_seconds=self.args.sample_interval,
            source_sha256=sources, fixture_sha256=before, binary_sha256=original.digest(self.binary), client_sha256=original.digest(self.args.client),
            pid=os.getpid(), production_ready=False, topology="three Linux VM kernels on one physical Mac",
            negative_closeout_control=self.args.negative_closeout_control,
            no_payload_replay=True, tls_verification=True)
        save(self.out/"soak-manifest.json",json.dumps(manifest,indent=2))
        failure=None
        self.status()
        try:
            self.provision(); self.deploy()
            self.workload_started=time.monotonic()
            self.phase="warmup"
            self.thread=threading.Thread(target=self.client,daemon=True); self.thread.start()
            self.connect_threads=[threading.Thread(target=self.connect_worker,args=(i,),daemon=True) for i in range(self.args.connect_workers)]
            for thread in self.connect_threads: thread.start()
            self.metrics_thread=threading.Thread(target=self.metrics_loop,daemon=True); self.metrics_thread.start()
            self.observe(self.args.warmup)
            self.phase="baseline"; self.observe(self.args.baseline)
            end=self.workload_started+self.args.duration
            actions=(self.kill_pod,self.kill_leader,self.partition,self.restart_node,self.wireguard_down)
            next_fault=time.monotonic()
            while time.monotonic()<end-self.args.final:
                if self.args.profile=="smoke" and self.fault_count>=len(FAULTS): break
                self.phase="steady"
                self.observe(max(0,min(next_fault,end-self.args.final)-time.monotonic()))
                if time.monotonic()>=end-self.args.final: break
                index=self.fault_count%len(FAULTS)
                self.fault(FAULTS[index],actions[index]); self.fault_count+=1
                self.status()
                next_fault+=self.args.fault_interval
            self.phase="soak"; self.observe(max(self.args.final,end-time.monotonic()))
            self.verify()
        except BaseException as exc:
            failure=type(exc).__name__+": "+str(exc)
            # Exceptions can contain HTTP details; never retain credentials.
            for secret in (self.user,self.token,self.cluster_secret,self.seal): failure=failure.replace(secret,"[REDACTED]")
            print(failure,file=sys.stderr,flush=True)
            try: self.diagnostics()
            except BaseException: pass
        finally:
            cleanup_completed=False
            try: self.cleanup()
            except BaseException as exc:
                failure=failure or "cleanup: "+type(exc).__name__
                self.event('cleanup.jsonl',error='cleanup interrupted/failed: '+type(exc).__name__)
            else:cleanup_completed=not (self.out/'cleanup.jsonl').exists()
            powered_off=self.poweroff()
            unchanged=before==fixtures() and sources=={str(p.relative_to(original.ROOT)):original.digest(p) for p in original.source_inventory()}
            passed=not failure and unchanged and powered_off and not (self.out/"cleanup.jsonl").exists() and all(c["passed"] for c in self.checks)
            report=dict(passed=bool(passed), failure=failure, checks=self.checks, duration_s=time.monotonic()-self.started,
                profile=self.args.profile, long_soak_qualified=bool(passed and self.args.profile=="full" and self.args.duration>=7200),
                workload_elapsed_s=None if self.workload_started is None else time.monotonic()-self.workload_started,
                source_and_fixtures_unchanged=unchanged, powered_off=powered_off, cleanup_completed=cleanup_completed, production_ready=False,
                non_claims=["physical host independence","distributed volume durability","exactly once","absence of all resource leaks","production certification"])
            save(self.out/"soak-report.json",json.dumps(report,indent=2))
            self.status("complete" if passed else "failed", passed=bool(passed))
        return int(not passed)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory",type=Path,required=True)
    parser.add_argument("--binary",type=Path,required=True)
    parser.add_argument("--client",type=Path,required=True)
    parser.add_argument("--caddy",type=Path,required=True)
    parser.add_argument("--profile",choices=("full","smoke"),default="full")
    parser.add_argument("--duration",type=int,default=7200)
    parser.add_argument("--negative-closeout-control",action="store_true",
                        help="smoke only: deliberately fail final traffic verification, still collect drain/resources")
    args=parser.parse_args()
    if args.profile=="full" and args.duration<7200: parser.error("full soak requires at least 7200 seconds")
    if args.profile=="smoke" and args.duration<360: parser.error("smoke requires at least 360 seconds")
    if args.negative_closeout_control and args.profile!="smoke": parser.error("negative closeout control is smoke-only, never a full qualification")
    for key,value in dict(seed=42,probe_mode="http",ui_check=False,rate=5,settle=20,node_outage=45,
        baseline_availability=.99,connect_workers=4,connect_rate=1,sample_interval=30 if args.profile=="full" else 10,
        warmup=300 if args.profile=="full" else 20,baseline=60 if args.profile=="full" else 25,
        final=600 if args.profile=="full" else 40,fault_interval=600 if args.profile=="full" else 40).items(): setattr(args,key,value)
    args.client,args.caddy=args.client.resolve(),args.caddy.resolve()
    if shutil.disk_usage(original.ROOT).free<60*1024**3: parser.error("need 60 GiB free before starting owned VMs")
    inventory=json.loads(args.inventory.read_text())
    if inventory.get("kind")!="royak-parallels-lab-v1" or len(inventory.get("nodes",[]))!=3:
        parser.error("need the existing owned three-VM inventory")
    build=json.loads(args.binary.with_name(args.binary.name+".build.json").read_text())
    current={str(p.relative_to(original.ROOT)):original.digest(p) for p in original.source_inventory()}
    if (build.get("source_sha256")!=current or build.get("binary_sha256")!=original.digest(args.binary)
            or build.get("source_unchanged_during_build") is not True or build.get("debug_symbols") is not False):
        parser.error("need unchanged current-source normal release artifact")
    for node in inventory["nodes"]: verify_owner(args.inventory.resolve().parent,node)
    # Reuse only the exact three existing owned guests; never provision a new VM.
    for node in inventory["nodes"]:
        if verify_owner(args.inventory.resolve().parent,node).get("State")=="stopped": run("prlctl","start",node["uuid"],timeout=90)
    for node in inventory["nodes"]:
        def ready(n=node):
            try: return ssh(args.inventory.resolve().parent,n,"sudo docker info --format '{{.ID}}'",timeout=5).strip()
            except (RuntimeError,subprocess.SubprocessError): return None
        original.wait_for(ready,"owned VM SSH and Docker",timeout=120)
    def interrupted(signum,frame): raise KeyboardInterrupt("runner interrupted; owned cleanup follows")
    signal.signal(signal.SIGTERM,interrupted)
    return SoakLab(args).execute_soak()


if __name__=="__main__":
    raise SystemExit(main())
