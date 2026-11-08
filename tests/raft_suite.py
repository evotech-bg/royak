#!/usr/bin/env python3
"""Raft/HA checks through the public API of a live 3-node Royak cluster.

Run by test-raft-cluster.sh, which starts the nodes with tests/cluster-lib.sh
and exports WORK, BASE_PORT, ADMIN_TOKEN and the cluster env. Node restarts
and kills go through the same shell helpers. Workloads live in namespace NS
(default "ci-raft"); the deployment "web" and configmap "cfg" are seeded by
the wrapper."""
import json, os, ssl, subprocess, sys, time, urllib.request, urllib.error

WORK = os.environ["WORK"]; TOK = os.environ["ADMIN_TOKEN"]
BASE = int(os.environ.get("BASE_PORT", "47700"))
NS = os.environ.get("NS", "ci-raft")
LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cluster-lib.sh")
CTX = ssl.create_default_context(); CTX.check_hostname = False; CTX.verify_mode = ssl.CERT_NONE
PORT = {n: BASE + n for n in (1, 2, 3)}
RESULTS = []


def req(node, method, path, body=None, ctype="application/yaml", timeout=25):
    data = body.encode() if isinstance(body, str) else body
    r = urllib.request.Request(f"https://127.0.0.1:{PORT[node]}{path}", data=data, method=method,
                               headers={"Authorization": f"Bearer {TOK}", "Content-Type": ctype})
    try:
        with urllib.request.urlopen(r, context=CTX, timeout=timeout) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:  # connection refused / timeout
        return 0, str(e)


def status(node):
    c, b = req(node, "GET", "/royak/v1/raft/status", timeout=3)
    return json.loads(b) if c == 200 else None


def leader(nodes=(1, 2, 3), wait=30):
    end = time.time() + wait
    while time.time() < end:
        for n in nodes:
            s = status(n)
            if s and s.get("isLeader"):
                return n
        time.sleep(0.3)
    return None


def sh(cmd):
    return subprocess.run(["bash", "-c", f'. "{LIB}" && {cmd}'], capture_output=True, text=True)


def kill(n, sig="KILL"):
    sh(f"stop_node {n} {sig}")


def start(n):
    sh(f"start_node {n}")
    end = time.time() + 30
    while time.time() < end and status(n) is None:
        time.sleep(0.3)


def log_of(n):
    with open(f"{WORK}/n{n}/server.log") as f:
        return f.read()


def check(name, ok, detail=""):
    RESULTS.append((name, ok, detail))
    print(f"  {'✓' if ok else '✗'} {name}  {detail}", flush=True)


def cm(name, val):
    return f"apiVersion: v1\nkind: ConfigMap\nmetadata: {{name: {name}, namespace: {NS}}}\ndata: {{V: \"{val}\"}}\n"


def get_cm(node, name):
    c, b = req(node, "GET", f"/api/v1/namespaces/{NS}/configmaps/{name}", timeout=5)
    return (json.loads(b).get("data", {}).get("V") if c == 200 else None), c


def write_via_leader(path, body, method="POST", ctype="application/yaml", tries=20):
    """Client retry loop: follow 421 to the leader, retry 503 / connection errors."""
    c, b = 0, ""
    for _ in range(tries):
        L = leader(wait=10)
        if not L:
            continue
        c, b = req(L, method, path, body, ctype)
        if c in (200, 201):
            return c, b, L
        time.sleep(0.5)
    return c, b, None


def running(label_extra=None):
    f = ["--filter", f"label=royak.namespace={NS}", "--filter", "status=running"]
    if label_extra:
        f += ["--filter", label_extra]
    out = subprocess.run(["docker", "ps", *f, "--format", "{{.Names}} {{.Label \"royak.node\"}}"], capture_output=True, text=True).stdout
    return [l.split() for l in out.splitlines() if l.strip()]


# ── 1. Failover ──
L = leader()
check("initial leader elected", L is not None, f"leader=n{L}")
t0 = time.time(); kill(L)
others = tuple(n for n in (1, 2, 3) if n != L)
NL = leader(others, wait=30)
check("failover: new leader after SIGKILL of leader", NL is not None, f"n{L} killed → n{NL} in {time.time()-t0:.2f}s")
c, b = req(NL, "POST", f"/api/v1/namespaces/{NS}/configmaps", cm("fo", "after-failover"))
check("write accepted by new leader", c in (200, 201), f"HTTP {c}")
c, b = req(NL, "PATCH", f"/apis/apps/v1/namespaces/{NS}/deployments/web/scale", '{"spec":{"replicas":4}}', "application/merge-patch+json")
check("scale via public API on new leader", c in (200, 201), f"HTTP {c}")
# All nodes share one Docker daemon here, so the killed node's container keeps
# running even though that node is gone; the cluster replaces it once the
# census grace expires (as a real dead host's pods would be). Count only pods
# on live nodes: they must reach exactly 4 and stay there (never more).
live = lambda: [p for p in running() if p[1] != f"ci-n{L}"]
end = time.time() + 90
while time.time() < end and len(live()) != 4:
    time.sleep(1)
reached, peak, t_hold = len(live()), 0, time.time() + 15
while time.time() < t_hold:
    peak = max(peak, len(live())); time.sleep(1)
check("scale converges to exactly 4 pods on live nodes with old leader down (stable 15s)",
      reached == 4 and peak == 4 and len(live()) == 4, f"reached={reached} peak={peak} all={running()}")
start(L)
end = time.time() + 30; v = None
while time.time() < end:
    v, _ = get_cm(L, "fo")
    if v == "after-failover":
        break
    time.sleep(0.5)
check("restarted old leader caught up (sees write made while it was down)", v == "after-failover", f"n{L} fo={v}")
check("old leader rejoins as follower", status(L) and not status(L).get("isLeader") or leader() != L, f"{status(L)}")

# ── 2. Minority partition: only one node alive ──
L = leader()
down = [n for n in (1, 2, 3) if n != L][:2]
lone = [n for n in (1, 2, 3) if n not in down][0]
for n in down:
    kill(n, "TERM")
log_off = os.path.getsize(f"{WORK}/n{lone}/server.log")
time.sleep(2)
t0 = time.time()
c, b = req(lone, "POST", f"/api/v1/namespaces/{NS}/configmaps", cm("minority", "x"), timeout=40)
check("minority node does NOT confirm a write (504 outcome unknown)", c == 504 and "outcome unknown" in b, f"n{lone} HTTP {c} after {time.time()-t0:.1f}s: {b[:160]}")
# Kill a pod so a scheduler would have work to do, then make sure the lone
# node does not schedule (its leader lease cannot be renewed without quorum).
victims = running()
if victims:
    subprocess.run(["docker", "kill", victims[0][0]], capture_output=True)
time.sleep(15)
with open(f"{WORK}/n{lone}/server.log") as f:
    f.seek(log_off); seg = f.read()
sched = [l for l in seg.splitlines() if "[scale]" in l or "[create]" in l or "[multi-node]" in l]
check("lone node does not schedule without quorum", not sched, f"status={status(lone)} sched_lines={sched[:3]}")
check("lone node reports leadership as unconfirmed", (status(lone) or {}).get("leaderConfirmed") is False, f"{status(lone)}")
for n in down:
    start(n)
L = leader(wait=30)
# An unconfirmed entry may legally commit after quorum returns (Raft); it
# must never have been reported as success, and all nodes must agree.
end = time.time() + 15
vals = {}
while time.time() < end:
    vals = {n: get_cm(n, "minority")[0] for n in (1, 2, 3)}
    if len(set(vals.values())) == 1:
        break
    time.sleep(0.5)
check("after heal: every node agrees on the unconfirmed write's outcome", len(set(vals.values())) == 1, f"{vals}")
c, b, L2 = write_via_leader(f"/api/v1/namespaces/{NS}/configmaps", cm("minority", "retried"), method="POST")
check("client retry after heal succeeds", c in (200, 201), f"HTTP {c} via n{L2}")
vals = {n: get_cm(n, "minority")[0] for n in (1, 2, 3)}
end = time.time() + 10
while time.time() < end and set(vals.values()) != {"retried"}:
    time.sleep(0.5); vals = {n: get_cm(n, "minority")[0] for n in (1, 2, 3)}
check("retried write visible on every node", set(vals.values()) == {"retried"}, f"{vals}")

# ── 3. Delete propagation ──
dep = """apiVersion: apps/v1
kind: Deployment
metadata: {name: del, namespace: NSX}
spec:
  replicas: 3
  selector: {matchLabels: {app: del}}
  template:
    metadata: {labels: {app: del}}
    spec:
      containers:
      - {name: main, image: alpine:3.22, command: ["sleep", "3600"]}
""".replace("NSX", NS)
c, b, L = write_via_leader(f"/apis/apps/v1/namespaces/{NS}/deployments", dep)
check("create deployment 'del' (3 replicas)", c in (200, 201), f"HTTP {c} via n{L}")
end = time.time() + 60
while time.time() < end and len(running("label=royak.deployment=del")) < 3:
    time.sleep(1)
nodes_used = sorted({n for _, n in running("label=royak.deployment=del")})
check("'del' pods running across nodes", len(running("label=royak.deployment=del")) == 3, f"nodes={nodes_used}")
t0 = time.time()
c, b, L = write_via_leader(f"/apis/apps/v1/namespaces/{NS}/deployments/del", None, method="DELETE")
check("DELETE via public API", c in (200, 201), f"HTTP {c} via n{L}")
end = time.time() + 60
while time.time() < end and running("label=royak.deployment=del"):
    time.sleep(0.5)
left = running("label=royak.deployment=del")
check("delete propagates: all 'del' pods gone on every node", not left, f"in {time.time()-t0:.1f}s, left={left}")
codes = {n: req(n, "GET", f"/apis/apps/v1/namespaces/{NS}/deployments/del")[0] for n in (1, 2, 3)}
check("every node returns 404 for the deleted deployment", set(codes.values()) == {404}, f"{codes}")

# ── 4. Snapshot install + restore ──
L = leader()
lag = [n for n in (1, 2, 3) if n != L][0]
kill(lag, "TERM")
okw = 0
for i in range(200):
    c, b = req(L, "POST", f"/api/v1/namespaces/{NS}/configmaps", cm(f"snap{i}", f"v{i}"))
    okw += c in (200, 201)
check("200 writes while one follower is down", okw == 200, f"{okw}/200 via n{L}")
start(lag)
end = time.time() + 40; have = 0
while time.time() < end:
    c, b = req(lag, "GET", f"/api/v1/namespaces/{NS}/configmaps")
    if c == 200:
        names = {i["metadata"]["name"] for i in json.loads(b)["items"]}
        have = sum(f"snap{i}" in names for i in range(200))
        if have == 200 and "fo" in names and "cfg" in names:
            break
    time.sleep(0.5)
log = open(f"{WORK}/n{lag}/server.log").read()
check("lagging node catches up to full state (200 + earlier objects)", have == 200, f"n{lag} has {have}/200")
check("catch-up used a snapshot", "installing snapshot from leader" in log[log.rfind("Royak v0.4"):], "")
c, b = req(lag, "GET", f"/apis/apps/v1/namespaces/{NS}/deployments/web")
check("snapshot restored deployments too", c == 200, f"HTTP {c}")
kill(lag, "KILL"); start(lag)
c, b = req(lag, "GET", f"/api/v1/namespaces/{NS}/configmaps/snap199")
log = open(f"{WORK}/n{lag}/server.log").read()
check("node restarted after snapshot restores state from its own disk", c == 200 and "restored snapshot from disk" in log[log.rfind("Royak v0.4"):], f"HTTP {c}")

# ── restore scale ──
write_via_leader(f"/apis/apps/v1/namespaces/{NS}/deployments/web/scale", '{"spec":{"replicas":3}}', method="PATCH", ctype="application/merge-patch+json")

fails = [r for r in RESULTS if not r[1]]
print(f"\n  Raft: {len(RESULTS)-len(fails)}/{len(RESULTS)} checks passed")
sys.exit(1 if fails else 0)
