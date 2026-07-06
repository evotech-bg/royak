#!/bin/bash
# Royak Mesh Proxy Test (v0.3 MVP) — verifies cross-node service
# routing layer end-to-end:
#   1. watch reconciles a deployment + service
#   2. mesh proxy listens on a well-known port
#   3. client requests to mesh with Host header → forwarded to the pod
#
# This is the single-node variant. Real cross-node is the same wire
# protocol with a second mesh instance; tested in v0.3 release gate.

set -e
BIN="./target/release/royak"
STATE=".royak-state.json"
MESH_PORT=6550
PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi }

cleanup() {
    lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    lsof -ti:$MESH_PORT 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    docker ps -a --filter "name=rk-" -q | xargs -r docker rm -f 2>/dev/null || true
    rm -f "$STATE" "$STATE.nrns" "$STATE.lock" "$STATE.leader" 2>/dev/null || true
}
trap cleanup EXIT

echo "╔════════════════════════════════════════════╗"
echo "║  Royak Mesh Proxy Test                ║"
echo "╚════════════════════════════════════════════╝"
echo ""

cleanup
sleep 1

if [ ! -f "$BIN" ]; then
    echo "Building..."
    cargo build --release 2>/dev/null
fi

# ═══════════════════════════════════════════
echo "1. Bring up cluster state + a service"
echo "─────────────────────────────────────"
$BIN watch --interval 60 > /tmp/rk-mesh-watch.log 2>&1 &
WATCH_PID=$!
sleep 3
$BIN apply - >/dev/null 2>&1 <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mesh-target
spec:
  replicas: 1
  selector: {matchLabels: {app: mesh-target}}
  template:
    metadata: {labels: {app: mesh-target}}
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
---
apiVersion: v1
kind: Service
metadata:
  name: mesh-target-svc
spec:
  selector: {app: mesh-target}
  ports: [{port: 80, targetPort: 80}]
YAML
sleep 5
check "target pod is running" "docker ps --filter name=rk-mesh-target-1 --filter status=running -q | grep -q ."

# ═══════════════════════════════════════════
echo ""
echo "2. Start the mesh proxy"
echo "───────────────────────"
$BIN mesh --port $MESH_PORT > /tmp/rk-mesh.log 2>&1 &
MESH_PID=$!
sleep 3
check "mesh proxy listening" "lsof -ti:$MESH_PORT | grep -q ."
check "mesh log shows listen" "grep -q 'mesh proxy listening' /tmp/rk-mesh.log"

# ═══════════════════════════════════════════
echo ""
echo "3. Route via Host header to a local pod"
echo "───────────────────────────────────────"
# Explicit Host: mesh-target-svc resolves through Router → Local → docker IP
CODE=$(curl -s -o /tmp/rk-mesh-body.html -w "%{http_code}" \
    --resolve mesh-target-svc:$MESH_PORT:127.0.0.1 \
    http://mesh-target-svc:$MESH_PORT/ 2>&1 || echo "fail")
check "mesh forwarded to pod (HTTP 200)" "[ \"$CODE\" = \"200\" ]"
check "response is nginx default page" "grep -qi 'welcome to nginx' /tmp/rk-mesh-body.html"

# ═══════════════════════════════════════════
echo ""
echo "4. Unknown service → 404"
echo "────────────────────────"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --resolve does-not-exist:$MESH_PORT:127.0.0.1 \
    http://does-not-exist:$MESH_PORT/ 2>&1 || echo "fail")
check "unknown service returns 404" "[ \"$CODE\" = \"404\" ]"

# ═══════════════════════════════════════════
echo ""
echo "5. FQDN host header (svc.namespace.svc.cluster.local)"
echo "─────────────────────────────────────────────────────"
# svc.default.svc.cluster.local → parse_ns extracts (svc=mesh-target-svc, ns=default)
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --resolve mesh-target-svc.default.svc.cluster.local:$MESH_PORT:127.0.0.1 \
    http://mesh-target-svc.default.svc.cluster.local:$MESH_PORT/ 2>&1 || echo "fail")
check "K8s-style FQDN host resolves" "[ \"$CODE\" = \"200\" ]"

# ═══════════════════════════════════════════
echo ""
echo "6. Mesh survives concurrent requests"
echo "────────────────────────────────────"
# Fire 10 requests in parallel, all should return 200.
# curl -w "%{http_code}\n" so each file ends with a newline grep can match.
PIDS=()
OUT_PREFIX=/tmp/rk-mesh-par
for i in $(seq 1 10); do
    (curl -s -o /dev/null -w "%{http_code}\n" \
        --resolve mesh-target-svc:$MESH_PORT:127.0.0.1 \
        http://mesh-target-svc:$MESH_PORT/ > "$OUT_PREFIX-$i.code") &
    PIDS+=($!)
done
for p in "${PIDS[@]}"; do wait "$p"; done
OK_COUNT=$(grep -l "^200$" "$OUT_PREFIX-"*.code 2>/dev/null | wc -l | tr -d ' ')
check "10/10 concurrent requests returned 200" "[ \"$OK_COUNT\" = \"10\" ]"
rm -f "$OUT_PREFIX-"*.code 2>/dev/null

# ═══════════════════════════════════════════
# Shutdown
kill -TERM $MESH_PID 2>/dev/null || true
kill -TERM $WATCH_PID 2>/dev/null || true
wait 2>/dev/null || true

echo ""
echo "════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed (of $TOTAL)"
echo "════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    echo "  SOME TESTS FAILED"
    echo "  --- mesh log tail ---"
    tail -20 /tmp/rk-mesh.log 2>/dev/null | sed 's/^/    /'
    exit 1
else
    echo "  ALL TESTS PASSED"
    exit 0
fi
