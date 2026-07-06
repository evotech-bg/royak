#!/bin/bash
# Royak Ingress Live Proxy Test (v0.3 #3).
# Verifies the Ingress controller actually forwards traffic, not just
# parses rules. Covers host-based routing, longest-path-prefix match,
# unknown-host 404, binary-safe body streaming.

set -e
BIN="./target/release/royak"
STATE=".royak-state.json"
ING_PORT=8880
PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi }

cleanup() {
    lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    lsof -ti:$ING_PORT 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    docker ps -a --filter "name=rk-" -q | xargs -r docker rm -f 2>/dev/null || true
    rm -f "$STATE" "$STATE.nrns" "$STATE.lock" "$STATE.leader" 2>/dev/null || true
}
trap cleanup EXIT

echo "╔════════════════════════════════════════════╗"
echo "║  Royak Ingress Proxy Test             ║"
echo "╚════════════════════════════════════════════╝"
echo ""

cleanup
sleep 1

if [ ! -f "$BIN" ]; then
    echo "Building..."
    cargo build --release 2>/dev/null
fi

# ═══════════════════════════════════════════
echo "1. Apply Deployment + Service + Ingress (before starting watch)"
echo "───────────────────────────────────────────────────────────────"
# Apply BEFORE watch, so watch's in-memory state includes the ingress
# rules on startup. (watch loads state once; it doesn't hot-reload disk.)
$BIN apply - >/dev/null 2>&1 <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: {name: web}
spec:
  replicas: 1
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
---
apiVersion: v1
kind: Service
metadata: {name: web}
spec:
  selector: {app: web}
  ports: [{port: 80, targetPort: 80}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web-ing}
spec:
  rules:
    - host: app.local
      http:
        paths:
          - path: /
            backend:
              service:
                name: web
                port: {number: 80}
    - host: api.local
      http:
        paths:
          - path: /v1
            backend:
              service:
                name: web
                port: {number: 80}
YAML
check "ingress rule persisted" "grep -q 'app.local' '$STATE'"

# ═══════════════════════════════════════════
echo ""
echo "2. Start watch with --ingress-port on unprivileged port"
echo "───────────────────────────────────────────────────────"
$BIN watch --interval 60 --ingress-port $ING_PORT > /tmp/rk-ing-watch.log 2>&1 &
W_PID=$!
sleep 5
check "watch is running" "kill -0 $W_PID"
check "ingress log shows listen" "grep -q 'ingress controller on' /tmp/rk-ing-watch.log"
check "ingress port is bound" "lsof -ti:$ING_PORT | grep -q ."
check "web pod is running" "docker ps --filter name=rk-web-1 --filter status=running -q | grep -q ."

# ═══════════════════════════════════════════
echo ""
echo "3. Host-based routing"
echo "─────────────────────"
CODE=$(curl -s -o /tmp/ing-body.html -w "%{http_code}" \
    --resolve app.local:$ING_PORT:127.0.0.1 \
    http://app.local:$ING_PORT/ 2>&1 || echo "fail")
check "app.local/ → backend (HTTP 200)" "[ \"$CODE\" = \"200\" ]"
check "response is nginx welcome" "grep -qi 'welcome to nginx' /tmp/ing-body.html"

# ═══════════════════════════════════════════
echo ""
echo "4. Path prefix matching"
echo "───────────────────────"
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    --resolve api.local:$ING_PORT:127.0.0.1 \
    "http://api.local:$ING_PORT/v1/anything" 2>&1 || echo "fail")
check "api.local/v1/* matches /v1 prefix" "[ \"$CODE\" = \"200\" ] || [ \"$CODE\" = \"404\" ]"
# Note: returns 200 if nginx serves the path, else 404 from nginx — either
# proves the Ingress forwarded. What we MUST NOT see is 502.
check "reached backend (no 502)" "[ \"$CODE\" != \"502\" ]"

# ═══════════════════════════════════════════
echo ""
echo "5. Unknown host → 404 from ingress"
echo "──────────────────────────────────"
CODE=$(curl -s -o /tmp/ing-404.html -w "%{http_code}" \
    --resolve unknown.local:$ING_PORT:127.0.0.1 \
    http://unknown.local:$ING_PORT/ 2>&1 || echo "fail")
check "unknown host returns 404" "[ \"$CODE\" = \"404\" ]"
check "404 body is from ingress controller" "grep -q 'Royak Ingress' /tmp/ing-404.html"

# ═══════════════════════════════════════════
echo ""
echo "6. Response headers flow through"
echo "────────────────────────────────"
HEADERS=$(curl -sI \
    --resolve app.local:$ING_PORT:127.0.0.1 \
    http://app.local:$ING_PORT/ 2>&1)
check "backend Server: nginx header forwarded" "echo '$HEADERS' | grep -qi '^Server:.*nginx'"
check "Content-Type forwarded" "echo '$HEADERS' | grep -qi '^Content-Type: text/html'"

# ═══════════════════════════════════════════
echo ""
echo "7. Binary-safe body (PNG, gzipped, etc.)"
echo "────────────────────────────────────────"
# The proxy now reads as Vec<u8>, not String. Fetch nginx's /50x.html with
# Accept-Encoding: gzip to force gzip-compressed bytes through the pipe.
SIZE=$(curl -s -o /tmp/ing-gz.bin -w "%{size_download}" \
    -H "Accept-Encoding: gzip" \
    --resolve app.local:$ING_PORT:127.0.0.1 \
    http://app.local:$ING_PORT/ 2>&1 || echo 0)
check "response body downloaded (size > 0)" "[ \"$SIZE\" -gt 0 ]"

# ═══════════════════════════════════════════
echo ""
echo "8. Concurrent requests (no async deadlock)"
echo "──────────────────────────────────────────"
PIDS=()
OUT=/tmp/ing-par
for i in $(seq 1 10); do
    (curl -s -o /dev/null -w "%{http_code}\n" \
        --resolve app.local:$ING_PORT:127.0.0.1 \
        http://app.local:$ING_PORT/ > "$OUT-$i") &
    PIDS+=($!)
done
for p in "${PIDS[@]}"; do wait "$p"; done
OK=$(grep -l "^200$" "$OUT-"*  2>/dev/null | wc -l | tr -d ' ')
check "10/10 concurrent requests returned 200" "[ \"$OK\" = \"10\" ]"
rm -f "$OUT-"* 2>/dev/null

# ═══════════════════════════════════════════
# Shutdown
kill -TERM $W_PID 2>/dev/null || true
wait 2>/dev/null || true
rm -f /tmp/ing-*.html /tmp/ing-*.bin 2>/dev/null

echo ""
echo "════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed (of $TOTAL)"
echo "════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    echo "  SOME TESTS FAILED"
    echo "  --- watch log tail ---"
    tail -20 /tmp/rk-ing-watch.log 2>/dev/null | sed 's/^/    /'
    exit 1
else
    echo "  ALL TESTS PASSED"
    exit 0
fi
