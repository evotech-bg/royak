#!/bin/bash
# Royak Load / Chaos Test — many deployments, reconcile convergence.
# Run: ./test-load.sh
# Exit 0 = all converged within timeout. Slower than test-demo.sh; run pre-release.

set -e
BIN="./target/release/royak"
STATE=".royak-state.json"
N_DEPLOYS="${N_DEPLOYS:-10}"   # deployments to create
REPLICAS="${REPLICAS:-2}"      # replicas each (default 10×2 = 20 pods)
TIMEOUT_SECS="${TIMEOUT_SECS:-90}"
PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi }

echo "╔════════════════════════════════════════════╗"
echo "║  Royak Load Test                      ║"
echo "║  $N_DEPLOYS deployments × $REPLICAS replicas = $((N_DEPLOYS * REPLICAS)) pods"
echo "╚════════════════════════════════════════════╝"
echo ""

# ─── Setup ───
echo "Cleaning up..."
docker ps -a --filter "name=rk-load-" --format '{{.ID}}' | xargs -r docker rm -f 2>/dev/null || true
rm -f "$STATE" "$STATE.nrns" "$STATE.lock" 2>/dev/null || true
lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true
sleep 1

if [ ! -f "$BIN" ]; then
    echo "Building..."
    cargo build --release 2>/dev/null
fi

# ─── Apply N deployments ───
echo ""
echo "1. Apply $N_DEPLOYS deployments"
echo "──────────────────────────────"
T0=$(date +%s)
YAML_FILE=/tmp/rk-load-deploys.yaml
: > "$YAML_FILE"
for i in $(seq 1 "$N_DEPLOYS"); do
    cat >> "$YAML_FILE" <<YAML
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: load-$i
spec:
  replicas: $REPLICAS
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
YAML
done

OUT=$($BIN apply "$YAML_FILE" 2>&1)
T1=$(date +%s)
APPLY_SECS=$((T1 - T0))
APPLIED=$(echo "$OUT" | grep -c 'deployment/load-' || echo 0)
check "All $N_DEPLOYS deployments applied" "[ \"$APPLIED\" -ge \"$N_DEPLOYS\" ]"
echo "    (apply took ${APPLY_SECS}s)"

# ─── Convergence: run watch ticks until all pods up, or timeout ───
echo ""
echo "2. Reconcile convergence"
echo "────────────────────────"
$BIN watch --interval 2 > /tmp/rk-load-watch.log 2>&1 &
WATCH_PID=$!

DEADLINE=$((T1 + TIMEOUT_SECS))
CONVERGED=0
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    RUNNING=$(docker ps --filter "name=rk-load-" --filter "status=running" --format '{{.Names}}' | wc -l | tr -d ' ')
    EXPECTED=$((N_DEPLOYS * REPLICAS))
    if [ "$RUNNING" -ge "$EXPECTED" ]; then
        CONVERGED=1
        break
    fi
    sleep 2
done
TCONV=$(date +%s)
CONV_SECS=$((TCONV - T1))
kill -TERM "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

check "All pods running within ${TIMEOUT_SECS}s" "[ \"$CONVERGED\" = \"1\" ]"
RUNNING=$(docker ps --filter "name=rk-load-" --filter "status=running" --format '{{.Names}}' | wc -l | tr -d ' ')
check "Container count matches expectation ($((N_DEPLOYS * REPLICAS)))" "[ \"$RUNNING\" -ge \"$((N_DEPLOYS * REPLICAS))\" ]"
echo "    (converged in ${CONV_SECS}s, $RUNNING containers)"

# ─── Chaos: kill a container, expect reconcile to recreate ───
echo ""
echo "3. Chaos: kill one container, expect respawn"
echo "────────────────────────────────────────────"
VICTIM=$(docker ps --filter "name=rk-load-1" --format '{{.Names}}' | head -1)
if [ -n "$VICTIM" ]; then
    docker rm -f "$VICTIM" >/dev/null 2>&1 || true
    $BIN watch --interval 2 > /tmp/rk-load-watch2.log 2>&1 &
    WATCH_PID=$!
    sleep 10
    kill -TERM "$WATCH_PID" 2>/dev/null || true
    wait "$WATCH_PID" 2>/dev/null || true
    RUNNING2=$(docker ps --filter "name=rk-load-1" --filter "status=running" --format '{{.Names}}' | wc -l | tr -d ' ')
    check "Reconcile respawned killed pod" "[ \"$RUNNING2\" -ge \"$REPLICAS\" ]"
else
    fail "Could not find victim container"
fi

# ─── Scale down all to 0 ───
echo ""
echo "4. Scale-down teardown"
echo "──────────────────────"
for i in $(seq 1 "$N_DEPLOYS"); do
    $BIN delete "deployment/load-$i" >/dev/null 2>&1 || true
done
sleep 4
REMAINING=$(docker ps --filter "name=rk-load-" -q | wc -l | tr -d ' ')
check "All containers removed after delete" "[ \"$REMAINING\" = \"0\" ]"

# ─── Cleanup ───
docker ps -a --filter "name=rk-load-" --format '{{.ID}}' | xargs -r docker rm -f 2>/dev/null || true
rm -f "$STATE" "$STATE.nrns" "$STATE.lock" "$YAML_FILE" 2>/dev/null || true

echo ""
echo "════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed (out of $TOTAL)"
echo "  Timings: apply=${APPLY_SECS}s, converge=${CONV_SECS}s"
echo "════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    echo "  SOME TESTS FAILED"
    exit 1
else
    echo "  ALL TESTS PASSED"
    exit 0
fi
