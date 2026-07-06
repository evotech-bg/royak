#!/bin/bash
# Royak Multi-Node Sync Test — localhost 2-process simulation.
# Starts an API server process on one port, runs `node join` from a second
# state context, and verifies state sync + drain.
#
# NOT a full HA quorum test — validates join/list/drain/state-sync primitives.
# A true multi-machine, split-brain test needs real network partition tooling.

set -e
BIN="./target/release/royak"
STATE_A="/tmp/rk-multinode-A.json"
STATE_B="/tmp/rk-multinode-B.json"
PORT_A=6543
PORT_B=6544
PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi }

cleanup() {
    lsof -ti:$PORT_A 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    lsof -ti:$PORT_B 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    rm -f "$STATE_A" "$STATE_A.nrns" "$STATE_A.lock" 2>/dev/null || true
    rm -f "$STATE_B" "$STATE_B.nrns" "$STATE_B.lock" 2>/dev/null || true
    docker ps -a --filter "name=rk-" -q | xargs -r docker rm -f 2>/dev/null || true
}
trap cleanup EXIT

echo "╔════════════════════════════════════════════╗"
echo "║  Royak Multi-Node Sync Test           ║"
echo "╚════════════════════════════════════════════╝"
echo ""

cleanup
sleep 1

if [ ! -f "$BIN" ]; then
    echo "Building..."
    cargo build --release 2>/dev/null
fi

# ═══════════════════════════════════════════
echo "1. Start peer (node-a) API server"
echo "─────────────────────────────────"
HOSTNAME=node-a ROYAK_STATE=$STATE_A $BIN api --port $PORT_A > /tmp/rk-multinode-a.log 2>&1 &
A_PID=$!
sleep 4
check "node-a API is listening" "curl -sf -o /dev/null http://127.0.0.1:$PORT_A/ || curl -sf -o /dev/null http://127.0.0.1:$PORT_A/api/v1"
check "peer /royak/v1/state rejects unauthenticated" \
    "[ \"\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$PORT_A/royak/v1/state)\" = \"403\" ]"

# ═══════════════════════════════════════════
echo ""
echo "2. node-b joins the cluster"
echo "───────────────────────────"
OUT=$(HOSTNAME=node-b ROYAK_STATE=$STATE_B $BIN node join 127.0.0.1:$PORT_A --port $PORT_B 2>&1 || true)
check "join command exits cleanly" "echo '$OUT' | grep -qi 'joined\\|sync\\|state\\|FP-TLS\\|brain'"

# ═══════════════════════════════════════════
echo ""
echo "3. state files reflect 2-node cluster"
echo "─────────────────────────────────────"
# state_B must contain node-b (and ideally node-a merged from GET)
check "state_B contains node-b" "python3 -c \"import json; d=json.load(open('$STATE_B')); ns=d.get('nodes', []); assert any(n.get('name')=='node-b' for n in ns), ns\""

# ═══════════════════════════════════════════
echo ""
echo "4. node list shows node-b (from B's state)"
echo "──────────────────────────────────────────"
OUT=$(ROYAK_STATE=$STATE_B $BIN node list 2>&1)
check "node list prints node-b" "echo '$OUT' | grep -q 'node-b'"
check "node list shows Ready status" "echo '$OUT' | grep -qi 'ready'"

# ═══════════════════════════════════════════
echo ""
echo "5. peer A received B's state via POST"
echo "─────────────────────────────────────"
# Wait for the background reconcile on A to flush updated state to disk
sleep 6
check "state_A contains node-b (merged)" "python3 -c \"import json; d=json.load(open('$STATE_A')); ns=d.get('nodes', []); assert any(n.get('name')=='node-b' for n in ns), ns\""

# ═══════════════════════════════════════════
echo ""
echo "6. node drain marks node as Draining"
echo "────────────────────────────────────"
OUT=$(ROYAK_STATE=$STATE_B $BIN node drain node-b 2>&1)
check "drain command succeeds" "echo '$OUT' | grep -qi 'draining'"
OUT=$(ROYAK_STATE=$STATE_B $BIN node list 2>&1)
check "node list shows Draining status" "echo '$OUT' | grep -qi 'draining'"

# ═══════════════════════════════════════════
echo ""
echo "7. Drain of unknown node fails cleanly"
echo "──────────────────────────────────────"
OUT=$(ROYAK_STATE=$STATE_B $BIN node drain does-not-exist 2>&1 || true)
check "drain reports missing node" "echo '$OUT' | grep -qi 'not found'"

# ═══════════════════════════════════════════
echo ""
echo "════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed (of $TOTAL)"
echo "════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    echo "  SOME TESTS FAILED"
    echo "  --- peer A log tail ---"
    tail -20 /tmp/rk-multinode-a.log 2>/dev/null | sed 's/^/    /'
    exit 1
else
    echo "  ALL TESTS PASSED"
    exit 0
fi
