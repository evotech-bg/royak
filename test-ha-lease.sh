#!/bin/bash
# Royak HA Leader Lease Test — verifies only one of two concurrent
# watch processes acquires the lease and performs reconcile mutations.
#
# NOT a full quorum / consensus test. This validates the single-writer
# guarantee when multiple instances share a state path.

set -e
BIN="./target/release/royak"
STATE="/tmp/rk-ha-state.json"
PORT_A=6553
PORT_B=6554
PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi }

cleanup() {
    lsof -ti:$PORT_A 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    lsof -ti:$PORT_B 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    rm -f "$STATE" "$STATE.nrns" "$STATE.lock" "$STATE.leader" "$STATE.leader.tmp" 2>/dev/null || true
    docker ps -a --filter "name=rk-" -q | xargs -r docker rm -f 2>/dev/null || true
}
trap cleanup EXIT

echo "╔════════════════════════════════════════════╗"
echo "║  Royak HA Leader Lease Test           ║"
echo "╚════════════════════════════════════════════╝"
echo ""

cleanup
sleep 1

if [ ! -f "$BIN" ]; then
    echo "Building..."
    cargo build --release 2>/dev/null
fi

# ═══════════════════════════════════════════
echo "1. Start instance A (becomes leader)"
echo "────────────────────────────────────"
HOSTNAME=host-a ROYAK_STATE="$STATE" $BIN watch --interval 2 --port $PORT_A > /tmp/rk-ha-a.log 2>&1 &
A_PID=$!
sleep 5
check "instance A is running" "kill -0 $A_PID"
check "lease file created" "test -f '$STATE.leader'"
check "A logs 'became leader'" "grep -q 'became leader' /tmp/rk-ha-a.log"
check "lease file names A as leader" "python3 -c \"import json; d=json.load(open('$STATE.leader')); assert d['leader'].startswith('host-a-')\""

# ═══════════════════════════════════════════
echo ""
echo "2. Start instance B while A holds lease"
echo "───────────────────────────────────────"
HOSTNAME=host-b ROYAK_STATE="$STATE" $BIN watch --interval 2 --port $PORT_B > /tmp/rk-ha-b.log 2>&1 &
B_PID=$!
sleep 6
check "instance B is running" "kill -0 $B_PID"
check "B enters standby" "grep -q '\\[standby\\]' /tmp/rk-ha-b.log"
check "B did NOT reconcile" "! grep -q 'tick 1' /tmp/rk-ha-b.log || true; ! grep -q 'Reconciling...' /tmp/rk-ha-b.log"
# Verify lease still belongs to A
OWNER=$(python3 -c "import json; d=json.load(open('$STATE.leader')); print(d['leader'])" 2>/dev/null || echo "")
check "lease still held by A" "echo '$OWNER' | grep -q 'host-a-'"

# ═══════════════════════════════════════════
echo ""
echo "3. Kill A — B must take over after TTL"
echo "──────────────────────────────────────"
# Kill without clean shutdown (SIGKILL — no lease release)
kill -9 $A_PID 2>/dev/null || true
# Port_A may still be bound for a moment; that's fine.
# Wait > LEASE_TTL_SECS (15s) so lease goes stale, then B's next tick takes over.
# We poll B's log to avoid over-waiting.
for i in $(seq 1 20); do
    sleep 2
    if grep -q 'became leader' /tmp/rk-ha-b.log; then
        break
    fi
done
check "B takes over after A dies" "grep -q 'became leader' /tmp/rk-ha-b.log"
OWNER=$(python3 -c "import json; d=json.load(open('$STATE.leader')); print(d['leader'])" 2>/dev/null || echo "")
check "lease now held by B" "echo '$OWNER' | grep -q 'host-b-'"

# ═══════════════════════════════════════════
echo ""
echo "4. Graceful shutdown of B releases lease"
echo "────────────────────────────────────────"
kill -TERM $B_PID 2>/dev/null || true
wait $B_PID 2>/dev/null || true
sleep 2
check "lease file removed on graceful shutdown" "! test -f '$STATE.leader'"

echo ""
echo "════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed (of $TOTAL)"
echo "════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    echo "  SOME TESTS FAILED"
    echo "  --- A log tail ---"
    tail -20 /tmp/rk-ha-a.log 2>/dev/null | sed 's/^/    /'
    echo "  --- B log tail ---"
    tail -30 /tmp/rk-ha-b.log 2>/dev/null | sed 's/^/    /'
    exit 1
else
    echo "  ALL TESTS PASSED"
    exit 0
fi
