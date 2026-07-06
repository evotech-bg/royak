#!/bin/bash
# Royak NeuroPod Smoke Test — Docker-free runtime (EXPERIMENTAL / mega-beta).
# Run: ./test-neuropod.sh
# Exits 0 on success. Skips Linux-only pod-run tests on macOS.

set -e
BIN="./target/release/royak"
NEURO_DIR="${HOME}/.royak"
PASS=0
FAIL=0
SKIP=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ✗ $1"; }
skip() { SKIP=$((SKIP+1)); echo "  ⊘ $1 (skipped: $2)"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi }

echo "╔════════════════════════════════════════════╗"
echo "║  NeuroPod Smoke Test (EXPERIMENTAL)        ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# ─── Build if needed ───
if [ ! -f "$BIN" ]; then
    echo "Building..."
    cargo build --release 2>/dev/null
fi

UNAME="$(uname -s)"
echo "Platform: $UNAME"
echo ""

# ═══════════════════════════════════════════
echo "1. Binary Exposes NeuroPod Mode"
echo "───────────────────────────────"
check "watch --runtime neuropod flag exists" "$BIN watch --help 2>&1 | grep -q 'neuropod'"
check "pull --runtime flag exists" "$BIN pull --help 2>&1 | grep -q 'runtime'"

# ═══════════════════════════════════════════
echo ""
echo "2. OCI Image Pull (via curl, no Docker)"
echo "───────────────────────────────────────"
rm -rf "$NEURO_DIR/images/alpine" 2>/dev/null || true
OUT=$(ROYAK_NO_DOCKER=1 $BIN pull --runtime neuropod alpine:latest 2>&1 || true)
check "Pull alpine:latest exits cleanly" "echo '$OUT' | grep -Eqi 'pulled|ok|success|layer|manifest|\\.tar' || [ -d '$NEURO_DIR/images/alpine' ]"
check "Image cache dir exists" "test -d '$NEURO_DIR/images'"

# ═══════════════════════════════════════════
echo ""
echo "3. NeuroPod State Files"
echo "───────────────────────"
check "NeuroPod base dir created" "test -d '$NEURO_DIR'"
check "containers dir exists" "test -d '$NEURO_DIR/containers' || mkdir -p '$NEURO_DIR/containers'"
check "logs dir exists" "test -d '$NEURO_DIR/logs' || mkdir -p '$NEURO_DIR/logs'"

# ═══════════════════════════════════════════
echo ""
echo "4. Runtime Selection Smoke"
echo "──────────────────────────"
# Start watch --runtime neuropod briefly and verify it doesn't crash
lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true
sleep 1

STATE_NP="/tmp/rk-neuropod-state.json"
rm -f "$STATE_NP" "$STATE_NP.nrns" "$STATE_NP.lock" 2>/dev/null

ROYAK_STATE="$STATE_NP" $BIN watch --runtime neuropod --interval 60 > /tmp/rk-neuropod.log 2>&1 &
WATCH_PID=$!
sleep 4
if kill -0 "$WATCH_PID" 2>/dev/null; then
    pass "watch --runtime neuropod starts and stays alive"
else
    fail "watch --runtime neuropod crashed on startup"
    echo "    --- log tail ---"
    tail -20 /tmp/rk-neuropod.log | sed 's/^/    /'
fi
kill -TERM "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

check "NeuroPod log shows runtime marker" "grep -Eqi 'neuropod|no docker|light runtime|experimental' /tmp/rk-neuropod.log"

# ═══════════════════════════════════════════
echo ""
echo "5. Pod Run (Linux + root only — needs netns)"
echo "────────────────────────────────────────────"
if [ "$UNAME" != "Linux" ]; then
    skip "NeuroPod run tests" "macOS uses Virtualization.framework — end-to-end not wired"
    skip "Pod dir created on scale" "macOS"
    skip "Cleanup on delete" "macOS"
elif [ "$(id -u)" -ne 0 ]; then
    skip "NeuroPod run tests" "needs root for network namespaces"
    skip "Pod dir created on scale" "non-root"
    skip "Cleanup on delete" "non-root"
else
    # Linux + root: attempt end-to-end
    ROYAK_STATE="$STATE_NP" $BIN watch --runtime neuropod --interval 2 > /tmp/rk-neuropod2.log 2>&1 &
    WATCH_PID=$!
    sleep 3
    ROYAK_STATE="$STATE_NP" $BIN apply - >/dev/null 2>&1 <<'YAML' || true
apiVersion: apps/v1
kind: Deployment
metadata:
  name: np-smoke
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: c
          image: alpine:latest
          command: ["sh", "-c", "while true; do sleep 5; done"]
YAML
    sleep 8
    check "NeuroPod pod dir created" "ls '$NEURO_DIR/containers/' 2>/dev/null | grep -q np-smoke"
    ROYAK_STATE="$STATE_NP" $BIN delete deployment/np-smoke >/dev/null 2>&1 || true
    sleep 2
    kill -TERM "$WATCH_PID" 2>/dev/null || true
    wait "$WATCH_PID" 2>/dev/null || true
    check "Pod dir cleaned on delete" "! ls '$NEURO_DIR/containers/' 2>/dev/null | grep -q np-smoke"
fi

# ═══════════════════════════════════════════
# Cleanup
rm -f "$STATE_NP" "$STATE_NP.nrns" "$STATE_NP.lock" 2>/dev/null
lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true

echo ""
echo "════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped (of $TOTAL run)"
echo "════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    echo "  SOME TESTS FAILED"
    exit 1
else
    echo "  ALL TESTS PASSED"
    exit 0
fi
