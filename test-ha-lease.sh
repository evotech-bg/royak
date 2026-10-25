#!/bin/bash
# Royak single-writer (state owner lock) test — two `watch` processes share
# one state file. Exactly one owns it (an exclusive flock held for the whole
# process life); the other is a read-only standby whose writes return 421.
# The kernel drops the lock the moment the owner dies, so a SIGKILLed owner
# hands over at the standby's next tick (no lease TTL to wait out).
#
# NOT a consensus test (see test-raft-cluster.sh). Cleanup touches only the
# processes this run started and its temporary directory.

set -u
cd "$(dirname "$0")"
BIN="$PWD/target/release/royak"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/royak-ha.XXXXXX")
STATE="$WORK/state.json"
PORT_A=${PORT_A:-6553}
PORT_B=${PORT_B:-6554}
PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi }

export ROYAK_TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
export ROYAK_STATE="$STATE" HOME="$WORK/home" ROYAK_DATA_DIR="$WORK/data"
mkdir -p "$HOME" "$ROYAK_DATA_DIR"
A_PID=""; B_PID=""
cleanup() {
    for p in $A_PID $B_PID; do kill -9 "$p" 2>/dev/null || true; done
    CID=$(python3 -c "import json;print(json.load(open('$STATE'))['clusterId'])" 2>/dev/null)
    [ -n "$CID" ] && docker ps -aq --filter "label=royak.cluster=$CID" | xargs -r docker rm -f >/dev/null 2>&1
    if [ $FAIL -gt 0 ]; then
        echo "  --- A log tail ---"; tail -20 "$WORK/a.log" 2>/dev/null | sed 's/^/    /'
        echo "  --- B log tail ---"; tail -20 "$WORK/b.log" 2>/dev/null | sed 's/^/    /'
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT
[ -x "$BIN" ] || cargo build --release

post_cm() { # post_cm PORT NAME → HTTP code
    curl -s -o /dev/null -w '%{http_code}' -m 10 -X POST -H "Authorization: Bearer $ROYAK_TOKEN" \
        -H 'Content-Type: application/yaml' \
        --data-binary "$(printf 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: %s}\ndata: {k: v}\n' "$2")" \
        "http://127.0.0.1:$1/api/v1/namespaces/default/configmaps"
}
on_disk() { python3 -c "import json,sys; d=json.load(open('$STATE')); sys.exit(0 if 'default/$1' in d['state']['configmaps'] else 1)"; }
wait_up() { for _ in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:$1/healthz" && return 0; sleep 0.2; done; return 1; }

echo "Royak state-owner lock test (work dir $WORK)"
echo ""
echo "1. Instance A owns the state"
"$BIN" watch --interval 2 --port $PORT_A --ingress-port 0 > "$WORK/a.log" 2>&1 & A_PID=$!
wait_up $PORT_A
check "A is running" "kill -0 $A_PID"
check "A reports ownership" "grep -q 'state owner: $STATE' '$WORK/a.log'"
check "A accepts a write (201) and it is durable" "[ \$(post_cm $PORT_A from-a) = 201 ] && on_disk from-a"

echo ""
echo "2. Instance B on the same state is a read-only standby"
"$BIN" watch --interval 2 --port $PORT_B --ingress-port 0 > "$WORK/b.log" 2>&1 & B_PID=$!
wait_up $PORT_B
sleep 3
check "B is running" "kill -0 $B_PID"
check "B starts in standby" "grep -q 'owned by another Royak process' '$WORK/b.log'"
check "B does not reconcile" "! grep -q '── tick' '$WORK/b.log'"
C=$(post_cm $PORT_B from-b)
check "a write to the standby is refused (421, not applied)" "[ '$C' = 421 ]"
check "the refused write is not on disk" "! on_disk from-b"
OUT=$("$BIN" apply - 2>&1 <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata: {name: from-cli}
data: {k: v}
YAML
); RC=$?
check "an offline CLI write is refused while a server owns the state (exit 3)" "[ $RC = 3 ] && echo \"\$OUT\" | grep -q 'owns'"

echo ""
echo "3. SIGKILL A — B takes over without a lease timeout"
kill -9 $A_PID; T0=$(date +%s)
for _ in $(seq 1 30); do grep -q 'acquired state ownership' "$WORK/b.log" && break; sleep 0.5; done
T1=$(date +%s)
check "B acquires ownership after A dies ($((T1-T0))s, interval 2s)" "grep -q 'acquired state ownership' '$WORK/b.log'"
for _ in $(seq 1 20); do grep -q '── tick' "$WORK/b.log" && break; sleep 0.5; done
check "B reconciles as owner" "grep -q '── tick' '$WORK/b.log'"
check "B kept A's acknowledged write" "curl -sf -H 'Authorization: Bearer $ROYAK_TOKEN' http://127.0.0.1:$PORT_B/api/v1/namespaces/default/configmaps/from-a"
check "B now accepts writes (201), durably" "[ \$(post_cm $PORT_B from-b2) = 201 ] && on_disk from-b2"

echo ""
echo "4. SIGTERM B — clean exit releases the lock"
kill -TERM $B_PID
for _ in $(seq 1 20); do kill -0 $B_PID 2>/dev/null || break; sleep 0.5; done
check "B exits on SIGTERM" "! kill -0 $B_PID"
OUT=$("$BIN" apply - 2>&1 <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata: {name: from-cli}
data: {k: v}
YAML
); RC=$?
check "with no server running, the CLI can own and write the state" "[ $RC = 0 ] && on_disk from-cli"

echo ""
echo "  Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
