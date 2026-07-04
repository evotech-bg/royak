#!/bin/bash
# Royak Raft cluster — real 3-node consensus over HTTP.
# Election, replication through the leader, and leader-failover, verified over
# actual TCP sockets (not the in-process test transport).
set -u
BIN="./target/release/royak"
PASS=0; FAIL=0
pass(){ PASS=$((PASS+1)); echo "  ✓ $1"; }
fail(){ FAIL=$((FAIL+1)); echo "  ✗ $1"; }

P1=7001; P2=7002; P3=7003
S1="$PWD/.raft1.json"; S2="$PWD/.raft2.json"; S3="$PWD/.raft3.json"

cleanup(){
  for pid in ${PID1:-} ${PID2:-} ${PID3:-}; do kill -9 "$pid" 2>/dev/null; done
  rm -f .raft1.json* .raft2.json* .raft3.json* 2>/dev/null
}
trap cleanup EXIT
cleanup

echo "╔════════════════════════════════════════════╗"
echo "║  Royak Raft Cluster Test (3 nodes, HTTP)   ║"
echo "╚════════════════════════════════════════════╝"

# ROYAK_NO_DOCKER lets the api run without a Docker daemon (consensus is
# independent of the container runtime).
export ROYAK_NO_DOCKER=1

peers_for(){ # $1 = self id → echo the other two as id@host:port
  case "$1" in
    1) echo "2@127.0.0.1:$P2,3@127.0.0.1:$P3";;
    2) echo "1@127.0.0.1:$P1,3@127.0.0.1:$P3";;
    3) echo "1@127.0.0.1:$P1,2@127.0.0.1:$P2";;
  esac
}

ROYAK_STATE="$S1" $BIN watch --interval 60 --ingress-port 0 --port $P1 --node-id 1 --peers "$(peers_for 1)" --bootstrap > /tmp/raft1.log 2>&1 &
PID1=$!
ROYAK_STATE="$S2" $BIN watch --interval 60 --ingress-port 0 --port $P2 --node-id 2 --peers "$(peers_for 2)" > /tmp/raft2.log 2>&1 &
PID2=$!
ROYAK_STATE="$S3" $BIN watch --interval 60 --ingress-port 0 --port $P3 --node-id 3 --peers "$(peers_for 3)" > /tmp/raft3.log 2>&1 &
PID3=$!

echo ""
echo "1. Election"
echo "───────────"
LEADER=""
for _ in $(seq 1 40); do
  for p in $P1 $P2 $P3; do
    L=$(curl -s --max-time 2 "http://127.0.0.1:$p/royak/v1/raft/status" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('leader') or '')" 2>/dev/null)
    if [ -n "$L" ] && [ "$L" != "None" ]; then LEADER="$L"; break; fi
  done
  [ -n "$LEADER" ] && break
  sleep 1
done
if [ -n "$LEADER" ]; then pass "cluster elected leader (node $LEADER)"; else fail "no leader elected"; cat /tmp/raft1.log | tail -5; fi

leader_port(){ case "$1" in 1) echo $P1;; 2) echo $P2;; 3) echo $P3;; esac; }

echo ""
echo "2. Replication through leader"
echo "─────────────────────────────"
LP=$(leader_port "$LEADER")
# Seed a deployment on the leader (plain apply), then scale via consensus.
printf 'kind: Deployment\nmetadata: {name: svc}\nspec:\n  replicas: 1\n  template: {spec: {containers: [{name: c, image: nginx:alpine}]}}\n' | ROYAK_STATE="$S1" $BIN apply - >/dev/null 2>&1 || true
RESP=$(curl -s --max-time 3 -X POST "http://127.0.0.1:$LP/royak/v1/raft/scale" -H 'Content-Type: application/json' -d '{"name":"svc","replicas":5}' 2>/dev/null)
echo "$RESP" | grep -q '"committed":true' && pass "scale committed through raft leader" || { fail "scale did not commit: $RESP"; }

echo ""
echo "3. Leader failover"
echo "──────────────────"
# Kill the leader; a survivor must take over.
case "$LEADER" in 1) kill -9 $PID1; PID1=;; 2) kill -9 $PID2; PID2=;; 3) kill -9 $PID3; PID3=;; esac
NEW=""
for _ in $(seq 1 40); do
  for p in $P1 $P2 $P3; do
    [ "$p" = "$LP" ] && continue
    L=$(curl -s --max-time 2 "http://127.0.0.1:$p/royak/v1/raft/status" 2>/dev/null | python3 -c "import sys,json;print(json.load(sys.stdin).get('leader') or '')" 2>/dev/null)
    if [ -n "$L" ] && [ "$L" != "None" ] && [ "$L" != "$LEADER" ]; then NEW="$L"; break; fi
  done
  [ -n "$NEW" ] && break
  sleep 1
done
if [ -n "$NEW" ]; then pass "survivors re-elected a new leader (node $NEW)"; else fail "no failover leader"; fi

echo ""
echo "4. Writes commit on the new leader"
echo "──────────────────────────────────"
NP=$(leader_port "$NEW")
RESP=$(curl -s --max-time 3 -X POST "http://127.0.0.1:$NP/royak/v1/raft/scale" -H 'Content-Type: application/json' -d '{"name":"svc","replicas":8}' 2>/dev/null)
echo "$RESP" | grep -q '"committed":true' && pass "post-failover write committed" || fail "post-failover write failed: $RESP"

echo ""
echo "════════════════════════════════════════"
echo "  Raft: $PASS passed, $FAIL failed"
echo "════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && echo "  ALL TESTS PASSED" || echo "  SOME TESTS FAILED"
exit $FAIL
