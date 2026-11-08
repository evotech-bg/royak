#!/bin/bash
# Royak Raft cluster — three `watch` processes, consensus over signed TLS node
# RPC, checked only through the public (token-authenticated) API:
# failover, catch-up after restart, minority partition (no confirmed write,
# no scheduling), retry after heal, delete propagation, snapshot install and
# restore from disk. The checks live in tests/raft_suite.py.
#
# Cleanup touches only this run's node processes and the containers/networks
# labelled with this run's cluster id.
set -u
cd "$(dirname "$0")"
export BASE_PORT=${BASE_PORT:-47750}
export INTERVAL=${INTERVAL:-5}
. tests/cluster-lib.sh
export BIN NS=ci-raft

[ -x "$BIN" ] || cargo build --release
cluster_init "$(mktemp -d "${TMPDIR:-/tmp}/royak-raft.XXXXXX")"
CLUSTER_ID=""
RC=1
trap 'cluster_cleanup; [ $RC -ne 0 ] && for i in $NODES; do echo "--- node $i log tail"; tail -25 "$WORK/n$i/server.log"; done; rm -rf "$WORK"' EXIT

echo "Royak Raft cluster test (work dir $WORK)"
for i in $NODES; do start_node "$i" || exit 1; done
L=$(leader 40) || { echo "  ✗ no confirmed leader"; exit 1; }
echo "  ✓ leader elected and confirmed (node $L)"

cat > "$WORK/seed.yaml" <<YAML
apiVersion: v1
kind: Namespace
metadata: {name: $NS}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: cfg, namespace: $NS}
data: {V: seed}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: $NS}
spec:
  replicas: 3
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      containers:
      - {name: main, image: alpine:3.22, command: ["sleep", "3600"]}
YAML
docker pull -q alpine:3.22 >/dev/null 2>&1 || true
C=$(api "$L" POST /apis/apps/v1/namespaces/$NS/deployments "$WORK/seed.yaml" | code_of)
[ "$C" = 201 ] || [ "$C" = 200 ] || { echo "  ✗ seed apply failed (HTTP $C)"; exit 1; }
end=$((SECONDS+90))
while [ $SECONDS -lt $end ] && [ "$(running_in $NS | wc -l)" -lt 3 ]; do sleep 1; done
[ "$(running_in $NS | wc -l)" -ge 3 ] || { echo "  ✗ seed deployment did not reach 3 pods"; exit 1; }
CLUSTER_ID=$(docker ps --filter "label=royak.namespace=$NS" --format '{{.Label "royak.cluster"}}' | head -1)
echo "  ✓ seeded $NS/web (3 pods) and $NS/cfg"
echo ""

python3 tests/raft_suite.py
RC=$?
exit $RC
