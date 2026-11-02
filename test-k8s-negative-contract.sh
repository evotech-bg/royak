#!/bin/bash
# A Kubernetes-looking security manifest must be enforced or explicitly refused.
# No exploit is attempted: inspect only a harmless sleeping Alpine container.
# Run only through the isolated qualification suite driver.
set -u
cd "$(dirname "$0")"
NODES=1
BASE_PORT=${BASE_PORT:-48120}
. tests/cluster-lib.sh
PASS=0; FAIL=0; CLUSTER_ID=""
pass() { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi; }
cluster_init "$(mktemp -d "${TMPDIR:-/tmp}/royak-negative.XXXXXX")"
trap 'cluster_cleanup; rm -rf "$WORK"' EXIT
start_node 1 || exit 1
leader 40 >/dev/null || exit 1
NS=ci-negative
cat > "$WORK/security.yaml" <<YAML
apiVersion: v1
kind: Namespace
metadata: {name: $NS}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: constrained, namespace: $NS}
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: main
        image: alpine:3.22
        command: [sleep, '3600']
        securityContext:
          runAsNonRoot: true
          runAsUser: 10001
          runAsGroup: 10002
          readOnlyRootFilesystem: true
          allowPrivilegeEscalation: false
          capabilities: {drop: [ALL]}
YAML
C=$(api 1 POST /apis/apps/v1/namespaces/$NS/deployments "$WORK/security.yaml" | code_of)
case "$C" in
  400|422) fail "supported security constraints must be enforced, not merely refused ($C)";;
  200|201)
    end=$((SECONDS+45)); P=""
    while [ $SECONDS -lt $end ]; do
        P=$(docker ps --filter "label=royak.namespace=$NS" --format '{{.Names}}' | head -1)
        [ -n "$P" ] && break
        sleep 1
    done
    CLUSTER_ID=$(docker ps --filter "label=royak.namespace=$NS" --format '{{.Label "royak.cluster"}}' | head -1)
    check "accepted constrained workload exists" "[ -n '$P' ]"
    if [ -n "$P" ]; then
        echo "Observed UID: $(docker exec "$P" id -u)"
        echo "Observed ReadonlyRootfs: $(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$P")"
        echo "Observed CapDrop: $(docker inspect -f '{{json .HostConfig.CapDrop}}' "$P")"
        echo "Observed SecurityOpt: $(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$P")"
    fi
    check "runAsNonRoot/runAsUser are enforced, not silently ignored" "[ \"\$(docker exec $P id -u)\" = 10001 ]"
    check "runAsGroup is enforced" "[ \"\$(docker exec $P id -g)\" = 10002 ]"
    check "readOnlyRootFilesystem is enforced" "[ \"\$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' $P)\" = true ]"
    check "capabilities drop ALL is enforced" "docker inspect -f '{{json .HostConfig.CapDrop}}' $P | grep -q ALL"
    check "allowPrivilegeEscalation false is enforced" "docker inspect -f '{{json .HostConfig.SecurityOpt}}' $P | grep -q no-new-privileges"
    check "kernel sees no effective capabilities" "docker exec $P cat /proc/1/status | grep -Eq '^CapEff:[[:space:]]*0+$'"
    check "kernel capability bounding set is empty" "docker exec $P cat /proc/1/status | grep -Eq '^CapBnd:[[:space:]]*0+$'"
    check "kernel sees NoNewPrivs=1" "docker exec $P cat /proc/1/status | grep -Eq '^NoNewPrivs:[[:space:]]*1$'"
    stop_node 1
    start_node 1 || exit 1
    leader 40 >/dev/null || exit 1
    docker rm -f "$P" >/dev/null
    end=$((SECONDS+30)); NEW=""
    while [ $SECONDS -lt $end ]; do
        NEW=$(docker ps --filter "label=royak.namespace=$NS" --format '{{.Names}}' | head -1)
        [ -n "$NEW" ] && break
        sleep 1
    done
    check "state restart and pod replacement preserve UID/GID" "[ \"\$(docker exec $NEW id -u)\" = 10001 ] && [ \"\$(docker exec $NEW id -g)\" = 10002 ]"
    check "replacement preserves read-only root and capability drop" "[ \"\$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' $NEW)\" = true ] && docker inspect -f '{{json .HostConfig.CapDrop}}' $NEW | grep -q ALL"
    ;;
  *) fail "unexpected apply result $C (not a valid explicit rejection)";;
esac

for field in 'runAsNonRoot: true, runAsUser: 0' 'seccompProfile: {type: RuntimeDefault}'; do
    cat > "$WORK/refused.yaml" <<YAML
kind: Deployment
metadata: {name: refused, namespace: $NS}
spec:
  template:
    spec:
      containers:
      - {name: c, image: 'alpine:3.22', securityContext: {$field}}
YAML
    check "unsafe or unsupported context is explicitly refused: $field" "api 1 POST /apis/apps/v1/namespaces/$NS/deployments $WORK/refused.yaml | code_of | grep -Eq '400|422'"
done
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
