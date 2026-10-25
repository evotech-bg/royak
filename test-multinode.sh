#!/bin/bash
# Royak multi-node test — three local `watch` processes forming one cluster
# over signed TLS node RPC (Raft for desired state, signed heartbeats for the
# census). All nodes share this host's Docker daemon, so "remote" placement
# here means "created by another node's process", not another machine.
#
# Checks: census, inter-node request signing, the workload contract on pods
# placed by other nodes (command/args, env literal + configMap/secret refs,
# limits, namespace, ports, probes), self-healing after a pod kill and after a
# node loss (time measured, no overprovisioning), delete propagation, RBAC.
#
# Cleanup touches only this run's node processes and the containers/networks
# labelled with this run's cluster id.

set -u
cd "$(dirname "$0")"
. tests/cluster-lib.sh

BASE_PORT=${BASE_PORT:-47700}
NS=ci-mn
PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi }

[ -x "$BIN" ] || cargo build --release
cluster_init "$(mktemp -d "${TMPDIR:-/tmp}/royak-mn.XXXXXX")"
CLUSTER_ID=""
trap 'cluster_cleanup; [ $FAIL -gt 0 ] && for i in $NODES; do echo "--- node $i log tail"; tail -25 "$WORK/n$i/server.log"; done; rm -rf "$WORK"' EXIT

echo "Royak multi-node test (work dir $WORK)"
echo ""
echo "1. Three nodes, one cluster"
for i in $NODES; do start_node "$i" || exit 1; done
L=$(leader 40)
check "a leader is elected and confirmed by a quorum" "[ -n '$L' ]"
[ -n "$L" ] || exit 1

ready_nodes() { api "$L" GET /api/v1/nodes | python3 -c "
import json,sys; d=json.loads(sys.stdin.read().rsplit('\nHTTP',1)[0])
print(sum(1 for n in d['items'] for c in n['status']['conditions'] if c['type']=='Ready' and c['status']=='True'))"; }
end=$((SECONDS+40)); R=0
while [ $SECONDS -lt $end ]; do R=$(ready_nodes 2>/dev/null || echo 0); [ "$R" = 3 ] && break; sleep 1; done
check "census: 3 nodes Ready via signed heartbeats" "[ '$R' = 3 ]"

echo ""
echo "2. Inter-node requests must be signed"
P=$(cport "$L")
C=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{}' "https://127.0.0.1:$P/royak/v1/heartbeat")
check "unsigned heartbeat → 401" "[ '$C' = 401 ]"
C=$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ADMIN_TOKEN" "https://127.0.0.1:$P/royak/v1/pods")
check "an admin bearer token is not a node identity → 401" "[ '$C' = 401 ]"
C=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'x-royak-node: ci-n2' -H "x-royak-timestamp: $(date +%s)" -H "x-royak-nonce: n$RANDOM" -H "x-royak-signature: $(rand_hex 32)" -d '{}' "https://127.0.0.1:$P/royak/v1/create-pod")
check "forged signature → 401" "[ '$C' = 401 ]"
C=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$P/api/v1/namespaces")
check "anonymous API read → 401" "[ '$C' = 401 ]"

echo ""
echo "3. Workload contract on pods placed by every node"
cat > "$WORK/app.yaml" <<YAML
apiVersion: v1
kind: Namespace
metadata: {name: $NS}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: cfg, namespace: $NS}
data: {GREETING: hello-from-cfg}
---
apiVersion: v1
kind: Secret
metadata: {name: sec, namespace: $NS}
stringData: {TOKEN: s3cr3t-value}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ci-viewers}
roleRef: {kind: ClusterRole, name: view}
subjects: [{kind: Group, name: viewers}]
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
      - name: main
        image: alpine:3.22
        command: ["/bin/sh", "-c"]
        args: ["echo \"\$GREETING \$TOKEN \$MODE\" | tee /tmp/out; while true; do printf 'HTTP/1.1 200 OK\\\\r\\\\nContent-Length: 2\\\\r\\\\n\\\\r\\\\nok' | nc -l -p 8080 >/dev/null; done"]
        env:
        - {name: MODE, value: literal-mode}
        - name: GREETING
          valueFrom: {configMapKeyRef: {name: cfg, key: GREETING}}
        - name: TOKEN
          valueFrom: {secretKeyRef: {name: sec, key: TOKEN}}
        ports: [{containerPort: 8080}]
        resources: {limits: {memory: 64Mi, cpu: 250m}}
        readinessProbe:
          tcpSocket: {port: 8080}
          periodSeconds: 2
YAML
docker pull -q alpine:3.22 >/dev/null 2>&1 || true
OUT=$(api "$L" POST /apis/apps/v1/namespaces/$NS/deployments "$WORK/app.yaml")
check "apply through the leader" "echo \"\$OUT\" | tail -1 | grep -Eq 'HTTP 20[01]'"
end=$((SECONDS+90))
while [ $SECONDS -lt $end ] && [ "$(running_in $NS | wc -l)" -lt 3 ]; do sleep 1; done
check "3 pods running" "[ \$(running_in $NS | wc -l) -eq 3 ]"
CLUSTER_ID=$(docker ps --filter "label=royak.namespace=$NS" --format '{{.Label "royak.cluster"}}' | head -1)
NODES_USED=$(running_in $NS | awk '{print $2}' | sort -u | wc -l)
check "pods spread over more than one node ($NODES_USED)" "[ $NODES_USED -ge 2 ]"
REMOTE=$(running_in $NS | awk -v l="ci-n$L" '$2 != l {print $1; exit}')
check "a pod was placed by a non-leader node" "[ -n '$REMOTE' ]"
if [ -n "$REMOTE" ]; then
    check "remote pod: command+args, literal and configMap/secret env" \
        "docker exec $REMOTE cat /tmp/out | grep -qx 'hello-from-cfg s3cr3t-value literal-mode'"
    check "remote pod: memory limit 64Mi" "[ \$(docker inspect -f '{{.HostConfig.Memory}}' $REMOTE) = 67108864 ]"
    check "remote pod: cpu limit 250m" "[ \$(docker inspect -f '{{.HostConfig.NanoCpus}}' $REMOTE) = 250000000 ]"
    check "remote pod: namespace label" "[ \$(docker inspect -f '{{index .Config.Labels \"royak.namespace\"}}' $REMOTE) = $NS ]"
    check "remote pod: serves on its container port" "docker exec $REMOTE wget -qO- -T 3 http://127.0.0.1:8080/ | grep -qx ok"
    # Logs of a pod on another node travel over node RPC (signed + sealed).
    # The leader learns about a peer's pods through the census poll, so a pod
    # that just started can be unknown to it for a few seconds (404).
    end=$((SECONDS+20))
    while :; do
        RLOGS=$(api "$L" GET "/api/v1/namespaces/$NS/pods/$REMOTE/log")
        echo "$RLOGS" | tail -1 | grep -q 'HTTP 404' && [ $SECONDS -lt $end ] || break
        sleep 1
    done
    check "remote pod logs through the leader (node RPC)" \
        "echo \"\$RLOGS\" | grep -qx 'hello-from-cfg s3cr3t-value literal-mode'"
    echo "$RLOGS" | grep -qx 'hello-from-cfg s3cr3t-value literal-mode' || echo "    got: $(echo "$RLOGS" | head -c 300)"
fi

echo ""
echo "4. RBAC through any node"
F=$(( L % 3 + 1 ))
C=$(api "$F" GET /api/v1/namespaces/$NS/configmaps "" "$VIEW_TOKEN" | code_of)
check "viewer can read (node $F)" "[ '$C' = 200 ]"
printf 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: nope, namespace: %s}\ndata: {a: b}\n' $NS > "$WORK/nope.yaml"
C=$(api "$L" POST /api/v1/namespaces/$NS/configmaps "$WORK/nope.yaml" "$VIEW_TOKEN" | code_of)
check "viewer cannot write → 403" "[ '$C' = 403 ]"
C=$(api "$F" GET /api/v1/namespaces/$NS/secrets "" "$VIEW_TOKEN" | code_of)
check "viewer cannot read secrets → 403" "[ '$C' = 403 ]"
# Empty path segments must not smuggle a resource read past the gate as "discovery".
for P in "/apis///secrets" "/apis///secrets/sec" "/apis/x//secrets"; do
    OUT=$(api "$F" GET "$P" "" "$VIEW_TOKEN")
    C=$(echo "$OUT" | code_of)
    check "viewer GET $P is refused ($C) and leaks nothing" "[ '$C' != 200 ] && ! echo \"\$OUT\" | grep -q s3cr3t"
done

echo ""
echo "5. Self-healing after a pod kill"
heal() { # heal VICTIM → sets T (seconds until 3 running again without the victim) and MAXR
    local v=$1 t0=$SECONDS n vid start
    vid=$(docker inspect -f '{{.Id}}' "$v")
    start=$(date +%s.%N)
    docker kill "$v" >/dev/null
    MAXR=0; T=timeout
    while [ $((SECONDS - t0)) -lt 120 ]; do
        n=$(running_in $NS | wc -l); [ "$n" -gt "$MAXR" ] && MAXR=$n
        if [ "$n" -ge 3 ] && ! docker ps -q --no-trunc --filter status=running | grep -q "$vid"; then
            T=$(python3 -c "import time;print(f'{time.time()-$start:.2f}')"); return 0
        fi
        sleep 0.3
    done
}
V=$(running_in $NS | awk '{print $1; exit}')
heal "$V"
for _ in $(seq 1 15); do n=$(running_in $NS | wc -l); [ "$n" -gt "$MAXR" ] && MAXR=$n; sleep 0.5; done
echo "    recovered in ${T}s (interval ${INTERVAL}s), max running $MAXR"
check "pod replaced" "[ '$T' != timeout ]"
check "no overprovisioning during recovery (max 3)" "[ $MAXR -le 3 ]"

echo ""
echo "6. Node loss"
DEAD=$(( L % 3 + 1 ))
stop_node "$DEAD" KILL
docker ps -q --filter "label=royak.namespace=$NS" --filter "label=royak.node=ci-n$DEAD" | xargs -r docker rm -f >/dev/null
start=$(date +%s.%N); MAXR=0; OK=""
end=$((SECONDS+120))
while [ $SECONDS -lt $end ]; do
    n=$(running_in $NS | grep -v " ci-n$DEAD\$" | wc -l); [ "$n" -gt "$MAXR" ] && MAXR=$n
    [ "$n" -ge 3 ] && { OK=$(python3 -c "import time;print(f'{time.time()-$start:.2f}')"); break; }
    sleep 0.5
done
for _ in $(seq 1 15); do n=$(running_in $NS | wc -l); [ "$n" -gt "$MAXR" ] && MAXR=$n; sleep 0.5; done
echo "    3 pods on the surviving nodes after ${OK:-timeout}s, max running $MAXR"
check "workload recovered on the surviving nodes" "[ -n '$OK' ]"
check "no overprovisioning after node loss (max 3)" "[ $MAXR -le 3 ]"
L=$(leader 30)
check "cluster still has a confirmed leader" "[ -n '$L' ]"

echo ""
echo "7. Delete propagates"
C=$(api "$L" DELETE /apis/apps/v1/namespaces/$NS/deployments/web | code_of)
check "DELETE accepted" "[ '$C' = 200 ]"
end=$((SECONDS+60))
while [ $SECONDS -lt $end ] && [ -n "$(running_in $NS)" ]; do sleep 0.5; done
check "every pod of the deployment is gone" "[ -z \"\$(running_in $NS)\" ]"
G=""
for i in $NODES; do [ "$i" = "$DEAD" ] && continue; G="$G$(api "$i" GET /apis/apps/v1/namespaces/$NS/deployments/web | code_of)"; done
check "the deployment is 404 on every live node" "[ '$G' = 404404 ]"

echo ""
echo "  Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
