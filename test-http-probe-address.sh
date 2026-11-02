#!/bin/bash
# Real HTTP probe regression: IPv4-only reachable app vs loopback-only app.
# Run through tests/qualification/suites.py, never against valuable workloads.
set -u
cd "$(dirname "$0")"
NODES=1
BASE_PORT=${BASE_PORT:-48020}
. tests/cluster-lib.sh
PASS=0; FAIL=0; CLUSTER_ID=""
pass() { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi; }
cluster_init "$(mktemp -d "${TMPDIR:-/tmp}/royak-http-ip.XXXXXX")"
trap 'cluster_cleanup; [ $FAIL -gt 0 ] && tail -40 "$WORK/n1/server.log"; rm -rf "$WORK"' EXIT
start_node 1 || exit 1
leader 40 >/dev/null || exit 1
NS=ci-http-ip
for bind in public loopback; do
    addr=0.0.0.0; [ "$bind" = loopback ] && addr=127.0.0.1
    cat > "$WORK/$bind.yaml" <<YAML
apiVersion: v1
kind: Namespace
metadata: {name: $NS}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: $bind, namespace: $NS}
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: main
        image: alpine:3.22
        command: [sh, -ec, "while true; do printf 'HTTP/1.1 200 OK\\\\r\\\\nContent-Length: 3\\\\r\\\\n\\\\r\\\\nok\\\\n' | nc -l -s $addr -p 8000; done"]
        readinessProbe:
          httpGet: {path: /health, port: 8000}
YAML
    check "create $bind HTTP probe workload" "api 1 POST /apis/apps/v1/namespaces/$NS/deployments $WORK/$bind.yaml | code_of | grep -Eq '20[01]'"
done
pod() { docker ps --filter "label=royak.namespace=$NS" --filter "label=royak.deployment=$1" --format '{{.Names}}' | head -1; }
ready() {
    api 1 GET "/api/v1/namespaces/$NS/pods" | python3 -c '
import json,sys
d=json.loads(sys.stdin.read().rsplit("\nHTTP",1)[0])
for p in d["items"]:
    if p["metadata"]["name"]==sys.argv[1]: print(str(p["status"]["containerStatuses"][0]["ready"]).lower())
' "$1"
}
end=$((SECONDS+60))
while [ $SECONDS -lt $end ]; do
    P=$(pod public); L=$(pod loopback)
    [ -n "$P" ] && [ -n "$L" ] && break
    sleep 1
done
CLUSTER_ID=$(docker ps --filter "label=royak.namespace=$NS" --format '{{.Label "royak.cluster"}}' | head -1)
check "both test containers exist" "[ -n '${P:-}' ] && [ -n '${L:-}' ]"
end=$((SECONDS+30))
while [ $SECONDS -lt $end ] && [ "$(ready "${P:-missing}")" != true ]; do sleep 1; done
check "IPv4-only HTTP listener becomes Ready with wget-only image" "[ \"\$(ready $P)\" = true ]"
check "loopback app itself is healthy" "docker exec $L wget -q -O - http://127.0.0.1:8000/health | grep -qx ok"
sleep 4
check "loopback-only listener is NOT Ready on the pod interface" "[ \"\$(ready $L)\" = false ]"
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
