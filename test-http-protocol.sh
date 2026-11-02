#!/bin/bash
# Real HTTP framing regression; run only in the isolated suite daemon.
set -u
cd "$(dirname "$0")"
NODES=1
BASE_PORT=${BASE_PORT:-48220}
. tests/cluster-lib.sh
PASS=0; FAIL=0; CLUSTER_ID=""
check() { if eval "$2" >/dev/null 2>&1; then PASS=$((PASS+1)); echo "  ✓ $1"; else FAIL=$((FAIL+1)); echo "  ✗ $1"; fi; }
cluster_init "$(mktemp -d "${TMPDIR:-/tmp}/royak-http-wire.XXXXXX")"
trap 'cluster_cleanup; rm -rf "$WORK"' EXIT
check "failed image pull returns a failing CLI exit status without Docker/network" "python3 -B tests/qualification/cli_exit.py --binary '$BIN' --output '$WORK/cli-exit.json'"
start_node 1 || exit 1
leader 40 >/dev/null || exit 1
NS=ci-http-wire
cat > "$WORK/app.yaml" <<YAML
apiVersion: v1
kind: Namespace
metadata: {name: $NS}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: chunked, namespace: $NS}
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: main
        image: alpine:3.22
        command: [sh, -ec, "while true; do printf 'HTTP/1.1 200 OK\\\\r\\\\nTransfer-Encoding: chunked\\\\r\\\\nConnection: close\\\\r\\\\n\\\\r\\\\n5\\\\r\\\\nhello\\\\r\\\\n0\\\\r\\\\n\\\\r\\\\n' | nc -l -p 8000; done"]
---
apiVersion: v1
kind: Service
metadata: {name: chunked, namespace: $NS}
spec: {selector: {app: chunked}, ports: [{port: 80, targetPort: 8000}]}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: chunked, namespace: $NS}
spec:
  rules:
  - host: chunked.test
    http:
      paths:
      - path: /
        backend: {service: {name: chunked, port: {number: 80}}}
YAML
check "chunked fixture applies" "api 1 POST /apis/apps/v1/namespaces/$NS/deployments $WORK/app.yaml | code_of | grep -Eq '20[01]'"
end=$((SECONDS+45)); P=""
while [ $SECONDS -lt $end ]; do
    P=$(docker ps --filter "label=royak.namespace=$NS" --format '{{.Names}}' | head -1)
    [ -n "$P" ] && break
    sleep 1
done
CLUSTER_ID=$(docker ps --filter "label=royak.namespace=$NS" --format '{{.Label "royak.cluster"}}' | head -1)
IP=$(docker inspect "$P" | python3 -c 'import json,sys; n=json.load(sys.stdin)[0]["NetworkSettings"]["Networks"]; print(next(v["IPAddress"] for v in n.values() if v.get("IPAddress")))')
check "upstream fixture itself decodes to hello" "[ \"\$(curl -s --max-time 3 http://$IP:8000/)\" = hello ]"
end=$((SECONDS+20)); C=""
while [ $SECONDS -lt $end ]; do
    C=$(curl -sk --max-time 3 -H 'Host: chunked.test' -o "$WORK/body" -w '%{http_code}' "https://127.0.0.1:$(iport 1)/")
    [ "$C" = 200 ] && break
    sleep 1
done
check "ingress returns HTTP 200" "[ '$C' = 200 ]"
echo "Observed ingress body: $(python3 -c 'import sys; print(repr(open(sys.argv[1],"rb").read()))' "$WORK/body")"
check "ingress preserves application body, not chunk framing" "[ \"\$(cat $WORK/body)\" = hello ]"
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
