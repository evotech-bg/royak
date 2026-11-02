#!/bin/bash
# Royak ServiceLB + probe regression test — one real node on Docker.
#
# 1. ServiceLB only forwards to Ready pods (NodePort and LoadBalancer): no
#    traffic before Ready, a pod drops out when it loses readiness, with one
#    Ready and one NotReady replica only the Ready one is reached. The API
#    reports the same readiness.
# 2. Service changes reach the live listener: selector change and targetPort
#    change on the same port, delete frees the port, delete + recreate never
#    keeps the old route, same-named Services in two namespaces keep their own
#    backends, a node port claimed twice is rejected.
# 3. tcpSocket readiness: closed → NotReady, open → Ready, open → closed →
#    open flips, probes keep running after a Royak restart; httpGet (alpine has
#    no curl, only wget) and exec probes still work; an invalid probe is
#    rejected at apply.
#
# Cleanup touches only this run's node process and the containers/networks
# labelled with this run's cluster id.

set -u
cd "$(dirname "$0")"
NODES=1
BASE_PORT=${BASE_PORT:-47900}
. tests/cluster-lib.sh

NP=${NP_BASE:-31870}          # node ports used: NP .. NP+6
NS=ci-slb
NS2=ci-slb2
PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi }

[ -x "$BIN" ] || cargo build --release
command -v nc >/dev/null && command -v python3 >/dev/null || { echo "nc and python3 are required"; exit 1; }
for p in $(seq $NP $((NP + 6))) $(cport 1) $(iport 1); do
    if nc -z -w 1 127.0.0.1 "$p" 2>/dev/null; then echo "port $p is already in use — set NP_BASE/BASE_PORT"; exit 1; fi
done

cluster_init "$(mktemp -d "${TMPDIR:-/tmp}/royak-slb.XXXXXX")"
CLUSTER_ID=""
trap 'cluster_cleanup; [ $FAIL -gt 0 ] && { echo "--- node log tail"; tail -40 "$WORK/n1/server.log"; }; rm -rf "$WORK"' EXIT

# hit PORT — what the backend behind 127.0.0.1:PORT answers ("" = nothing).
# Connects, half-closes, reads until EOF (2s budget).
hit() {
    python3 - "$1" <<'PY' 2>/dev/null
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=2)
    s.shutdown(socket.SHUT_WR)
except OSError:
    sys.exit(0)
out = b""
try:
    while True:
        b = s.recv(4096)
        if not b: break
        out += b
except OSError:
    pass
sys.stdout.write(out.decode(errors="replace").replace("\r", "").replace("\n", ""))
PY
}
# hits PORT N — N answers, sorted unique.
hits() { local i; for i in $(seq 1 "$2"); do hit "$1"; echo; done | sort -u | sed '/^$/d' | tr '\n' ' '; }
# wait_for SECS CMD — poll CMD until it succeeds.
wait_for() { local end=$((SECONDS + $1)); shift; while [ $SECONDS -lt $end ]; do eval "$1" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
apply() { api 1 POST /apis/apps/v1/namespaces/$NS/deployments "$1"; }
del() { api 1 DELETE "$1" | code_of; }
pods_of() { docker ps --filter "label=royak.namespace=$1" --filter "label=royak.deployment=$2" --filter status=running --format '{{.Names}}' | sort; }
# api_ready NS POD — "true"/"false" as the API reports it.
api_ready() {
    api 1 GET "/api/v1/namespaces/$1/pods" | python3 -c "
import json,sys
d=json.loads(sys.stdin.read().rsplit('\nHTTP',1)[0])
for p in d['items']:
    if p['metadata']['name']=='$2': print(str(p['status']['containerStatuses'][0]['ready']).lower())"
}
yaml() { cat > "$WORK/$1.yaml"; echo "$WORK/$1.yaml"; }

# A server that answers every connection on PORT with TEXT (busybox nc).
serve() { echo "nc -lk -p $1 -e echo $2"; }
# Same, but then echoes the client until it closes (a long-lived connection).
serve_long() { echo "nc -lk -p $1 -e sh -c 'echo $2; exec cat'"; }

echo "Royak ServiceLB + probes test (work dir $WORK)"
start_node 1 || exit 1
L=$(leader 40); [ "$L" = 1 ] || { fail "single node did not become leader"; exit 1; }
docker pull -q alpine:3.22 >/dev/null 2>&1 || true

echo ""
echo "1. ServiceLB forwards only to Ready pods"
F=$(yaml gate <<YAML
apiVersion: v1
kind: Namespace
metadata: {name: $NS}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: gate, namespace: $NS}
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: main
        image: alpine:3.22
        command: ["sh", "-c", "$(serve 8080 'GATE-$HOSTNAME')"]
        readinessProbe:
          exec: {command: [cat, /tmp/ready]}
          periodSeconds: 1
---
apiVersion: v1
kind: Service
metadata: {name: gate, namespace: $NS}
spec:
  type: NodePort
  selector: {app: gate}
  ports: [{port: 80, targetPort: 8080, nodePort: $NP}]
---
apiVersion: v1
kind: Service
metadata: {name: gate-lb, namespace: $NS}
spec:
  type: LoadBalancer
  selector: {app: gate}
  ports: [{port: $((NP + 1)), targetPort: 8080}]
YAML
)
check "apply gate deployment + NodePort + LoadBalancer" "apply $F | code_of | grep -Eq '20[01]'"
wait_for 90 '[ $(pods_of $NS gate | wc -l) -eq 2 ]'
CLUSTER_ID=$(docker ps --filter "label=royak.namespace=$NS" --format '{{.Label "royak.cluster"}}' | head -1)
G1=$(pods_of $NS gate | sed -n 1p); G2=$(pods_of $NS gate | sed -n 2p)
check "2 gate pods running" "[ -n '$G1' ] && [ -n '$G2' ]"
check "probe containers explicitly use Docker's PID-1 reaper" "[ \"\$(docker inspect -f '{{.HostConfig.Init}}' $G1)\" = true ] && [ \"\$(docker inspect -f '{{.HostConfig.Init}}' $G2)\" = true ]"
H1=$(docker exec "$G1" hostname 2>/dev/null); H2=$(docker exec "$G2" hostname 2>/dev/null)
sleep 4
check "running but NotReady: the API reports ready=false" "[ \"\$(api_ready $NS $G1)\" = false ] && [ \"\$(api_ready $NS $G2)\" = false ]"
check "no NodePort traffic before Ready" "[ -z \"\$(hits $NP 5)\" ]"
check "no LoadBalancer traffic before Ready" "[ -z \"\$(hits $((NP + 1)) 5)\" ]"

docker exec "$G1" touch /tmp/ready
wait_for 20 "[ \"\$(api_ready $NS $G1)\" = true ]"
check "API: $G1 Ready, $G2 still NotReady" "[ \"\$(api_ready $NS $G1)\" = true ] && [ \"\$(api_ready $NS $G2)\" = false ]"
check "NodePort: 1 Ready + 1 NotReady → only the Ready pod answers" "[ \"\$(hits $NP 12)\" = 'GATE-$H1 ' ]"
check "LoadBalancer: only the Ready pod answers" "[ \"\$(hits $((NP + 1)) 12)\" = 'GATE-$H1 ' ]"

docker exec "$G2" touch /tmp/ready
BOTH=$(printf 'GATE-%s ' $(printf '%s\n' "$H1" "$H2" | sort))
check "both Ready → both receive traffic" "wait_for 20 '[ \"\$(hits $NP 12)\" = \"$BOTH\" ]'"

docker exec "$G1" rm -f /tmp/ready
wait_for 20 "[ \"\$(api_ready $NS $G1)\" = false ]"
check "$G1 lost readiness → the API reports it NotReady" "[ \"\$(api_ready $NS $G1)\" = false ]"
check "NodePort: a pod that lost readiness gets no traffic" "[ \"\$(hits $NP 12)\" = 'GATE-$H2 ' ]"
check "LoadBalancer: a pod that lost readiness gets no traffic" "[ \"\$(hits $((NP + 1)) 12)\" = 'GATE-$H2 ' ]"

echo ""
echo "2. Service changes reach the live listener"
F=$(yaml routes <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: a, namespace: $NS}
spec:
  template:
    spec:
      containers:
      - name: main
        image: alpine:3.22
        command: ["sh", "-c", "$(serve 9090 A9090) & $(serve_long 8080 A8080)"]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: alt, namespace: $NS}
spec:
  template:
    spec:
      containers:
      - name: main
        image: alpine:3.22
        command: ["sh", "-c", "$(serve 8080 ALT8080)"]
---
apiVersion: v1
kind: Service
metadata: {name: front, namespace: $NS}
spec:
  type: NodePort
  selector: {app: a}
  ports: [{port: 80, targetPort: 8080, nodePort: $((NP + 2))}]
YAML
)
check "apply deployments a, alt + service front (→ a)" "apply $F | code_of | grep -Eq '20[01]'"
check "front → a:8080" "wait_for 60 '[ \"\$(hit $((NP + 2)))\" = A8080 ]'"
check "unprobed containers retain their existing PID-1 contract" "[ \"\$(docker inspect -f '{{.HostConfig.Init}}' \$(pods_of $NS a))\" != true ]"
OPEN=0
if exec 7<>/dev/tcp/127.0.0.1/$((NP + 2)); then
    read -r -t 3 FIRST <&7 && [ "$FIRST" = A8080 ] && OPEN=1
fi
check "a long-lived connection is open to a" "[ $OPEN = 1 ]"

svc_front() {  # svc_front SELECTOR TARGETPORT
    yaml front <<YAML
apiVersion: v1
kind: Service
metadata: {name: front, namespace: $NS}
spec:
  type: NodePort
  selector: {app: $1}
  ports: [{port: 80, targetPort: $2, nodePort: $((NP + 2))}]
YAML
}
ALT_BEFORE=$(pods_of $NS alt); A_BEFORE=$(pods_of $NS a)
check "alt's pod does not publish 8080 yet (no Service selected it)" "[ -z \"\$(docker port $ALT_BEFORE 8080 2>/dev/null)\" ]"
T0=$SECONDS
check "change selector a → alt on the same nodePort" "api 1 POST /api/v1/namespaces/$NS/services \$(svc_front alt 8080) | code_of | grep -Eq '20[01]'"
check "front → alt:8080 without a Royak restart" "wait_for 90 '[ \"\$(hit $((NP + 2)))\" = ALT8080 ]'"
echo "    (selector switch took $((SECONDS - T0))s, including replacing alt's pods to publish 8080)"
# replaced_by_publisher DEP OLD PORT — the rollout finished: one pod, not OLD, publishing PORT.
replaced_by_publisher() { local p; p=$(pods_of $NS "$1"); [ "$(echo "$p" | wc -l)" -eq 1 ] && [ -n "$p" ] && [ "$p" != "$2" ] && docker port "$p" "$3" | grep -q .; }
check "alt's pod was replaced by one that publishes 8080" "wait_for 30 'replaced_by_publisher alt $ALT_BEFORE 8080'"
check "no stale answers from a after the switch" "[ \"\$(hits $((NP + 2)) 8)\" = 'ALT8080 ' ]"
if [ "$OPEN" = 1 ]; then
    printf 'still-there\n' >&7 2>/dev/null
    ECHO=""; read -r -t 3 ECHO <&7
    check "the connection opened before the change was not cut (still talks to a)" "[ '$ECHO' = still-there ]"
    exec 7>&- 7<&-
fi

T0=$SECONDS
check "change targetPort 8080 → 9090 (selector back to a)" "api 1 POST /api/v1/namespaces/$NS/services \$(svc_front a 9090) | code_of | grep -Eq '20[01]'"
check "front → a:9090 (pods rolled to publish 9090)" "wait_for 90 '[ \"\$(hit $((NP + 2)))\" = A9090 ]'"
echo "    (targetPort switch took $((SECONDS - T0))s)"
check "a's pod was replaced by one that publishes 9090" "wait_for 30 'replaced_by_publisher a $A_BEFORE 9090'"

check "delete service front" "[ \"\$(del /api/v1/namespaces/$NS/services/front)\" = 200 ]"
check "removed service frees its port" "wait_for 10 '! nc -z -w 1 127.0.0.1 $((NP + 2))'"
check "the port can be bound by someone else" "python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((\"0.0.0.0\", $((NP + 2)))); s.close()'"
check "recreate front on the same nodePort → alt" "api 1 POST /api/v1/namespaces/$NS/services \$(svc_front alt 8080) | code_of | grep -Eq '20[01]'"
check "recreated service never serves the old route" "wait_for 30 '[ \"\$(hit $((NP + 2)))\" = ALT8080 ]' && [ \"\$(hits $((NP + 2)) 8)\" = 'ALT8080 ' ]"

web_in() {  # web_in NAMESPACE NODEPORT ANSWER — namespace, web deployment, web service
    yaml "web-$1" <<YAML
apiVersion: v1
kind: Namespace
metadata: {name: $1}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: $1}
spec:
  template:
    spec:
      containers:
      - {name: main, image: "alpine:3.22", command: ["sh", "-c", "$(serve 8080 $3)"]}
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: $1}
spec:
  type: NodePort
  selector: {app: web}
  ports: [{port: 80, targetPort: 8080, nodePort: $2}]
YAML
}
check "apply web deployment + service in $NS" "api 1 POST /apis/apps/v1/namespaces/$NS/deployments \$(web_in $NS $((NP + 3)) NS1) | code_of | grep -Eq '20[01]'"
check "apply same-named web deployment + service in $NS2" "api 1 POST /apis/apps/v1/namespaces/$NS2/deployments \$(web_in $NS2 $((NP + 4)) NS2) | code_of | grep -Eq '20[01]'"
check "$NS/web answers from $NS only" "wait_for 60 '[ \"\$(hits $((NP + 3)) 8)\" = \"NS1 \" ]'"
check "$NS2/web answers from $NS2 only" "wait_for 60 '[ \"\$(hits $((NP + 4)) 8)\" = \"NS2 \" ]'"
DUP=$(yaml dup <<YAML
apiVersion: v1
kind: Service
metadata: {name: thief, namespace: $NS2}
spec:
  type: NodePort
  selector: {app: web}
  ports: [{port: 80, targetPort: 8080, nodePort: $((NP + 3))}]
YAML
)
OUT=$(api 1 POST /api/v1/namespaces/$NS2/services "$DUP")
check "a nodePort already allocated is rejected at apply" "echo \"\$OUT\" | tail -1 | grep -Evq 'HTTP 20' && echo \"\$OUT\" | grep -q 'already allocated'"
check "… and the original route is untouched" "[ \"\$(hits $((NP + 3)) 6)\" = 'NS1 ' ]"

echo ""
echo "3. tcpSocket / httpGet / exec readiness"
F=$(yaml probes <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: tcp, namespace: $NS}
spec:
  template:
    spec:
      containers:
      - name: main
        image: alpine:3.22
        command: ["sleep", "100000"]
        readinessProbe:
          tcpSocket: {port: 7000}
          periodSeconds: 1
---
apiVersion: v1
kind: Service
metadata: {name: tcp, namespace: $NS}
spec:
  type: NodePort
  selector: {app: tcp}
  ports: [{port: 80, targetPort: 7000, nodePort: $((NP + 5))}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: http, namespace: $NS}
spec:
  template:
    spec:
      containers:
      - name: main
        image: alpine:3.22
        command: ["sh", "-c", "nc -lk -p 8080 -e sh -c 'printf \"HTTP/1.1 200 OK\\\\r\\\\nContent-Length: 2\\\\r\\\\n\\\\r\\\\nok\"'"]
        readinessProbe:
          httpGet: {path: /healthz, port: 8080}
          periodSeconds: 1
YAML
)
check "apply tcp + http probe deployments" "apply $F | code_of | grep -Eq '20[01]'"
wait_for 60 '[ -n "$(pods_of $NS tcp)" ] && [ -n "$(pods_of $NS http)" ]'
T=$(pods_of $NS tcp | head -1); HP=$(pods_of $NS http | head -1)
sleep 5
check "tcpSocket on a closed port → NotReady" "[ \"\$(api_ready $NS $T)\" = false ]"
check "… and no NodePort traffic" "[ -z \"\$(hits $((NP + 5)) 4)\" ]"
docker exec -d "$T" sh -c "$(serve 7000 TCP7000)"
check "port opened → Ready" "wait_for 20 '[ \"\$(api_ready $NS $T)\" = true ]'"
check "… and the NodePort reaches it" "wait_for 10 '[ \"\$(hit $((NP + 5)))\" = TCP7000 ]'"
docker exec "$T" pkill -f "nc -lk -p 7000"
check "port closed → NotReady again" "wait_for 20 '[ \"\$(api_ready $NS $T)\" = false ]'"
check "… and the NodePort stops forwarding" "wait_for 10 '[ -z \"\$(hits $((NP + 5)) 4)\" ]'"
docker exec -d "$T" sh -c "$(serve 7000 TCP7000)"
check "port reopened → Ready" "wait_for 20 '[ \"\$(api_ready $NS $T)\" = true ]'"
check "httpGet probe on an image with wget but no curl → Ready" "wait_for 30 '[ \"\$(api_ready $NS $HP)\" = true ]'"
check "exec probe still gates readiness ($G2 has /tmp/ready)" "[ \"\$(api_ready $NS $G2)\" = true ] && [ \"\$(api_ready $NS $G1)\" = false ]"

echo ""
echo "4. Probes keep running after a Royak restart"
stop_node 1
check "pods survive the Royak restart" "[ \"\$(pods_of $NS tcp)\" = '$T' ]"
start_node 1 || exit 1
leader 40 >/dev/null
check "after restart: open port → Ready" "wait_for 30 '[ \"\$(api_ready $NS $T)\" = true ]'"
docker exec "$T" pkill -f "nc -lk -p 7000"
check "after restart: closed port → NotReady" "wait_for 20 '[ \"\$(api_ready $NS $T)\" = false ]'"
check "after restart: no traffic to the NotReady pod" "wait_for 10 '[ -z \"\$(hits $((NP + 5)) 4)\" ]'"
check "after restart: listeners are back and still readiness-gated" "wait_for 20 '[ \"\$(hits $NP 8)\" = \"GATE-$H2 \" ]'"

echo ""
echo "5. Invalid probes are rejected at apply"
for bad in "periodSeconds: 1|no handler" "tcpSocket: {port: http}|named port" "grpc: {port: 9000}|grpc"; do
    PROBE=${bad%%|*}; WANT=${bad##*|}
    B=$(yaml bad <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: bad, namespace: $NS}
spec:
  template:
    spec:
      containers:
      - name: main
        image: alpine:3.22
        readinessProbe: {$PROBE}
YAML
)
    OUT=$(apply "$B")
    check "readinessProbe {$PROBE} → rejected ($WANT)" "echo \"\$OUT\" | tail -1 | grep -Evq 'HTTP 20' && echo \"\$OUT\" | grep -q '$WANT'"
done
check "a rejected deployment was not stored" "api 1 GET /apis/apps/v1/namespaces/$NS/deployments/bad | code_of | grep -q 404"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
