#!/bin/bash
# Royak auth regression test — the authorization fixes, exercised through the
# real HTTPS API of a running node (not unit tests):
#
#   * malformed paths (empty segments such as /apis///secrets) never bypass
#     authorization or leak a Secret;
#   * a Function trigger cannot shadow Kubernetes, Royak, discovery or health
#     endpoints, while a normal trigger still invokes the function;
#   * `get` on pods/exec does not grant exec — only `create` does;
#   * discovery and ordinary kubectl workflows keep working.
#
# kubectl runs against a kubeconfig in this run's temp dir (the user's
# kubeconfig is never read or written). Cleanup touches only this run's node
# process, the containers/networks labelled with this run's cluster id, and the
# function container this run created.

set -u
cd "$(dirname "$0")"
NODES=1
BASE_PORT=${BASE_PORT:-47950}
. tests/cluster-lib.sh

NS=ci-auth
FN=ci-auth-fn-$RANDOM
PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi }
wait_for() { local end=$((SECONDS + $1)); shift; while [ $SECONDS -lt $end ]; do eval "$1" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

[ -x "$BIN" ] || cargo build --release
command -v kubectl >/dev/null || { echo "kubectl is required"; exit 1; }

cluster_init "$(mktemp -d "${TMPDIR:-/tmp}/royak-auth.XXXXXX")"
GET_TOKEN=$(rand_hex 24); EXEC_TOKEN=$(rand_hex 24)
printf '%s,gina,u3,"exec-getters"\n%s,eddie,u4,"exec-creators"\n' "$GET_TOKEN" "$EXEC_TOKEN" >> "$WORK/tokens.csv"
CLUSTER_ID=""
trap 'cluster_cleanup; docker rm -f "rk-fn-$FN" >/dev/null 2>&1; [ $FAIL -gt 0 ] && { echo "--- node log tail"; tail -30 "$WORK/n1/server.log"; }; rm -rf "$WORK"' EXIT

URL="https://127.0.0.1:$(cport 1)"
# raw METHOD PATH [TOKEN] — status code; the path is sent byte-for-byte.
raw() { curl -sk --path-as-is -m 20 -o "$WORK/body" -w '%{http_code}' -X "$1" ${3:+-H "Authorization: Bearer $3"} "$URL$2"; }
body() { cat "$WORK/body"; }
yaml() { cat > "$WORK/$1.yaml"; echo "$WORK/$1.yaml"; }
kc() { local tok=$1; shift; KUBECONFIG="$WORK/kubeconfig" kubectl --token="$tok" --request-timeout=20s "$@"; }

cat > "$WORK/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters: [{name: ci, cluster: {server: "$URL", insecure-skip-tls-verify: true}}]
contexts: [{name: ci, context: {cluster: ci, namespace: $NS}}]
current-context: ci
users: []
EOF

echo "Royak auth HTTP test (work dir $WORK)"
start_node 1 || exit 1
leader 40 >/dev/null || { fail "node did not become leader"; exit 1; }
docker pull -q alpine:3.22 >/dev/null 2>&1 || true

SECRET_VALUE="ci-$(rand_hex 12)"
F=$(yaml base <<YAML
apiVersion: v1
kind: Namespace
metadata: {name: $NS}
---
apiVersion: v1
kind: Secret
metadata: {name: s1, namespace: $NS}
stringData: {password: $SECRET_VALUE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ci-auth-viewers}
roleRef: {kind: ClusterRole, name: view}
subjects: [{kind: Group, name: viewers}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: exec-get, namespace: $NS}
rules: [{apiGroups: [""], resources: [pods, pods/exec], verbs: [get, list]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: exec-get, namespace: $NS}
roleRef: {kind: Role, name: exec-get}
subjects: [{kind: Group, name: exec-getters}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: exec-create, namespace: $NS}
rules:
- {apiGroups: [""], resources: [pods], verbs: [get, list]}
- {apiGroups: [""], resources: [pods/exec], verbs: [create]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: exec-create, namespace: $NS}
roleRef: {kind: Role, name: exec-create}
subjects: [{kind: Group, name: exec-creators}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: shell, namespace: $NS}
spec:
  template:
    spec:
      containers:
      - {name: main, image: "alpine:3.22", command: ["sleep", "100000"]}
YAML
)
OUT=$(api 1 POST /apis/apps/v1/namespaces/$NS/deployments "$F")
check "admin applies namespace, secret, RBAC and a deployment" "echo \"\$OUT\" | code_of | grep -Eq '20[01]'"
wait_for 60 "docker ps --filter label=royak.namespace=$NS --filter status=running -q | grep -q ."
POD=$(docker ps --filter "label=royak.namespace=$NS" --filter status=running --format '{{.Names}}' | head -1)
CLUSTER_ID=$(docker ps --filter "label=royak.namespace=$NS" --format '{{.Label "royak.cluster"}}' | head -1)
check "shell pod running" "[ -n '$POD' ]"

echo ""
echo "1. Malformed paths never bypass authorization"
check "viewer: list secrets → 403" "[ \$(raw GET /api/v1/namespaces/$NS/secrets $VIEW_TOKEN) = 403 ]"
check "viewer: get secret → 403" "[ \$(raw GET /api/v1/namespaces/$NS/secrets/s1 $VIEW_TOKEN) = 403 ]"
check "admin: get secret → 200 (the secret exists)" "[ \$(raw GET /api/v1/namespaces/$NS/secrets/s1 $ADMIN_TOKEN) = 200 ]"
B64=$(printf '%s' "$SECRET_VALUE" | base64)
for p in "/apis///secrets" "/api/v1/namespaces//secrets" "//api/v1/namespaces/$NS/secrets" \
         "/api/v1/namespaces/$NS//secrets/s1" "/api//v1/secrets" "/api/v1/namespaces/$NS/secrets//s1" \
         "/apis//v1/namespaces/$NS/secrets" "/api/v1/secrets/"; do
    C=$(raw GET "$p" "$VIEW_TOKEN")
    check "viewer GET $p → $C, not 200, no secret in the body" "[ '$C' != 200 ] && ! body | grep -q -e '$SECRET_VALUE' -e '$B64'"
    # Malformed paths are refused before authentication (400); well-formed
    # ones reach the gate (401). Either way: refused, nothing leaks.
    C=$(raw GET "$p")
    check "anonymous GET $p → $C (400/401), no secret in the body" "{ [ '$C' = 400 ] || [ '$C' = 401 ]; } && ! body | grep -q -e '$SECRET_VALUE' -e '$B64'"
done
C=$(raw DELETE "/api/v1/namespaces/$NS//secrets/s1" "$VIEW_TOKEN")
check "viewer DELETE with an empty segment → $C, secret still there" "[ '$C' != 200 ] && [ \$(raw GET /api/v1/namespaces/$NS/secrets/s1 $ADMIN_TOKEN) = 200 ]"

echo ""
echo "2. Function triggers cannot shadow other endpoints"
for t in /api/v1/namespaces/$NS/secrets /api /apis /apis/apps/v1 /healthz /readyz /version \
         /royak/v1/raft/status /royak/v1/heartbeat /hooks/repo/x /openapi/v2 /livez; do
    F=$(yaml fnbad <<YAML
apiVersion: royak/v1
kind: Function
metadata: {name: $FN-bad}
spec:
  image: alpine:3.22
  command: [echo, shadowed]
  trigger: [{http: "$t"}]
YAML
)
    OUT=$(api 1 POST /apis/apps/v1/namespaces/$NS/deployments "$F")
    check "trigger $t → rejected at apply" "echo \"\$OUT\" | code_of | grep -Evq '^20' && echo \"\$OUT\" | grep -q reserved"
done
F=$(yaml fn <<YAML
apiVersion: royak/v1
kind: Function
metadata: {name: $FN}
spec:
  image: alpine:3.22
  command: [echo, hello-from-$FN]
  trigger: [{http: /fn/$FN}, {webhook: /hooks/$FN}]
YAML
)
check "a normal trigger path is accepted" "api 1 POST /apis/apps/v1/namespaces/$NS/deployments $F | code_of | grep -Eq '20[01]'"
check "admin invokes the http trigger → function output" "[ \$(raw POST /fn/$FN $ADMIN_TOKEN) = 200 ] && body | grep -q hello-from-$FN"
check "admin invokes the webhook trigger → function output" "[ \$(raw POST /hooks/$FN $ADMIN_TOKEN) = 200 ] && body | grep -q hello-from-$FN"
check "viewer invoking the function → 403" "[ \$(raw POST /fn/$FN $VIEW_TOKEN) = 403 ]"
check "anonymous invoking the function → 401" "[ \$(raw POST /fn/$FN) = 401 ]"
check "/healthz still public and answered by the server" "[ \$(raw GET /healthz) = 200 ] && ! body | grep -q shadowed"
check "/version still public" "[ \$(raw GET /version) = 200 ] && body | grep -q gitVersion"

echo ""
echo "3. get on pods/exec does not grant exec"
check "exec-getter can get the pod" "[ \$(raw GET /api/v1/namespaces/$NS/pods/$POD $GET_TOKEN) = 200 ]"
check "exec-getter: POST pods/exec → 403" "[ \$(raw POST '/api/v1/namespaces/$NS/pods/$POD/exec?command=id&stdout=true' $GET_TOKEN) = 403 ]"
check "exec-getter: GET pods/exec → 403" "[ \$(raw GET '/api/v1/namespaces/$NS/pods/$POD/exec?command=id&stdout=true' $GET_TOKEN) = 403 ]"
check "exec-getter: kubectl exec is Forbidden" "! kc $GET_TOKEN exec $POD -- echo pwned 2>&1 | grep -q pwned && kc $GET_TOKEN exec $POD -- echo x 2>&1 | grep -qi forbidden"
check "exec-creator: kubectl exec works" "[ \"\$(kc $EXEC_TOKEN exec $POD -- echo exec-ok 2>/dev/null | tr -d '\r')\" = exec-ok ]"
check "viewer: kubectl exec is Forbidden" "kc $VIEW_TOKEN exec $POD -- echo x 2>&1 | grep -qi forbidden"

echo ""
echo "4. Discovery and kubectl workflows"
for p in /api /apis /api/v1 /apis/apps/v1 /version; do
    check "viewer GET $p → 200" "[ \$(raw GET $p $VIEW_TOKEN) = 200 ]"
done
check "kubectl api-resources" "kc $VIEW_TOKEN api-resources | grep -q deployments"
check "kubectl get namespaces" "kc $VIEW_TOKEN get namespaces | grep -q $NS"
check "kubectl get pods (viewer)" "kc $VIEW_TOKEN get pods | grep -q $POD"
check "kubectl get secrets (viewer) is Forbidden" "kc $VIEW_TOKEN get secrets 2>&1 | grep -qi forbidden"
cat > "$WORK/cm.yaml" <<YAML
apiVersion: v1
kind: ConfigMap
metadata: {name: kc-cm, namespace: $NS}
data: {k: v}
YAML
check "kubectl apply (admin)" "kc $ADMIN_TOKEN apply -f $WORK/cm.yaml | grep -q kc-cm"
check "kubectl get configmap (viewer) shows it" "kc $VIEW_TOKEN get configmap kc-cm -o jsonpath='{.data.k}' | grep -qx v"
check "kubectl apply (viewer) is Forbidden" "kc $VIEW_TOKEN apply -f $WORK/cm.yaml 2>&1 | grep -qi forbidden"
check "kubectl delete (admin)" "kc $ADMIN_TOKEN delete configmap kc-cm | grep -q deleted"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
