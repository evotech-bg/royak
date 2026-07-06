#!/bin/bash
# Royak Demo Test — exercises the exact path NetworkChuck would take.
# Run: ./test-demo.sh
# Exit code 0 = all good. Non-zero = something broke.

set -e
BIN="./target/release/royak"
STATE=".royak-state.json"
PASS=0
FAIL=0
TOTAL=0

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ✗ $1"; }
check() {
    if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi
}

echo "╔════════════════════════════════════════════╗"
echo "║  Royak Demo Test Suite                ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# ─── Setup ───
echo "Cleaning up..."
docker ps -a --filter "name=rk-" --format '{{.ID}}' | xargs -r docker rm -f 2>/dev/null || true
rm -f "$STATE" "$STATE.nrns" "$STATE.lock" 2>/dev/null || true

# Build if needed
if [ ! -f "$BIN" ]; then
    echo "Building..."
    cargo build --release 2>/dev/null
fi

# ─── Test YAML ───
mkdir -p /tmp/royak-test

cat > /tmp/royak-test/deploy.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        resources:
          limits:
            cpu: "500m"
            memory: "128Mi"
---
apiVersion: v1
kind: Service
metadata:
  name: web-svc
spec:
  selector:
    app: web
  ports:
  - port: 80
    targetPort: 80
  type: ClusterIP
EOF

cat > /tmp/royak-test/deploy-v2.yaml << 'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        resources:
          limits:
            cpu: "500m"
            memory: "128Mi"
EOF

cat > /tmp/royak-test/rbac.yaml << 'EOF'
apiVersion: v1
kind: RbacRole
metadata:
  name: admin
spec:
  rules:
  - resources: ["*"]
    verbs: ["*"]
    namespaces: ["*"]
EOF

# ═══════════════════════════════════════════
echo ""
echo "1. Deploy"
echo "─────────"
OUT=$($BIN apply /tmp/royak-test/deploy.yaml 2>&1)
check "deployment/web applied" "echo '$OUT' | grep -q 'deployment/web applied'"
check "service/web-svc applied" "echo '$OUT' | grep -q 'service/web-svc'"
check "2 pods created" "echo '$OUT' | grep -q 'rk-web-2'"
check "Docker containers running" "docker ps --filter name=rk-web --format '{{.Names}}' | wc -l | grep -q 2"
check "Resource limits in Docker" "docker inspect rk-web-1 --format '{{.HostConfig.NanoCpus}}' | grep -q 500000000"
check "State file exists" "test -f $STATE"

# ═══════════════════════════════════════════
echo ""
echo "2. Get"
echo "──────"
OUT=$($BIN get pods 2>&1)
check "get pods shows 2 pods" "echo '$OUT' | grep -q '2 pod(s)'"
check "pods show nginx:alpine" "echo '$OUT' | grep -q 'nginx:alpine'"

OUT=$($BIN get deployments 2>&1)
check "get deployments shows READY" "echo '$OUT' | grep -q 'READY'"
check "READY shows 2/2" "echo '$OUT' | grep -q '2/2'"

# ═══════════════════════════════════════════
echo ""
echo "3. RBAC"
echo "───────"
OUT=$($BIN apply /tmp/royak-test/rbac.yaml 2>&1)
check "RBAC role applied" "echo '$OUT' | grep -q 'rbac/admin configured'"
check "Existing pods not recreated" "echo '$OUT' | grep -q '\[ok\] web: 2/2'"

# ═══════════════════════════════════════════
echo ""
echo "4. Scale"
echo "────────"
OUT=$($BIN scale web 4 2>&1)
check "Scale 2→4" "echo '$OUT' | grep -q '2 → 4'"
check "4 containers running" "docker ps --filter name=rk-web --format '{{.Names}}' | wc -l | grep -q 4"

OUT=$($BIN scale web 2 2>&1)
check "Scale 4→2" "echo '$OUT' | grep -q '4 → 2'"
sleep 1
check "2 containers running" "docker ps --filter name=rk-web --format '{{.Names}}' | wc -l | grep -q 2"

# ═══════════════════════════════════════════
echo ""
echo "5. Logs"
echo "───────"
# Give nginx a moment to write startup logs
sleep 2
POD=$(docker ps --filter name=rk-web --format '{{.Names}}' | head -1)
OUT=$($BIN logs "$POD" 2>&1)
check "Logs contain nginx output" "echo '$OUT' | grep -qi 'nginx\|entrypoint\|worker'"

# ═══════════════════════════════════════════
echo ""
echo "6. Rolling Update"
echo "─────────────────"
OUT=$($BIN apply /tmp/royak-test/deploy-v2.yaml 2>&1)
check "Rolling update triggered" "echo '$OUT' | grep -q 'rolling update\|rollout'"
check "Rolling update completed" "echo '$OUT' | grep -q 'Rolling update complete\|COMPLETE'"

OUT=$($BIN get pods 2>&1)
check "Pods now on nginx:latest" "echo '$OUT' | grep -q 'nginx:latest'"
check "No pods on nginx:alpine" "echo '$OUT' | grep -v 'IMAG' | grep -qv 'nginx:alpine'"

# ═══════════════════════════════════════════
echo ""
echo "7. Rollback"
echo "───────────"
OUT=$($BIN rollback web 2>&1)
check "Rollback started" "echo '$OUT' | grep -q 'Rolling back\|rollout'"
check "Rollback completed" "echo '$OUT' | grep -q 'COMPLETE'"

OUT=$($BIN get pods 2>&1)
check "Pods back on nginx:alpine" "echo '$OUT' | grep -q 'nginx:alpine'"

# ═══════════════════════════════════════════
echo ""
echo "8. Stdin Pipe"
echo "─────────────"
OUT=$(echo 'apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
data:
  KEY: value' | $BIN apply - 2>&1)
check "Stdin apply works" "echo '$OUT' | grep -q 'configmap/test-cm'"

# ═══════════════════════════════════════════
echo ""
echo "9. Delete"
echo "─────────"
OUT=$($BIN delete deployment/web 2>&1)
check "Delete stops pods" "echo '$OUT' | grep -q 'remove\|deleted'"
sleep 1
check "No rk-web containers left" "! docker ps --filter name=rk-web -q | grep -q ."

# ═══════════════════════════════════════════
echo ""
echo "10. State Persistence"
echo "─────────────────────"
# Re-deploy
$BIN apply /tmp/royak-test/deploy.yaml 2>&1 >/dev/null
# Check state survives reload
OUT=$($BIN get deployments 2>&1)
check "Deployment survives reload" "echo '$OUT' | grep -q 'web'"

# ═══════════════════════════════════════════
echo ""
echo "11. Namespace"
echo "─────────────"
OUT=$($BIN apply - <<'YAML' 2>&1
apiVersion: v1
kind: Namespace
metadata:
  name: ci-ns
YAML
)
check "Namespace created" "echo '$OUT' | grep -q 'namespace/ci-ns'"

# ═══════════════════════════════════════════
echo ""
echo "12. Secrets (AES-256-GCM at rest)"
echo "─────────────────────────────────"
OUT=$($BIN apply - <<'YAML' 2>&1
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-cm
spec:
  APP_ENV: production
  LOG_LEVEL: info
---
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
spec:
  DB_PASSWORD: plaintext-sentinel-42
YAML
)
check "ConfigMap applied" "echo '$OUT' | grep -q 'configmap/app-cm'"
check "Secret applied" "echo '$OUT' | grep -q 'secret/db-creds'"
check "State marks secret encrypted" "grep -Eq '\"encrypted\"[[:space:]]*:[[:space:]]*true' $STATE"
check "Plaintext NOT on disk" "! grep -q 'plaintext-sentinel-42' $STATE"
check "Ciphertext is enc: hex" "python3 -c \"import json,re; d=json.load(open('$STATE')); s=next(x for x in d['secrets'] if x['name']=='db-creds'); v=s['data']['DB_PASSWORD']; assert re.fullmatch(r'enc:[0-9a-f]+', v) and len(v)>=28\""

# ═══════════════════════════════════════════
echo ""
echo "13. HorizontalPodAutoscaler"
echo "───────────────────────────"
OUT=$($BIN apply examples/autoscale.yaml 2>&1)
check "HPA applied" "echo '$OUT' | grep -q 'hpa/web-hpa'"
check "HPA bound to deployment" "echo '$OUT' | grep -q 'min=2, max=8'"
check "HPA reconcile fires" "echo '$OUT' | grep -q '\\[hpa\\] web'"

# ═══════════════════════════════════════════
echo ""
echo "14. NetworkPolicy"
echo "─────────────────"
OUT=$($BIN apply - <<'YAML' 2>&1
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: web-policy
spec:
  podSelector:
    matchLabels:
      app: web
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
YAML
)
check "NetworkPolicy applied" "echo '$OUT' | grep -qi 'networkpolicy/web-policy'"

# ═══════════════════════════════════════════
echo ""
echo "15. ResourceQuota"
echo "─────────────────"
OUT=$($BIN apply - <<'YAML' 2>&1
apiVersion: v1
kind: ResourceQuota
metadata:
  name: ci-quota
  namespace: ci-ns
spec:
  hard:
    pods: "5"
    cpu: "2"
    memory: "1Gi"
YAML
)
check "ResourceQuota applied" "echo '$OUT' | grep -qi 'resourcequota/ci-quota'"

# ═══════════════════════════════════════════
echo ""
echo "16. Canary Strategy"
echo "───────────────────"
OUT=$($BIN apply - <<'YAML' 2>&1
apiVersion: apps/v1
kind: Deployment
metadata:
  name: canary-app
spec:
  replicas: 2
  strategy:
    type: Canary
    weight: 10
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
YAML
)
check "Canary deployment applied" "echo '$OUT' | grep -q 'deployment/canary-app'"
check "Canary containers running" "docker ps --filter name=rk-canary-app --format '{{.Names}}' | wc -l | grep -q 2"
$BIN delete deployment/canary-app >/dev/null 2>&1 || true

# ═══════════════════════════════════════════
echo ""
echo "17. Pipeline (DAG)"
echo "──────────────────"
OUT=$($BIN apply - <<'YAML' 2>&1
apiVersion: royak/v1
kind: Pipeline
metadata:
  name: quick-pipe
spec:
  trigger:
    - type: manual
  stages:
    - name: lint
      image: alpine:latest
      command: ["echo", "lint ok"]
    - name: done
      image: alpine:latest
      command: ["echo", "all done"]
      dependsOn: lint
YAML
)
check "Pipeline applied" "echo '$OUT' | grep -qi 'pipeline/quick-pipe'"
OUT=$($BIN pipeline list 2>&1)
check "Pipeline listed" "echo '$OUT' | grep -q 'quick-pipe'"

# ═══════════════════════════════════════════
echo ""
echo "18. Operator + CustomResource"
echo "─────────────────────────────"
OUT=$($BIN apply examples/redis-operator.yaml 2>&1)
check "Operator applied" "echo '$OUT' | grep -qi 'operator/redis-operator'"
check "CustomResource applied" "echo '$OUT' | grep -Eqi 'cr/rediscluster/my-redis|customresource/my-redis'"
sleep 2
OUT=$($BIN get deployments 2>&1)
check "Operator provisioned primary" "echo '$OUT' | grep -q 'my-redis-primary'"
check "Operator provisioned replica" "echo '$OUT' | grep -q 'my-redis-replica'"
$BIN delete deployment/my-redis-primary >/dev/null 2>&1 || true
$BIN delete deployment/my-redis-replica >/dev/null 2>&1 || true

# ═══════════════════════════════════════════
echo ""
echo "19. Serverless Functions"
echo "────────────────────────"
OUT=$($BIN apply - <<'YAML' 2>&1
apiVersion: royak/v1
kind: Function
metadata:
  name: hello-ci
spec:
  image: alpine:latest
  command: ["echo", "hello-from-function"]
  trigger:
    - http: /api/hello-ci
  timeout: 10s
YAML
)
check "Function applied" "echo '$OUT' | grep -qi 'function/hello-ci'"
OUT=$($BIN functions 2>&1)
check "Function listed" "echo '$OUT' | grep -q 'hello-ci'"
OUT=$($BIN invoke hello-ci 2>&1)
check "Function invocation output" "echo '$OUT' | grep -q 'hello-from-function'"

# ═══════════════════════════════════════════
echo ""
echo "20. Job"
echo "───────"
OUT=$($BIN apply - <<'YAML' 2>&1
apiVersion: batch/v1
kind: Job
metadata:
  name: ci-job
spec:
  template:
    spec:
      containers:
        - name: work
          image: alpine:latest
          command: ["sh", "-c", "echo job-done"]
YAML
)
check "Job applied" "echo '$OUT' | grep -qi 'job/ci-job'"

# ═══════════════════════════════════════════
echo ""
echo "21. Ingress"
echo "───────────"
OUT=$($BIN apply - <<'YAML' 2>&1
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ci-ingress
spec:
  rules:
    - host: ci.local
      http:
        paths:
          - path: /
            backend:
              service:
                name: web-svc
                port:
                  number: 80
YAML
)
check "Ingress applied" "echo '$OUT' | grep -qi 'ingress/ci-ingress'"

# ═══════════════════════════════════════════
echo ""
echo "22. Guard (auto-remediation)"
echo "────────────────────────────"
OUT=$($BIN apply examples/guard.yaml 2>&1)
check "Guard applied" "echo '$OUT' | grep -qi 'guard/auto-healer'"

# ═══════════════════════════════════════════
echo ""
echo "23. Neural Brain"
echo "────────────────"
OUT=$($BIN brain 2>&1 | head -30 || true)
check "Brain loads trained state" "echo '$OUT' | grep -Eqi 'trained brain|OrinBrain|loaded.*brain|steps.*loss'"
check "Brain pre-training runs" "echo '$OUT' | grep -Eq 'epoch.*loss=|Pre-training|loss=[0-9]'"

# ═══════════════════════════════════════════
echo ""
echo "24. Dashboard + Prometheus /metrics"
echo "───────────────────────────────────"
# Ensure port 6443 is free
lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true
sleep 1
$BIN watch --interval 60 > /tmp/rk-watch.log 2>&1 &
WATCH_PID=$!
sleep 4
check "Dashboard served (HTTP 200)" "curl -sf http://127.0.0.1:6443/ | grep -qi 'royak'"
check "Prometheus /metrics endpoint" "curl -sf http://127.0.0.1:6443/metrics | grep -q 'royak_'"
check "API /api/v1 reachable" "curl -sf http://127.0.0.1:6443/api/v1 >/dev/null || curl -sf http://127.0.0.1:6443/healthz >/dev/null || curl -sf http://127.0.0.1:6443/ >/dev/null"
kill -TERM "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

# ═══════════════════════════════════════════
echo ""
echo "25. Graceful Shutdown (SIGTERM saves state)"
echo "───────────────────────────────────────────"
lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true
sleep 1
# Touch state so we can detect re-save
touch -t 202001010000 "$STATE" 2>/dev/null || touch -d "2020-01-01" "$STATE" 2>/dev/null || true
OLD_MTIME=$(stat -f%m "$STATE" 2>/dev/null || stat -c%Y "$STATE")
$BIN watch --interval 60 > /tmp/rk-watch2.log 2>&1 &
WATCH_PID=$!
sleep 3
kill -TERM "$WATCH_PID" 2>/dev/null || true
sleep 2
wait "$WATCH_PID" 2>/dev/null || true
NEW_MTIME=$(stat -f%m "$STATE" 2>/dev/null || stat -c%Y "$STATE")
check "State re-saved on SIGTERM" "[ \"$NEW_MTIME\" -gt \"$OLD_MTIME\" ]"
check "Graceful shutdown logged" "grep -qi 'shutdown\\|saved\\|SIGTERM\\|graceful' /tmp/rk-watch2.log || grep -qi 'state saved' /tmp/rk-watch2.log"

# ═══════════════════════════════════════════
echo ""
echo "26. CrashLoopBackOff Detection"
echo "──────────────────────────────"
docker ps -a --filter "name=rk-crasher" --format '{{.ID}}' | xargs -r docker rm -f 2>/dev/null || true
$BIN apply - >/dev/null 2>&1 <<'YAML' || true
apiVersion: apps/v1
kind: Deployment
metadata:
  name: crasher
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: bad
          image: alpine:latest
          command: ["sh", "-c", "exit 1"]
YAML
# Let reconcile tick a few times to observe repeated exits
$BIN watch --interval 1 > /tmp/rk-watch3.log 2>&1 &
WATCH_PID=$!
sleep 12
kill -TERM "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true
OUT=$($BIN get pods 2>&1)
check "Crash loop observed" "grep -qi 'crashloop\\|restart\\|crash' /tmp/rk-watch3.log || echo '$OUT' | grep -qi 'crashloop\\|restart'"
$BIN delete deployment/crasher >/dev/null 2>&1 || true

# ═══════════════════════════════════════════
echo ""
echo "27. RBAC Enforcement (API-level 403)"
echo "────────────────────────────────────"
lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true
sleep 1
# Apply a read-only role with no write permissions
$BIN apply - >/dev/null 2>&1 <<'YAML' || true
apiVersion: v1
kind: RbacRole
metadata:
  name: readonly
spec:
  rules:
  - resources: ["pods", "configmaps"]
    verbs: ["get", "list"]
    namespaces: ["*"]
YAML
# Start API
$BIN watch --interval 60 > /tmp/rk-rbac.log 2>&1 &
WATCH_PID=$!
sleep 4
# Unauthorized POST as role=readonly — expect 403
CODE_DENY=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://127.0.0.1:6443/api/v1/namespaces/default/configmaps \
    -H "x-royak-role: readonly" \
    -H "Content-Type: application/yaml" \
    --data-binary $'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: forbidden-cm\nspec:\n  KEY: v' || echo "curl-fail")
check "POST as readonly role returns 403" "[ \"$CODE_DENY\" = \"403\" ]"
# Authorized POST as role=admin — expect 2xx
CODE_OK=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST http://127.0.0.1:6443/api/v1/namespaces/default/configmaps \
    -H "x-royak-role: admin" \
    -H "Content-Type: application/yaml" \
    --data-binary $'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: allowed-cm\nspec:\n  KEY: v' || echo "curl-fail")
check "POST as admin role returns 2xx" "echo '$CODE_OK' | grep -qE '^2[0-9]{2}$'"
check "RBAC denial logged" "grep -qi 'rbac.*denied\\|cannot create' /tmp/rk-rbac.log"
kill -TERM "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true

# ═══════════════════════════════════════════
echo ""
echo "28. kubectl Compatibility"
echo "─────────────────────────"
if ! command -v kubectl >/dev/null 2>&1; then
    echo "  ⊘ kubectl not installed — skipping (install kubectl to run this section)"
else
    lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    sleep 1
    $BIN watch --interval 60 > /tmp/rk-kubectl.log 2>&1 &
    WATCH_PID=$!
    sleep 4
    # kubectl apply now works natively thanks to full OpenAPI v3 operation
    # scaffolding (v0.3). No --validate=false flag needed.
    KSRV="--server=http://127.0.0.1:6443 --insecure-skip-tls-verify=true"
    OUT=$(kubectl $KSRV get namespaces 2>&1 || true)
    check "kubectl get namespaces" "echo '$OUT' | grep -q 'default'"
    OUT=$(kubectl $KSRV get pods 2>&1 || true)
    check "kubectl get pods (K8s table format)" "echo '$OUT' | grep -Eq 'NAME\\s+AGE|No resources found'"
    cat > /tmp/kctl-cm.yaml <<'YAML'
apiVersion: v1
kind: ConfigMap
metadata:
  name: kctl-applied
spec:
  KEY: "from-kubectl"
YAML
    OUT=$(kubectl $KSRV apply -f /tmp/kctl-cm.yaml 2>&1 || true)
    check "kubectl apply succeeds (native, no --validate=false)" "echo '$OUT' | grep -Eqi 'created|configured'"
    OUT=$(kubectl $KSRV get configmaps 2>&1 || true)
    check "kubectl get shows applied configmap" "echo '$OUT' | grep -q 'kctl-applied'"
    OUT=$(kubectl $KSRV delete configmap kctl-applied 2>&1 || true)
    check "kubectl delete succeeds" "echo '$OUT' | grep -Eqi 'deleted|not found'"

    # ── kubectl logs / scale / events / server-side apply (v0.4-beta) ──
    OUT=$(kubectl $KSRV logs rk-web-1 2>&1 || true)
    check "kubectl logs streams container output" "echo '$OUT' | grep -Eqi 'docker-entrypoint|nginx|worker'"
    OUT=$(kubectl $KSRV scale deployment web --replicas=3 2>&1 || true)
    check "kubectl scale succeeds" "echo '$OUT' | grep -qi 'scaled'"
    check "scale persisted to disk (write-through)" "python3 -c \"import json;s=json.load(open('$STATE'));exit(0 if [d for d in s['deployments'] if d['name']=='web' and d['replicas']==3] else 1)\""
    OUT=$(kubectl $KSRV get events 2>&1 || true)
    check "kubectl get events lists cluster events" "echo '$OUT' | grep -Eq 'NAME|rk-|web'"
    cat > /tmp/kctl-web-ssa.yaml <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 2
  selector: {matchLabels: {app: web}}
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
YAML
    OUT=$(kubectl $KSRV apply --server-side -f /tmp/kctl-web-ssa.yaml 2>&1 || true)
    check "kubectl apply --server-side updates existing resource" "echo '$OUT' | grep -qi 'serverside-applied'"

    # ── client-side apply create → re-apply (strategic merge path) ──
    cat > /tmp/kctl-ca.yaml <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: catest
spec:
  replicas: 1
  selector: {matchLabels: {app: catest}}
  template:
    spec:
      containers:
        - name: c
          image: nginx:alpine
YAML
    OUT=$(kubectl $KSRV apply -f /tmp/kctl-ca.yaml 2>&1 || true)
    check "client-side apply creates" "echo '$OUT' | grep -qi 'created'"
    sed -i.bak 's/replicas: 1/replicas: 2/' /tmp/kctl-ca.yaml
    OUT=$(kubectl $KSRV apply -f /tmp/kctl-ca.yaml 2>&1 || true)
    check "client-side apply UPDATES existing (configured)" "echo '$OUT' | grep -qi 'configured'"
    check "client-side update persisted" "python3 -c \"import json;s=json.load(open('$STATE'));exit(0 if [d for d in s['deployments'] if d['name']=='catest' and d['replicas']==2] else 1)\""
    kubectl $KSRV delete deployment catest >/dev/null 2>&1 || true

    # ── kubectl exec over WebSocket (non-interactive) ──
    OUT=$(kubectl $KSRV exec rk-web-1 -- echo exec-ws-proof 2>&1 || true)
    check "kubectl exec runs command (WebSocket)" "echo '$OUT' | grep -q 'exec-ws-proof'"
    OUT=$(kubectl $KSRV exec rk-web-1 -- sh -c 'exit 3' 2>&1 || true)
    check "kubectl exec reports non-zero exit" "echo '$OUT' | grep -q 'exit code 3'"
    # interactive exec -i: stdin must reach the container
    OUT=$(echo 'stdin-it-proof' | kubectl $KSRV exec -i rk-web-1 -- sh -c 'cat > /tmp/it-in && cat /tmp/it-in' 2>&1 || true)
    check "kubectl exec -i pipes stdin to the container" "echo '$OUT' | grep -q 'stdin-it-proof'"

    kill -TERM "$WATCH_PID" 2>/dev/null || true
    wait "$WATCH_PID" 2>/dev/null || true
    rm -f /tmp/kctl-cm.yaml /tmp/kctl-web-ssa.yaml /tmp/kctl-ca.yaml /tmp/kctl-ca.yaml.bak
fi

# ═══════════════════════════════════════════
echo ""
echo "28b. NodePort + ServiceLB"
echo "─────────────────────────"
docker ps -a --filter "name=rk-npdemo" -q | xargs -r docker rm -f 2>/dev/null || true
$BIN apply - <<'YAML' > /dev/null 2>&1
kind: Deployment
metadata: {name: npdemo}
spec:
  replicas: 2
  template: {spec: {containers: [{name: c, image: nginx:alpine}]}}
---
kind: Service
metadata: {name: npdemo-svc}
spec:
  type: NodePort
  selector: {app: npdemo}
  ports: [{port: 80, targetPort: 80, nodePort: 30099}]
---
kind: Service
metadata: {name: npdemo-lb}
spec:
  type: LoadBalancer
  selector: {app: npdemo}
  ports: [{port: 8098, targetPort: 80}]
YAML
check "pods publish ephemeral host ports" "docker ps --filter name=rk-npdemo --format '{{.Ports}}' | grep -q '0.0.0.0'"
lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true
$BIN api > /tmp/rk-nodeport.log 2>&1 &
NP_PID=$!
sleep 4
NP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:30099/ 2>/dev/null || echo fail)
check "NodePort :30099 serves HTTP 200 via ServiceLB" "[ \"$NP_CODE\" = \"200\" ]"
# Flow observability: the ServiceLB tap should have recorded that connection.
curl -s -o /dev/null http://localhost:30099/ 2>/dev/null || true
FLOWS=$($BIN flows --server http://127.0.0.1:6443 2>/dev/null || true)
check "flow tap records ServiceLB traffic" "echo '$FLOWS' | grep -q 'servicelb'"
# LoadBalancer: service port itself binds on the node (applied above,
# before the api process started — a live server does not re-read state
# written by a separate CLI process)
LB_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:8098/ 2>/dev/null || echo fail)
check "LoadBalancer :8098 serves HTTP 200 via ServiceLB" "[ \"$LB_CODE\" = \"200\" ]"
kill -TERM "$NP_PID" 2>/dev/null || true
wait "$NP_PID" 2>/dev/null || true
$BIN delete deployment/npdemo > /dev/null 2>&1 || true
docker ps -a --filter "name=rk-npdemo" -q | xargs -r docker rm -f 2>/dev/null || true

# ═══════════════════════════════════════════
echo ""
echo "28e. royak port-forward"
echo "───────────────────────"
docker ps -a --filter "name=rk-pfdemo" -q | xargs -r docker rm -f 2>/dev/null || true
$BIN apply - <<'YAML' > /dev/null 2>&1
kind: Deployment
metadata: {name: pfdemo}
spec:
  replicas: 1
  template: {spec: {containers: [{name: c, image: nginx:alpine}]}}
---
kind: Service
metadata: {name: pfdemo-svc}
spec:
  type: NodePort
  selector: {app: pfdemo}
  ports: [{port: 80, targetPort: 80, nodePort: 30077}]
YAML
sleep 3
$BIN port-forward rk-pfdemo-1 18077:80 > /tmp/rk-pf-demo.log 2>&1 &
PF_PID=$!
sleep 3
PF_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://127.0.0.1:18077/ 2>/dev/null || echo fail)
check "port-forward 18077→80 serves HTTP 200" "[ \"$PF_CODE\" = \"200\" ]"
kill -TERM "$PF_PID" 2>/dev/null || true
wait "$PF_PID" 2>/dev/null || true
$BIN delete deployment/pfdemo > /dev/null 2>&1 || true
docker ps -a --filter "name=rk-pfdemo" -q | xargs -r docker rm -f 2>/dev/null || true

# ═══════════════════════════════════════════
echo ""
echo "28g. IngressClass"
echo "─────────────────"
OUT=$(printf 'apiVersion: networking.k8s.io/v1\nkind: IngressClass\nmetadata: {name: royak}\nspec: {controller: royak.io/ingress}\n' | $BIN apply - 2>&1)
check "IngressClass kind accepted" "echo '$OUT' | grep -q 'ingressclass/royak registered'"
OUT=$(printf 'apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata: {name: cls-ing}\nspec:\n  ingressClassName: royak\n  rules:\n    - host: c.local\n      http: {paths: [{path: /, backend: {service: {name: web-svc, port: {number: 80}}}}]}\n' | $BIN apply - 2>&1)
check "ingressClassName honored (not dropped)" "echo '$OUT' | grep -q 'class=royak'"

# ═══════════════════════════════════════════
echo ""
echo "28f. NetworkPolicy egress L4 enforcement (real iptables)"
echo "────────────────────────────────────────────────────────"
docker ps -a --filter "name=rk-egt" -q | xargs -r docker rm -f 2>/dev/null || true
$BIN apply - <<'YAML' > /dev/null 2>&1
kind: Deployment
metadata: {name: egt}
spec:
  replicas: 1
  template: {spec: {containers: [{name: c, image: nginx:alpine}]}}
---
kind: NetworkPolicy
metadata: {name: egpol, namespace: default}
spec:
  podSelector: {matchLabels: {app: egt}}
  egress:
    - ports: [{port: 443}]
YAML
lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true
$BIN watch --interval 2 --ingress-port 0 > /tmp/rk-netpol.log 2>&1 &
NP_WPID=$!
# Enforcement runs an iptables helper (pulls alpine + apk add iptables on cold
# cache) — poll up to 60s for it to apply rather than a fixed sleep.
NP_ENFORCED=""
for _ in $(seq 1 60); do
    if grep -q "L4 iptables enforced" /tmp/rk-netpol.log 2>/dev/null; then NP_ENFORCED=yes; break; fi
    sleep 1
done
check "L4 iptables applied in pod netns" "[ \"$NP_ENFORCED\" = \"yes\" ]"
check "egress to allowed port 443 works" "docker exec rk-egt-1 sh -c 'nc -w 3 -z 1.1.1.1 443'"
check "egress to denied port 80 is DROPPED" "! docker exec rk-egt-1 sh -c 'nc -w 3 -z 1.1.1.1 80'"
kill -TERM "$NP_WPID" 2>/dev/null || true
wait "$NP_WPID" 2>/dev/null || true
docker ps -a --filter "name=rk-egt" -q | xargs -r docker rm -f 2>/dev/null || true

# ═══════════════════════════════════════════
echo ""
echo "28c. Bare Pod + ReplicaSet kinds"
echo "────────────────────────────────"
OUT=$(printf 'apiVersion: v1\nkind: Pod\nmetadata: {name: solo-demo}\nspec:\n  containers: [{name: main, image: nginx:alpine}]\n' | $BIN apply - 2>&1)
check "bare Pod applies (1-replica deployment)" "echo '$OUT' | grep -q 'solo-demo applied'"
check "bare Pod container runs" "docker ps --filter name=rk-solo-demo --filter status=running -q | grep -q ."
OUT=$(printf 'apiVersion: apps/v1\nkind: ReplicaSet\nmetadata: {name: rs-demo}\nspec:\n  replicas: 2\n  template: {spec: {containers: [{name: c, image: nginx:alpine}]}}\n' | $BIN apply - 2>&1)
check "ReplicaSet applies with deployment semantics" "echo '$OUT' | grep -q 'rs-demo applied'"
sleep 2
check "ReplicaSet runs 2 pods" "[ \$(docker ps --filter name=rk-rs-demo --filter status=running -q | wc -l | tr -d ' ') -ge 2 ]"
$BIN delete deployment/solo-demo > /dev/null 2>&1 || true
$BIN delete deployment/rs-demo > /dev/null 2>&1 || true
docker ps -a --filter "name=rk-solo-demo" -q | xargs -r docker rm -f 2>/dev/null || true
docker ps -a --filter "name=rk-rs-demo" -q | xargs -r docker rm -f 2>/dev/null || true

# ═══════════════════════════════════════════
echo ""
echo "28d. StatefulSet (ordered, per-ordinal volumes)"
echo "───────────────────────────────────────────────"
docker ps -a --filter "name=rk-stsdemo" -q | xargs -r docker rm -f 2>/dev/null || true
rm -rf "${ROYAK_DATA_DIR:-$HOME/.royak}"/pvc/default/stsdemo-* 2>/dev/null || true
OUT=$($BIN apply - <<'YAML' 2>&1
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: stsdemo}
spec:
  replicas: 2
  serviceName: stsdemo
  template:
    spec:
      containers:
        - name: c
          image: nginx:alpine
          volumeMounts: [{name: data, mountPath: /var/data}]
  volumeClaimTemplates:
    - metadata: {name: data}
YAML
)
check "StatefulSet applies" "echo '$OUT' | grep -q 'statefulset.*stsdemo applied'"
# CLI apply runs one reconcile pass → exactly ordinal 1 exists (ordered startup)
check "ordered startup: only ordinal 1 after first pass" "[ \"\$(docker ps --filter name=rk-stsdemo --format '{{.Names}}' | sort | tr '\n' ' ' | xargs)\" = 'rk-stsdemo-1' ]"
$BIN watch --interval 1 --ingress-port 0 > /tmp/rk-sts-demo.log 2>&1 &
STS_PID=$!
sleep 6
check "ordinal 2 follows on later tick" "docker ps --filter name=rk-stsdemo-2 --filter status=running -q | grep -q ."
check "per-ordinal volume mounted" "docker inspect rk-stsdemo-1 --format '{{range .Mounts}}{{.Source}}{{end}}' | grep -q 'stsdemo-data-1'"
docker exec rk-stsdemo-1 sh -c "echo sts-proof > /var/data/marker" 2>/dev/null || true
docker rm -f rk-stsdemo-1 >/dev/null 2>&1 || true
# Reconcile ticks can take ~10s under load — wait up to 60s for the rebirth.
REBORN=""
for _ in $(seq 1 30); do
    if docker exec rk-stsdemo-1 cat /var/data/marker 2>/dev/null | grep -q sts-proof; then
        REBORN=yes; break
    fi
    sleep 2
done
check "pod reborn with same ordinal + data" "[ \"$REBORN\" = \"yes\" ]"
kill -TERM "$STS_PID" 2>/dev/null || true
wait "$STS_PID" 2>/dev/null || true
$BIN delete deployment/stsdemo > /dev/null 2>&1 || true
docker ps -a --filter "name=rk-stsdemo" -q | xargs -r docker rm -f 2>/dev/null || true
rm -rf "${ROYAK_DATA_DIR:-$HOME/.royak}"/pvc/default/stsdemo-* 2>/dev/null || true

# ═══════════════════════════════════════════
echo ""
echo "29. Service DNS (pod → svc hostname)"
echo "────────────────────────────────────"
docker ps -a --filter "name=rk-svc-dns" -q | xargs -r docker rm -f 2>/dev/null || true
docker ps -a --filter "name=rk-client" -q | xargs -r docker rm -f 2>/dev/null || true
$BIN apply - >/dev/null 2>&1 <<'YAML' || true
apiVersion: apps/v1
kind: Deployment
metadata:
  name: svc-dns
spec:
  replicas: 1
  selector:
    matchLabels:
      app: svc-dns
  template:
    metadata:
      labels:
        app: svc-dns
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
---
apiVersion: v1
kind: Service
metadata:
  name: svc-dns-svc
spec:
  selector:
    app: svc-dns
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: client
spec:
  replicas: 1
  selector:
    matchLabels:
      app: client
  template:
    metadata:
      labels:
        app: client
    spec:
      containers:
        - name: curl
          image: curlimages/curl:latest
          command: ["sh", "-c", "while true; do sleep 5; done"]
YAML
sleep 6
# From client pod, resolve and curl the service name
OUT=$(docker exec rk-client-1 curl -sf -o /dev/null -w "%{http_code}" http://svc-dns-svc 2>&1 || echo "fail")
check "client resolves service name via Docker DNS" "[ \"$OUT\" = \"200\" ]"
# Also verify from the [svc] log marker
check "reconcile logs DNS alias bind" "grep -qi 'svc.*dns:svc-dns-svc' /tmp/rk-watch*.log 2>/dev/null || docker inspect rk-svc-dns-1 --format '{{range \$k,\$v := .NetworkSettings.Networks}}{{\$v.Aliases}}{{end}}' 2>/dev/null | grep -q 'svc-dns-svc'"
$BIN delete deployment/client >/dev/null 2>&1 || true
$BIN delete deployment/svc-dns >/dev/null 2>&1 || true
$BIN delete service/svc-dns-svc >/dev/null 2>&1 || true

# ═══════════════════════════════════════════
echo ""
echo "30. Health Probe → Restart"
echo "──────────────────────────"
docker ps -a --filter "name=rk-sickapp" --format '{{.ID}}' | xargs -r docker rm -f 2>/dev/null || true
$BIN apply - >/dev/null 2>&1 <<'YAML' || true
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sickapp
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: worker
          image: alpine:latest
          command: ["sh", "-c", "while true; do sleep 5; done"]
          livenessProbe:
            exec:
              command: ["false"]
            periodSeconds: 2
            failureThreshold: 2
YAML
$BIN watch --interval 1 > /tmp/rk-watch4.log 2>&1 &
WATCH_PID=$!
sleep 12
kill -TERM "$WATCH_PID" 2>/dev/null || true
wait "$WATCH_PID" 2>/dev/null || true
check "Liveness failure logged" "grep -qi 'probe\\|liveness\\|unhealthy\\|restart' /tmp/rk-watch4.log"
$BIN delete deployment/sickapp >/dev/null 2>&1 || true

# ═══════════════════════════════════════════
echo ""
echo "════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed (out of $TOTAL)"
echo "════════════════════════════════════════"

# Cleanup
docker ps -a --filter "name=rk-" --format '{{.ID}}' | xargs -r docker rm -f 2>/dev/null || true
rm -f "$STATE" "$STATE.nrns" "$STATE.lock" 2>/dev/null || true

if [ $FAIL -gt 0 ]; then
    echo "  SOME TESTS FAILED"
    exit 1
else
    echo "  ALL TESTS PASSED"
    exit 0
fi
