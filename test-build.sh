#!/bin/bash
# Verify the PaaS build pipeline: git context → image build → deploy → serve.
#
# This proves the "build stage" keystone that turns Royak from GitOps (deploy
# existing images) into a Coolify/Dokploy-style PaaS (build from source, then
# deploy) — end to end against a real Docker daemon:
#
#   register repo (with Dockerfile) → webhook → pipeline:
#     stage build  (action: build) → docker build via the Engine /build API
#     stage deploy (action: apply) → run the freshly built image
#   → the running container serves a UNIQUE marker baked in at build time,
#     which proves the deployed image is the one WE built from source.
#
# Needs Docker running. ~1-2 min (nginx:alpine pull on cold cache).
set -e
cd "$(dirname "$0")"
BIN="./target/release/royak"
[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; }
check() { if eval "$2" >/dev/null 2>&1; then pass "$1"; else fail "$1"; fi; }

echo "╔════════════════════════════════════════════╗"
echo "║  Royak Build Pipeline Test (PaaS keystone) ║"
echo "╚════════════════════════════════════════════╝"

WORK="$(mktemp -d)"
APP="$WORK/app"
MARK="royak-build-$$-$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')"
mkdir -p "$APP"
printf '<h1>%s</h1>\n' "$MARK" > "$APP/index.html"
cat > "$APP/Dockerfile" <<'DOCKER'
FROM nginx:alpine
COPY index.html /usr/share/nginx/html/index.html
DOCKER
( cd "$APP" && git init -q && git add -A && git -c user.email=a@b.c -c user.name=x commit -qm init )

cat > "$WORK/repo.yaml" <<YAML
apiVersion: royak/v1
kind: Repository
metadata: {name: bt}
spec: {path: $APP, branch: main, pipeline: btpipe}
YAML
cat > "$WORK/deploy.yaml" <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: {name: btweb}
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: web
          image: royak-bt:v1
          ports: [{containerPort: 80}]
YAML
cat > "$WORK/pipeline.yaml" <<YAML
apiVersion: royak/v1
kind: Pipeline
metadata: {name: btpipe}
spec:
  stages:
    - {name: build, action: build, context: bt, tag: royak-bt:v1}
    - {name: deploy, action: apply, file: $WORK/deploy.yaml, dependsOn: build}
YAML

cleanup() {
    kill -TERM "$WPID" 2>/dev/null || true
    docker ps -a --filter "name=rk-btweb" -q | xargs -r docker rm -f 2>/dev/null || true
    docker rmi -f royak-bt:v1 >/dev/null 2>&1 || true
    rm -f .royak-state.json .royak-state.json.nrns .royak-state.json.lock 2>/dev/null || true
    rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

docker ps -a --filter "name=rk-btweb" -q | xargs -r docker rm -f 2>/dev/null || true
docker rmi -f royak-bt:v1 >/dev/null 2>&1 || true
rm -f .royak-state.json .royak-state.json.nrns .royak-state.json.lock 2>/dev/null || true
lsof -ti:6443 2>/dev/null | xargs -r kill -9 2>/dev/null || true

echo ""
echo "1. Register repo + build pipeline"
echo "─────────────────────────────────"
# NB: capture apply output into a var, don't pipe to `grep -q` — grep -q exits
# on first match and SIGPIPEs `apply` before it persists state (the "registered"
# line prints before the save), which would silently lose the resource.
RO=$($BIN apply "$WORK/repo.yaml" 2>&1);      check "repository applies" "echo \"\$RO\" | grep -qi 'repository/bt'"
PO=$($BIN apply "$WORK/pipeline.yaml" 2>&1);  check "pipeline applies"   "echo \"\$PO\" | grep -qi 'btpipe'"

$BIN watch --interval 2 --ingress-port 0 > /tmp/rk-buildtest.log 2>&1 &
WPID=$!
# Wait for the API server to be ready before firing the webhook (avoids a
# race where the first request hits before the listener binds).
for _ in $(seq 1 30); do
    curl -s -o /dev/null http://127.0.0.1:6443/ 2>/dev/null && break
    sleep 1
done

echo ""
echo "2. Trigger build → deploy via webhook (single process)"
echo "──────────────────────────────────────────────────────"
WH=$(curl -s -X POST http://127.0.0.1:6443/hooks/repo/bt)
check "webhook accepts trigger" "echo \"\$WH\" | grep -q '\"status\":\"ok\"'"

# Poll for the true end state — the deployed container is up and serving — so the
# assertions never race the build/deploy (build time + local-image create vary by
# host; a fresh runner also pays a cold nginx:alpine pull). Up to ~150s.
CID=""
for _ in $(seq 1 75); do
    CID=$(docker ps --filter "name=rk-btweb" --filter "status=running" -q | head -1)
    [ -n "$CID" ] && docker exec "$CID" wget -qO- localhost 2>/dev/null | grep -q "$MARK" && break
    sleep 2
done

check "build stage produced the image" "docker images royak-bt:v1 --format '{{.ID}}' | grep -q ."
check "build stage logged success"      "grep -q \"built royak-bt:v1 ✓\" /tmp/rk-buildtest.log"
check "deploy stage ran"                "grep -q \"stage 'deploy'\" /tmp/rk-buildtest.log"
check "container is running our image"  "docker ps --filter name=rk-btweb --filter status=running -q | grep -q ."

echo ""
echo "3. Proof: the running app serves OUR built content"
echo "──────────────────────────────────────────────────"
CID=$(docker ps --filter "name=rk-btweb" -q | head -1)
check "deployed app serves the build-time marker ($MARK)" \
    "[ -n '$CID' ] && docker exec $CID wget -qO- localhost 2>/dev/null | grep -q '$MARK'"

echo ""
echo "════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed"
echo "════════════════════════════════════════"
[ "$FAIL" -eq 0 ] && echo "  ALL TESTS PASSED" || echo "  SOME TESTS FAILED"
exit "$FAIL"
