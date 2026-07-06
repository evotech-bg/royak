# Royak live demo — `demo.royak.io`

A self-contained page that shows **this Royak cluster's real, live state** and lets
visitors break it — kill a pod, scale the demo app — and watch Royak self-heal.
It's meant to run *on* Royak (deployed by the `build` pipeline, served by Royak's
ingress), so the demo is also proof the platform works.

## What it shows

- Live cluster stats (pods, deployments, nodes, services, mTLS certs, reconcile ticks)
  polled from `/royak/v1/brain`, `/top/pods`, `/top/nodes`, `/flows` every 2s.
- Timelines: pods over time, neural-brain training loss; per-pod CPU/memory bars.
- **Interactive controls** (sandboxed): `Scale ▲▼`, `💥 Kill a pod`, optional auto-chaos.
- **Resilience panel**: disruptions, recoveries, average/last recovery time, "stable for…"
  — so you can watch stability across restarts.

## The sandbox (safety)

Interactivity is served by a tiny, opt-in endpoint in Royak, enabled only with
`ROYAK_DEMO=1`. It exposes **only**:

- `GET  /demo/info`  — demo app name + current replicas
- `POST /demo/scale?n=N` — clamp to `1..5` on the demo deployment only
- `POST /demo/kill` — remove one running pod of the demo deployment only

Rate-limited, no token, and it touches **nothing else** in the cluster. Without
`ROYAK_DEMO=1` every `/demo/*` route returns 404 (fail-safe closed). Read-only stats
endpoints send `Access-Control-Allow-Origin: *`; mutations still require the
`X-Royak-Token` (which CORS never bypasses).

## Deploy (when the VPS is ready)

On a small Linux VPS with Docker + the `royak` binary:

```bash
# 1. run Royak with the demo sandbox on, and an ingress on :80
ROYAK_DEMO=1 ROYAK_DEMO_APP=demo royak watch --ingress-port 80 &

# 2. the demo app whose pods visitors will kill/scale
cat <<'YAML' | royak apply -
apiVersion: apps/v1
kind: Deployment
metadata: {name: demo}
spec: {replicas: 3, template: {spec: {containers: [{name: c, image: nginx:alpine}]}}}
YAML

# 3. build + deploy THIS page via Royak's own build pipeline (dogfood)
cat <<'YAML' | royak apply -
apiVersion: royak/v1
kind: Repository
metadata: {name: demosite}
spec: {url: https://github.com/evotech-bg/royak, branch: main, pipeline: demosite}
---
apiVersion: royak/v1
kind: Pipeline
metadata: {name: demosite}
spec:
  stages:
    - {name: build,  action: build, context: demosite, dockerfile: demo-site/Dockerfile, tag: royak-demosite:v1}
    - {name: deploy, action: apply, file: demo-site/deploy.yaml, dependsOn: build}
YAML
```

`demo-site/Dockerfile` serves `index.html`; set `ROYAK_API` on the container if the
page and the API are not same-origin.

### systemd unit (auto-restart)
`/etc/systemd/system/royak.service`:

```ini
[Unit]
Description=Royak (demo)
After=docker.service
Requires=docker.service

[Service]
Environment=ROYAK_DEMO=1
Environment=ROYAK_DEMO_APP=demo
ExecStart=/usr/local/bin/royak watch --ingress-port 80
Restart=always
RestartSec=3
WorkingDirectory=/opt/royak

[Install]
WantedBy=multi-user.target
```
`systemctl enable --now royak` — it survives reboots and restarts on crash.

### TLS / routing (Cloudflare)
A record `demo.royak.io` → VPS IP, **proxied** (orange cloud). Browser↔Cloudflare TLS
works immediately (Flexible SSL) — fine for a demo. For end-to-end encryption add a
free **Cloudflare Origin Certificate** on the VPS later (Full SSL). This keeps Royak's
beta ACME out of the path entirely.

For the live stats/controls the page must reach the API. Simplest: set `ROYAK_API` on
the demo-site container to `https://demo.royak.io` and route `/royak/*` + `/demo/*`
through the same host, **or** serve them same-origin via ingress.

> Beta, unattended, public: keep only throwaway demo containers here, run Royak under
> systemd with auto-restart, and never put anything sensitive on this box.
