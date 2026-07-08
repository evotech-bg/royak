#!/bin/sh
# Inject the Royak API base so the live-stats page can reach the cluster.
# Default: same-origin (works when Royak's ingress proxies /royak and /demo to
# the API). Set ROYAK_API (e.g. https://demo.royak.io) to point elsewhere.
if [ -n "$ROYAK_API" ]; then
  sed -i "s#<head>#<head><script>window.ROYAK_API='${ROYAK_API}'</script>#" \
    /usr/share/nginx/html/index.html
fi
# Stamp THIS pod's identity into the page. Each replica bakes its own hostname,
# so a refresh visibly lands on a real, live pod — and across replicas, a
# different one (Royak's ingress round-robins). Proves it isn't a static file.
POD="${HOSTNAME:-unknown}"
sed -i "s/__POD__/${POD}/g" /usr/share/nginx/html/index.html
exec nginx -g 'daemon off;'
