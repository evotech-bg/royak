#!/bin/bash
# Only run via the isolated qualification suite driver.
set -u
cd "$(dirname "$0")"
NODES=1
INTERVAL=1
BASE_PORT=${BASE_PORT:-48220}
. tests/cluster-lib.sh
cluster_init "$(mktemp -d "${TMPDIR:-/tmp}/royak-beta.XXXXXX")"
trap 'cluster_cleanup; rm -rf "$WORK"' EXIT
start_node 1 || exit 1
leader 40 >/dev/null || exit 1
python3 -B tests/qualification/beta_runtime.py "https://127.0.0.1:$(cport 1)"
