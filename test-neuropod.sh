#!/bin/bash
# Real Linux/root NeuroPod lifecycle; run ONLY through qualification/suites.py.
set -eu
cd "$(dirname "$0")"
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" != 0 ] || [ -z "${ROYAK_QUALIFICATION_NODE:-}" ]; then
    echo "NeuroPod qualification requires the owned Linux/root test node; no checks were skipped." >&2
    exit 2
fi
exec python3 -B tests/qualification/neuropod_runtime.py ./target/release/royak
