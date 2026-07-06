#!/bin/bash
# Verify the cross-node mesh + ingress data path ON macOS.
#
# On macOS, Docker (Colima/Docker Desktop) runs containers inside a Linux VM,
# so the macOS host cannot reach container IPs (172.17.x.x). The mesh/ingress
# data path needs host-routable container IPs — i.e. Linux. This script closes
# that gap without a Linux box: it builds a native aarch64-linux royak inside
# an Alpine container, then runs the mesh/ingress suites INSIDE a container on
# the Docker bridge, where sibling container IPs ARE routable.
#
# Result: real end-to-end mesh/ingress verification on a Mac.
#
# Usage: ./test-mesh-macos.sh   (needs Docker running; ~6 min for the first build)
set -e
cd "$(dirname "$0")"

echo "▶ Building native Linux royak (musl static) inside Alpine…"
docker run --rm -v "$PWD":/build -w /build -e CARGO_HOME=/build/.cargo-docker \
  rust:1-alpine sh -c 'apk add --no-cache musl-dev >/dev/null && cargo build --release --target-dir /build/target-linux' \
  2>&1 | tail -1

echo "▶ Staging binary + tests (under the Colima-mounted project dir)…"
rm -rf _linuxtest && mkdir -p _linuxtest/target/release
cp target-linux/release/royak _linuxtest/target/release/royak
cp test-mesh.sh test-ingress.sh _linuxtest/
cp -r examples _linuxtest/

echo "▶ Running mesh + ingress inside a Linux container (IPs routable there)…"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD/_linuxtest":/work -w /work --network bridge \
  alpine:3.21 sh -c '
    apk add --no-cache docker-cli curl bash lsof >/dev/null 2>&1
    echo "── MESH ──";            bash test-mesh.sh    2>&1 | grep -E "Results|ALL TESTS|✗"
    echo "── INGRESS ──";         bash test-ingress.sh 2>&1 | grep -E "Results|ALL TESTS|✗"
    export ROYAK_CLUSTER_SECRET=test-secret
    echo "── ENCRYPTED MESH ──";  bash test-mesh.sh    2>&1 | grep -E "Results|ALL TESTS|✗"
  ' 2>&1 | grep -vE "WARNING: The requested|Emulate"

rm -rf _linuxtest
echo "▶ Done."
