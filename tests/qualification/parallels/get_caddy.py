#!/usr/bin/env python3
"""Fetch a checksum-verified official Caddy binary into the owned lab only."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile
from bootstrap import run, save

VERSION = "2.11.7"
BASE = f"https://github.com/caddyserver/caddy/releases/download/v{VERSION}/"


def fetch(root):
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    archive = root / f"caddy_{VERSION}_mac_arm64.tar.gz"
    sums = root / f"caddy_{VERSION}_checksums.txt"
    for path in (sums, archive):
        if not path.exists():
            run("curl", "--fail", "--location", "--retry", "3", "--output", path, BASE + path.name, timeout=180)
    expected = next(line.split()[0] for line in sums.read_text().splitlines() if line.split()[-1] == archive.name)
    algorithm = {64: "sha256", 128: "sha512"}.get(len(expected))
    if algorithm is None:
        raise RuntimeError("Unknown official checksum format")
    with archive.open("rb") as stream:
        actual = hashlib.file_digest(stream, algorithm).hexdigest()
    if actual != expected:
        raise RuntimeError("Caddy archive checksum mismatch")
    binary = root / "caddy"
    with tarfile.open(archive) as tar:
        tar.extract("caddy", root, filter="data")
    binary.chmod(0o755)
    with binary.open("rb") as stream:
        binary_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    save(root / "caddy-build.json", json.dumps(dict(version=VERSION, archive_checksum=actual, checksum_algorithm=algorithm,
         binary_sha256=binary_hash, source=BASE + archive.name, version_output=run(binary, "version")), indent=2))
    print(binary)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    fetch(parser.parse_args().root)
