#!/usr/bin/env python3
"""Pin official restic tools below qualification .runs; never install on PATH."""
import argparse
import bz2
import hashlib
import json
import os
from pathlib import Path
import platform as host
import re
import stat
import subprocess
import tempfile
import urllib.request

VERSION = "0.19.1"
FINGERPRINT = "CF8F18F2844575973F79D4E191A6868BD3F7A907"
BASE = f"https://github.com/restic/restic/releases/download/v{VERSION}/"
KEY = "https://restic.net/gpg-key-alex.asc"
RUNS = Path(__file__).resolve().parents[1] / ".runs"
DEFAULT_PLATFORMS = ("darwin_arm64", "linux_arm64")
SUPPORTED_PLATFORMS = DEFAULT_PLATFORMS + ("darwin_amd64", "linux_amd64")
MAX_METADATA = 256 * 1024
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXECUTABLE = 64 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def host_platform(system=None, machine=None):
    system = (host.system() if system is None else system).lower()
    machine = (host.machine() if machine is None else machine).lower()
    operating_system = {"darwin": "darwin", "linux": "linux"}.get(system)
    architecture = {"arm64": "arm64", "aarch64": "arm64", "amd64": "amd64", "x86_64": "amd64"}.get(machine)
    if not operating_system or not architecture:
        raise ValueError("unsupported restic host OS/architecture; explicit supported platform is required")
    return operating_system + "_" + architecture


def select_platforms(requested=None):
    if requested is None:
        return DEFAULT_PLATFORMS  # Preserve legacy fetch(root) and CLI defaults.
    if not requested or len(requested) != len(set(requested)) or any(p not in SUPPORTED_PLATFORMS for p in requested):
        raise ValueError("select distinct supported restic platforms")
    # Stable evidence independent of CLI flag order; legacy ARM pair unchanged.
    return tuple(p for p in SUPPORTED_PLATFORMS if p in requested)


def read_private(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1 or before.st_mode & 0o077 or before.st_size > limit:
            raise ValueError("cached tool evidence must be bounded, owner-private, regular and singly linked")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if len(data) > limit or len(data) != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("cached tool evidence changed during read")
        return data


def cached_or_fetch(path, url, limit, timeout, immutable):
    if path.is_symlink():
        raise ValueError("refusing tool evidence symlink")
    if not path.exists():
        if immutable:
            raise ValueError("existing build evidence is incomplete; use a new output directory")
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("official tool download exceeds admitted size")
        with path.open("xb") as stream:
            stream.write(data)
    return read_private(path, limit)


def verify_signature(root):
    # Short private home avoids macOS Unix socket limits and user keyring writes.
    with tempfile.TemporaryDirectory(prefix="rkq-restic-gpg-", dir="/tmp") as home:
        gpg = ["gpg", "--no-options", "--homedir", home, "--batch", "--no-autostart"]
        subprocess.run(gpg + ["--import", str(root / "key.asc")], check=True, capture_output=True, timeout=60)
        verified = subprocess.run(gpg + ["--status-fd", "1", "--verify", str(root / "SHA256SUMS.asc"), str(root / "SHA256SUMS")],
                                  check=True, capture_output=True, text=True, timeout=60)
        signatures = [line.split() for line in verified.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        if not any(len(row) >= 3 and (row[2] == FINGERPRINT or row[-1] == FINGERPRINT) for row in signatures):
            raise ValueError("release signature does not match the pinned official key")


def parse_checksums(data):
    sums = {}
    for line in data.decode("ascii").splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 2 or not re.fullmatch(r"[0-9a-f]{64}", fields[0]):
            raise ValueError("malformed signed checksum entry")
        name = fields[1].lstrip("*")
        if not name or "/" in name or "\\" in name or name in sums:
            raise ValueError("duplicate or invalid signed checksum filename")
        sums[name] = fields[0]
    return sums


def decompress(data):
    decoder = bz2.BZ2Decompressor()
    executable = decoder.decompress(data, max_length=MAX_EXECUTABLE + 1)
    if len(executable) > MAX_EXECUTABLE or not decoder.eof or decoder.unused_data:
        raise ValueError("restic archive is oversized, incomplete or concatenated")
    return executable


def validate_architecture(executable, selected):
    if len(executable) < 32:
        raise ValueError("restic executable header is truncated")
    if selected.startswith("linux_"):
        actual = {62: "linux_amd64", 183: "linux_arm64"}.get(int.from_bytes(executable[18:20], "little"))
        valid = executable[:4] == b"\x7fELF" and executable[4:7] == bytes([2, 1, 1])
    else:
        actual = {0x01000007: "darwin_amd64", 0x0100000C: "darwin_arm64"}.get(int.from_bytes(executable[4:8], "little"))
        valid = executable[:4] == b"\xcf\xfa\xed\xfe"
    if not valid or actual != selected:
        raise ValueError("signed restic asset does not match requested OS/architecture")


def fetch(root, platforms=None):
    os.umask(0o077)
    platforms = select_platforms(platforms)
    if root.is_symlink():
        raise ValueError("refusing tool output directory symlink")
    root = root.resolve()
    if not root.is_relative_to(RUNS.resolve()) or root == RUNS.resolve() or any(c in str(root) for c in "\r\n\0"):
        raise ValueError("tools must be in a dedicated qualification .runs subdirectory")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = root.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("tool output directory must be owner-private")
    destination = root / "restic-build.json"
    if destination.is_symlink():
        raise ValueError("refusing build evidence symlink")
    immutable = destination.exists()
    previous = json.loads(read_private(destination, MAX_METADATA)) if immutable else None
    if immutable and (not isinstance(previous, dict) or not isinstance(previous.get("builds"), list)
                      or any(not isinstance(b, dict) for b in previous["builds"])):
        raise ValueError("existing build evidence is malformed; use a new output directory")
    if immutable and (previous.get("version") != VERSION or previous.get("signature_fingerprint") != FINGERPRINT
                      or [b.get("platform") for b in previous.get("builds", [])] != list(platforms)):
        # Refuse BEFORE adding downloads/assets to a differently selected old run.
        raise ValueError("existing build evidence selects different tools; use a new output directory")
    payloads = {}
    for name, url in [("key.asc", KEY), ("SHA256SUMS", BASE + "SHA256SUMS"), ("SHA256SUMS.asc", BASE + "SHA256SUMS.asc")]:
        payloads[name] = cached_or_fetch(root / name, url, MAX_METADATA, 90, immutable)
    verify_signature(root)
    sums = parse_checksums(payloads["SHA256SUMS"])
    builds = []
    for selected in platforms:
        name = f"restic_{VERSION}_{selected}.bz2"
        data = cached_or_fetch(root / name, BASE + name, MAX_ARCHIVE, 180, immutable)
        if sha(data) != sums.get(name):
            raise ValueError("official archive checksum mismatch")
        executable = decompress(data)
        validate_architecture(executable, selected)
        target = root / f"restic-{VERSION}-{selected}"
        if target.is_symlink():
            raise ValueError("refusing executable symlink")
        if target.exists():
            if read_private(target, MAX_EXECUTABLE) != executable or not target.stat().st_mode & 0o111:
                raise ValueError("refusing to overwrite a different/non-executable pinned executable")
        else:
            if immutable:
                raise ValueError("existing executable is missing; use a new output directory")
            with target.open("xb") as stream:
                stream.write(executable)
                os.fchmod(stream.fileno(), 0o700)
        builds.append(dict(platform=selected, path=str(target), sha256=sha(executable), archive_sha256=sha(data), source=BASE + name))
    # Intentionally preserve the original manifest schema and legacy default pair.
    report = dict(version=VERSION, signature_fingerprint=FINGERPRINT, checksums_sha256=sha(payloads["SHA256SUMS"]), builds=builds)
    if immutable:
        if previous != report:
            raise ValueError("refusing to overwrite previous build evidence")
    else:
        with destination.open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
    return report


def export_github_env(report, environment_file):
    selected = host_platform()
    builds = [b for b in report["builds"] if b["platform"] == selected]
    if len(builds) != 1:
        raise ValueError("verified output does not select exactly one executable for this host")
    binary = Path(builds[0]["path"])
    if not binary.is_absolute() or any(c in str(binary) for c in "\r\n\0") or sha(read_private(binary, MAX_EXECUTABLE)) != builds[0]["sha256"]:
        raise ValueError("verified host executable changed before environment export")
    # This explicit CLI option writes one fixed key to the runner-provided file,
    # not PATH; no shell evaluation or caller-controlled environment key exists.
    descriptor = os.open(environment_file, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "ab") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_mode & 0o022:
            raise ValueError("GitHub environment output must be a trusted owned regular file")
        stream.write(("ROYAK_STAGE_RESTIC=" + str(binary) + "\n").encode())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--platform", action="append", choices=SUPPORTED_PLATFORMS, dest="platforms")
    selection.add_argument("--host", action="store_true", help="Select this Linux/macOS host's actual ARM64/AMD64 architecture")
    parser.add_argument("--github-env", type=Path, help="Append fixed ROYAK_STAGE_RESTIC only after --host verification; never edits PATH")
    args = parser.parse_args(argv)
    if args.github_env and not args.host:
        parser.error("--github-env requires --host")
    selected = (host_platform(),) if args.host else args.platforms
    report = fetch(args.root, selected)
    if args.github_env:
        export_github_env(report, args.github_env)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
