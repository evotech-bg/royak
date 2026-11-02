#!/usr/bin/env python3
"""Owned Parallels ARM64 lab. No existing VM, host network or shared folder changes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
BASE = "https://cloud-images.ubuntu.com/noble/current/"
IMAGE = "noble-server-cloudimg-arm64.img"


def run(*args, timeout=120, **kw):
    result = subprocess.run([str(a) for a in args], capture_output=True, timeout=timeout, **kw)
    if result.returncode:
        raise RuntimeError(f"{args[0:3]} failed ({result.returncode}): "
                           + result.stderr.decode(errors="replace")[-1800:])
    return result.stdout.decode()


def save(path, value, mode=0o600):
    path.write_text(value)
    path.chmod(mode)


def persist(root, manifest):
    save(root / "inventory.json", json.dumps(manifest, indent=2) + "\n")


def ssh(root, node, command, timeout=120):
    return run("ssh", "-i", root / "operator", "-o", "IdentitiesOnly=yes",
               "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
               "-o", "UserKnownHostsFile=" + str(root / "known_hosts"),
               "-o", "ConnectTimeout=3", "royak@" + node["ip"], command, timeout=timeout)


def verify_owner(root, node):
    info = json.loads(run("prlctl", "list", "-i", node["uuid"], "--json"))[0]
    # Never address a machine by a mutable name, and validate its owned home.
    home = info.get("Home", info.get("home", ""))
    if not home or not Path(home).resolve().is_relative_to(root.resolve() / "vms"):
        raise RuntimeError("VM ownership/path mismatch; refusing operation")
    return info


def bootstrap(root, count, wait=True):
    os.umask(0o077)
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if shutil.disk_usage(root).free < 60 * 1024**3:
        raise RuntimeError("Need 60 GiB free before VM provisioning")
    if (root / "inventory.json").exists():
        manifest = json.loads((root / "inventory.json").read_text())
        if manifest.get("root") != str(root) or manifest.get("kind") != "royak-parallels-lab-v1":
            raise RuntimeError("Not an owned Royak lab")
    else:
        manifest = dict(kind="royak-parallels-lab-v1", root=str(root),
                        run_id=root.name, topology="three-linux-vms-one-physical-mac",
                        production_ready=False, nodes=[], created_at=time.time())
        persist(root, manifest)
    (root / "vms").mkdir(exist_ok=True)
    (root / "cache").mkdir(exist_ok=True)
    if not (root / "operator").exists():
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", root.name,
            "-f", root / "operator")
    public = (root / "operator.pub").read_text().strip()
    image = root / "cache" / IMAGE
    sums = root / "cache" / "SHA256SUMS"
    if not sums.exists():
        run("curl", "--fail", "--location", "--retry", "3", "--output", sums,
            BASE + "SHA256SUMS", timeout=90)
    expected = next(line.split()[0] for line in sums.read_text().splitlines()
                    if line.split()[-1].lstrip("*") == IMAGE)
    if not image.exists():
        print("Downloading official Ubuntu ARM64 cloud image…", flush=True)
        run("curl", "--fail", "--location", "--retry", "3", "--output", image,
            BASE + IMAGE, timeout=900)
    actual = hashlib.file_digest(image.open("rb"), "sha256").hexdigest()
    if actual != expected:
        raise RuntimeError("Ubuntu SHA256 mismatch; image not used")
    manifest["ubuntu"] = dict(url=BASE + IMAGE, sha256=actual,
                              checksum_source=BASE + "SHA256SUMS")
    persist(root, manifest)
    for index in range(1, count + 1):
        existing = next((n for n in manifest["nodes"] if n["id"] == index), None)
        registered = json.loads(run("prlctl", "list", "-a", "--json"))
        if existing and any(n.get("uuid", n.get("ID", "")).strip("{}") == existing["uuid"].strip("{}") for n in registered):
            info = verify_owner(root, existing)
            if info.get("State") == "stopped":
                if "hdd0" not in info.get("Hardware", {}) or not (root / f"seed-{index}.iso").exists():
                    raise RuntimeError("Owned VM creation was interrupted before disk setup; inspect before resuming")
                run("prlctl", "set", existing["uuid"], "--device-bootorder", "hdd0")
                run("prlctl", "set", existing["uuid"], "--device-set", "serial0", "--output", root / f"serial-{index}.log", "--connect")
                run("prlctl", "start", existing["uuid"], timeout=90)
            print("Existing owned VM: " + existing["name"], flush=True)
            continue
        name = root.name + "-n" + str(index)
        ident = existing["uuid"].strip("{}") if existing else str(uuid.uuid4())
        node = existing or dict(id=index, uuid=ident, name=name, ip="10.37.129." + str(210 + index),
                    wg_ip="10.246.73." + str(index), cpu=2, memory_mib=2048,
                    boot_disk_gib=16, status="creating")
        # Persist the exact UUID before any external creation, including partial failures.
        node["uuid"] = ident
        if not existing:
            manifest["nodes"].append(node)
        persist(root, manifest)
        run("prlctl", "create", name, "--distribution", "ubuntu", "--no-hdd",
            "--uuid", ident, "--dst", root / "vms")
        info = run("prlctl", "list", "-i", ident)
        save(root / f"node-{index}-created.txt", info)
        for options in [
            ["--cpus", "2", "--memsize", "2048"],
            ["--isolate-vm", "on"],
            ["--shf-host", "off", "--shf-host-defined", "off", "--shf-guest", "off"],
            ["--shared-profile", "off"],
            ["--autostart", "off", "--autostop", "shutdown", "--startup-view", "headless"],
            ["--device-set", "net0", "--type", "host-only", "--mac", f"0200730000{index:02x}"],
            ["--device-add", "net", "--type", "shared", "--mac", f"0200730001{index:02x}"],
        ]:
            run("prlctl", "set", ident, *options)
        data = root / f"seed-{index}"
        data.mkdir()
        run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name,
            "-f", data / "hostkey")
        host_private = (data / "hostkey").read_text()
        host_public = (data / "hostkey.pub").read_text().strip()
        host_key_record = node["ip"] + " " + host_public + "\n"
        with (root / "known_hosts").open("a") as stream:
            stream.write(host_key_record)
        # JSON is valid YAML. Never put passwords, operator private keys or cluster
        # credentials into CLI argv; only the guest's own SSH host key goes here.
        config = dict(hostname=name, manage_etc_hosts=True, ssh_pwauth=False,
                      disable_root=True, users=[dict(name="royak", shell="/bin/bash",
                      lock_passwd=True, sudo="ALL=(ALL) NOPASSWD:ALL",
                      ssh_authorized_keys=[public])],
                      ssh_keys=dict(ed25519_private=host_private, ed25519_public=host_public),
                      package_update=True, packages=["docker.io", "wireguard-tools", "openssl",
                      "python3", "iproute2", "iptables", "curl", "e2fsprogs", "util-linux"],
                      write_files=[dict(path="/etc/royak-lab-owner", permissions="0600", content=root.name)],
                      runcmd=[["systemctl", "enable", "--now", "docker"],
                              ["touch", "/var/lib/royak-lab-ready"]])
        save(data / "user-data", "#cloud-config\n" + json.dumps(config, indent=2) + "\n")
        save(data / "meta-data", json.dumps({"instance-id": name, "local-hostname": name}))
        network = dict(version=2, ethernets={
            "lab0": dict(match={"macaddress": f"02:00:73:00:00:{index:02x}"},
                         **{"set-name": "lab0"}, addresses=[node["ip"] + "/24"], dhcp4=False, dhcp6=False),
            "wan0": dict(match={"macaddress": f"02:00:73:00:01:{index:02x}"},
                         **{"set-name": "wan0"}, dhcp4=True, dhcp6=False)})
        save(data / "network-config", json.dumps(network, indent=2))
        iso = root / f"seed-{index}.iso"
        run("hdiutil", "makehybrid", "-iso", "-joliet", "-default-volume-name", "CIDATA",
            "-o", iso, data)
        iso.chmod(0o600)
        disk = root / "vms" / (name + ".pvm") / "boot.hdd"
        run("prl_disk_tool", "create", "--hdd", disk, "--size", "16G", "--alloc-policy", "sparse")
        tree = ET.parse(disk / "DiskDescriptor.xml")
        hds = disk / tree.find(".//StorageData/Storage/Image/File").text
        if not hds.resolve().is_relative_to(disk) or hds.stat().st_size != 16 * 1024**3:
            raise RuntimeError("Unexpected plain disk descriptor")
        qemu = shutil.which("qemu-img")
        if not qemu:
            raise RuntimeError("qemu-img is required for the official cloud image conversion")
        run(qemu, "convert", "-n", "-f", "qcow2", "-O", "raw", image, hds, timeout=180)
        run("prlctl", "set", ident, "--device-add", "hdd", "--image", disk)
        # Default VM has cdrom0 even with --no-hdd.
        run("prlctl", "set", ident, "--device-set", "cdrom0", "--image", iso, "--connect")
        run("prlctl", "set", ident, "--device-set", "serial0", "--output", root / f"serial-{index}.log", "--connect")
        run("prlctl", "set", ident, "--device-bootorder", "hdd0")
        node["status"] = "configured"
        persist(root, manifest)
        print("Starting " + name, flush=True)
        run("prlctl", "start", ident, timeout=90)
        node["status"] = "started"
        persist(root, manifest)
    for node in manifest["nodes"][:count] if wait else []:
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            try:
                value = ssh(root, node, "sudo test -f /var/lib/royak-lab-ready && "
                            "cat /proc/sys/kernel/random/boot_id && uname -r && "
                            "sudo docker info --format '{{.ID}}'", timeout=15)
                node["status"] = "ready"
                node["initial_identity"] = value.strip().splitlines()
                persist(root, manifest)
                print("READY " + node["name"] + " " + node["ip"], flush=True)
                break
            except (RuntimeError, subprocess.TimeoutExpired):
                time.sleep(3)
        else:
            raise RuntimeError("VM bootstrap timed out: " + node["name"] + "; see owned serial/cloud-init logs")
    print(root / "inventory.json", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--nodes", type=int, choices=[1, 2, 3], default=3)
    parser.add_argument("--no-wait", action="store_true", help="create/start owned guests without waiting for SSH")
    args = parser.parse_args()
    bootstrap(args.root, args.nodes, not args.no_wait)
