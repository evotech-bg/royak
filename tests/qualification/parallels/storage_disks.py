#!/usr/bin/env python3
"""Create three fresh capped disposable data disks; never format a guest disk.

Exact owned VM UUIDs only, with cold attachment and retained before/after
inventory. Boot disks and all earlier qualification evidence remain unchanged.
Interrupted creation is not retried automatically: an explicit --resume-created
checks the retained manifest, exact backing inode/descriptor and stopped VM.
No wildcard deletion or existing disk adoption.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bootstrap import run, ssh, verify_owner
from storage_preflight import UUIDS

SIZE = 2 * 1024**3
RUNS = Path(__file__).resolve().parents[1] / ".runs"


def wait_for(fn, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if fn(): return
        except (OSError, RuntimeError): pass
        time.sleep(1)
    raise RuntimeError("owned VM transition did not complete")


def disks(root, n):
    return json.loads(ssh(root, n, "lsblk -b -J -o NAME,PATH,SIZE,TYPE,MOUNTPOINTS,SERIAL,MODEL,UUID", timeout=20))["blockdevices"]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lab", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.add_argument("--components", type=Path, required=True)
    p.add_argument("--resume-created", action="store_true")
    a = p.parse_args()
    os.umask(0o077)
    root, out = a.lab.resolve(), a.output_dir.resolve()
    i = json.loads((root / "inventory.json").read_text())
    assert i["root"] == str(root) and i["kind"] == "royak-parallels-lab-v1"
    assert {n["uuid"] for n in i["nodes"]} == UUIDS
    assert out.is_relative_to(RUNS.resolve()) and out != RUNS.resolve()
    for n in i["nodes"]:
        c = json.loads((a.components / f"node-{n['id']}.json").read_text())
        assert c["passed"] is True and c["uuid"] == n["uuid"]
    if shutil.disk_usage(root).free < 32 * 1024**3:
        raise RuntimeError("Need 32 GiB raw free: 6 GiB capped data disks plus 20 GiB floor and headroom")
    if a.resume_created:
        manifest = json.loads((out / "inventory.json").read_text())
        assert manifest["kind"] == "royak-disposable-storage-disks-v1" and manifest["root"] == str(out)
        assert manifest["lab"] == str(root) and manifest["size_bytes_per_disk"] == SIZE and not manifest["complete"]
        assert len(manifest['nodes']) == 1 and manifest['nodes'][0]['status'] == 'created'
        # The first attachment was rejected by Parallels' EFI/BusLogic check.
        # Preserve the pre-recovery operational inventory, do not create a new
        # disk or enable the unsupported controller to make attachment succeed.
        with (out / "inventory-before-explicit-resume.json").open('x') as stream:
            json.dump(manifest, stream, indent=2); stream.write('\n')
        manifest['recovery_fixture_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    else:
        out.mkdir(parents=True, mode=0o700, exist_ok=False)
        manifest = dict(kind="royak-disposable-storage-disks-v1", root=str(out), lab=str(root),
                    size_bytes_per_disk=SIZE, maximum_total_data_bytes=3*SIZE,
                    fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    nodes=[], complete=False, created_at=time.time())

    def save():
        temporary = out / "inventory.tmp"
        with temporary.open("x") as stream:
            json.dump(manifest, stream, indent=2); stream.write("\n")
            stream.flush(); os.fsync(stream.fileno())
        temporary.replace(out / "inventory.json")

    save()
    for n in i["nodes"]:
        if shutil.disk_usage(root).free < 20 * 1024**3:
            raise RuntimeError("host reserve below 20 GiB; no further disk operations")
        info = verify_owner(root, n)
        assert list(k for k in info["Hardware"] if k.startswith("hdd")) == ["hdd0"]
        existing = next((row for row in manifest['nodes'] if row['uuid'] == n['uuid']), None)
        if existing:
            assert a.resume_created and existing['status'] == 'created' and info['State'] == 'stopped'
            row = existing
            disk, before = Path(row['host_disk']), row['before']
            assert disk == out / f"owned-data-n{n['id']}.hdd" and info['Hardware']['hdd0'] == row['boot_hardware']
            assert hashlib.sha256((disk / 'DiskDescriptor.xml').read_bytes()).hexdigest() == row['descriptor_sha256']
            backing = disk / row['backing_name']
            assert backing.resolve().is_relative_to(disk) and backing.stat().st_ino == row['backing_inode'] and backing.stat().st_size == SIZE
        else:
            assert info['State'] == 'running'
            before = disks(root, n)
        # All current activity must be absent before stopping this exact VM.
            ssh(root, n, "set -eu; test -z \"$(sudo docker ps -aq)\"; "
            "test \"$(systemctl is-active royak-qualification.service || true)\" = inactive; "
            "test -z \"$(sudo pvs --noheadings)\"; "
            "sudo drbdsetup status --json | python3 -c 'import json,sys; assert json.load(sys.stdin)==[]'", timeout=25)
            disk = out / f"owned-data-n{n['id']}.hdd"
            row = dict(node=n["id"], uuid=n["uuid"], host_disk=str(disk), before=before,
                   boot_hardware=info["Hardware"]["hdd0"], status="planned")
            manifest["nodes"].append(row); save()
            print(f"Preparing fresh 2 GiB disk for owned node {n['id']}", flush=True)
            try: ssh(root, n, "sudo shutdown -h now", timeout=15)
            except RuntimeError: pass  # SSH can close during a successful shutdown.
            wait_for(lambda: verify_owner(root, n).get("State") == "stopped", 75)
            verify_owner(root, n)
            assert not disk.exists()
            run("prl_disk_tool", "create", "--hdd", disk, "--size", "2G", "--alloc-policy", "sparse")
            descriptor = disk / "DiskDescriptor.xml"
            tree = ET.parse(descriptor)
            backing = disk / tree.find(".//StorageData/Storage/Image/File").text
            assert backing.resolve().is_relative_to(disk) and backing.stat().st_size == SIZE
            row.update(status="created", descriptor_sha256=hashlib.sha256(descriptor.read_bytes()).hexdigest(),
                   backing_name=backing.name, backing_inode=backing.stat().st_ino)
            save()
        verify_owner(root, n)
        run("prlctl", "set", n["uuid"], "--device-add", "hdd", "--image", disk, "--iface", "sata")
        attached = verify_owner(root, n)
        assert attached["Hardware"]["hdd0"] == row["boot_hardware"]
        new = {k:v for k,v in attached["Hardware"].items() if k.startswith("hdd") and k != "hdd0"}
        assert len(new) == 1 and Path(next(iter(new.values()))["image"]).resolve() == disk
        row.update(status="attached", hardware=new); save()
        run("prlctl", "start", n["uuid"], timeout=90)
        wait_for(lambda: ssh(root, n, "test -f /var/lib/royak-lab-ready; uname -r", timeout=5), 120)
        after = disks(root, n)
        old_serials = {d["serial"] for d in before if d["type"] == "disk"}
        fresh = [d for d in after if d["type"] == "disk" and d["serial"] not in old_serials]
        assert len(fresh) == 1
        guest = fresh[0]
        assert guest["serial"] and guest["size"] == SIZE and not guest.get("children")
        assert all(m is None for m in guest["mountpoints"])
        assert {d["serial"] for d in after if d["type"] == "disk"} == old_serials | {guest["serial"]}
        row.update(status="guest-identified-unformatted", guest_disk=guest, after=after); save()
    manifest["complete"] = True; save()
    print(out / "inventory.json", flush=True)


if __name__ == "__main__": main()
