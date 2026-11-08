#!/usr/bin/env python3
"""Install pinned evaluation-only DRBD components in the exact owned lab.

Requires the prior signed APT plan; no VM creation, disk operations or workloads.
Each node's immutable result is saved even on failure; reruns need a new output
directory. Never changes host packages, routing, VPN or the public demo.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bootstrap import ssh, verify_owner
from storage_preflight import UUIDS, PPA_KEY, DRBD, UTILS


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lab", type=Path, required=True)
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    a = p.parse_args()
    os.umask(0o077)
    root = a.lab.resolve()
    i = json.loads((root / "inventory.json").read_text())
    assert i["root"] == str(root) and i["kind"] == "royak-parallels-lab-v1"
    assert {n["uuid"] for n in i["nodes"]} == UUIDS
    plan = json.loads(a.plan.read_text())
    assert plan["signing_key"] == PPA_KEY and plan["drbd_version"] == DRBD and plan["utils_version"] == UTILS
    assert {n["uuid"] for n in plan["nodes"]} == UUIDS and all(n.get("package_plan") for n in plan["nodes"])
    # These already-provisioned guests need 175 MB installed packages/node
    # (signed APT plan), not the initial VM image/bootstrap disk budget. Reserve
    # 12 GiB for this bounded experiment above the unchanged 20 GiB stop floor.
    # bootstrap.py retains its separate 60 GiB new-VM provisioning guard.
    if shutil.disk_usage(root).free < 32 * 1024**3:
        raise RuntimeError("Need 32 GiB raw free for the capped component experiment")
    a.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    for n in i["nodes"]:
        row = dict(node=n["id"], uuid=n["uuid"], started_at=time.time(), passed=False,
                   plan_sha256=hashlib.sha256(a.plan.read_bytes()).hexdigest(),
                   fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   evaluation_only=True, disks_changed=False)
        try:
            if shutil.disk_usage(root).free < 20 * 1024**3:
                raise RuntimeError("host disk reserve below 20 GiB")
            assert verify_owner(root, n).get("State") == "running"
            print(f"Installing pinned components on owned node {n['id']}", flush=True)
            command = f"""set -eu
d=/var/lib/royak-storage-qualification/preflight-20261030
test -f "$d/package-plan-complete"
test -z "$(sudo docker ps -aq)"
test "$(systemctl is-active royak-qualification.service || true)" = inactive
test -z "$(sudo pvs --noheadings)"
test "$(df -B1 --output=avail / | tail -1)" -ge 8589934592
test "$(gpg --show-keys --with-colons "$d/key.asc" 2>/dev/null | awk -F: '$1=="fpr" {{ print $10; exit }}')" = {PPA_KEY}
dpkg-query -W > /dev/null
sudo env DEBIAN_FRONTEND=noninteractive apt-get -y --no-install-recommends -o Dir::Etc::sourcelist="$d/ppa.list" install drbd-dkms={DRBD} drbd-utils={UTILS}
sudo systemctl disable --now drbd.service
sudo modprobe drbd
test "$(modinfo -F version drbd)" = 9.3.4
sudo drbdsetup status --json | python3 -c 'import json,sys; assert json.load(sys.stdin)==[]'
cat /proc/drbd
drbdadm --version
sudo drbdsetup status --json
sudo dkms status
dpkg-query -W drbd-dkms drbd-utils lvm2
df -B1 /
"""
            # Preserve both streams on a failed assertion (bootstrap.ssh only
            # raises a bounded stderr excerpt, insufficient for build evidence).
            result = subprocess.run(["ssh", "-i", str(root / "operator"), "-o", "IdentitiesOnly=yes",
                "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o",
                "UserKnownHostsFile=" + str(root / "known_hosts"), "-o", "ConnectTimeout=3",
                "royak@" + n["ip"], command], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=900)
            row["output"], row["exit_code"] = result.stdout, result.returncode
            if result.returncode:
                raise RuntimeError(f"component verification exited {result.returncode}; full output retained")
            row["passed"] = True
        except Exception as e:
            row["error"] = str(e)
        row["finished_at"] = time.time()
        with (a.output_dir / f"node-{n['id']}.json").open("x") as stream:
            json.dump(row, stream, indent=2)
            stream.write("\n")
        print(f"Node {n['id']}: {'component check passed' if row['passed'] else 'FAILED'}", flush=True)
        if not row["passed"]:
            raise RuntimeError(row["error"])


if __name__ == "__main__":
    main()
