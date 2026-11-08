#!/usr/bin/env python3
"""Read-only owned-VM storage inventory plus optional pinned DRBD package preflight.

No disk creation, formatting, mounting, module loading or package installation.
Only --package-plan writes a private guest package-source/key directory and
refreshes APT indexes; the installed package set remains unchanged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bootstrap import verify_owner, ssh

PPA_KEY = "CC1B5A793C04BB3905AD837734893610CEAA9512"
DRBD = "9.3.4-1ppa1~noble1"
UTILS = "9.35.0-1ppa1~noble1"
UUIDS = {"29cbe522-6829-412f-a480-ab52283a1158", "1752e81e-a541-4099-a054-842f71f3cc64",
         "12422c3b-1e89-444b-8faf-426d2da0b15e"}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lab", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--package-plan", action="store_true")
    a = p.parse_args()
    root = a.lab.resolve()
    inventory = json.loads((root / "inventory.json").read_text())
    assert inventory["kind"] == "royak-parallels-lab-v1" and inventory["root"] == str(root)
    assert {n["uuid"] for n in inventory["nodes"]} == UUIDS
    if a.output.exists():
        p.error("refusing to overwrite earlier evidence")
    os.umask(0o077)
    results = []
    for n in inventory["nodes"]:
        info = verify_owner(root, n)
        if info.get("State") != "running":
            raise RuntimeError("preflight never starts a stopped VM")
        print(f"Inspecting owned node {n['id']}", flush=True)
        text = ssh(root, n, "uname -r; dpkg --print-architecture; df -B1 /; "
                   "systemctl is-active royak-qualification.service || true; "
                   "sudo docker ps -aq; sudo pvs --noheadings; sudo vgs --noheadings; sudo lvs --noheadings; "
                   "lsblk -b -J -o NAME,PATH,SIZE,TYPE,MOUNTPOINTS,SERIAL,MODEL,UUID; "
                   "modinfo -F version drbd 2>/dev/null || true; "
                   "dpkg-query -W lvm2 'linux-headers*' drbd-dkms drbd-utils 2>/dev/null || true", timeout=40)
        row = dict(node=n["id"], uuid=n["uuid"], inventory=text)
        if a.package_plan:
            # Dedicated immutable experiment namespace. No untrusted APT key is
            # accepted before its full primary fingerprint has been checked.
            directory = "/var/lib/royak-storage-qualification/preflight-20261030"
            command = f"""set -eu
d={shlex.quote(directory)}
sudo install -d -m 0755 "$d"
test ! -e "$d/package-plan-complete"
test "$(dpkg --print-architecture)" = arm64
test -z "$(sudo docker ps -aq)"
test "$(systemctl is-active royak-qualification.service || true)" = inactive
test -z "$(sudo pvs --noheadings)"
curl --fail --location --silent --show-error 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x{PPA_KEY}' | sudo tee "$d/key.asc" >/dev/null
f=$(gpg --show-keys --with-colons "$d/key.asc" 2>/dev/null | awk -F: '$1=="fpr" {{ print $10; exit }}')
test "$f" = {PPA_KEY}
sudo gpg --batch --yes --dearmor -o "$d/key.gpg" "$d/key.asc"
printf '%s\n' "deb [arch=arm64 signed-by={directory}/key.gpg] https://ppa.launchpadcontent.net/linbit/linbit-drbd9-stack/ubuntu noble main" | sudo tee "$d/ppa.list" >/dev/null
sudo apt-get -o Dir::Etc::sourcelist="$d/ppa.list" update
sudo apt-get -o Dir::Etc::sourcelist="$d/ppa.list" --simulate --no-install-recommends install drbd-dkms={DRBD} drbd-utils={UTILS}
sudo touch "$d/package-plan-complete"
"""
            row["package_plan"] = ssh(root, n, command, timeout=180)
        results.append(row)
    report = dict(kind="royak-storage-preflight-v1", created_at=time.time(), nodes=results,
                  fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  package_installation=False, disks_changed=False, ppa_evaluation_only=True,
                  drbd_version=DRBD, utils_version=UTILS, signing_key=PPA_KEY)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(a.output)


if __name__ == "__main__":
    main()
