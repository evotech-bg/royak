#!/usr/bin/env python3
"""Recover exact owned test resources after an interrupted runner; preserve VMs/data."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
from bootstrap import run, ssh, verify_owner, save


def validate_run_id(run_id):
    if not re.fullmatch(r"rkq-(?:soak-)?[0-9]{8}-[0-9]{6}-[0-9a-f]{6}", run_id):
        raise ValueError("Invalid exact qualification run id")


def recover(inventory, run_id, selected_nodes=None):
    validate_run_id(run_id)
    root = inventory.resolve().parent
    data = json.loads(inventory.read_text())
    nodes=data['nodes']
    if selected_nodes is not None:
        selected=set(selected_nodes)
        if len(selected)!=len(selected_nodes) or not selected or selected-{n['id'] for n in nodes}:
            raise ValueError('Invalid exact node selection')
        nodes=[n for n in nodes if n['id'] in selected]
    image = run_id + ":workload"
    results = []
    # Validate every pointer before the first mutation, including partial
    # recovery after one VM has already been prepared for a newer attempt.
    for node in nodes:
        verify_owner(root, node)
        target = ssh(root, node, "sudo readlink -f /lab").strip()
        if target != "/var/lib/royak-qualification/" + run_id:
            raise RuntimeError("Guest now belongs to another active run; refusing cleanup")
    for node in nodes:
        command = "set -eu; systemctl disable --now royak-qualification.service; "
        command += "if test -f /lab/fault-rollback.sh; then sh /lab/fault-rollback.sh; fi; "
        command += "systemctl stop " + shlex.quote(run_id + "-wg-up.timer") + " 2>/dev/null || true; "
        command += "ids=$(docker ps -aq --filter ancestor=" + shlex.quote(image) + "); "
        command += 'if test -n "$ids"; then docker rm -f $ids; fi; '
        command += "docker image rm " + shlex.quote(image) + " 2>/dev/null || true; "
        command += "if ip link show rkconn >/dev/null 2>&1; then ip link delete rkconn; fi"
        ssh(root, node, "sudo sh -ec " + shlex.quote(command))
        results.append(dict(node=node["id"], cleaned=True))
    processes = subprocess.check_output(["ps", "-axo", "pid=,command="], text=True).splitlines()
    exact_config = str(root.parent / run_id / "Caddyfile")
    for line in processes:
        pid_text, _, command = line.strip().partition(" ")
        is_caddy = "caddy run --config " + exact_config + " --adapter caddyfile" in command
        is_tunnel = (command.startswith("ssh ") and " -N " in command and str(root / "known_hosts") in command and
                     any(command.endswith('royak@'+n['ip']) for n in nodes))
        if not (is_caddy or is_tunnel):
            continue
        pid = int(pid_text)
        current = subprocess.check_output(["ps", "-p", str(pid), "-o", "command="], text=True).strip()
        if current == command.strip():
            os.kill(pid, signal.SIGTERM)
    output = root.parent / run_id / "recovery-cleanup.json"
    save(output, json.dumps(dict(run=run_id, nodes=results, scope="exact interrupted lab resources; VMs/state preserved"), indent=2))
    print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--run", required=True)
    parser.add_argument('--node',type=int,action='append',help='exact subset only; defaults to all owned nodes')
    args = parser.parse_args()
    recover(args.inventory, args.run, args.node)
