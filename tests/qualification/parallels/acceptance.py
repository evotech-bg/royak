#!/usr/bin/env python3
"""Strict latest-attempt gate for the bounded three-VM contract, not production."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from run import digest, source_inventory, ROOT, HERE


REQUIRED = {
    "capacity": {
        "Linux artifact matches unchanged current working sources",
        "three distinct VM kernels, machine identities and Docker daemons",
        "real kernel WireGuard reaches every other VM",
        *(f"API and ingress share one persisted TLS identity on VM {i}" for i in (1, 2, 3)),
        *(f"cycle {i}: eight remote streams transfer and stay open" for i in range(12)),
        *(f"cycle {i}: one revoke closes all eight streams" for i in range(12)),
    },
    "connect": {
        "Linux artifact matches unchanged current working sources",
        "three distinct VM kernels, machine identities and Docker daemons",
        "real kernel WireGuard reaches every other VM",
        "laptop CLI uses verified TLS without Docker or cluster-state access",
        "WireGuard failure has no ordinary-route fallback",
        "removing RoleBinding closes already-open TCP socket",
        "quorum loss closes active access even while WireGuard remains up",
        "team-a explicit denyAll blocks direct TCP into team-b",
        "team-b explicit denyAll blocks direct TCP into team-a",
    },
    "fault": {
        "three distinct VM kernels, machine identities and Docker daemons",
        "application ledger is external to all three VMs",
        "hard-stopped VM actually hosts a live application replica",
        "whole-VM restart preserves the exact trusted TLS identity",
        "other VMs replace lost VM replicas before it returns",
        "restarted VM has a genuinely new kernel boot identity",
        "acknowledged application writes retained without corruption",
        "isolated minority explicitly does not acknowledge a state write",
        "acknowledged control writes survive faults and converge",
        "all surviving/replacement pods retain enforced security constraints",
    },
}


def acceptable(report, mode):
    checks = report.get("checks", [])
    return (report.get("passed") is True and checks and
            all(c.get("passed") is True and not c.get("skipped") for c in checks) and
            not report.get("skips") and not report.get("skip_lines") and
            REQUIRED[mode].issubset({c.get("name") for c in checks}))


def choose(rows, mode, required):
    latest = sorted(rows, key=lambda row: row["run"])[-required:]
    return dict(passed=len(latest) == required and all(acceptable(row["report"], mode) and row["clean"] for row in latest),
                required_runs=required, attempts=[dict(run=row["run"], passed=acceptable(row["report"], mode),
                                                     cleanup_ok=row["clean"], checks=len(row["report"].get("checks", []))) for row in latest])


def capacity_attempt(directory, fixture_sha, client_sha):
    """A focused run is a separate mandatory gate, never a full Connect run."""
    path = directory / "capacity-report.json"
    if not path.exists():
        return None
    try:
        report = json.loads(path.read_text())
    except (OSError, ValueError):
        report = {}
    if not isinstance(report, dict):
        report = {}
    valid = (report.get("focused_reproducer") is True and
             report.get("vm_fixture_sha256") == fixture_sha and
             report.get("client_sha256") == client_sha)
    return dict(run=directory.name, report=report if valid else {"passed": False, "checks": []},
                clean=not (directory / "cleanup.jsonl").exists())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--runs", type=Path, default=HERE / ".runs")
    args = parser.parse_args()
    sources = {str(p.relative_to(ROOT)): digest(p) for p in source_inventory()}
    binary, client, fixture = digest(args.binary), digest(args.client), digest(Path(__file__).with_name("qualify.py"))
    rows = {"connect": [], "fault": [], "capacity": []}
    for directory in sorted(args.runs.glob("rkq-*")):
        manifest = directory / "vm-manifest.json"
        if not manifest.exists():
            continue
        vm = json.loads(manifest.read_text())
        if vm.get("source_sha256") != sources or vm.get("binary_sha256") != binary:
            continue
        if vm.get("connect_fixture_sha256") != digest(HERE / "connect_e2e.py") or vm.get("fault_fixture_sha256") != digest(HERE / "run.py"):
            continue
        capacity = capacity_attempt(directory, digest(Path(__file__).with_name("connect_capacity.py")), client)
        if capacity is not None:
            rows["capacity"].append(capacity)
            continue
        lb_path = directory / "lb-report.json"
        if (directory / "Caddyfile").exists() and not lb_path.exists() and vm.get("fixture_sha256") == fixture:
            rows["fault"].append(dict(run=directory.name, report={"passed": False, "checks": []}, clean=False))
            continue
        if lb_path.exists():
            lb = json.loads(lb_path.read_text())
            lb_fixtures = {str(p): digest(p) for p in (Path(__file__).with_name("load_balancer.py"), Path(__file__).with_name("qualify.py"))}
            if (lb.get("fixture_sha256") == lb_fixtures and lb.get("source_sha256") == sources
                    and lb.get("binary_sha256") == binary):
                rows["fault"].append(dict(run=directory.name, report=lb, clean=not (directory / "cleanup.jsonl").exists()))
            continue  # LB attempts must never fall back to an older generic verdict.
        expected_mode = "connect" if (directory / "build-manifest.json").exists() else "fault"
        for mode, name in (("connect", "connect-report.json"), ("fault", "report.json")):
            path = directory / name
            if not path.exists():
                if mode == expected_mode and vm.get("fixture_sha256") == fixture:
                    rows[mode].append(dict(run=directory.name, report={"passed": False, "checks": []}, clean=False))
                continue
            report = json.loads(path.read_text())
            if report.get("vm_fixture_sha256") != fixture:
                continue
            if mode == "connect" and report.get("client_sha256") != client:
                continue
            rows[mode].append(dict(run=directory.name, report=report, clean=not (directory / "cleanup.jsonl").exists()))
    gates = {mode: choose(rows[mode], mode, count) for mode, count in (("connect", 3), ("capacity", 1), ("fault", 1))}
    result = dict(passed=all(g["passed"] for g in gates.values()), gates=gates,
                  binary_sha256=binary, client_sha256=client, fixture_sha256=fixture,
                  topology="three-parallels-linux-kernels-one-physical-mac", production_ready=False,
                  non_claims=["independent physical failure domains", "full Kubernetes conformance", "distributed volume durability", "long soak"])
    output = args.runs / "current-vm-acceptance.json"
    output.write_text(json.dumps(result, indent=2) + "\n")
    print("PASS" if result["passed"] else "FAIL")
    print(output)
    return int(not result["passed"])


if __name__ == "__main__":
    raise SystemExit(main())
