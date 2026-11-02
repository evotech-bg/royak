"""Current normal-release Connect + integration gate; never a production certificate."""
import argparse
import json
from pathlib import Path

from coverage_report import collect
from run import HERE, ROOT, digest, source_inventory


def consecutive_gate(attempts, required=3):
    recent = sorted(attempts, key=lambda a: a["run_id"])[-required:]
    return len(recent) == required and all(a["passed"] for a in recent), recent


def matches(manifest, report, build, binary_sha, client_sha, sources, fixture_sha, dependencies):
    return (
        report.get("binary_sha256") == binary_sha
        and report.get("client_sha256") == client_sha
        and report.get("fixture_sha256") == fixture_sha
        and build.get("binary_sha256") == binary_sha
        and build.get("source_unchanged_during_build") is True
        and build.get("debug_symbols") is False
        and build.get("source_sha256") == sources
        and all(manifest.get("source_sha256", {}).get(k) == v for k, v in sources.items())
        and all(manifest.get("harness_sha256", {}).get(k) == v for k, v in dependencies.items())
    )


def acceptance(binary, client):
    binary_sha, client_sha = digest(binary), digest(client)
    sources = {str(p.relative_to(ROOT)): digest(p) for p in source_inventory()}
    fixture_sha = digest(HERE / "connect_e2e.py")
    dependencies = {name: digest(HERE / name) for name in ("run.py", "connect_e2e.py")}
    attempts = []
    for path in sorted((HERE / ".runs").glob("*/connect-report.json")):
        manifest_path, build_path = path.parent / "manifest.json", path.parent / "build-manifest.json"
        if not manifest_path.exists() or not build_path.exists():
            continue
        manifest, report, build = (json.loads(p.read_text()) for p in (manifest_path, path, build_path))
        if matches(manifest, report, build, binary_sha, client_sha, sources, fixture_sha, dependencies):
            attempts.append(dict(run_id=path.parent.name, passed=report["passed"], checks=len(report["checks"]), failure=report.get("failure")))
    connect_ok, recent = consecutive_gate(attempts)
    suites = collect(binary)["suites"]
    for row in suites:
        if "run_id" in row:
            parent = json.loads((HERE / ".runs" / row["run_id"] / "report.json").read_text())
            if parent.get("failure") or parent.get("cleanup_errors"):
                row["passed"] = False
                row["attempt_error"] = parent.get("failure") or parent["cleanup_errors"]
    return dict(
        schema_version=1, passed=connect_ok and all(row["passed"] for row in suites),
        binary_sha256=binary_sha, client_sha256=client_sha, source_sha256=sources,
        fixture_sha256=fixture_sha, connect_runs=recent, matching_connect_attempts=len(attempts),
        required_consecutive_runs=3, suites=suites,
        scope="local Connect contract and 15 integration suites; three independent Docker daemons with real kernel WireGuard",
        production_ready=False, full_kubernetes_conformance=False, cross_host_qualified=False,
        policy="latest three matching normal-release attempts and latest current-source integration evidence; never best pass",
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = acceptance(args.binary, args.client)
    args.output.write_text(json.dumps(report, indent=2))
    print("PASS" if report["passed"] else "FAIL / incomplete Connect qualification")
    raise SystemExit(0 if report["passed"] else 1)
