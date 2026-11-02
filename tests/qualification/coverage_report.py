"""Join current-source evidence without cherry-picking older green attempts."""
import argparse
import json
from pathlib import Path
import sys

from run import HERE, ROOT, digest, source_inventory
from suites import SUITES


def latest_suite(attempts, suite, fixture_sha, dependency_shas=None):
    eligible = [(manifest, report) for manifest, report in attempts
                if manifest.get("source_sha256", {}).get(suite) == fixture_sha
                and all(manifest.get("source_sha256", {}).get(name) == sha for name,sha in (dependency_shas or {}).items())]
    eligible.sort(key=lambda pair: pair[0]["run_id"])
    result = None
    for manifest, report in eligible:
        for row in report.get("suites", []):
            if row["suite"] == suite:
                result = dict(row, run_id=manifest["run_id"])
                if result.get("skip_lines"):
                    result["passed"]=False
    return result


def collect(binary):
    binary_sha = digest(binary)
    source = {str(p.relative_to(ROOT)): digest(p) for p in source_inventory()}
    attempts, qualification = [], []
    for path in sorted((HERE / ".runs").glob("*/manifest.json")):
        report_path = path.parent / "report.json"
        if not report_path.exists():
            continue
        manifest = json.loads(path.read_text())
        if manifest.get("binary_sha256") != binary_sha:
            continue
        if any(manifest.get("source_sha256", {}).get(name) != sha for name, sha in source.items()):
            continue
        report = json.loads(report_path.read_text())
        if "suites" in report:
            attempts.append((manifest, report))
        elif manifest.get("probe_mode") == "http" and manifest.get("contract", {}).get("soak_seconds", 0) >= 300 and manifest.get("ui_fixture_sha256") == digest(HERE / "topology_live.cjs"):
            if all(manifest.get("harness_sha256", {}).get(name) == digest(HERE / name) for name in ("run.py", "checker.py", "workload.py")):
                qualification.append((manifest, report))
    rows = []
    for suite in SUITES:
        dependencies = {"tests/cluster-lib.sh": digest(ROOT / "tests/cluster-lib.sh")}
        if suite == "test-beta-lifecycle-topology.sh":
            dependencies["tests/qualification/beta_runtime.py"] = digest(HERE / "beta_runtime.py")
            dependencies["tests/qualification/watchdog_runtime.py"] = digest(HERE / "watchdog_runtime.py")
        if suite == "test-neuropod.sh":
            dependencies["tests/qualification/neuropod_runtime.py"] = digest(HERE / "neuropod_runtime.py")
        if suite == "test-http-protocol.sh":
            dependencies["tests/qualification/cli_exit.py"] = digest(HERE / "cli_exit.py")
        row = latest_suite(attempts, suite, digest(ROOT / suite), dependencies)
        rows.append(row or dict(suite=suite, passed=False, missing_current_evidence=True))
    qualification.sort(key=lambda pair: pair[0]["run_id"])
    fault = qualification[-1][1] if qualification else None
    return dict(schema_version=1, binary_sha256=binary_sha, source_sha256=source,
                passed=all(r["passed"] for r in rows) and bool(fault and fault["passed"]),
                suites=rows, fault_qualification=fault, full_kubernetes_conformance=False,
                policy="latest matching current-source/current-fixture attempt, not best passing attempt; old failures retained")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = collect(args.binary)
    args.output.write_text(json.dumps(report, indent=2))
    print(args.output)
    print("PASS" if report["passed"] else "FAIL / incomplete qualification")
    sys.exit(0 if report["passed"] else 1)
