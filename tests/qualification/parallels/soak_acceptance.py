#!/usr/bin/env python3
"""Latest long-soak evidence only; a short pass cannot substitute for endurance."""
import argparse
import json
from pathlib import Path

from bootstrap import save
from qualify import original
from soak_checks import guest_cleanup_passed


def resource_contract(resource):
    """An old RSS-only pass cannot qualify the repaired PID/Raft boundary."""
    paths={'/lab/state.json.raft','/lab/royak.log'}
    trends=resource.get('container_trends',[])
    issuers=set(resource.get('audit_required_nodes',[]))
    return (resource.get('schema_version')==2 and resource.get('passed') is True and
            resource.get('drain_complete') is True and
            resource.get('drain_samples_per_node')=={'1':3,'2':3,'3':3} and
            {t.get('node') for t in trends if t.get('passed') is True}=={1,2,3} and
            all(t.get('passed') is True and not t.get('persistent_zombies') for t in trends) and
            all({p.get('path') for p in resource.get('paths',[]) if p.get('node')==node and p.get('passed') is True}>=paths for node in (1,2,3)) and
            bool(issuers) and issuers<={1,2,3} and all(any(p.get('node')==n and p.get('path')=='/lab/data/connect-audit.jsonl' and p.get('passed') is True
                                                       for p in resource.get('paths',[])) for n in issuers))


def drain_contract(rows):
    return (isinstance(rows,list) and len(rows)==3 and {r.get('node') for r in rows}=={1,2,3} and
            all(r.get('status')==200 and r.get('active')==0 and r.get('open')==0 and
                isinstance(r.get('retained'),int) and 0<=r['retained']<=256 for r in rows))


def completed(report, manifest):
    checks=report.get("checks",[])
    duration=next((c for c in checks if c.get("name")=="requested workload duration actually completed"),{})
    return (report.get("passed") is True and report.get("long_soak_qualified") is True and
            report.get("profile")==manifest.get("profile")=="full" and manifest.get("requested_seconds",0)>=7200 and
            not manifest.get('negative_closeout_control',False) and
            duration.get("observed_seconds",0)>=manifest["requested_seconds"] and
            report.get("source_and_fixtures_unchanged") is True and report.get("powered_off") is True and
            report.get('cleanup_completed') is True and
            bool(checks) and all(c.get("passed") is True and not c.get("skipped") for c in checks))


def collect(args):
    candidates=[]
    for path in sorted(args.runs.glob("rkq-soak-*/soak-manifest.json")):
        data=json.loads(path.read_text())
        if data.get("profile")=="full": candidates.append((path.parent,data))
    result=dict(passed=False,production_ready=False,policy="latest full attempt only, never older best pass",long_soak_qualified=False)
    if not candidates:
        return dict(result,failure="no long-soak evidence")
    directory,manifest=candidates[-1]
    result.update(run=directory.name,evidence=str(directory))
    report_path=directory/"soak-report.json"
    if not report_path.exists():
        return dict(result,failure="long soak still running or incomplete")
    report=json.loads(report_path.read_text())
    sources={str(p.relative_to(original.ROOT)):original.digest(p) for p in original.source_inventory()}
    build=json.loads(args.binary.with_name(args.binary.name+".build.json").read_text())
    checks=dict(complete_long_run=completed(report,manifest),
        current_sources=manifest.get("source_sha256")==sources==build.get("source_sha256"),
        current_binary=manifest.get("binary_sha256")==original.digest(args.binary)==build.get("binary_sha256"),
        normal_unchanged_build=build.get("debug_symbols") is False and build.get("source_unchanged_during_build") is True,
        current_client=manifest.get("client_sha256")==original.digest(args.client),
        current_fixtures=bool(manifest.get("fixture_sha256")) and all(Path(p).is_file() and original.digest(p)==sha for p,sha in manifest.get("fixture_sha256",{}).items()),
        cleanup_ok=not (directory/"cleanup.jsonl").exists())
    review_failure=None
    try:
        lb=json.loads((directory/"lb-contract.json").read_text())
        checks["current_caddy"]=lb.get("binary_sha256")==original.digest(args.caddy)
        power=json.loads((directory/"power-state.json").read_text())
        checks["three_guests_stopped"]=len(power)==3 and all(p.get("stopped") is True for p in power)
        cleanup=json.loads((directory/'cleanup-verification.json').read_text())
        checks['guest_cleanup_verified_before_shutdown']=({r.get('node') for r in cleanup}=={1,2,3} and
            all(r.get('passed') is True and guest_cleanup_passed(r) for r in cleanup))
        resource=json.loads((directory/"resource-report.json").read_text())
        checks["resource_report_passed"]=resource_contract(resource)
        checks['resource_audit_history_matches']=resource.get('audit_history_sha256')==original.digest(directory/'connect-access.jsonl')
        drain=json.loads((directory/'connect-drain.json').read_text())
        checks['connect_drain_verified']=drain_contract(drain)
        continuous=json.loads((directory/"traffic-continuity.json").read_text())
        checks["three_continuous_paths"]=set(continuous)=={"direct","lb","connect"} and all(
            row.get("passed") is True and len(row.get("windows",[]))>=60 for row in continuous.values())
        # Preserve the original automated verdict. A recorded, evidence-bound
        # closeout finding must not be hidden by its narrower boolean gates.
        review_path=directory/"closeout-review.json"
        checks['closeout_review_present']=review_path.is_file()
        if review_path.exists():
            review=json.loads(review_path.read_text())
            checks["closeout_review_matches_evidence"]=(review.get("binary_sha256")==manifest.get("binary_sha256") and
                review.get("resource_samples_sha256")==original.digest(directory/"resources.jsonl") and
                review.get('resource_report_sha256')==original.digest(directory/'resource-report.json') and
                review.get('cleanup_verification_sha256')==original.digest(directory/'cleanup-verification.json') and
                review.get('connect_drain_sha256')==original.digest(directory/'connect-drain.json'))
            checks["closeout_review_passed"]=review.get("passed") is True
            if not checks["closeout_review_passed"]:
                review_failure=review.get("disposition") or "recorded closeout resource finding"
    except (OSError,ValueError):
        checks["complete_supporting_evidence"]=False
    passed=all(checks.values())
    return dict(result,passed=passed,long_soak_qualified=passed,checks=checks,
                failure=report.get("failure") if passed else report.get("failure") or review_failure or "incomplete, failed or stale current-artifact evidence")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("binary","client","caddy"): parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--runs",type=Path,default=original.HERE/".runs")
    args=parser.parse_args()
    result=collect(args)
    target=args.runs/"current-soak-acceptance.json"
    save(target,json.dumps(result,indent=2))
    print("PASS" if result["passed"] else "NOT QUALIFIED: "+str(result.get("failure")))
    print(target)
    return int(not result["passed"])


if __name__=="__main__": raise SystemExit(main())
