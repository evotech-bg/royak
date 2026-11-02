"""Offline, conservative history checker. Not a linearizability proof."""
import json
import math
from pathlib import Path


def check_history(events, ledger):
    acknowledgements = [e for e in events if e.get("kind") == "app_complete" and e.get("status") == 200]
    errors = []
    for event in acknowledgements:
        if event.get("returned_id") != event["id"] or event.get("returned_value") != event["value"]:
            errors.append({"type": "wrong_response", "id": event["id"]})
        if ledger.get(event["id"]) != event["value"]:
            errors.append({"type": "lost_or_corrupt_acknowledged_write", "id": event["id"]})
    return {"passed": bool(acknowledgements) and not errors,
            "acknowledged": len(acknowledgements), "ledger_entries": len(ledger),
            "ambiguous_or_failed": sum(e.get("kind") == "app_complete" and e.get("status") != 200 for e in events),
            "errors": errors, "claim": "acknowledged application writes survive in an external ledger"}


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def percentile(values, percent):
    values = sorted(values)
    return values[max(0, math.ceil(percent / 100 * len(values)) - 1)] if values else None


def summarize(events):
    phases = {}
    for event in events:
        if event.get("kind") != "app_complete":
            continue
        bucket = phases.setdefault(event["phase"], {"requests": 0, "successes": 0, "latencies": [], "nodes": set()})
        bucket["requests"] += 1
        if event["status"] == 200:
            bucket["successes"] += 1
            bucket["nodes"].add(event["node"])
        bucket["latencies"].append(event["latency_ms"])
    result = {}
    for phase, bucket in phases.items():
        values = sorted(bucket["latencies"])
        result[phase] = dict(requests=bucket["requests"], successes=bucket["successes"],
                             availability=bucket["successes"] / bucket["requests"],
                             successful_ingress_nodes=sorted(bucket["nodes"]),
                             latency_quantile_method="nearest-rank",
                             latency_ms={"p" + str(p): percentile(values, p) for p in (50, 95, 99)})
    return result
