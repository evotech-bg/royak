"""Causal, offline feature extraction. Labels are never copied into features.

This is recovery/diagnostic data, NOT proof that random injected failures can be
predicted. Inference/training/control-plane integration is deliberately absent.
"""
import argparse
from collections import deque
import json
from pathlib import Path

from checker import read_jsonl, percentile


def build_rows(samples, events, run_id, window=10):
    completions = iter(sorted((e for e in events if e.get("kind") == "app_complete"), key=lambda e: e["elapsed_s"]))
    upcoming = next(completions, None)
    past = deque()
    for sample in sorted(samples, key=lambda s: s["elapsed_s"]):
        now = sample["elapsed_s"]
        while upcoming is not None and upcoming["elapsed_s"] <= now:
            past.append(upcoming)
            upcoming = next(completions, None)
        while past and past[0]["elapsed_s"] <= now - window:
            past.popleft()
        latencies = sorted(e["latency_ms"] for e in past)
        nodes = sample.get("nodes", [])
        yield dict(schema_version=1, run_id=run_id, elapsed_s=now,
                   features=dict(window_s=window, completed_requests=len(past),
                                 request_rate=len(past) / window,
                                 error_fraction=sum(e["status"] != 200 for e in past) / len(past) if past else None,
                                 latency_p95_ms=percentile(latencies, 95),
                                 reachable_control_nodes=sum(n["http_status"] == 200 for n in nodes),
                                 confirmed_leaders=sum(bool((n.get("raft") or {}).get("leaderConfirmed")) for n in nodes),
                                 cpu_percent=sample.get("cpu_percent"), memory_bytes=sample.get("memory_bytes")),
                   labels=dict(injector_phase=sample["phase"]),
                   purpose="diagnostic/recovery observations; not predictive validation")


def export(directory):
    directory = Path(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    rows = build_rows(read_jsonl(directory / "telemetry.jsonl"), read_jsonl(directory / "history.jsonl"), manifest["run_id"])
    destination = directory / "dataset.jsonl"
    with destination.open("w") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(export(parser.parse_args().directory))
