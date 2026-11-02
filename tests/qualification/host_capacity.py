"""Read-only host capacity preflight, including macOS reclaimable-space totals.

This estimates allocation headroom. It does not reserve space, force purging,
delete caches/snapshots, or prove that any raw-free-space floor was maintained.
Existing qualification artifacts with a raw-space prerequisite remain unchanged.
"""
import argparse
import datetime
import json
from pathlib import Path
import shutil
import subprocess
import sys

GIB = 1024 ** 3
MAX_BYTES = 2 ** 63 - 1
APPLE_CAPACITY = "https://developer.apple.com/documentation/foundation/checking-volume-storage-capacity"
JXA = r'''ObjC.import("Foundation");
function run(argv) {
  var url = $.NSURL.fileURLWithPath(argv[0]);
  var out = {};
  var names = {
    immediate: "NSURLVolumeAvailableCapacityKey",
    important: "NSURLVolumeAvailableCapacityForImportantUsageKey",
    opportunistic: "NSURLVolumeAvailableCapacityForOpportunisticUsageKey",
    total: "NSURLVolumeTotalCapacityKey"
  };
  Object.keys(names).forEach(function(name) {
    var value = Ref(); var error = Ref();
    var ok = url.getResourceValueForKeyError(value, $[names[name]], error);
    out[name] = ok ? ObjC.unwrap(value[0]) : null;
  });
  return JSON.stringify(out);
}'''


def byte_count(value):
    return type(value) is int and 0 <= value <= MAX_BYTES


def allocation_capacity(raw, total, foundation=None):
    """Foundation values are totals, never additional bytes to add to raw."""
    if not byte_count(raw) or not byte_count(total) or raw > total:
        raise ValueError("invalid raw filesystem capacity")
    if isinstance(foundation, dict) and all(
            byte_count(foundation.get(key)) for key in
            ("immediate", "important", "opportunistic", "total")):
        if (foundation["total"] == total and
                all(raw <= foundation[key] <= total for key in
                    ("important", "opportunistic")) and
                foundation["immediate"] <= total):
            return min(foundation["important"], foundation["opportunistic"]), "macOS-reclaimable-aware-estimate"
    return raw, "raw-free-fallback"


def measure(path):
    path = Path(path).resolve(strict=True)
    before = path.stat().st_dev
    usage = shutil.disk_usage(path)
    foundation = None
    error = None
    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/usr/bin/osascript", "-l", "JavaScript", "-e", JXA, str(path)],
                capture_output=True, text=True, timeout=15, check=True)
            if len(result.stdout) > 4096:
                raise ValueError("unexpectedly large capacity response")
            foundation = json.loads(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError):
            error = "Foundation observation unavailable; used raw free space"
    after = path.stat().st_dev
    if before != after:
        raise RuntimeError("filesystem changed during capacity observation")
    effective, basis = allocation_capacity(usage.free, usage.total, foundation)
    return dict(path=str(path), device=before, total_bytes=usage.total,
                raw_free_bytes=usage.free, foundation=foundation,
                allocation_available_bytes=effective, basis=basis,
                observation_error=error)


def assess(samples, planned_bytes, reserve_bytes=32 * GIB):
    if not samples or not byte_count(planned_bytes) or not byte_count(reserve_bytes):
        raise ValueError("need observed volumes and valid planned/reserved byte counts")
    # Repeated paths or shared APFS pools must never multiply headroom. Require
    # each actual write location to fit the entire conservative write envelope.
    observed = [sample.get("allocation_available_bytes") for sample in samples]
    if not all(byte_count(value) for value in observed):
        raise ValueError("invalid observed allocation capacity")
    available = min(observed)
    return dict(admitted=available - planned_bytes >= reserve_bytes,
                planned_bytes=planned_bytes, reserve_bytes=reserve_bytes,
                minimum_allocation_available_bytes=available, samples=samples,
                capacity_is_estimate_not_reservation=True,
                raw_free_floor_verified=False,
                method="minimum across locations, not summed capacity",
                apple_capacity_reference=APPLE_CAPACITY)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, action="append", required=True,
                        help="existing actual write location; repeat for output/TMP/Docker backing")
    parser.add_argument("--planned-gib", type=int, required=True)
    parser.add_argument("--output", type=Path, help="new evidence file, never overwritten")
    args = parser.parse_args()
    report = assess([measure(path) for path in args.path], args.planned_gib * GIB)
    report["observed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    text = json.dumps(report, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(text)
    print(text, end="")
    return int(not report["admitted"])


if __name__ == "__main__":
    raise SystemExit(main())
