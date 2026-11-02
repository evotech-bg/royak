"""Real offline CLI admission/persistence regressions. No Docker daemon is used."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def resource(kind, name, spec, ns="a"):
    return dict(apiVersion="v1", kind=kind, metadata=dict(name=name, namespace=ns), spec=spec)


def collect(binary):
    checks = []
    with tempfile.TemporaryDirectory(prefix="rkq-storage-cli-") as directory:
        root = Path(directory)
        source = root / "state.json"
        data = root / "data"
        env = dict(HOME=str(root), PATH=os.environ.get("PATH", ""), ROYAK_STATE=str(source),
                   ROYAK_DATA_DIR=str(root / 'runtime'), ROYAK_NO_DOCKER="1", DOCKER_HOST="unix://" + str(root / "missing.sock"))

        def execute(action, *args, body=None):
            return subprocess.run([str(binary.resolve()), action, *args], input=body, capture_output=True,
                                  text=True, env=env, timeout=15)

        def apply(*objects):
            return execute("apply", "-", body="\n---\n".join(json.dumps(obj) for obj in objects))

        def state():
            return json.loads(source.read_text())["state"]

        def check(name, passed):
            checks.append(dict(name=name, passed=bool(passed)))

        def pv(name, size):
            return resource("PersistentVolume", name, dict(capacity=dict(storage=size), hostPath=dict(path=str(data / name))))

        def claim(name, size, ns="a"):
            return resource("PersistentVolumeClaim", name, dict(resources=dict(requests=dict(storage=size))), ns)

        r = apply(pv("small", "512Mi"), claim("data", "1Gi"))
        check("undersized PV remains Available; claim Pending across CLI restart", r.returncode == 0
              and state()["pvcs"]["a/data"]["bound_pv"] is None and state()["pvs"]["small"]["status"] == "Available")
        r = apply(pv("large", "2Gi"), claim("data", "1Gi"))
        check("sufficient capacity binds persistently", r.returncode == 0 and state()["pvcs"]["a/data"]["bound_pv"] == "large")
        r = apply(pv("large", "2Gi"))
        check("PV reapply preserves reciprocal owner", r.returncode == 0 and state()["pvs"]["large"]["bound_to"] == "a/data")
        before = source.read_bytes()
        reserved=resource('PersistentVolume','reserved',dict(
            capacity=dict(storage='1Gi'),hostPath=dict(path=str(root/'runtime'/'pools'))))
        rejected=apply(reserved)
        check('reserved runtime roots cannot become legacy host-path PVs',rejected.returncode!=0 and source.read_bytes()==before)
        r = apply(claim("data", "3Gi"))
        check("bound claim expansion returns failure without state mutation", r.returncode != 0 and source.read_bytes() == before)
        r = apply(resource("ConfigMap", "must-not-commit", {}), pv("bad", "-1Gi"))
        check("invalid multi-document input is rejected before any partial commit", r.returncode != 0 and source.read_bytes() == before)
        r = apply(claim("other", "1Gi", "b"))
        check("another namespace cannot bind an already-owned PV", r.returncode == 0 and state()["pvcs"]["b/other"]["bound_pv"] is None)
        r = execute("delete", "pvc/a/data")
        r2 = apply(pv("large", "2Gi"), claim("recreated", "1Gi"))
        check("Released data is not rearmed by reapply", r.returncode == 0 and r2.returncode == 0
              and state()["pvs"]["large"]["status"] == "Released" and state()["pvcs"]["a/recreated"]["bound_pv"] is None)
        sc = resource("StorageClass", "local", dict(hostPathPrefix=str(data / "dynamic"), reclaimPolicy="Retain"))
        r = apply(sc, claim("dynamic", "1Gi"))
        first = state()["pvcs"]["a/dynamic"]["bound_pv"]
        first_path = state()["pvs"][first]["host_path"]
        r2 = apply(sc)
        r3 = execute("delete", "pvc/a/dynamic")
        r4 = apply(claim("dynamic", "1Gi"))
        second = state()["pvcs"]["a/dynamic"]["bound_pv"]
        check("same-name dynamic claim gets fresh path and keeps retained predecessor", all(x.returncode == 0 for x in (r,r2,r3,r4))
              and first != second and state()["pvs"][first]["status"] == "Released"
              and first_path != state()["pvs"][second]["host_path"])
        before = source.read_bytes()
        r = apply(resource("StorageClass", "local", dict(hostPathPrefix=str(data / "other"), reclaimPolicy="Delete")))
        check("class reapply cannot reset provisioning or change retained-data policy", r.returncode != 0 and source.read_bytes() == before)
    return checks


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.output.exists(): p.error("refusing to overwrite earlier evidence")
    try:
        checks = collect(a.binary)
    except Exception as error:
        checks = [dict(name='fixture completion',passed=False,error=type(error).__name__+': '+str(error))]
    report = dict(passed=all(row["passed"] for row in checks), checks=checks,
                  binary_sha256=hashlib.sha256(a.binary.read_bytes()).hexdigest(),
                  fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  scope="offline admission and persistence only; not replicated-volume qualification")
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__": main()
