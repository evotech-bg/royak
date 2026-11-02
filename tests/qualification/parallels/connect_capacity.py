#!/usr/bin/env python3
"""Focused real-VM eight-stream reproducer, not full Connect acceptance."""
import argparse
import json
from pathlib import Path
import time
from qualify import VMConnectLab, connect, original
from bootstrap import save


class CapacityLab(VMConnectLab):
    def scenarios(self):
        self.resource("Namespace", "team-a")
        for i in range(3):
            self.app("app" + str(i))
        self.gateway = original.wait_for(self.leader, "capacity issuer")
        def remote():
            return next((p for p in self.pods("team-a") if p["spec"]["nodeName"] != "q-n" + str(self.gateway["id"])
                         and any(c.get("ready") for c in p["status"]["containerStatuses"])), None)
        pod = original.wait_for(remote, "actual Ready remote capacity backend")
        self.backend_node = next(n for n in self.nodes if "q-n" + str(n["id"]) == pod["spec"]["nodeName"])
        owner = pod["metadata"]["labels"]["app"]
        self.resource("Service", "api", {"selector": {"app": owner}, "ports": [{"port": 80, "targetPort": 9090}]})
        self.grant()
        original.wait_for(lambda: self.service_converged(owner), "capacity Service committed everywhere")
        self.ca = self.out / "gateway-ca.pem"
        self.transport("cp", self.gateway["name"] + ":/root/.kube/royak-ca.pem", str(self.ca))
        for cycle in range(self.args.cycles):
            self.event("capacity.jsonl", action="cycle-start", cycle=cycle)
            ident = self.session(ttl=120)
            sockets = [self.stream(ident) for _ in range(8)]
            for stream in sockets:
                self.echo(stream)
            self.stream(ident, expected=429)
            end = time.monotonic() + 3
            while time.monotonic() < end:
                for stream in sockets:
                    self.live(stream)
                time.sleep(.1)
            self.check(f"cycle {cycle}: eight remote streams transfer and stay open", self.call("GET", self.cp() + "/" + ident)[1]["active_connections"] == 8)
            self.call("DELETE", self.cp() + "/" + ident)
            self.check(f"cycle {cycle}: one revoke closes all eight streams", all(self.closed(s) for s in sockets))
            for stream in sockets:
                stream.close()

    def diagnostics(self):
        super().diagnostics()
        if hasattr(self, "gateway"):
            try:
                code, data = self.call("GET", "/royak/v1/connect/namespaces/team-a/audit")
                if code == 200:
                    save(self.out / "issuer-audit.json", json.dumps(data, indent=2))
            except Exception:
                pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--cycles", type=int, default=12)
    args = parser.parse_args()
    args.client = args.client.resolve()
    for key, value in dict(seed=42, probe_mode="http", ui_check=False, rate=5, settle=20, duration=60,
                           node_outage=45, baseline_availability=.99).items():
        setattr(args, key, value)
    lab = CapacityLab(args)
    result = lab.execute_connect()
    path = lab.out / "connect-report.json"
    report = json.loads(path.read_text())
    report.update(focused_reproducer=True, topology="three-Parallels-kernels-one-Mac; eight-stream reproducer",
                  vm_fixture_sha256=original.digest(Path(__file__)))
    save(lab.out / "capacity-report.json", json.dumps(report, indent=2))
    path.unlink()  # do not let a focused test masquerade as a complete suite
    print(lab.out / "capacity-report.json", flush=True)
    raise SystemExit(result)
