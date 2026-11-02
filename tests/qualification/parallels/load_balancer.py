#!/usr/bin/env python3
"""External Caddy LB plus independent direct-node traffic during real VM faults."""
import argparse
import json
import os
from pathlib import Path
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request

from bootstrap import run, save
from qualify import VMFaultLab, local_port, original
from checker import check_history, read_jsonl, summarize


class LBVMFaultLab(VMFaultLab):
    def __init__(self, args):
        super().__init__(args)
        self.lb_process = None
        self.lb_log = None
        self.lb_thread = None
        self.lb_error = None
        self.lb_url = None

    def deploy(self):
        super().deploy()
        # Pin the actual ingress leaf out of band over authenticated SSH (even
        # when API and ingress share it), never by trusting an
        # unauthenticated network discovery or disabling TLS verification.
        ca = "".join(self.remote(n, ["sh", "-ec", "openssl s_client -connect 127.0.0.1:8080 -servername localhost </dev/null 2>/dev/null | openssl x509 -outform PEM"]) for n in self.nodes)
        save(self.out / "backend-ca.pem", ca)
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
            "-subj", "/CN=Royak isolated LB test", "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", self.out / "lb.key", "-out", self.out / "lb.pem")
        (self.out / "lb.key").chmod(0o600)
        self.lb_context = ssl.create_default_context(cafile=str(self.out / "lb.pem"))
        self.lb_url = "https://127.0.0.1:" + str(local_port())
        upstreams = " ".join("https://" + n["ip"] + ":8080" for n in self.nodes)
        config = """{
 admin off
 auto_https off
}
%s {
 bind 127.0.0.1
 tls %s %s
 reverse_proxy %s {
  lb_policy round_robin
  lb_retries 0
  lb_try_duration 0
  health_uri /health
  health_headers {
   Host qualification.test
  }
  health_interval 500ms
  health_timeout 1s
  health_fails 2
  health_passes 2
  health_status 200
  fail_duration 2s
  max_fails 1
  transport http {
   tls_trust_pool file %s
   tls_server_name localhost
   tls_timeout 1s
   dial_timeout 800ms
   response_header_timeout 3s
   keepalive off
   versions 1.1
  }
  header_down X-Royak-Test-Backend {http.reverse_proxy.upstream.hostport}
  header_up Host qualification.test
 }
 log {
  output file %s
  format json
 }
}
""" % (self.lb_url, self.out / "lb.pem", self.out / "lb.key", upstreams,
       self.out / "backend-ca.pem", self.out / "lb-access.jsonl")
        save(self.out / "Caddyfile", config)
        environment = dict(os.environ, XDG_DATA_HOME=str(self.out / "caddy-data"),
                           XDG_CONFIG_HOME=str(self.out / "caddy-config"))
        validated = run(self.args.caddy, "validate", "--config", self.out / "Caddyfile", "--adapter", "caddyfile", env=environment)
        save(self.out / "lb-validation.log", validated)
        self.lb_log = (self.out / "lb-runtime.jsonl").open("w")
        self.lb_process = subprocess.Popen([str(self.args.caddy), "run", "--config", str(self.out / "Caddyfile"), "--adapter", "caddyfile"],
                                           env=environment, stdout=self.lb_log, stderr=self.lb_log)
        original.wait_for(lambda: self.lb_request("GET", "/health")[0] == 200, "verified TLS LB health", timeout=30)
        self.check("external LB uses one stable loopback TLS address and verified TLS to all VM backends", True)
        save(self.out / "lb-contract.json", json.dumps(dict(
            implementation=run(self.args.caddy, "version").strip(), binary_sha256=original.digest(self.args.caddy),
            frontend=self.lb_url, backends=[n["ip"] + ":8080" for n in self.nodes],
            health_interval_ms=500, unhealthy_after_failures=2, healthy_after_passes=2,
            retries=0, post_payload_replay=False, upstream_keepalive=False,
            baseline_availability=.99, vm_fault_window_availability=.95, final_availability=.99,
            lb_failure_domain="Mac outside the three guests, not redundant LB HA"), indent=2))

    def lb_request(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.lb_url + path, data,
                {"Content-Type": "application/json"}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=3, context=self.lb_context) as response:
                return response.status, json.load(response), response.headers.get("X-Royak-Test-Backend")
        except urllib.error.HTTPError as error:
            with error:
                return error.code, {}, error.headers.get("X-Royak-Test-Backend")
        except (OSError, TimeoutError, ValueError):
            return 0, {}, None

    def lb_loop(self):
        try:
            sequence = 0
            while not self.stop.is_set():
                ident = self.run + "-lb-" + str(sequence)
                value = original.hashlib.sha256(ident.encode()).hexdigest()
                started = time.monotonic()
                self.event("lb-history.jsonl", kind="app_invoke", id=ident, value=value, node=0)
                code, body, backend = self.lb_request("POST", "/write", dict(id=ident, value=value))
                self.event("lb-history.jsonl", kind="app_complete", id=ident, value=value, node=0,
                           status=code, returned_id=body.get("id"), returned_value=body.get("value"),
                           instance=body.get("instance"), selected_backend=backend,
                           latency_ms=round((time.monotonic() - started) * 1000, 3))
                sequence += 1
                self.stop.wait(max(0, 1 / self.args.rate - (time.monotonic() - started)))
        except BaseException as error:
            self.lb_error = type(error).__name__ + ": " + str(error)
            self.stop.set()

    def client(self):
        self.lb_thread = threading.Thread(target=self.lb_loop, daemon=True)
        self.lb_thread.start()
        try:
            super().client()
        finally:
            self.lb_thread.join(timeout=8)

    def observe(self, seconds):
        if self.lb_process and self.lb_process.poll() is not None:
            raise RuntimeError("external LB exited; inspect lb-runtime.jsonl")
        if self.lb_error:
            raise RuntimeError("LB client failed: " + self.lb_error)
        super().observe(seconds)

    def select_vm_outage_target(self, candidates):
        def eligible():
            with self.lock:
                events = read_jsonl(self.out / "lb-history.jsonl")
            now = time.monotonic() - self.started
            serving = {e.get("selected_backend") for e in events if e.get("status") == 200
                       and now - e.get("elapsed_s", 0) <= 3}
            return [(node, ids) for node, ids in candidates if node["ip"] + ":8080" in serving]
        choices = original.wait_for(eligible, "occupied VM actively serving through LB before hard stop", timeout=15)
        selected = self.random.choice(choices)
        self.check("hard-stopped VM is an actively serving LB backend", True, node=selected[0]["id"],
                   evidence="successful LB response from this ingress in preceding three seconds")
        return selected

    def verify(self):
        super().verify()
        events = read_jsonl(self.out / "lb-history.jsonl")
        ledger = json.loads((self.out / "ledger.json").read_text())
        result = check_history(events, ledger)
        performance = summarize(events)
        save(self.out / "lb-performance.json", json.dumps(performance, indent=2))
        self.check("LB client and process remained live through all VM faults", not self.lb_error and self.lb_process.poll() is None)
        self.check("all acknowledged LB writes survive exactly in the independent ledger", result["passed"], **{k:v for k,v in result.items() if k != "passed"})
        self.check("LB healthy baseline and final observation meet declared 99 percent threshold",
                   performance.get("baseline", {}).get("availability", 0) >= .99 and
                   performance.get("soak", {}).get("availability", 0) >= .99, observed=performance)
        self.check("LB VM-hard-stop window meets declared 95 percent threshold",
                   performance.get("node-restart", {}).get("availability", 0) >= .95, observed=performance.get("node-restart"))
        baseline_backends = sorted({e.get("selected_backend") for e in events if e.get("phase") == "baseline" and e.get("status") == 200})
        expected = sorted(n["ip"] + ":8080" for n in self.nodes)
        self.check("stable LB address actually distributed successful requests to all three VM ingresses", baseline_backends == expected, backends=baseline_backends)
        self.check("LB continued serving during each injected fault", all(performance.get(phase, {}).get("successes", 0) > 0 for phase in ("pod-kill", "leader-sigkill", "control-partition", "node-restart")))
        final_backends = sorted({e.get("selected_backend") for e in events if e.get("phase") == "soak" and e.get("status") == 200})
        self.check("recovered VM rejoined LB rotation", final_backends == expected, backends=final_backends)

    def cleanup(self):
        super().cleanup()
        if self.lb_process:
            self.lb_process.terminate()
            try:
                self.lb_process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.lb_process.kill()
                self.lb_process.wait()
        if self.lb_log:
            self.lb_log.close()
        # The ephemeral frontend key is not needed in the evidence bundle.
        (self.out / "lb.key").unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--caddy", type=Path, required=True)
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()
    args.client, args.caddy = args.client.resolve(), args.caddy.resolve()
    for key, value in dict(seed=42, probe_mode="http", ui_check=False, rate=5, settle=20,
                           node_outage=45, baseline_availability=.99).items():
        setattr(args, key, value)
    lab = LBVMFaultLab(args)
    sources = {str(p.relative_to(original.ROOT)): original.digest(p) for p in original.source_inventory()}
    fixtures = {str(p): original.digest(p) for p in (Path(__file__), Path(__file__).with_name("qualify.py"))}
    result = lab.execute()
    report = json.loads((lab.out / "report.json").read_text())
    if sources != {str(p.relative_to(original.ROOT)): original.digest(p) for p in original.source_inventory()} or fixtures != {p: original.digest(p) for p in fixtures}:
        result = 1
        report.update(passed=False, failure="source or LB fixture changed during test")
    if (lab.out / "cleanup.jsonl").exists():
        result = 1
        report.update(passed=False, failure=report.get("failure") or "owned cleanup failed")
    report.update(topology="external-Caddy-LB-three-Parallels-kernels-one-physical-Mac", production_ready=False,
                  binary_sha256=original.digest(args.binary), source_sha256=sources, fixture_sha256=fixtures,
                  qualification="bounded multi-VM application LB fault test; Connect stability is a separate gate")
    save(lab.out / "lb-report.json", json.dumps(report, indent=2))
    print(lab.out / "lb-report.json", flush=True)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
