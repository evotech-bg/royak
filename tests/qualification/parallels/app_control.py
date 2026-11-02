#!/usr/bin/env python3
"""Control: same 64 MiB/250m Python fixture, eight direct TCP streams, no Connect."""
import argparse
import json
from pathlib import Path
import secrets
import shlex
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from connect_e2e import APP
from bootstrap import ssh, verify_owner, save


def main(inventory):
    root = inventory.resolve().parent
    node = json.loads(inventory.read_text())["nodes"][2]
    verify_owner(root, node)
    ident = "rkq-app-control-" + secrets.token_hex(4)
    out = root.parent / ident
    out.mkdir(mode=0o700)
    def remote(*args):
        return ssh(root, node, "sudo " + shlex.join(args))
    result = dict(run=ident, scope="application-only control, not Connect acceptance", passed=False)
    try:
        remote("docker", "run", "-d", "--name", ident, "--label", "royak.qualification=" + ident,
               "--memory", "64m", "--cpus", "0.25", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--user", "10001:10001", "-e", "MARKER=TEAM_A",
               "python:3.13-alpine", "python3", "-u", "-c", APP)
        address = remote("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", ident).strip()
        script = """import socket,time
time.sleep(1)
sockets=[socket.create_connection(('ADDRESS',9090),3) for _ in range(8)]
for s in sockets:
 s.sendall(b'first'); data=b''
 while len(data)<12:
  part=s.recv(128);assert part;data+=part
 assert data==b'TEAM_A\\nfirst',data
for i in range(100):
 for s in sockets:
  s.sendall(b'control');data=b''
  while len(data)<7:
   part=s.recv(7-len(data));assert part;data+=part
  assert data==b'control'
 time.sleep(.05)
for s in sockets:s.close()
print('PASS: eight direct streams, 800 echoes under identical limits')
""".replace("ADDRESS", address)
        result["traffic"] = remote("python3", "-c", script)
        result["state"] = json.loads(remote("docker", "inspect", "-f", "{{json .State}}", ident))
        result["stats"] = remote("docker", "stats", "--no-stream", "--format", "{{json .}}", ident)
        result["passed"] = result["state"]["Running"] and not result["state"]["OOMKilled"]
    except Exception as error:
        result["error"] = str(error)
    finally:
        if remote("docker", "inspect", "-f", '{{index .Config.Labels "royak.qualification"}}', ident).strip() == ident:
            remote("docker", "rm", "-f", ident)
        save(out / "report.json", json.dumps(result, indent=2))
    print(out / "report.json")
    print("PASS" if result["passed"] else "FAIL")
    return int(not result["passed"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    raise SystemExit(main(parser.parse_args().inventory))
