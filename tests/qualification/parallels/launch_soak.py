#!/usr/bin/env python3
"""Launch one durable two-hour-or-longer local run; no scheduler or public target."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

from bootstrap import save, verify_owner, ssh


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("inventory","binary","client","caddy"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--duration",type=int,default=7200)
    args=parser.parse_args()
    if args.duration<7200: parser.error("long soak must be at least 7200 seconds")
    inventory=json.loads(args.inventory.read_text())
    if inventory.get("kind")!="royak-parallels-lab-v1" or len(inventory.get("nodes",[]))!=3:
        parser.error("need existing owned three-VM inventory")
    root=args.inventory.resolve().parent
    for node in inventory["nodes"]:
        info=verify_owner(root,node)
        if info.get("State")!="stopped":
            active=ssh(root,node,"sudo systemctl is-active royak-qualification.service || true").strip()
            if active=="active": parser.error("qualification already active; no duplicate launched")
    here=Path(__file__).resolve().parent
    launch="soak-launch-"+time.strftime("%Y%m%d-%H%M%S")+"-"+secrets.token_hex(3)
    log=here.parent/".runs"/(launch+".log")
    record=log.with_suffix(".json")
    command=["caffeinate","-i",sys.executable,"-u","-B",str(here/"soak.py")]
    for name in ("inventory","binary","client","caddy"):
        command += ["--"+name,str(getattr(args,name).resolve())]
    command += ["--profile","full","--duration",str(args.duration)]
    fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w") as stream:
        process=subprocess.Popen(command,stdout=stream,stderr=subprocess.STDOUT,start_new_session=True,
                                 cwd=here.parents[2])
    value=dict(pid=process.pid,launched_at=time.time(),duration_seconds=args.duration,log=str(log),
               command=command,inventory=str(args.inventory.resolve()),status="launched, not qualified")
    save(record,json.dumps(value,indent=2))
    print(json.dumps(dict(launch_record=str(record),**value),indent=2))


if __name__=="__main__":
    main()
