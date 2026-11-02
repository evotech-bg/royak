"""Actual NeuroPod processes/mounts/netns/retention. Owned Linux lab only."""
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error

BIN=Path(sys.argv[1]).resolve()
assert sys.platform.startswith("linux") and os.geteuid()==0 and os.environ.get("ROYAK_QUALIFICATION_NODE","").startswith("rkq-suites-"),"Owned Linux/root lab required"
HOME=Path(tempfile.mkdtemp(prefix="royak-neuro-gc-",dir="/var/lib/docker"))
ROOT=HOME/".royak";PODS=ROOT/"pods";STATE=HOME/"state.json"
TOKEN=secrets.token_hex(24)
ENV=dict(os.environ,HOME=str(HOME),ROYAK_STATE=str(STATE),ROYAK_DATA_DIR=str(ROOT),ROYAK_TOKEN=TOKEN,
         ROYAK_NO_DOCKER="1",DOCKER_HOST="unix:///does-not-exist-neuropod-test",ROYAK_NODE_NAME="neuro-gc-test")
with socket.socket() as sock:sock.bind(("127.0.0.1",0));PORT=sock.getsockname()[1]
URL=f"http://127.0.0.1:{PORT}";server=None;foreign=None;known={};passed=0;log=None

def run(*args,timeout=30):
    result=subprocess.run([str(x) for x in args],capture_output=True,text=True,env=ENV,timeout=timeout)
    assert result.returncode==0,(args[:3],result.stderr[-1000:])
    return result.stdout.strip()

def check(name,condition):
    global passed
    assert condition,name
    passed+=1;print("  ✓ "+name,flush=True)

def wait(fn,name,timeout=45):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        value=fn()
        if value:return value
        time.sleep(.15)
    raise AssertionError("Timed out: "+name)

def api(path,method="GET",body=None):
    req=urllib.request.Request(URL+path,None if body is None else json.dumps(body).encode(),
        {"Authorization":"Bearer "+TOKEN,"Content-Type":"application/json"},method=method)
    try:
        with urllib.request.urlopen(req,timeout=12) as response:return response.status,json.loads(response.read())
    except urllib.error.HTTPError as error:
        with error:return error.code,json.loads(error.read())

def start():
    global server,log
    log=(HOME/"server.log").open("a")
    server=subprocess.Popen([str(BIN),"watch","--runtime","neuropod","--interval","1","--port",str(PORT)],env=ENV,stdout=log,stderr=subprocess.STDOUT)
    def ready():
        assert server.poll() is None,"NeuroPod server exited"
        try:return api("/version")[0]==200
        except OSError:return False
    wait(ready,"NeuroPod API")

def birth(pid):
    try:
        fields=Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()
        return None if fields[0]=="Z" else int(fields[19])
    except (FileNotFoundError,ProcessLookupError):return None

def tree(pid):
    found={};queue=[pid]
    while queue:
        current=queue.pop();stamp=birth(current)
        if stamp is None:continue
        found[current]=stamp
        try:queue.extend(map(int,Path(f"/proc/{current}/task/{current}/children").read_text().split()))
        except FileNotFoundError:pass
    known.update(found);return found

def pod(name):
    try:meta=json.loads((PODS/name/"meta.json").read_text())
    except (FileNotFoundError,json.JSONDecodeError):return None
    process=meta.get("process",{})
    if not process:return None
    assert birth(process["pid"])==process["start_ticks"],"Actual NeuroPod process exited: "+name
    if not (PODS/name/"data/marker").exists():return None
    if len(tree(process["pid"]))<3:return None
    return meta

def deployment(ns,replicas):
    body=dict(apiVersion="apps/v1",kind="Deployment",metadata=dict(name="smoke",namespace=ns),spec={"replicas":replicas,"template":{"spec":{"containers":[{
        "name":"main","image":"alpine:3.22","resources":{"limits":{"memory":"16Mi"}},"command":["sh","-c","echo $ROYAK_NAMESPACE/$ROYAK_DEPLOYMENT > /data/marker; sleep 3600 & wait"]}]}}})
    code,data=api(f"/apis/apps/v1/namespaces/{ns}/deployments","POST",body)
    assert code in (200,201),(code,data)

def mounts(base):
    return [line.split()[4] for line in Path("/proc/self/mountinfo").read_text().splitlines() if Path(line.split()[4]).is_relative_to(base)]

def gone(name,meta,processes):
    net=meta["network"]
    return not (PODS/name).exists() and not mounts(PODS/name) and not Path("/var/run/netns",net["namespace"]).exists() and not Path("/sys/class/net",net["veth_host"]).exists() and all(birth(pid)!=stamp for pid,stamp in processes.items())

def retained(name,marker):
    disks=list((ROOT/"retained-neuropod-data"/name).glob("*/data.img"))
    assert len(disks)==1,(name,len(disks))
    assert not run("losetup","-j",disks[0]),"retained disk is still attached to a loop device"
    target=HOME/"retained-check";target.mkdir(exist_ok=True)
    run("mount","-o","loop,ro",disks[0],target)
    try:assert (target/"marker").read_text().strip()==marker
    finally:run("umount",target)
    return disks[0]

def main():
    global foreign,server,log
    for tool in ("unshare","mount","umount","mkfs.ext4","ip","losetup","curl","tar"):
        assert shutil.which(tool),"Missing Linux runtime prerequisite: "+tool
    check("Linux/root runtime prerequisites available without skips",True)
    check("runtime flags are available","neuropod" in run(BIN,"watch","--help") and "runtime" in run(BIN,"pull","--help"))
    pull=subprocess.run([str(BIN),"pull","--runtime","neuropod","alpine:3.22"],capture_output=True,text=True,env=ENV,timeout=120)
    if pull.returncode!=0 or not (ROOT/"images/alpine_3.22/manifest.json").exists():
        # Public image fixture only; retain the actual failure instead of a
        # misleading later cache assertion (the CLI used to return zero).
        print(pull.stdout,flush=True);print(pull.stderr,flush=True)
    assert pull.returncode==0,"OCI pull command failed"
    check("real OCI image cache populated without Docker socket",(ROOT/"images/alpine_3.22/manifest.json").exists())
    start()
    for ns in ("team-a","team-b"):
        assert api("/api/v1/namespaces","POST",dict(apiVersion="v1",kind="Namespace",metadata=dict(name=ns)))[0] in (200,201)
    deployment("team-a",2)
    a1="rk-team-a_smoke-1";a2="rk-team-a_smoke-2";b1="rk-team-b_smoke-1"
    for name in (a1,a2):wait(lambda name=name:pod(name),"initial team-a pod "+name,timeout=60)
    deployment("team-b",1)
    metas={name:wait(lambda name=name:pod(name),"actual running pod "+name,timeout=60) for name in (a1,a2,b1)}
    check("three actual NeuroPods run with namespace-correct data",all((PODS/name/"data/marker").read_text().strip()==metas[name]["owner"]["namespace"]+"/smoke" for name in metas))
    check("all NeuroPods have durable cluster/node/state/generation ownership",all(m["owner"]["node"]=="neuro-gc-test" and m["owner"]["state"]==str(STATE) and m["owner"]["generation"]>0 for m in metas.values()))
    check("metadata and requested 16 MiB data disks are private",all((PODS/name/"data.img").stat().st_size==16*1024*1024 and (PODS/name/"data.img").stat().st_mode&0o077==0 and (PODS/name/"meta.json").stat().st_mode&0o077==0 for name in metas))
    check("namespace-similar names have distinct network resources",len({m["network"]["veth_host"] for m in metas.values()})==3)
    check("pod process actually joins its recorded network namespace",all(os.stat(f'/proc/{m["process"]["pid"]}/ns/net').st_ino==os.stat('/var/run/netns/'+m["network"]["namespace"]).st_ino for m in metas.values()))
    check("private OverlayFS and data mounts really exist",all(len(mounts(PODS/name))>=3 for name in metas))
    old_a2=tree(metas[a2]["process"]["pid"])
    deployment("team-a",1)
    wait(lambda:gone(a2,metas[a2],old_a2),"scale-down complete process/mount/network GC")
    check("scale-down reclaims the excess pod and descendants",True)
    retained_a2=retained(a2,"team-a/smoke");check("scale-down retains a readable persistent data disk",True)
    check("scale-down detaches the loop device of the retained disk",not run("losetup","-j",retained_a2))
    deployment("team-a",2)
    replacement=wait(lambda:pod(a2),"new pod after scale-up")
    check("scale-up after GC does not reuse a surviving peer IP",replacement["network"]["ip"] not in {metas[a1]["network"]["ip"],metas[b1]["network"]["ip"]})
    check("scale-up uses a new process identity",replacement["process"]!=metas[a2]["process"])
    replacement_tree=tree(replacement["process"]["pid"]);deployment("team-a",1)
    wait(lambda:gone(a2,replacement,replacement_tree),"repeated scale-down GC")
    foreign=subprocess.Popen(["sleep","3600"]);foreign_birth=birth(foreign.pid)
    legacy=PODS/"legacy";legacy.mkdir();(legacy/"meta.json").write_text(json.dumps({"name":"legacy","pid":foreign.pid}));(legacy/"sentinel").write_text("keep")
    outside=HOME/"outside";outside.mkdir();(outside/"sentinel").write_text("keep");(PODS/"link").symlink_to(outside,target_is_directory=True)
    foreign_name="rk-team-x_smoke-1";other=PODS/foreign_name;other.mkdir()
    fake=json.loads(json.dumps(metas[a1]));fake["name"]=foreign_name;fake["owner"].update(cluster="foreign-cluster",namespace="team-x");(other/"meta.json").write_text(json.dumps(fake));(other/"sentinel").write_text("keep")
    check("same-name deployment in another namespace stays live",pod(b1) is not None)
    check("remaining desired replica stays live",pod(a1) is not None)
    before=metas[a1]["process"]
    server.kill();server.wait(timeout=5);log.close();start()
    check("controller restart does not recreate a live owned pod",wait(lambda:pod(a1),"pod survives controller restart")["process"]==before)
    processes=tree(before["pid"])
    assert api("/apis/apps/v1/namespaces/team-a/deployments/smoke","DELETE")[0]==200
    wait(lambda:gone(a1,metas[a1],processes),"deleted workload complete GC after controller restart")
    check("deleted workload is reclaimed after controller restart",True)
    retained(a1,"team-a/smoke");check("deletion retains actual data rather than destroying it",True)
    check("foreign cluster and unowned directories are preserved",(other/"sentinel").read_text()=="keep" and (legacy/"sentinel").read_text()=="keep")
    check("symlink target outside pod inventory is untouched",(outside/"sentinel").read_text()=="keep")
    check("unrelated live process is never signalled",birth(foreign.pid)==foreign_birth)
    stale=PODS/"rk-team-a_smoke-9";stale.mkdir();stale_meta=json.loads(json.dumps(metas[a1]));stale_meta["name"]=stale.name
    stale_meta.pop("network");stale_meta["process"].update(pid=foreign.pid,start_ticks=foreign_birth+1)
    (stale/"meta.json").write_text(json.dumps(stale_meta))
    wait(lambda:not stale.exists(),"stale PID record reclaimed without signalling its recycled PID")
    check("recycled PID metadata cannot kill an unrelated process",birth(foreign.pid)==foreign_birth)
    b_processes=tree(metas[b1]["process"]["pid"])
    assert api("/apis/apps/v1/namespaces/team-b/deployments/smoke","DELETE")[0]==200
    wait(lambda:gone(b1,metas[b1],b_processes),"second namespace deletion GC")
    check("second namespace is reclaimed only after its own deletion",True)
    check("shared image cache survives every workload deletion",(ROOT/"images/alpine_3.22/rootfs/bin/sh").exists())
    time.sleep(2)
    check("repeated GC ticks are idempotent",not (PODS/a1).exists() and not (PODS/a2).exists() and not (PODS/b1).exists() and birth(foreign.pid)==foreign_birth)

try:
    main()
    print(f"Results: {passed} passed, 0 failed, 0 skipped",flush=True)
except BaseException:
    for path in PODS.glob("*/neuropod.log"):
        print(path.parent.name+": "+path.read_text()[-3000:].replace(TOKEN,"[REDACTED]"),flush=True)
    if (HOME/"server.log").exists():print((HOME/"server.log").read_text()[-7000:].replace(TOKEN,"[REDACTED]"),flush=True)
    raise
finally:
    if server and server.poll() is None:server.kill();server.wait(timeout=5)
    if log:log.close()
    for pid,stamp in known.items():
        if birth(pid)==stamp:
            try:os.kill(pid,signal.SIGKILL)
            except ProcessLookupError:pass
    if foreign and foreign.poll() is None:foreign.kill();foreign.wait(timeout=5)
    for mount in sorted(mounts(HOME),key=len,reverse=True):subprocess.run(["umount",mount],capture_output=True)
    for path in PODS.glob("*/meta.json"):
        try:
            net=json.loads(path.read_text()).get("network",{})
            if net.get("namespace","").startswith("rk-np-"):subprocess.run(["ip","netns","del",net["namespace"]],capture_output=True)
            if net.get("veth_host","").startswith("vh"):subprocess.run(["ip","link","del",net["veth_host"]],capture_output=True)
        except (OSError,ValueError):pass
    if not mounts(HOME):shutil.rmtree(HOME)
