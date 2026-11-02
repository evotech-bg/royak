#!/usr/bin/env python3
"""Focused diagnosis, not remediation or release acceptance. No Royak state writes."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import time

from bootstrap import run,save,ssh,verify_owner
from pid_guest import CASES

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory',type=Path,required=True)
    parser.add_argument('--node',type=int,action='append',required=True)
    parser.add_argument('--iterations',type=int,default=40)
    args=parser.parse_args()
    if not 10<=args.iterations<=100:parser.error('iterations must be 10..100')
    if shutil.disk_usage(ROOT).free<20*1024**3:parser.error('need 20 GiB host reserve')
    root=args.inventory.resolve().parent
    inventory=json.loads(args.inventory.read_text())
    if inventory.get('kind')!='royak-parallels-lab-v1' or inventory.get('root')!=str(root):parser.error('invalid owned inventory')
    nodes=[n for n in inventory['nodes'] if n['id'] in set(args.node)]
    if len(nodes)!=len(set(args.node)):parser.error('unknown/duplicate node selection')
    ident='rkq-pid-'+time.strftime('%Y%m%d-%H%M%S')+'-'+secrets.token_hex(3)
    out=root.parent/ident;out.mkdir(mode=0o700)
    print('Evidence: '+str(out),flush=True)
    source_files=[ROOT/'src/probe-watchdog.sh',ROOT/'src/docker.rs',HERE/'pid_census.py',HERE/'pid_guest.py',Path(__file__),HERE.parent/'workload.py']
    hashes={str(p):digest(p) for p in source_files}
    app=(HERE.parent/'workload.py').read_text().replace('class Handler(BaseHTTPRequestHandler):','class Handler(BaseHTTPRequestHandler):\n    protocol_version = "HTTP/1.1"')
    report=dict(run=ident,scope='current watchdog primitive regressions and explicit no-init hard-kill negative control on owned VMs; product binary not executed',nodes=[],power=[],cleanup_errors=[],source_sha256=hashes,
                production_qualified=False,product_code_changed=False)
    started=[]
    def remote(node,*cmd,timeout=30):return ssh(root,node,'sudo -- '+shlex.join(str(x) for x in cmd),timeout=timeout)
    def put(node,path,data,mode='600'):
        command='sudo sh -ec '+shlex.quote('umask 077; tee '+shlex.quote(path)+' >/dev/null; chmod '+mode+' '+shlex.quote(path))
        run('ssh','-i',root/'operator','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
            '-o','UserKnownHostsFile='+str(root/'known_hosts'),'-o','ConnectTimeout=3','royak@'+node['ip'],command,
            input=data if isinstance(data,bytes) else data.encode())
    def execute(node):
        print('START VM '+str(node['id']),flush=True)
        before=verify_owner(root,node)
        if before.get('State')=='stopped':
            run('prlctl','start',node['uuid'],timeout=90);started.append(node)
        deadline=time.monotonic()+120
        while True:
            try:remote(node,'docker','info','--format','{{.ID}}',timeout=5);break
            except (RuntimeError,subprocess.SubprocessError):
                if time.monotonic()>deadline:raise
                time.sleep(1)
        if remote(node,'cat','/etc/royak-lab-owner').strip()!=inventory['run_id']:raise RuntimeError('guest ownership mismatch')
        active=remote(node,'sh','-ec','systemctl is-active royak-qualification.service || true').strip()
        if active=='active' or remote(node,'docker','ps','-aq').strip():raise RuntimeError('guest has existing qualification/workload; refusing changes')
        previous_lab=remote(node,'readlink','-f','/lab').strip()
        directory='/var/lib/royak-qualification/'+ident
        remote(node,'install','-d','-m','700',directory)
        put(node,directory+'/app.py',app,'644')
        for local,destination,mode in [(ROOT/'src/probe-watchdog.sh','watchdog.sh','644'),(HERE/'pid_census.py','pid_census.py','644'),(HERE/'pid_guest.py','pid_guest.py','600')]:
            put(node,directory+'/'+destination,local.read_bytes(),mode)
        image=remote(node,'docker','image','inspect','python:3.13-alpine','-f','{{.Id}}').strip()
        value=json.loads(remote(node,'python3',directory+'/pid_guest.py','--run-id',ident,'--directory',directory,'--iterations',str(args.iterations),timeout=360))
        value.update(node=node['id'],uuid=node['uuid'],image=image,kernel=remote(node,'uname','-r').strip(),
                     boot_id=remote(node,'cat','/proc/sys/kernel/random/boot_id').strip(),
                     previous_lab_unchanged=remote(node,'readlink','-f','/lab').strip()==previous_lab)
        raft=remote(node,'sh','-ec','if test -d /lab/state.json.raft; then du -sb /lab/state.json.raft; fi').strip()
        value['retained_raft_directory_apparent_bytes']=int(raft.split()[0]) if raft else None
        if remote(node,'docker','ps','-aq').strip():raise RuntimeError('diagnostic left a container')
        save(out/('node-'+str(node['id'])+'.json'),json.dumps(value,indent=2))
        print('DONE VM '+str(node['id'])+' '+str({r['case']:r.get('zombie_delta') for r in value['cases']}),flush=True)
        return value
    try:
        for node in nodes:verify_owner(root,node)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(nodes)) as pool:
            report['nodes']=list(pool.map(execute,nodes))
    except BaseException as error:report['failure']=type(error).__name__+': '+str(error)
    finally:
        # Recover only exact, label-verified names, including a timed-out guest driver.
        for node in nodes:
            try:
                for case in CASES:
                    name=ident+'-'+case
                    exists=remote(node,'docker','ps','-aq','--filter','name=^/'+name+'$').strip()
                    if exists:
                        owner=remote(node,'docker','inspect','-f','{{index .Config.Labels "royak.qualification"}}',name).strip()
                        if owner!=ident:raise RuntimeError('refusing foreign cleanup')
                        remote(node,'docker','rm','-f',name)
            except Exception as error:report['cleanup_errors'].append(str(error))
        for node in started:
            try:
                verify_owner(root,node)
                active=remote(node,'sh','-ec','systemctl is-active royak-qualification.service || true').strip()
                if active=='active' or remote(node,'docker','ps','-aq').strip():
                    raise RuntimeError('guest became busy; refusing to power off foreign work')
                try:remote(node,'systemctl','poweroff',timeout=15)
                except RuntimeError:pass
                deadline=time.monotonic()+30
                while time.monotonic()<deadline and verify_owner(root,node).get('State')!='stopped':time.sleep(1)
                report['power'].append(dict(node=node['id'],restored_stopped=verify_owner(root,node).get('State')=='stopped'))
            except Exception as error:report['cleanup_errors'].append(str(error))
        report['sources_unchanged']=hashes=={str(p):digest(p) for p in source_files}
        report['diagnosis_complete']=not report.get('failure') and not report['cleanup_errors'] and len(report['nodes'])==len(nodes) and all(n['completed'] and n['previous_lab_unchanged'] for n in report['nodes']) and all(p['restored_stopped'] for p in report['power']) and report['sources_unchanged']
        report['regression_passed']=report['diagnosis_complete'] and all(n.get('regression_passed') for n in report['nodes'])
        save(out/'report.json',json.dumps(report,indent=2))
    print(out/'report.json',flush=True)
    return int(not report['regression_passed'])


if __name__=='__main__':raise SystemExit(main())
