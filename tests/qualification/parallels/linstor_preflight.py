#!/usr/bin/env python3
"""Signed package/dependency evaluation only, in the three exact owned VMs.

Boots the idle owned lab, checks the existing pinned PPA trust anchor and
refreshes package indexes, then SIMULATES installation. No package install,
storage adoption/formatting, service start, host routes or public demo changes.
Normal closeout independently proves idle guests and stops all three again.
This is not a measured runtime-footprint comparison or backend selection.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from bootstrap import run,ssh,verify_owner
from storage_disks import wait_for
from storage_preflight import UUIDS,PPA_KEY


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    a=p.parse_args();os.umask(0o077)
    root=a.lab.resolve();inv=json.loads((root/'inventory.json').read_text())
    assert inv['root']==str(root) and inv['kind']=='royak-parallels-lab-v1'
    assert {n['uuid'] for n in inv['nodes']}==UUIDS
    if a.output_dir.exists():p.error('never overwrite prior evidence')
    if shutil.disk_usage(root).free<32*1024**3:raise RuntimeError('need 32 GiB raw free before bounded evaluation')
    # A new work owner must not silently reuse a VM that another test started.
    for n in inv['nodes']:assert verify_owner(root,n)['State']=='stopped'
    a.output_dir.mkdir(parents=True,mode=0o700)
    report=dict(kind='royak-linstor-package-preflight-v1',passed=False,created_at=time.time(),nodes=[],
        fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        package_installation=False,disks_changed=False,runtime_footprint_measured=False,backend_selected=False)
    booted=[]
    try:
        for n in inv['nodes']:
            verify_owner(root,n);run('prlctl','start',n['uuid'],timeout=90);booted.append(n)
        for n in inv['nodes']:
            wait_for(lambda:ssh(root,n,'printf ready',timeout=5).strip()=='ready',120)
            assert verify_owner(root,n)['State']=='running'
            command="""import hashlib,json,pathlib,subprocess
def run(*args):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT,timeout=120)
base=pathlib.Path('/var/lib/royak-storage-qualification/preflight-20261030')
fingerprints=run('gpg','--show-keys','--with-colons',str(base/'key.asc'))
assert %r in fingerprints
enabled=subprocess.run(['systemctl','is-enabled','drbd.service'],capture_output=True,text=True)
assert enabled.stdout.strip()=='disabled' and enabled.returncode in (0,1)
assert subprocess.run(['systemctl','is-active','royak-qualification.service'],capture_output=True,text=True).stdout.strip()=='inactive'
assert json.loads(run('drbdsetup','status','--json'))==[]
assert run('docker','ps','-aq').strip()==''
assert run('wg','show','interfaces').strip()==''
before=run('dpkg-query','-W')
def apt(program,*args):return run(program,'-o','Dir::Etc::sourcelist='+str(base/'ppa.list'),*args)
updates=apt('apt-get','update')
packages={}
for pkg in ['linstor-common','linstor-controller','linstor-satellite','linstor-client','python-linstor','openjdk-21-jre-headless']:
 policy=apt('apt-cache','policy',pkg)
 candidates=[line.split(':',1)[1].strip() for line in policy.splitlines() if line.strip().startswith('Candidate:')]
 assert len(candidates)==1 and candidates[0]!='(none)',(pkg,policy)
 version=candidates[0]
 metadata=apt('apt-cache','show',pkg+'='+version)
 fields={}
 for line in metadata.splitlines():
  if ': ' in line and not line.startswith(' '):
   key,value=line.split(': ',1)
   if key in ['Package','Version','Architecture','Installed-Size','SHA256','Filename','Depends','Size']:fields[key]=value
 assert fields.get('SHA256') and fields.get('Version')==version and fields.get('Architecture') in ['all','arm64']
 packages[pkg]=dict(version=version,policy=policy,metadata=fields)
assert packages['linstor-controller']['version']==packages['linstor-satellite']['version']
simulation=apt('apt-get','--simulate','--no-install-recommends','install',
 'linstor-controller='+packages['linstor-controller']['version'],
 'linstor-satellite='+packages['linstor-satellite']['version'])
assert before==run('dpkg-query','-W'),'simulation changed installed packages'
value=dict(packages=packages,simulation=simulation,architecture=run('dpkg','--print-architecture').strip(),
 kernel=run('uname','-r').strip(),available_memory=pathlib.Path('/proc/meminfo').read_text(),
 baseline_lvs=json.loads(run('lvs','--reportformat','json','--units','b','--nosuffix','-o','vg_name,vg_uuid,lv_name,lv_uuid,lv_size,lv_attr')),
 baseline_vgs=json.loads(run('vgs','--reportformat','json','--units','b','--nosuffix','-o','vg_name,vg_uuid,vg_size,vg_free')),
 installed_packages_sha256=hashlib.sha256(before.encode()).hexdigest(),
 apt_update_sha256=hashlib.sha256(updates.encode()).hexdigest(),
 source_sha256=hashlib.sha256((base/'ppa.list').read_bytes()).hexdigest(),
 trust_anchor_sha256=hashlib.sha256((base/'key.asc').read_bytes()).hexdigest())
assert value['architecture']=='arm64'
print(json.dumps(value))
""" % PPA_KEY
            value=json.loads(ssh(root,n,'sudo python3 -c '+shlex.quote(command),timeout=240))
            report['nodes'].append(dict(id=n['id'],uuid=n['uuid'],evidence=value))
        versions={n['evidence']['packages']['linstor-controller']['version'] for n in report['nodes']}
        assert len(versions)==1
        report['candidate_version']=versions.pop();report['passed']=True
    except Exception as error:
        report['error']=str(error)
    finally:
        # Do not hide a cleanup failure behind an otherwise valid package plan.
        try:
            if len(booted)==3:
                completed=subprocess.run([sys.executable,str(Path(__file__).with_name('storage_closeout.py')),
                    '--lab',str(root),'--output',str(a.output_dir/'closeout.json')],capture_output=True,text=True,timeout=180)
                report['closeout_exit_code']=completed.returncode
                if completed.returncode:raise RuntimeError(completed.stderr[-1000:])
                closeout=json.loads((a.output_dir/'closeout.json').read_text())
                assert closeout['all_owned_vms_stopped']
                report['closeout_sha256']=hashlib.sha256((a.output_dir/'closeout.json').read_bytes()).hexdigest()
            else:
                raise RuntimeError('partial VM boot: inspect exact ownership/state before further cleanup')
        except Exception as error:
            report['cleanup_error']=str(error);report['passed']=False
        report['finished_at']=time.time()
        with (a.output_dir/'package-report.json').open('x') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({k:report.get(k) for k in ['passed','candidate_version','error','cleanup_error']},indent=2))
    return int(not report['passed'])


if __name__=='__main__':raise SystemExit(main())
