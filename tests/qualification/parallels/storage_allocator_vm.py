#!/usr/bin/env python3
"""Qualify new-LV driver primitives on the three exact owned 2 GiB data disks.

No production services, old LV data, host routes, unknown VMs or containers are
modified. Raw before/after predecessor hashes and all original failure reports
remain evidence. This is not integrated DRBD replication or fencing acceptance.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from bootstrap import run,ssh,verify_owner
from storage_disks import wait_for
from storage_preflight import UUIDS

REPO=Path(__file__).resolve().parents[3]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,required=True);p.add_argument('--disks',type=Path,required=True)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--predecessor',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--guest-fixture',choices=['storage_allocator_guest.py','storage_allocator_crash_guest.py'],default='storage_allocator_guest.py')
    a=p.parse_args();os.umask(0o077)
    root=a.lab.resolve();inv=json.loads((root/'inventory.json').read_text());disks=json.loads(a.disks.read_text())
    prior=json.loads((a.predecessor/'component-report.json').read_text())
    assert inv['root']==str(root) and inv['kind']=='royak-parallels-lab-v1' and {n['uuid'] for n in inv['nodes']}==UUIDS
    assert disks['lab']==str(root) and disks['complete'] and {n['uuid'] for n in disks['nodes']}==UUIDS
    assert re.fullmatch(r'rkqs[0-9a-f]{8}',prior['volume_group']) and {n['uuid'] for n in prior['nodes']}==UUIDS
    build_path=a.binary.with_name(a.binary.name+'.build.json');build=json.loads(build_path.read_text())
    assert build['binary_sha256']==sha(a.binary) and build['source_unchanged_during_build'] and not build['debug_symbols'] and not build['symbols_only']
    assert all(sha(REPO/k)==v for k,v in build['source_sha256'].items())
    if a.output_dir.exists():p.error('never overwrite earlier evidence')
    assert shutil.disk_usage(root).free>=32*1024**3
    for n in inv['nodes']:
        info=verify_owner(root,n);assert info['State']=='stopped'
        owned=next(d for d in disks['nodes'] if d['uuid']==n['uuid'])
        assert Path(info['Hardware']['hdd1']['image']).resolve()==Path(owned['host_disk']).resolve()
        assert (Path(owned['host_disk'])/owned['backing_name']).stat().st_ino==owned['backing_inode']
    a.output_dir.mkdir(parents=True,mode=0o700)
    run_id=secrets.token_hex(6);guest='/home/royak/.local/share/royak-qualification/lifecycle-allocator-'+run_id
    remote='/var/lib/royak-storage-qualification/allocator-'+run_id
    pool_uid=secrets.token_hex(16);volume_uid=secrets.token_hex(16)
    cluster_id=secrets.token_hex(6);namespace_uid=secrets.token_hex(16);claim_uid=secrets.token_hex(16);operation_uid=secrets.token_hex(16)
    fixture=Path(__file__).with_name(a.guest_fixture)
    report=dict(kind='royak-lvm-allocator-three-kernel-v1',passed=False,created_at=time.time(),nodes=[],
        binary_sha256=sha(a.binary),build_manifest_sha256=sha(build_path),source_sha256=build['source_sha256'],
        fixture_sha256=sha(Path(__file__)),guest_fixture_sha256=sha(fixture),guest_fixture=a.guest_fixture,disk_inventory_sha256=sha(a.disks),
        predecessor_report_sha256=sha(a.predecessor/'component-report.json'),pool_uid=pool_uid,volume_uid=volume_uid,
        guest_root=guest,remote_root=remote,normal_release_flags=True,drbd_replication_test=False,fencing_test=False,
        cluster_id=cluster_id,namespace_uid=namespace_uid,claim_uid=claim_uid,operation_uid=operation_uid,
        pod_access_granted=False,public_demo_untouched=True,host_routes_vpn_unchanged=True)
    for name,path in [('host-fixture.py',Path(__file__)),('guest-fixture.py',fixture)]:
        with (a.output_dir/name).open('xb') as stream:stream.write(path.read_bytes())
    assert sha(a.output_dir/'host-fixture.py')==report['fixture_sha256']
    assert sha(a.output_dir/'guest-fixture.py')==report['guest_fixture_sha256']
    fixture=a.output_dir/'guest-fixture.py'
    booted=[]
    try:
        for n in inv['nodes']:
            verify_owner(root,n);run('prlctl','start',n['uuid'],timeout=90);booted.append(n)
        for n in inv['nodes']:
            if shutil.disk_usage(root).free<20*1024**3:raise RuntimeError('raw host disk safety floor reached')
            wait_for(lambda:ssh(root,n,'printf ready',timeout=5).strip()=='ready',120)
            assert verify_owner(root,n)['State']=='running'
            disk=next(d for d in disks['nodes'] if d['uuid']==n['uuid'])['guest_disk']
            ssh(root,n,'test ! -e '+shlex.quote(guest)+' && install -d -m 0700 '+shlex.quote(guest))
            scp=['scp','-q','-i',str(root/'operator'),'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
                '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(root/'known_hosts')]
            destination='royak@'+n['ip']+':'+guest+'/'
            run(*scp,a.binary,destination+'royak',timeout=60);run(*scp,fixture,destination+'allocator_guest.py',timeout=30)
            hashes=ssh(root,n,'sha256sum '+shlex.quote(guest+'/royak')+' '+shlex.quote(guest+'/allocator_guest.py')).splitlines()
            assert hashes[0].split()[0]==sha(a.binary) and hashes[1].split()[0]==sha(fixture)
            command=shlex.join(['sudo','python3',guest+'/allocator_guest.py','--binary',guest+'/royak',
                '--serial',disk['serial'],'--device',disk['path'],'--vg',prior['volume_group'],
                '--cluster-id',cluster_id,'--namespace-uid',namespace_uid,'--claim-uid',claim_uid,'--operation-uid',operation_uid,
                '--node-uid',n['uuid'].replace('-',''),'--pool-uid',pool_uid,'--volume-uid',volume_uid,'--output-dir',remote])
            # A failed component still writes an immutable terminal report. An
            # observation/transport error is not permission to restart it.
            stdout=ssh(root,n,command+' || true',timeout=300)
            value=json.loads(ssh(root,n,'sudo cat '+shlex.quote(remote+'/component-report.json'),timeout=20))
            assert value['binary_sha256']==sha(a.binary) and value['fixture_sha256']==sha(fixture)
            node_dir=a.output_dir/('node-'+str(n['id']));node_dir.mkdir(mode=0o700)
            with (node_dir/'component-report.json').open('x') as f:json.dump(value,f,indent=2);f.write('\n')
            with (node_dir/'terminal.txt').open('x') as f:f.write(stdout)
            report['nodes'].append(dict(id=n['id'],uuid=n['uuid'],passed=value['passed'],checks=len(value['checks']),
                cleanup_complete=value.get('cleanup_complete',False),error=value.get('error'),cleanup_error=value.get('cleanup_error'),
                report_sha256=sha(node_dir/'component-report.json')))
            if not value.get('cleanup_complete'):raise RuntimeError('component left a non-idle owned resource; exact recovery required')
        assert all(sha(REPO/k)==v for k,v in build['source_sha256'].items())
        report['passed']=all(n['passed'] for n in report['nodes'])
    except Exception as error:report['error']=str(error)
    finally:
        try:
            if len(booted)!=3 or len(report['nodes'])!=3 or not all(n['cleanup_complete'] for n in report['nodes']):
                raise RuntimeError('incomplete component closeout: inspect exact process/resource ownership before poweroff')
            result=subprocess.run([sys.executable,str(Path(__file__).with_name('storage_closeout.py')),'--lab',str(root),
                '--output',str(a.output_dir/'closeout.json'),'--extra-binary',guest+'/royak'],capture_output=True,text=True,timeout=180)
            assert result.returncode==0,result.stderr[-1200:]
            assert json.loads((a.output_dir/'closeout.json').read_text())['all_owned_vms_stopped']
            report['closeout_sha256']=sha(a.output_dir/'closeout.json')
        except Exception as error:report['cleanup_error']=str(error);report['passed']=False
        report['finished_at']=time.time()
        with (a.output_dir/'allocator-report.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({k:report.get(k) for k in ['passed','error','cleanup_error','binary_sha256']},indent=2))
    return int(not report['passed'])


if __name__=='__main__':raise SystemExit(main())
