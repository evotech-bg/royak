#!/usr/bin/env python3
"""Real runtime access on the three owned Linux VMs, retaining all evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from bootstrap import run, ssh, verify_owner
from storage_disks import wait_for
from storage_preflight import UUIDS
sys.path.insert(1,str(Path(__file__).resolve().parents[1]))
from host_capacity import assess, measure, GIB

REPO=Path(__file__).resolve().parents[3]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def capacity_preflight(root, output, owned):
    locations=[root,output.parent,Path(tempfile.gettempdir())]
    locations.extend(Path(info.get('Home',info.get('home',''))) for info in owned)
    capacity=assess([measure(location) for location in locations],8*GIB)
    assert capacity['admitted'],'insufficient allocation headroom for bounded VM runtime test'
    return capacity


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,required=True)
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--resource-cycles',type=int,choices=[0,12],default=0)
    a=p.parse_args()
    os.umask(0o077)
    root=a.lab.resolve()
    inv=json.loads((root/'inventory.json').read_text())
    assert inv['kind']=='royak-parallels-lab-v1' and inv['root']==str(root) and {n['uuid'] for n in inv['nodes']}==UUIDS
    assert not a.output_dir.exists(),'never overwrite evidence'
    build_path=a.binary.with_name(a.binary.name+'.build.json')
    build=json.loads(build_path.read_text())
    assert build['binary_sha256']==sha(a.binary) and build['source_unchanged_during_build']
    assert not build['debug_symbols'] and not build['symbols_only']
    assert all(sha(REPO/name)==value for name,value in build['source_sha256'].items())
    fixture=REPO/'tests/qualification/pod_access_e2e.py'
    guest='/home/royak/.local/share/royak-qualification/lifecycle-access-'+secrets.token_hex(6)
    owned=[verify_owner(root,n) for n in inv['nodes']]
    assert all(info['State']=='stopped' for info in owned)
    capacity=capacity_preflight(root,a.output_dir.resolve(),owned)
    a.output_dir.mkdir(mode=0o700,parents=True)
    shutil.copyfile(fixture,a.output_dir/'pod_access_e2e.fixture.py')
    shutil.copyfile(Path(__file__),a.output_dir/'pod_access_vm.fixture.py')
    report=dict(kind='royak-pod-access-three-vm-runtime-v1',passed=False,started_at=time.time(),
        binary_sha256=sha(a.binary),fixture_sha256=sha(Path(__file__)),guest_fixture_sha256=sha(fixture),
        build_manifest_sha256=sha(build_path),source_sha256=build['source_sha256'],nodes=[],
        guest=guest,cross_host_forwarding_test=False,storage_replication_qualified=False,resource_cycles=a.resource_cycles,
        host_capacity=capacity,capacity_fixture_sha256=sha(REPO/'tests/qualification/host_capacity.py'))
    # Persist ownership/pointers BEFORE starting guests. Keep this launch
    # record immutable and separate from the terminal result.
    (a.output_dir/'launch.json').write_text(json.dumps(dict(report,owned_nodes=[dict(id=n['id'],uuid=n['uuid']) for n in inv['nodes']]),indent=2)+'\n')
    booted=[]
    try:
        for n in inv['nodes']:
            verify_owner(root,n)
            run('prlctl','start',n['uuid'],timeout=90)
            booted.append(n)
        for n in inv['nodes']:
            wait_for(lambda:ssh(root,n,'printf ready',timeout=5).strip()=='ready',120)
            assert verify_owner(root,n)['State']=='running'
            assert not ssh(root,n,'sudo docker ps -aq').strip()
            ssh(root,n,'test ! -e '+shlex.quote(guest)+' && install -d -m 0700 '+shlex.quote(guest))
            scp=['scp','-q','-i',str(root/'operator'),'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
                '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(root/'known_hosts')]
            dest='royak@'+n['ip']+':'+guest+'/'
            run(*scp,a.binary,dest+'royak',timeout=60)
            run(*scp,fixture,dest+'pod_access_e2e.py',timeout=30)
            ssh(root,n,'chmod 0700 '+shlex.quote(guest+'/royak'))
            assert ssh(root,n,'sha256sum '+shlex.quote(guest+'/royak')).split()[0]==report['binary_sha256']
            assert ssh(root,n,'sha256sum '+shlex.quote(guest+'/pod_access_e2e.py')).split()[0]==report['guest_fixture_sha256']
            # Keep failures as original evidence; the host wrapper still
            # attempts exact owned-resource closeout, never a rerun in place.
            command='sudo python3 '+shlex.quote(guest+'/pod_access_e2e.py')+' --binary '+shlex.quote(guest+'/royak')+' --output '+shlex.quote(guest+'/report.json')+' --resource-cycles '+str(a.resource_cycles)
            result=subprocess.run(['ssh','-i',str(root/'operator'),'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
                '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(root/'known_hosts'),
                'royak@'+n['ip'],command],capture_output=True,text=True,timeout=300)
            (a.output_dir/f'node-{n["id"]}.stdout').write_text(result.stdout)
            (a.output_dir/f'node-{n["id"]}.stderr').write_text(result.stderr)
            raw=ssh(root,n,'sudo cat '+shlex.quote(guest+'/report.json'))
            data=json.loads(raw)
            (a.output_dir/f'node-{n["id"]}.json').write_text(raw+'\n')
            assert data['binary_sha256']==report['binary_sha256'] and data['fixture_sha256']==report['guest_fixture_sha256']
            scratch=data['scratch']
            assert scratch.startswith('/var/lib/royak-storage-qualification/runtime-access-') and '..' not in Path(scratch).parts
            report['nodes'].append(dict(id=n['id'],uuid=n['uuid'],exit_code=result.returncode,report=data))
            if data.get('server_log_sha256'):
                # scp must preserve raw log bytes (the helper's text interface
                # strips final newlines, so it cannot be used for a hash join).
                raw_log=ssh(root,n,'sudo base64 -w0 '+shlex.quote(scratch+'/server.log'))
                server_log=__import__('base64').b64decode(raw_log)
                assert hashlib.sha256(server_log).hexdigest()==data['server_log_sha256']
                (a.output_dir/f'node-{n["id"]}.server.log').write_bytes(server_log)
            if data.get('resource_samples_sha256'):
                raw_resources=ssh(root,n,'sudo base64 -w0 '+shlex.quote(scratch+'/resources.jsonl'))
                resources=__import__('base64').b64decode(raw_resources)
                assert hashlib.sha256(resources).hexdigest()==data['resource_samples_sha256']
                (a.output_dir/f'node-{n["id"]}.resources.jsonl').write_bytes(resources)
            if data.get('pf_ip_reuse'):
                proof=data['pf_ip_reuse']
                raw_proof=__import__('base64').b64decode(ssh(root,n,'sudo base64 -w0 '+shlex.quote(scratch+'/pf-ip-reuse.json')))
                assert json.loads(raw_proof)==proof and proof['receiver_cleaned']
                if data['passed']:assert proof['passed']
                (a.output_dir/f'node-{n["id"]}.pf-ip-reuse.json').write_bytes(raw_proof)
                for guest_name,host_name,key in [
                    ('pf-reuse-before-direct-control.bin','pf-before-direct.bin','forward_received_sha256'),
                    ('pf-reuse-direct-control.bin','pf-direct-control.bin','direct_control_sha256')]:
                    if key not in proof:
                        assert not proof['passed'],'successful IP reuse lacks original byte evidence'
                        continue
                    payload=__import__('base64').b64decode(ssh(root,n,'sudo base64 -w0 '+shlex.quote(scratch+'/'+guest_name)))
                    assert len(payload)<=65536 and hashlib.sha256(payload).hexdigest()==proof[key]
                    if key=='forward_received_sha256':assert payload==b''
                    else:assert payload==('DIRECT-CONTROL-'+data['run']).encode()
                    (a.output_dir/f'node-{n["id"]}.{host_name}').write_bytes(payload)
            if len(report['nodes'])>1:
                assert data.get('image_id')==report['nodes'][0]['report'].get('image_id'),'image changed between VM runs'
            assert result.returncode==0 and data['passed'],data.get('error')
        report['passed']=True
    except Exception as error:
        report['error']=type(error).__name__+': '+str(error)
    finally:
        if booted:
            try:
                # All three machines were verified stopped/owned before the
                # run. closeout also refuses any residual container/process.
                run(sys.executable,REPO/'tests/qualification/parallels/storage_closeout.py',
                    '--lab',root,'--output',a.output_dir/'closeout.json','--extra-binary',guest+'/royak',timeout=300)
                closeout=json.loads((a.output_dir/'closeout.json').read_text())
                report['cleanup_passed']=closeout['all_owned_vms_stopped']
                report['closeout_sha256']=sha(a.output_dir/'closeout.json')
            except Exception as error:
                report['cleanup_passed']=False
                report['cleanup_error']=type(error).__name__+': '+str(error)
        report['passed']=bool(report['passed'] and report.get('cleanup_passed'))
        report['finished_at']=time.time()
        (a.output_dir/'vm-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=report['passed'],nodes=len(report['nodes']),error=report.get('error'),cleanup=report.get('cleanup_passed'))))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
