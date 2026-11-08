#!/usr/bin/env python3
"""Quiesce and stop only the three owned lab VMs, retaining all storage/evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from bootstrap import ssh,verify_owner
from storage_preflight import UUIDS
from storage_disks import wait_for


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--extra-binary',action='append',default=[],help='Exact private lifecycle-test executable to prove absent before poweroff')
    a=p.parse_args();os.umask(0o077)
    if a.output.exists():p.error('never overwrite earlier closeout evidence')
    root=a.lab.resolve();inv=json.loads((root/'inventory.json').read_text())
    assert inv['kind']=='royak-parallels-lab-v1' and inv['root']==str(root) and {n['uuid'] for n in inv['nodes']}==UUIDS
    result=dict(kind='royak-storage-foundation-closeout-v1',created_at=time.time(),nodes=[],
                fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                storage_qualified=False,all_storage_data_and_evidence_retained=True,host_routes_vpn_unchanged=True)
    for path in a.extra_binary:
        assert path.startswith('/home/royak/.local/share/royak-qualification/lifecycle-') and Path(path).name in ('royak','royak-old')
        assert '..' not in Path(path).parts
    checked_executables=['/opt/royak',*a.extra_binary]
    result['checked_executables']=checked_executables
    # All guests must independently prove quiescent before any poweroff. The
    # owned LVM/data volumes are intentionally retained, not removed as a way
    # to conceal a cleanup or integrity finding.
    for n in inv['nodes']:
        assert verify_owner(root,n)['State']=='running'
        program="""import json,pathlib,subprocess
def run(*args):return subprocess.check_output(args,text=True,timeout=15).strip()
alive=[];unexpected=[];checked=EXPECTED_EXECUTABLES
for p in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  executable=(p/'exe').resolve()
  if str(executable) in checked:alive.append(int(p.name))
  elif executable.name in ('royak','royak-old'):unexpected.append(int(p.name))
 except OSError:pass
value=dict(drbd_resources=json.loads(run('drbdsetup','status','--json')),
 storage_guard_tables=[v['table'] for v in json.loads(run('nft','--json','list','tables'))['nftables'] if v.get('table',{}).get('name','').startswith('rks_')],
 storage_qualification_holders=[v.strip() for v in run('dmsetup','info','-c','--noheadings','-o','name').splitlines() if v.strip().startswith('rksq_')],
 wireguard_interfaces=run('wg','show','interfaces').split(),containers=run('docker','ps','-aq').split(),
 royak_pids=alive,unexpected_royak_pids=unexpected,checked_executables=checked,qualification_active=subprocess.run(['systemctl','is-active','royak-qualification.service'],capture_output=True,text=True).stdout.strip(),
 qualification_enabled=subprocess.run(['systemctl','is-enabled','royak-qualification.service'],capture_output=True,text=True).stdout.strip(),
 drbd_service_enabled=subprocess.run(['systemctl','is-enabled','drbd.service'],capture_output=True,text=True).stdout.strip(),
 mounts=run('findmnt','--json'),retained_lvs=json.loads(run('lvs','--reportformat','json','-o','vg_name,lv_name,lv_size,lv_attr')))
assert value['drbd_resources']==[] and value['wireguard_interfaces']==[] and value['containers']==[] and value['royak_pids']==[] and value['unexpected_royak_pids']==[]
assert value['storage_guard_tables']==[] and value['storage_qualification_holders']==[]
assert value['qualification_active']=='inactive' and value['qualification_enabled']=='disabled' and value['drbd_service_enabled']=='disabled'
assert '/dev/drbd301' not in value['mounts'] and '/var/lib/royak-storage-qualification/' not in value['mounts']
print(json.dumps(value))
"""
        program=program.replace('EXPECTED_EXECUTABLES',repr(checked_executables))
        import shlex
        metrics=json.loads(ssh(root,n,'sudo python3 -c '+shlex.quote(program),timeout=45))
        result['nodes'].append(dict(node=n['id'],uuid=n['uuid'],pre_poweroff=metrics))
    for n in inv['nodes']:
        verify_owner(root,n)
        try:ssh(root,n,'sudo shutdown -h now',timeout=15)
        except RuntimeError:pass
        wait_for(lambda:verify_owner(root,n)['State']=='stopped',75)
    for row,n in zip(result['nodes'],inv['nodes']):row['final_state']=verify_owner(root,n)['State']
    result['all_owned_vms_stopped']=all(n['final_state']=='stopped' for n in result['nodes'])
    result['finished_at']=time.time()
    with a.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps(dict(all_owned_vms_stopped=result['all_owned_vms_stopped'],storage_qualified=False,evidence=str(a.output)),indent=2))


if __name__=='__main__':main()
