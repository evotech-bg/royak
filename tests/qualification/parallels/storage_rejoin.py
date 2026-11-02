#!/usr/bin/env python3
"""Rejoin the exact retained backend experiment without force/adoption/reset.

Requires its independently acknowledged 200 records and clean live preflight.
Verifies stale raw data before joining, normal DRBD resync, matching raw data
after joining, and a fresh filesystem read. No UUID/bitmap/quorum modifications.
This does not qualify a Royak storage driver, application DB or control lease.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from bootstrap import verify_owner
from storage_replication import Experiment, UUIDS, wait_for, disks


class Rejoin(Experiment):
    def __init__(self,a):
        self.root=a.lab.resolve();parent=a.parent.resolve()
        inventory=json.loads((self.root/'inventory.json').read_text())
        assert inventory['root']==str(self.root) and inventory['kind']=='royak-parallels-lab-v1'
        self.nodes=inventory['nodes'];assert {n['uuid'] for n in self.nodes}==UUIDS
        old=json.loads((parent/'component-report.json').read_text())
        assert old['kind']=='royak-drbd-component-experiment-v1' and len(old['checks'])==11 and all(c['passed'] for c in old['checks'])
        assert old['error'] is None
        # Preserve the original failed closeout: its SSH `true` readiness
        # predicate mistook successful empty stdout for not-ready. This run
        # requires fresh independent proof of idle nodes before any action.
        assert old['cleanup_errors']==[] or old['cleanup_errors']==[
            dict(node=1,stage='unmount/demote/down',error='owned VM transition did not complete')]
        self.name=old['resource'];assert re.fullmatch(r'rkqs[0-9a-f]{8}',self.name)
        self.remote=old['remote_root'];assert re.fullmatch('/var/lib/royak-storage-qualification/'+self.name+r'(?:-retry-[0-9a-f]{4})?',self.remote)
        self.config,self.mount=old['config'],old['mountpoint']
        assert self.config==self.remote+'/drbd.conf' and self.mount==self.remote+'/mount'
        self.iface=old['wireguard_interface'];assert self.iface=='rkstore0' and old['minor']==301
        self.disks=json.loads(a.disks.read_text())
        assert self.disks['complete'] and old['disk_inventory_sha256']==hashlib.sha256(a.disks.read_bytes()).hexdigest()
        self.expected=json.loads((parent/'acknowledged-0-100.json').read_text())+json.loads((parent/'acknowledged-100-200.json').read_text())
        assert len(self.expected)==200 and {r['id'] for r in self.expected}==set(range(200))
        self.size=next(c['bytes_per_replica'] for c in old['checks'] if 'empty exposed extents' in c['name'])
        assert 0<self.size<2*1024**3
        if shutil.disk_usage(self.root).free<32*1024**3:raise RuntimeError('need 32 GiB raw free')
        self.out=a.output_dir.resolve()
        runs=Path(__file__).resolve().parents[1]/'.runs'
        assert self.out.is_relative_to(runs.resolve()) and self.out!=runs.resolve()
        self.out.mkdir(mode=0o700,parents=True,exist_ok=False)
        self.started,self.drbd,self.mounted=[],[],set();self.checks,self.cleanup_errors=[],[];self.sensitive=[]
        self.report=dict(kind='royak-drbd-rejoin-component-v1',resource=self.name,remote_root=self.remote,
            parent_report_sha256=hashlib.sha256((parent/'component-report.json').read_bytes()).hexdigest(),
            parent_report_passed=old['passed'],parent_cleanup_errors=old['cleanup_errors'],created_at=time.time(),checks=self.checks,
            fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            dependencies_sha256={name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest()
                                 for name in ('storage_replication.py','storage_disks.py','bootstrap.py')},
            scope='stale replica backend rejoin/byte verification only; not Royak driver, PostgreSQL or physical-host HA')
        with (self.out/'ownership.json').open('x') as f:json.dump(self.report,f,indent=2)

    def raw_hashes(self):
        values=[]
        for n in self.nodes:
            program="""import hashlib,json
h=hashlib.sha256();remaining=%d
with open(%r,'rb',buffering=0) as f:
 while remaining:
  b=f.read(min(1024**2,remaining))
  if not b:raise RuntimeError('short extent')
  h.update(b);remaining-=len(b)
print(h.hexdigest())
""" % (self.size,'/dev/'+self.name+'/data')
            digest=self.command(n,'sudo python3 -c '+shlex.quote(program),timeout=90).strip()
            assert re.fullmatch('[0-9a-f]{64}',digest)
            values.append(digest)
        return values

    def execute(self):
        for n in self.nodes:
            assert verify_owner(self.root,n)['State']=='running'
            old=next(d for d in self.disks['nodes'] if d['uuid']==n['uuid'])['guest_disk']
            actual=next(d for d in disks(self.root,n) if d.get('serial')==old['serial'])
            assert all(actual[k]==old[k] for k in ('size','serial','path','type','model','mountpoints'))
            states=json.loads(self.command(n,'sudo drbdsetup status --json'));assert states==[]
            self.command(n,'set -eu; test -z "$(sudo docker ps -aq)"; '
                'test "$(systemctl is-active royak-qualification.service || true)" = inactive; '
                'test ! -e /sys/class/net/'+self.iface+'; '
                'sudo test ! -L '+self.config+'; test "$(sudo readlink -f '+self.config+')" = '+self.config+'; '
                'test "$(sudo stat -c \'%u %a\' '+self.config+')" = "0 600"; '
                '! sudo mountpoint -q '+self.mount)
            self.started.append(n)
        before=self.raw_hashes()
        self.check('power-failed replica is independently stale before rejoin',before[0]!=before[1] and before[1]==before[2],sha256_by_node=before)
        for n in self.nodes:
            self.command(n,'sudo ip link add '+self.iface+' type wireguard')
            self.command(n,'sudo wg setconf '+self.iface+' '+self.remote+'/wg.conf')
            self.command(n,f'sudo ip address add 10.246.74.{n["id"]}/32 dev '+self.iface)
            self.command(n,'sudo ip link set '+self.iface+' up')
            for other in self.nodes:
                if other['id']!=n['id']:self.command(n,f'sudo ip route add 10.246.74.{other["id"]}/32 dev '+self.iface)
            self.drbd.append(n);self.adm(n,'up')
        def synced():
            for n in self.nodes:
                s=self.status(n)
                if s['role']!='Secondary' or len(s['devices'])!=1 or s['devices'][0]['disk-state']!='UpToDate':return False
                if len(s['connections'])!=2 or any(c['connection-state']!='Connected' or any(p['peer-disk-state']!='UpToDate' or p.get('out-of-sync',1)!=0 for p in c['peer_devices']) for c in s['connections']):return False
            return True
        wait_for(synced,240)
        after=self.raw_hashes()
        self.check('normal resync converges stale data without force or bitmap reset',len(set(after))==1 and after[0]==before[1],sha256_by_node=after)
        self.adm(self.nodes[0],'primary');self.mount_on(self.nodes[0]);self.verify_records(self.nodes[0],self.expected)


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('lab','parent','disks','output-dir'):p.add_argument('--'+name,type=Path,required=True)
    e=Rejoin(p.parse_args());error=None
    try:e.execute()
    except Exception as x:error=f'{type(x).__name__}: {x}';print(error,flush=True)
    finally:e.cleanup()
    e.report.update(error=error,finished_at=time.time(),cleanup_errors=e.cleanup_errors,
                    passed=error is None and not e.cleanup_errors and bool(e.checks) and all(c['passed'] for c in e.checks))
    with (e.out/'rejoin-report.json').open('x') as f:json.dump(e.report,f,indent=2);f.write('\n')
    print(e.out/'rejoin-report.json',flush=True)
    raise SystemExit(0 if e.report['passed'] else 1)


if __name__=='__main__':main()
