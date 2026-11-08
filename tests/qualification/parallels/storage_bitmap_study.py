#!/usr/bin/env python3
"""Observe the retained DRBD peer-bitmap finding; never reset/invalidate data.

Normal connection setup, cryptographic online verification and optional normal
role transition only. Quorum, protocol, redundancy and conflict policy remain
unchanged. Independent O_DIRECT hashes remain mandatory; old failed reports
are never rewritten by this study.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from storage_rejoin import Rejoin
from storage_disks import wait_for
from bootstrap import verify_owner


class Study(Rejoin):
    def raw_hashes(self):
        values=[]
        for n in self.nodes:
            program="""import hashlib,mmap,os
fd=os.open(%r,os.O_RDONLY|os.O_DIRECT)
buffer=mmap.mmap(-1,1024**2);view=memoryview(buffer)
remaining=%d;h=hashlib.sha256()
try:
 while remaining:
  count=min(1024**2,remaining)
  got=os.readv(fd,[view[:count]])
  if got!=count:raise RuntimeError('short direct read')
  h.update(view[:got]);remaining-=got
finally:os.close(fd)
print(h.hexdigest())
""" % ('/dev/'+self.name+'/data',self.size)
            values.append(self.command(n,'sudo python3 -c '+shlex.quote(program),timeout=90).strip())
        return values

    def snapshots(self,label):
        values=[dict(node=n['id'],status=self.status(n)) for n in self.nodes]
        self.event(observation=label,statuses=values)
        return values

    @staticmethod
    def stable(values):
        return all(len(v['status']['devices'])==1 and v['status']['devices'][0]['disk-state']=='UpToDate'
            and v['status']['devices'][0].get('quorum') is True
            and len(v['status']['connections'])==2
            and all(c['connection-state']=='Connected' and all(p['peer-disk-state']=='UpToDate' and p['replication-state']=='Established'
                for p in c['peer_devices']) for c in v['status']['connections']) for v in values)

    @staticmethod
    def dirty(values):
        return [dict(node=v['node'],peer=c['peer-node-id'],out_of_sync_kib=p['out-of-sync'])
            for v in values for c in v['status']['connections'] for p in c['peer_devices'] if p.get('out-of-sync',0)!=0]

    def execute(self):
        if self.replay_al:
            # Apply the documented offline activity-log recovery, never a
            # bitmap reset. Preserve the exact original metadata bytes first;
            # application data is independently hashed before and after.
            self.check('pre-replay direct data matches the retained oracle',all(h==self.oracle for h in self.raw_hashes()))
            for n in self.nodes:
                assert json.loads(self.command(n,'sudo drbdsetup status --json'))==[]
                program="""import os,mmap,base64,json,hashlib
fd=os.open(%r,os.O_RDONLY|os.O_DIRECT)
size=os.lseek(fd,0,os.SEEK_END);offset=%d
remaining=size-offset
assert 0<remaining<64*1024**2 and offset%%4096==0 and remaining%%4096==0
os.lseek(fd,offset,os.SEEK_SET)
m=mmap.mmap(-1,remaining);view=memoryview(m)
assert os.readv(fd,[view])==remaining
print(json.dumps(dict(offset=offset,bytes=remaining,sha256=hashlib.sha256(view).hexdigest(),base64=base64.b64encode(view).decode())))
os.close(fd)
""" % ('/dev/'+self.name+'/data',self.size)
                md=json.loads(self.command(n,'sudo python3 -c '+shlex.quote(program)))
                with (self.out/f'node-{n["id"]}.metadata-before-al.bin').open('xb') as f:f.write(base64.b64decode(md['base64']))
                self.event(node=n['id'],metadata_backup=dict(offset=md['offset'],bytes=md['bytes'],sha256=md['sha256']))
                self.adm(n,'apply-al')
                dump=self.command(n,shlex.join(['sudo','drbdmeta','301','v09','/dev/'+self.name+'/data','internal','dump-md']))
                with (self.out/f'node-{n["id"]}.metadata-after-al.txt').open('x') as f:f.write(dump)
            self.check('offline activity-log replay does not alter application bytes',all(h==self.oracle for h in self.raw_hashes()))
        for n in self.nodes:
            assert verify_owner(self.root,n)['State']=='running'
            assert json.loads(self.command(n,'sudo drbdsetup status --json'))==[]
            self.command(n,'set -eu; test -z "$(sudo docker ps -aq)"; '
                'test "$(systemctl is-active royak-qualification.service || true)" = inactive; '
                'test ! -e /sys/class/net/'+self.iface+'; ! sudo mountpoint -q '+self.mount)
            self.started.append(n)
            self.command(n,'sudo ip link add '+self.iface+' type wireguard')
            self.command(n,'sudo wg setconf '+self.iface+' '+self.remote+'/wg.conf')
            self.command(n,f'sudo ip address add 10.246.74.{n["id"]}/32 dev '+self.iface)
            self.command(n,'sudo ip link set '+self.iface+' up')
            for other in self.nodes:
                if other['id']!=n['id']:self.command(n,f'sudo ip route add 10.246.74.{other["id"]}/32 dev '+self.iface)
            self.drbd.append(n);self.adm(n,'up')
        wait_for(lambda:self.stable(self.snapshots('connection convergence')),60)
        before=self.snapshots('initial connected state')
        hashes=self.raw_hashes()
        self.check('all current data equals the independent direct-IO oracle',all(h==self.oracle for h in hashes),sha256=hashes)
        self.report['initial_dirty_peers']=self.dirty(before)
        for n in self.nodes:
            for other in self.nodes:
                if other['id']!=n['id']:
                    self.command(n,shlex.join(['sudo','drbdsetup','net-options',self.name,str(other['id']-1),'--verify-alg','sha256']))
        self.report['verification_pairs']=[]
        for a,b in ((self.nodes[0],self.nodes[1]),(self.nodes[0],self.nodes[2]),(self.nodes[1],self.nodes[2])):
            self.command(a,shlex.join(['sudo','drbdsetup','verify',self.name,str(b['id']-1),'0']))
            seen=False;finished=False;deadline=time.monotonic()+120
            while time.monotonic()<deadline:
                values=self.snapshots('online verify '+str(a['id'])+'-'+str(b['id']))
                active=any(p['replication-state'] in ('VerifyS','VerifyT') for v in values for c in v['status']['connections'] for p in c['peer_devices'])
                seen=seen or active
                if seen and not active and self.stable(values):finished=True;break
                time.sleep(0.25)
            self.check('online verify lifecycle observed for pair '+str(a['id'])+'-'+str(b['id']),seen and finished)
            self.report['verification_pairs'].append(dict(nodes=[a['id'],b['id']],seen=seen,finished=finished))
        verified=self.snapshots('after all three verify pairs')
        self.report['dirty_peers_after_verify']=self.dirty(verified)
        self.check('full direct-IO bytes still match after online verify',all(h==self.oracle for h in self.raw_hashes()))
        if self.dirty(verified):
            # A normal promotion of independently verified, quorate node2 is
            # not a forced old-writer recovery. No application is mounted.
            self.adm(self.nodes[1],'primary')
            roles=self.snapshots('normal quorate primary on verified node2')
            self.report['dirty_peers_with_primary']=self.dirty(roles)
            self.adm(self.nodes[1],'secondary')
        final=self.snapshots('final quiescent state')
        self.report['unresolved_dirty_peers']=self.dirty(final)
        self.check('peer bitmap finding is absent without reset or policy relaxation',not self.dirty(final),dirty_peers=self.dirty(final))


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('lab','parent','disks','output-dir','oracle'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--replay-offline-al',action='store_true')
    a=p.parse_args();e=Study(a)
    e.replay_al=a.replay_offline_al
    oracle=json.loads(a.oracle.read_text());assert oracle['io_mode']=='O_DIRECT/debugfs-D'
    assert all(not n['incorrect_record_ids'] for n in oracle['nodes']) and len(oracle['nodes'])==3
    e.oracle=oracle['nodes'][0]['raw_sha256'];assert all(n['raw_sha256']==e.oracle for n in oracle['nodes'])
    e.report.update(kind='royak-drbd-bitmap-study-v1',fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        oracle_sha256=hashlib.sha256(a.oracle.read_bytes()).hexdigest(),
        scope='specific retained bitmap finding; not a rerun of the original failed failover qualification')
    error=None
    try:e.execute()
    except Exception as x:error=f'{type(x).__name__}: {x}';print(error,flush=True)
    finally:e.cleanup()
    e.report.update(error=error,finished_at=time.time(),cleanup_errors=e.cleanup_errors,
        passed=error is None and not e.cleanup_errors and bool(e.checks) and all(c['passed'] for c in e.checks))
    with (e.out/'bitmap-report.json').open('x') as f:json.dump(e.report,f,indent=2);f.write('\n')
    print(e.out/'bitmap-report.json',flush=True)
    raise SystemExit(0 if e.report['passed'] else 1)


if __name__=='__main__':main()
