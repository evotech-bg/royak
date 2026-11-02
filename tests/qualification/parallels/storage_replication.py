#!/usr/bin/env python3
"""Three-kernel DRBD/LVM component experiment, not a Royak storage driver gate.

Only newly inventoried blank 2 GiB disks may be initialized. Data and logs are
retained; finally unmounts/demotes/down only the exact owned resource and removes
its private WireGuard interface. No global DRBD/LVM cleanup or forced failover.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import re
import shlex
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bootstrap import run, ssh, verify_owner
from storage_disks import SIZE, UUIDS, wait_for, disks


class Experiment:
    def __init__(self, args):
        self.root = args.lab.resolve()
        inventory = json.loads((self.root / "inventory.json").read_text())
        assert inventory['root'] == str(self.root) and inventory['kind'] == 'royak-parallels-lab-v1'
        assert {n['uuid'] for n in inventory['nodes']} == UUIDS
        self.nodes = inventory['nodes']
        self.disks = json.loads(args.disks.read_text())
        assert self.disks['complete'] and self.disks['lab'] == str(self.root)
        assert {n['uuid'] for n in self.disks['nodes']} == UUIDS
        self.out = args.output_dir.resolve()
        runs = Path(__file__).resolve().parents[1] / '.runs'
        assert self.out.is_relative_to(runs.resolve()) and self.out != runs.resolve()
        if shutil.disk_usage(self.root).free < 32 * 1024**3: raise RuntimeError('need 32 GiB raw free')
        self.out.mkdir(parents=True, mode=0o700, exist_ok=False)
        self.name = 'rkqs' + secrets.token_hex(4)
        self.remote = '/var/lib/royak-storage-qualification/' + self.name
        self.resume = None
        self.reuse_config = bool(args.resume_inconsistent)
        self.initialize_verified_empty = args.initialize_verified_empty
        if self.initialize_verified_empty and not self.reuse_config:
            raise ValueError('verified-empty initialization requires the exact retained no-workload experiment')
        if args.resume_before_metadata or args.resume_inconsistent:
            assert not (args.resume_before_metadata and args.resume_inconsistent)
            prior = (args.resume_before_metadata or args.resume_inconsistent).resolve()
            report = json.loads((prior/'component-report.json').read_text())
            events = [json.loads(line) for line in (prior/'events.jsonl').read_text().splitlines()]
            md = [e for e in events if ' create-md ' in e.get('command','')]
            assert report['kind']=='royak-drbd-component-experiment-v1' and not report['passed']
            assert report['cleanup_errors']==[]
            if not self.reuse_config:
                assert report['checks']==[] and len(md)==1 and md[0]['exit_code']==10
                assert 'Value is too long' in md[0]['stderr'] and not any(' primary ' in e.get('command','') or ' up ' in e.get('command','') for e in events)
            else:
                assert len(md)==3 and all(e['exit_code']==0 for e in md)
                assert len(report['checks'])==3 and all(c['passed'] and 'WireGuard handshakes' in c['name'] for c in report['checks'])
                primary=[e for e in events if ' primary ' in e.get('command','')]
                assert len(primary)==1 and primary[0]['exit_code']==11 and 'No quorum' in primary[0]['stderr']
                assert not any('mkfs' in e.get('command','') or 'sudo mount ' in e.get('command','') for e in events)
            assert {n['uuid'] for n in report['nodes']}==UUIDS and re.fullmatch(r'rkqs[0-9a-f]{8}',report['resource'])
            assert report['disk_inventory_sha256']==hashlib.sha256(args.disks.read_bytes()).hexdigest()
            self.name = report['resource']
            self.remote = report['remote_root'] if self.reuse_config else report['remote_root']+'-retry-'+secrets.token_hex(2)
            self.resume = dict(prior=str(prior), before_any_workload_writes=True,
                phase='metadata-created-no-workload' if self.reuse_config else 'before-metadata',
                report_sha256=hashlib.sha256((prior/'component-report.json').read_bytes()).hexdigest())
        self.config = self.remote + '/drbd.conf'
        self.mount = self.remote + '/mount'
        self.iface = 'rkstore0'
        self.started, self.drbd, self.mounted = [], [], set()
        self.checks, self.cleanup_errors = [], []
        self.sensitive = []
        self.report = dict(kind='royak-drbd-component-experiment-v1', resource=self.name,
            volume_group=self.name, remote_root=self.remote, config=self.config, mountpoint=self.mount,
            wireguard_interface=self.iface, minor=301, created_at=time.time(), nodes=self.nodes,
            fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            disk_inventory_sha256=hashlib.sha256(args.disks.read_bytes()).hexdigest(),
            resumed_only_before_any_metadata_or_data=self.resume,
            checks=self.checks, passed=False, scope='backend component only; not Royak auth/attachment/fencing or production qualification')
        with (self.out/'ownership.json').open('x') as f: json.dump(self.report, f, indent=2)

    def event(self, **data):
        with (self.out/'events.jsonl').open('a') as f:
            f.write(json.dumps(dict(at=time.time(), **data))+'\n'); f.flush(); os.fsync(f.fileno())

    def command(self, n, command, input=None, timeout=120):
        verify_owner(self.root, n)
        result = subprocess.run(['ssh','-i',str(self.root/'operator'),'-o','IdentitiesOnly=yes',
            '-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(self.root/'known_hosts'),
            '-o','ConnectTimeout=3','royak@'+n['ip'], command], input=input, capture_output=True, timeout=timeout)
        # Commands containing credentials use stdin and are never journaled.
        stdout, stderr = result.stdout.decode(errors='replace'), result.stderr.decode(errors='replace')
        for value in self.sensitive:
            # drbdadm can abbreviate a rejected value to its prefix in a parse
            # diagnostic. Redact both full and abbreviated forms before logging.
            pattern = re.escape(value[:8])+r'[0-9a-f]*'
            stdout, stderr = re.sub(pattern,'[redacted]',stdout), re.sub(pattern,'[redacted]',stderr)
        self.last_result = dict(exit_code=result.returncode, stdout=stdout, stderr=stderr)
        if input is None:
            self.event(node=n['id'], command=command, exit_code=result.returncode,
                       stdout=stdout, stderr=stderr)
        else:
            self.event(node=n['id'], operation='write private owned configuration', exit_code=result.returncode)
        if result.returncode: raise RuntimeError(f"node {n['id']} command failed ({result.returncode}); see events")
        return stdout

    def write(self, n, path, data):
        assert path.startswith(self.remote+'/')
        self.command(n, 'sudo install -m 0600 /dev/stdin '+shlex.quote(path), input=data.encode())

    def adm(self, n, *args):
        if args==('up',):
            # A previous hard stop can leave uncommitted activity-log extents.
            # The owned resource must be offline (all callers prove this in
            # preflight) while drbdmeta replays that log into the peer bitmaps.
            self.command(n, shlex.join(['sudo','drbdadm','-c',self.config,'apply-al',self.name]))
        return self.command(n, shlex.join(['sudo','drbdadm','-c',self.config,*args,self.name]))

    def status(self, n):
        value=json.loads(self.command(n, 'sudo drbdsetup status '+self.name+' --json'))
        assert len(value)==1 and value[0]['name']==self.name
        return value[0]

    def check(self, name, passed, **data):
        self.checks.append(dict(name=name, passed=bool(passed), **data))
        self.event(check=self.checks[-1]); print(('PASS ' if passed else 'FAIL ')+name, flush=True)
        if not passed: raise RuntimeError(name)

    def provision(self):
        pub={}
        for n in self.nodes:
            owned=next(d for d in self.disks['nodes'] if d['uuid']==n['uuid'])
            assert verify_owner(self.root,n)['State']=='running'
            actual=next(d for d in disks(self.root,n) if d.get('serial')==owned['guest_disk']['serial'])
            assert all(actual[k]==owned['guest_disk'][k] for k in ('serial','size','path','type','model','mountpoints'))
            assert actual['size']==SIZE, 'owned data disk size changed'
            if not self.resume:
                assert not actual.get('children'), 'new disk has unexpected descendants'
            else:
                children=actual.get('children',[])
                assert len(children)==1, 'owned pre-metadata pool has unexpected descendants'
                child=children[0]
                assert child['path']=='/dev/mapper/'+self.name+'-data' and child['type']=='lvm' and child['size']==1024**3
                assert all(m is None for m in child['mountpoints']) and not child.get('children')
                if not self.reuse_config: assert not child.get('uuid')
            device=actual['path']
            signatures=json.loads(self.command(n, shlex.join(['sudo','wipefs','--no-act','--json',device])))
            if not self.resume: assert signatures['signatures']==[]
            else:
                assert {s['type'] for s in signatures['signatures']}=={'LVM2_member'}
                pvs=json.loads(self.command(n, shlex.join(['sudo','pvs','--devices',device,'--reportformat','json','-o','pv_name,vg_name,pv_uuid',device])))['report'][0]['pv']
                assert len(pvs)==1 and pvs[0]['pv_name']==device and pvs[0]['vg_name']==self.name
                lv_signatures=json.loads(self.command(n,shlex.join(['sudo','wipefs','--no-act','--json','/dev/'+self.name+'/data'])))
                if not self.reuse_config: assert lv_signatures['signatures']==[]
                else: assert {s['type'] for s in lv_signatures['signatures']}=={'drbd'}
            empty_pool = 'test -z "$(sudo pvs --noheadings)"; ' if not self.resume else ''
            self.command(n, "set -eu; test -z \"$(sudo docker ps -aq)\"; "+empty_pool+
                "sudo drbdsetup status --json | python3 -c 'import json,sys; assert json.load(sys.stdin)==[]'; "
                'test ! -e /sys/class/net/'+self.iface+'; sudo install -d -m 0700 '+self.remote)
            self.started.append(n)
            if not self.reuse_config:
                self.command(n, 'sudo sh -c '+shlex.quote('umask 077; wg genkey > '+self.remote+'/wg.key; wg pubkey < '+self.remote+'/wg.key > '+self.remote+'/wg.pub'))
            pub[n['id']]=self.command(n,'sudo cat '+self.remote+'/wg.pub').strip()
            # Every destructive disk operation is bound to the just-verified
            # serial/path and a fresh empty signature set, never a guessed sdb.
            if not self.resume:
                self.command(n, shlex.join(['sudo','pvcreate','--zero','y','--metadatasize','1M',device]))
                self.command(n, shlex.join(['sudo','vgcreate','--devices',device,self.name,device]))
                self.command(n, shlex.join(['sudo','lvcreate','--devices',device,'-L','1024M','-n','data',self.name]))
        secret=secrets.token_hex(24)  # drbdadm shared-secret maximum is 63 chars.
        self.sensitive.append(secret)
        config='global { usage-count no; }\nresource '+self.name+' {\n'
        config+='  options { auto-promote no; quorum majority; quorum-minimum-redundancy 2; on-no-quorum io-error; on-no-data-accessible io-error; }\n'
        config+='  net { protocol C; allow-two-primaries no; cram-hmac-alg sha256; shared-secret "'+secret+'"; }\n'
        for n in self.nodes:
            config+=f"  on {n['name']} {{ node-id {n['id']-1}; address 10.246.74.{n['id']}:7791; device /dev/drbd301; disk /dev/{self.name}/data; meta-disk internal; }}\n"
        config+='  connection-mesh { hosts '+' '.join(n['name'] for n in self.nodes)+'; }\n}\n'
        for n in self.nodes:
            # The private key never leaves its VM or appears in process argv.
            peers=''
            for other in self.nodes:
                if other['id']!=n['id']:
                    peers+=f"\n[Peer]\nPublicKey = {pub[other['id']]}\nAllowedIPs = 10.246.74.{other['id']}/32\nEndpoint = {other['ip']}:51931\nPersistentKeepalive = 5\n"
            if not self.reuse_config:
                self.write(n,self.remote+'/peers.conf',peers)
                self.command(n, 'sudo sh -c '+shlex.quote("umask 077; { printf '[Interface]\\nPrivateKey = '; cat "+self.remote+"/wg.key; printf 'ListenPort = 51931\\n'; cat "+self.remote+"/peers.conf; } > "+self.remote+'/wg.conf'))
            self.command(n, 'sudo ip link add '+self.iface+' type wireguard')
            self.command(n, 'sudo wg setconf '+self.iface+' '+self.remote+'/wg.conf')
            self.command(n, f'sudo ip address add 10.246.74.{n["id"]}/32 dev '+self.iface)
            self.command(n, 'sudo ip link set '+self.iface+' up')
            for other in self.nodes:
                if other['id']!=n['id']: self.command(n,f'sudo ip route add 10.246.74.{other["id"]}/32 dev '+self.iface)
            if not self.reuse_config:
                self.write(n,self.config,config)
                self.adm(n,'create-md')
            self.drbd.append(n)
            self.adm(n,'up')
        for n in self.nodes:
            for other in self.nodes:
                if n['id']!=other['id']: self.command(n,f'ping -c 1 -W 3 10.246.74.{other["id"]}',timeout=10)
            handshakes=self.command(n,'sudo wg show '+self.iface+' latest-handshakes')
            self.check(f"node {n['id']} has two real WireGuard handshakes", len(handshakes.splitlines())==2 and all(int(line.split()[1])>0 for line in handshakes.splitlines()))
        # Only bootstrap a brand-new empty data set; --force is never used on a
        # recovery or subsequent writer handoff.
        if self.initialize_verified_empty:
            self.initialize_empty_extent()
        else:
            try:self.adm(self.nodes[0],'primary','--force')
            except RuntimeError:
                last=self.last_result
                if last['exit_code']!=11 or 'No quorum' not in last['stderr'] or 'quorum-minimum-redundancy' not in last['stderr']:raise
                self.event(initial_bootstrap='write promotion refused until two replicas are UpToDate; quorum not changed')
        def synced():
            for n in self.nodes:
                s=self.status(n)
                if any(d.get('disk-state')!='UpToDate' for d in s.get('devices',[])): return False
                if len(s.get('connections',[]))!=2: return False
                if any(c.get('connection-state')!='Connected' or any(p.get('peer-disk-state')!='UpToDate' for p in c.get('peer_devices',[])) for c in s['connections']): return False
            return True
        wait_for(synced,240)
        self.check('all three diskful replicas synchronized',True)
        self.adm(self.nodes[0],'primary')
        self.command(self.nodes[0],'sudo mkfs.ext4 -F /dev/drbd301')

    def initialize_empty_extent(self):
        # Documented DRBD new-empty-volume initialization, NOT a recovery path.
        # Verify all exposed data bytes as identical zeroes independently before
        # declaring the three copies equal; never clear a populated bitmap or
        # change quorum/minimum redundancy to get an application online.
        sizes=[]; hashes=[]
        for n in self.nodes:
            status=self.status(n)
            assert status['role']=='Secondary' and len(status['devices'])==1
            device=status['devices'][0]
            assert device['disk-state']=='Inconsistent' and device.get('open') is False
            assert len(status['connections'])==2 and all(c['connection-state']=='Connected' for c in status['connections'])
            size=device['size']*1024  # DRBD status reports KiB.
            assert 0<size<SIZE
            program="""import hashlib,json
remaining=%d
h=hashlib.sha256()
with open(%r,'rb',buffering=0) as f:
 while remaining:
  b=f.read(min(1024**2,remaining))
  if not b:raise RuntimeError('short allocated extent read')
  h.update(b);remaining-=len(b)
print(json.dumps(dict(sha256=h.hexdigest(),bytes=%d)))
""" % (size,'/dev/'+self.name+'/data',size)
            result=json.loads(self.command(n,'sudo python3 -c '+shlex.quote(program),timeout=90))
            assert result['bytes']==size
            sizes.append(size);hashes.append(result['sha256'])
        assert len(set(sizes))==1
        h=hashlib.sha256();remaining=sizes[0];zeroes=bytes(1024**2)
        while remaining:
            part=zeroes[:min(len(zeroes),remaining)];h.update(part);remaining-=len(part)
        self.check('all new empty exposed extents independently hash to exact zero bytes',
                   all(value==h.hexdigest() for value in hashes), bytes_per_replica=sizes[0], sha256=h.hexdigest())
        self.adm(self.nodes[0],'new-current-uuid','--clear-bitmap')

    def mount_on(self,n):
        self.command(n,'sudo install -d -m 0700 '+self.mount+'; sudo mount /dev/drbd301 '+self.mount)
        self.mounted.add(n['id'])

    def write_records(self,n,first,last):
        program="""import os,hashlib,json
root=%r
for i in range(%d,%d):
 data=(('royak-storage-record-%%d:'%%i).encode()+bytes([i%%251])*8192)
 p=root+'/record-%%06d'%%i
 with open(p,'xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 d=os.open(root,os.O_DIRECTORY);os.fsync(d);os.close(d)
 print(json.dumps(dict(id=i,sha256=hashlib.sha256(data).hexdigest())),flush=True)
""" % (self.mount,first,last)
        result=self.command(n,'sudo python3 -c '+shlex.quote(program))
        rows=[json.loads(line) for line in result.splitlines()]
        self.check('fsync acknowledged records '+str(first)+'..'+str(last-1),len(rows)==last-first)
        with (self.out/f'acknowledged-{first}-{last}.json').open('x') as f:json.dump(rows,f,indent=2)
        return rows

    def verify_records(self,n,expected):
        program="import pathlib,hashlib,json; r=pathlib.Path("+repr(self.mount)+"); print(json.dumps({int(p.name.split('-')[1]):hashlib.sha256(p.read_bytes()).hexdigest() for p in r.glob('record-*')}))"
        actual=json.loads(self.command(n,'sudo python3 -c '+shlex.quote(program)))
        self.check('all acknowledged file identities and bytes survive on another node',actual=={str(r['id']):r['sha256'] for r in expected})

    def execute(self):
        self.provision(); one,two,three=self.nodes
        self.mount_on(one)
        acknowledged=self.write_records(one,0,100)
        denied=self.command(two,'sudo drbdadm -c '+self.config+' primary '+self.name+' 2>&1; code=$?; echo EXIT_CODE=$code; test $code -ne 0')
        self.check('second primary rejected while first writer remains online',
                   'multiple primaries' in denied.lower() or 'peer is primary' in denied.lower(), backend_reason=denied)
        verify_owner(self.root,one)
        self.event(node=one['id'],fault='exact owned writer VM hard stop')
        run('prlctl','stop',one['uuid'],'--kill',timeout=90)
        assert verify_owner(self.root,one)['State']=='stopped'
        self.mounted.discard(one['id'])
        # Normal promotion only, with the old writer independently power-fenced.
        def promote():
            self.adm(two,'primary');return True
        wait_for(promote,45)
        self.mount_on(two);self.verify_records(two,acknowledged)
        acknowledged+=self.write_records(two,100,200)
        self.command(two,'sudo umount '+self.mount);self.mounted.discard(two['id']);self.adm(two,'secondary')
        self.adm(three,'primary');self.mount_on(three);self.verify_records(three,acknowledged)
        self.command(three,'sudo umount '+self.mount);self.mounted.discard(three['id']);self.adm(three,'secondary')
        self.check('power-fenced failover and clean handoff preserve 200 fsynced records',True,
                   limitation='not automated Royak fencing or PostgreSQL recovery')

    def cleanup(self):
        for n in self.started:
            try:
                if verify_owner(self.root,n)['State']=='stopped':
                    run('prlctl','start',n['uuid'],timeout=90)
                    wait_for(lambda:ssh(self.root,n,'printf ready',timeout=5)=='ready',120)
                if n['id'] in self.mounted:
                    self.command(n,'sudo umount '+self.mount);self.mounted.discard(n['id'])
                if n in self.drbd:
                    states=json.loads(self.command(n,'sudo drbdsetup status --json'))
                    if any(s['name']==self.name for s in states):
                        self.adm(n,'secondary');self.adm(n,'down')
            except Exception as e:self.cleanup_errors.append(dict(node=n['id'],stage='unmount/demote/down',error=str(e)))
            # Attempt transport cleanup independently even if storage teardown
            # fails. Never report a stopped VM as evidence that it succeeded.
            try:
                self.command(n,'if test -e /sys/class/net/'+self.iface+'; then sudo ip link delete '+self.iface+'; fi')
                states=json.loads(self.command(n,'sudo drbdsetup status --json'))
                if any(s['name']==self.name for s in states):raise RuntimeError('owned DRBD resource remains active')
                self.command(n,'sudo lvs --reportformat json -o vg_name,lv_name,lv_size,lv_attr '+self.name)
            except Exception as e:self.cleanup_errors.append(dict(node=n['id'],stage='transport/final resource verification',error=str(e)))


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,required=True);p.add_argument('--disks',type=Path,required=True)
    p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--resume-before-metadata',type=Path)
    p.add_argument('--resume-inconsistent',type=Path)
    p.add_argument('--initialize-verified-empty',action='store_true')
    experiment=Experiment(p.parse_args());error=None
    try:experiment.execute()
    except Exception as e:error=f'{type(e).__name__}: {e}';print(error,flush=True)
    finally:experiment.cleanup()
    experiment.report.update(error=error,finished_at=time.time(),cleanup_errors=experiment.cleanup_errors,
        passed=bool(experiment.checks) and error is None and not experiment.cleanup_errors and all(c['passed'] for c in experiment.checks))
    with (experiment.out/'component-report.json').open('x') as f:json.dump(experiment.report,f,indent=2);f.write('\n')
    print(experiment.out/'component-report.json',flush=True)
    raise SystemExit(0 if experiment.report['passed'] else 1)


if __name__=='__main__':main()
