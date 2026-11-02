#!/usr/bin/env python3
"""Real Royak-managed, unpromoted DRBD replicas on the three exact owned VMs.

No filesystem, application writer, force/promotion/new-generation command,
public endpoint or host network change. New backing LVs/metadata are retained
intentionally and bounded, not silently discarded to make cleanup pass.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
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
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ['lab','disks','binary','pool-evidence','output-dir']:p.add_argument('--'+arg,type=Path,required=True)
    p.add_argument('--resume',type=Path)
    p.add_argument('--reuse-closed',type=Path,help='Reuse only an exact completed no-generation/no-filesystem closed-Secondary test dataset')
    p.add_argument('--requested-bytes',type=int)
    a=p.parse_args();os.umask(0o077)
    assert not (a.resume and a.reuse_closed)
    previous_run=a.resume or a.reuse_closed
    root=a.lab.resolve();inv=json.loads((root/'inventory.json').read_text());disks=json.loads(a.disks.read_text())
    assert inv['kind']=='royak-parallels-lab-v1' and inv['root']==str(root) and {n['uuid'] for n in inv['nodes']}==UUIDS
    assert disks['complete'] and disks['lab']==str(root) and {n['uuid'] for n in disks['nodes']}==UUIDS
    build=a.binary.with_name(a.binary.name+'.build.json');manifest=json.loads(build.read_text())
    assert manifest['binary_sha256']==sha(a.binary) and manifest['source_unchanged_during_build']
    assert not manifest['debug_symbols'] and not manifest['symbols_only']
    assert all(sha(REPO/f)==h for f,h in manifest['source_sha256'].items())
    assert shutil.disk_usage(root).free>=32*1024**3
    for n in inv['nodes']:
        info=verify_owner(root,n);assert info['State']=='stopped'
        d=next(d for d in disks['nodes'] if d['uuid']==n['uuid'])
        assert Path(info['Hardware']['hdd1']['image']).resolve()==Path(d['host_disk']).resolve()
        assert (Path(d['host_disk'])/d['backing_name']).stat().st_ino==d['backing_inode']
    a.output_dir.mkdir(mode=0o700,parents=True,exist_ok=False)
    (a.output_dir/'fixture.py').write_bytes(Path(__file__).read_bytes())
    if previous_run:
        old=json.loads((previous_run/'replica-report.json').read_text())
        assert old['passed']==bool(a.reuse_closed) and old.get('cleanup_complete') and old['pod_access_granted'] is False
        assert old['filesystem_formatted'] is False and old['data_generation_initialized'] is False
        assert old.get('retained_new_backing') and old['closeout_sha256']==sha(previous_run/'closeout.json')
        ownership=json.loads((previous_run/'ownership.json').read_text())
        assert old['ownership_sha256']==sha(previous_run/'ownership.json')
        assert ownership['lab']==str(root) and ownership['disk_inventory_sha256']==sha(a.disks)
    else:
        ident=secrets.token_hex(6)
        ownership=dict(kind='royak-secondary-replica-owned-lab-v1',lab=str(root),disk_inventory_sha256=sha(a.disks),
            remote='/var/lib/royak-storage-qualification/replica-'+ident,
            cluster_id=secrets.token_hex(6),namespace_uid=secrets.token_hex(16),claim_uid=secrets.token_hex(16),
            pool_uid=secrets.token_hex(16),volume_uid=secrets.token_hex(16),operation_uid=secrets.token_hex(16),
            minor=512,port=27791,interface='rkstore1',listen_port=51932,public_keys={},requested_bytes=a.requested_bytes if a.requested_bytes is not None else 64*1024**2)
    requested_bytes=ownership.get('requested_bytes',64*1024**2)
    if previous_run and a.requested_bytes is not None:assert a.requested_bytes==requested_bytes,'reuse cannot retarget capacity'
    assert 16*1024**2<=requested_bytes<=128*1024**2
    exposed_bytes=((requested_bytes+4095)//4096)*4096
    remote=ownership['remote'];iface=ownership['interface'];resource='rkv'+ownership['volume_uid']
    guest='/home/royak/.local/share/royak-qualification/lifecycle-replica-'+secrets.token_hex(6)
    assert re.fullmatch(r'/var/lib/royak-storage-qualification/replica-[0-9a-f]{12}',remote)
    def save_owner():
        temp=a.output_dir/'ownership.next'
        with temp.open('x') as f:json.dump(ownership,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        temp.replace(a.output_dir/'ownership.json')
    save_owner()
    report=dict(kind='royak-managed-secondary-replica-three-vm-v1',passed=False,created_at=time.time(),checks=[],nodes=[],
        binary_sha256=sha(a.binary),build_manifest_sha256=sha(build),source_sha256=manifest['source_sha256'],fixture_sha256=sha(Path(__file__)),
        ownership_sha256=None,pod_access_granted=False,filesystem_formatted=False,data_generation_initialized=False,
        core_controller_integrated=False,application_replication_test=False,public_demo_untouched=True,host_routes_vpn_unchanged=True,
        guest_root=guest,resumed_from=str(a.resume) if a.resume else None,retained_new_backing=True,
        reused_closed_from=str(a.reuse_closed) if a.reuse_closed else None,
        requested_bytes=requested_bytes,exposed_bytes=exposed_bytes)
    secret=secrets.token_hex(24) if not previous_run else None
    booted=[];allocated={};before={};configured=set();transport_up=set();cleanup_errors=[]
    pool_baselines={};nft_baselines={}
    for n in inv['nodes']:
        evidence=json.loads((a.pool_evidence/('node-'+str(n['id']))/'component-report.json').read_text())
        assert evidence['passed'] and evidence['cleanup_complete'] and evidence['retained_before']==evidence['retained_after']
        pool_baselines[n['id']]=evidence
    def event(**value):
        with (a.output_dir/'events.jsonl').open('a') as f:json.dump(dict(at=time.time(),**value),f);f.write('\n');f.flush();os.fsync(f.fileno())
    def command(n,cmd,input=None,timeout=60,allow_failure=False):
        verify_owner(root,n)
        c=subprocess.run(['ssh','-i',str(root/'operator'),'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
            '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(root/'known_hosts'),'-o','ConnectTimeout=3','royak@'+n['ip'],cmd],
            input=input,capture_output=True,timeout=timeout)
        out=c.stdout.decode(errors='replace');err=c.stderr.decode(errors='replace')
        if secret:
            out=out.replace(secret,'[redacted]');err=err.replace(secret,'[redacted]')
        event(node=n['id'],operation='private configuration write' if input is not None else cmd,exit_code=c.returncode,
            stdout_sha256=hashlib.sha256(c.stdout).hexdigest(),stderr_sha256=hashlib.sha256(c.stderr).hexdigest())
        if c.returncode and not allow_failure:raise RuntimeError('node '+str(n['id'])+' command failed: '+err[-1200:])
        return c.returncode,out,err
    def text(n,cmd,**kw):return command(n,cmd,**kw)[1]
    def write(n,name,value):
        assert re.fullmatch('[a-z.-]+',name)
        command(n,'sudo install -m 0600 /dev/stdin '+shlex.quote(remote+'/'+name),input=value.encode())
    def check(name,condition,**details):
        report['checks'].append(dict(name=name,passed=bool(condition),**details));assert condition,name
    def invoke(n,action,negative=False):
        args=['sudo',guest+'/royak','storage-driver',action,'--config',remote+'/pool.json']
        if action=='prepare':args+=['--request',remote+'/request.json']
        else:args+=['--plan',remote+'/plan.json']
        code,out,err=command(n,shlex.join(args),timeout=180,allow_failure=negative)
        if negative:return code,out,err
        value=json.loads(out)
        with (a.output_dir/('node-'+str(n['id'])+'-'+action+'-'+secrets.token_hex(3)+'.json')).open('x') as f:json.dump(value,f,indent=2);f.write('\n')
        return value
    def status(n):return json.loads(text(n,'sudo drbdsetup status --json'))
    def extent(n,path):
        program="""import os,mmap,hashlib,json
fd=os.open(%r,os.O_RDONLY|os.O_DIRECT);m=mmap.mmap(-1,1024**2);v=memoryview(m);h=hashlib.sha256()
try:
 size=os.lseek(fd,0,os.SEEK_END);os.lseek(fd,0,os.SEEK_SET);left=size
 while left:
  count=min(left,len(v));assert os.readv(fd,[v[:count]])==count;h.update(v[:count]);left-=count
 print(json.dumps(dict(bytes=size,sha256=h.hexdigest())))
finally:os.close(fd);v.release();m.close()
"""%path
        return json.loads(text(n,'sudo python3 -c '+shlex.quote(program),timeout=90))
    def guard(n):
        values=json.loads(text(n,'sudo nft --json list tables'))['nftables']
        names=[v['table']['name'] for v in values if v.get('table',{}).get('family')=='inet' and v['table']['name'].startswith('rks_'+ownership['volume_uid']+'_')]
        assert len(names)==1,names
        value=json.loads(text(n,'sudo nft --json list table inet '+names[0]))
        assert sum('rule' in v for v in value['nftables'])==12
        return value
    def packets(value,chain=None):
        return sum(e['counter']['packets'] for v in value['nftables'] if 'rule' in v and (chain is None or v['rule']['chain']==chain)
            for e in v['rule']['expr'] if 'counter' in e)
    def stable_nft(value):
        if isinstance(value,list):return [stable_nft(v) for v in value]
        if isinstance(value,dict):
            return {k:dict(packets=0,bytes=0) if k=='counter' and isinstance(v,dict) and set(v)=={'packets','bytes'} else stable_nft(v) for k,v in value.items()}
        return value
    def raw_inbound(sender,receiver,receiver_mac):
        dev=json.loads(text(sender,'ip -j route get '+receiver['ip']))[0]['dev']
        assert re.fullmatch('[a-zA-Z0-9_-]{1,15}',dev) and dev!=iface
        program=r'''import json,socket,struct,time
dev,src,dst,dmac,port=PARAMETERS
smac=bytes.fromhex(open('/sys/class/net/'+dev+'/address').read().strip().replace(':',''));dmac=bytes.fromhex(dmac.replace(':',''))
def checksum(b):
 if len(b)%2:b+=b'\0'
 n=sum(struct.unpack('!%dH'%(len(b)//2),b));n=(n>>16)+(n&65535);n+=(n>>16);return (~n)&65535
src=socket.inet_aton(src);dst=socket.inet_aton(dst)
ip=struct.pack('!BBHHHBBH4s4s',69,0,40,41177,0,64,6,0,src,dst)
ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
tcp=struct.pack('!HHLLBBHHH',40017,port,1,0,80,2,1024,0,0)
tcp=tcp[:16]+struct.pack('!H',checksum(src+dst+struct.pack('!BBH',0,6,len(tcp))+tcp))+tcp[18:]
frame=dmac+smac+b'\x08\x00'+ip+tcp
s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind((dev,0))
try:
 for _ in range(3):assert s.send(frame)==len(frame);time.sleep(.05)
finally:s.close()
print(json.dumps(dict(frames_sent=3,device=dev,destination=socket.inet_ntoa(dst),destination_port=port,payload_bytes=0)))
'''.replace('PARAMETERS',repr((dev,sender['ip'],'10.246.75.'+str(receiver['id']),receiver_mac,ownership['port'])))
        return json.loads(text(sender,'sudo python3 -c '+shlex.quote(program),timeout=10))
    def route_probe(n,underlay,peer,local_present):
        program=r'''import json,socket,struct,threading,time
dev,peer,port,local,local_present=PARAMETERS
counts=dict(protected_syn_out=0,control_syn_out=0);errors=[];ready=threading.Event()
def capture():
 s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((dev,0));s.settimeout(.05);ready.set();end=time.monotonic()+2.5
 try:
  while time.monotonic()<end:
   try:data,addr=s.recvfrom(65535)
   except socket.timeout:continue
   if addr[2]!=socket.PACKET_OUTGOING or len(data)<54 or data[12:14]!=b'\x08\x00' or data[23]!=6:continue
   ihl=(data[14]&15)*4;tcp=14+ihl
   if len(data)<tcp+20 or socket.inet_ntoa(data[30:34])!=peer or not data[tcp+13]&2:continue
   dport=struct.unpack('!H',data[tcp+2:tcp+4])[0]
   if dport==port:counts['protected_syn_out']+=1
   elif dport==port+1:counts['control_syn_out']+=1
 finally:s.close()
t=threading.Thread(target=capture);t.start();assert ready.wait(1)
for bind in ([None,local] if local_present else [None]):
 for _ in range(2):
  s=socket.socket();s.settimeout(.25)
  try:
   if bind:s.bind((bind,0))
   s.connect((peer,port));errors.append('protected TCP unexpectedly connected')
  except socket.timeout:pass
  except OSError as e:errors.append(type(e).__name__+':'+str(e.errno))
  finally:s.close()
for _ in range(2):
 s=socket.socket();s.settimeout(.25)
 try:s.connect((peer,port+1))
 except OSError:pass
 finally:s.close()
t.join(4);assert not t.is_alive()
print(json.dumps(dict(**counts,errors=errors,reader_joined=True,local_present=local_present)))
'''.replace('PARAMETERS',repr((underlay,peer,ownership['port'],'10.246.75.'+str(n['id']),local_present)))
        return json.loads(text(n,'sudo python3 -c '+shlex.quote(program),timeout=15))
    try:
        for n in inv['nodes']:run('prlctl','start',n['uuid'],timeout=90);booted.append(n)
        for n in inv['nodes']:
            assert shutil.disk_usage(root).free>=20*1024**3
            wait_for(lambda:ssh(root,n,'printf ready',timeout=5).strip()=='ready',120)
            # nft is a declared driver prerequisite; never install/start a
            # generic firewall service or flush the guest ruleset here.
            version=text(n,'test -x /usr/sbin/nft && /usr/sbin/nft --version').strip()
            event(node=n['id'],nft_version=version)
            nft_baselines[n['id']]=json.loads(text(n,'sudo nft --json list ruleset'))
            assert not any(v.get('table',{}).get('name','').startswith('rks_') for v in nft_baselines[n['id']]['nftables'])
            with (a.output_dir/('node-'+str(n['id'])+'-firewall-before.json')).open('x') as f:json.dump(nft_baselines[n['id']],f,indent=2);f.write('\n')
            assert status(n)==[] and text(n,'sudo wg show interfaces').strip()=='' and text(n,'sudo docker ps -aq').strip()==''
            preflight="""import json,pathlib,subprocess
alive=[]
for p in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  if (p/'exe').resolve().name in ('royak','royak-old'):alive.append(int(p.name))
 except OSError:pass
value=dict(royak_pids=alive,active=subprocess.run(['systemctl','is-active','royak-qualification.service'],capture_output=True,text=True).stdout.strip(),
 enabled=subprocess.run(['systemctl','is-enabled','royak-qualification.service'],capture_output=True,text=True).stdout.strip())
assert not alive and value['active']=='inactive' and value['enabled']=='disabled'
print(json.dumps(value))
"""
            preflight=json.loads(text(n,'sudo python3 -c '+shlex.quote(preflight)))
            event(node=n['id'],preflight=preflight)
            oldpool=pool_baselines[n['id']]['approved_pool'];vg=oldpool['vg_name']
            actual=json.loads(text(n,"sudo pvs --reportformat json -o pv_name,pv_uuid,vg_uuid,vg_name"))['report'][0]['pv']
            actual=[r for r in actual if r['pv_uuid']==oldpool['pv_uuid'] and r['vg_uuid']==oldpool['vg_uuid']]
            assert len(actual)==1 and actual[0]['pv_name']=='/dev/sdb' and actual[0]['vg_name']==vg
            old_lvs=json.loads(text(n,'sudo lvs --reportformat json -o vg_name,lv_name,lv_uuid'))['report'][0]['lv']
            old_lvs=[v for v in old_lvs if v['vg_name']==vg and v['lv_name']=='data']
            expected_old=next(v for v in pool_baselines[n['id']]['baseline_lvs'] if v['lv_name']=='data')
            assert len(old_lvs)==1 and old_lvs[0]['lv_uuid']==expected_old['lv_uuid']
            serial=text(n,'lsblk -dn -o SERIAL /dev/sdb').strip();assert serial==oldpool['disk_serial']
            before[n['id']]=extent(n,'/dev/'+vg+'/data')
            assert before[n['id']]==pool_baselines[n['id']]['retained_after']
            text(n,'test ! -e '+shlex.quote(guest)+' && install -d -m 0700 '+shlex.quote(guest))
            run('scp','-q','-i',root/'operator','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                '-o','UserKnownHostsFile='+str(root/'known_hosts'),a.binary,'royak@'+n['ip']+':'+guest+'/royak',timeout=60)
            assert text(n,'sha256sum '+shlex.quote(guest+'/royak')).split()[0]==sha(a.binary)
            if not previous_run:
                text(n,'test ! -e '+remote+' && sudo install -d -m 0700 '+remote)
                cfg=dict(version=1,cluster_id=ownership['cluster_id'],node_uid=n['uuid'].replace('-',''),pool_uid=ownership['pool_uid'],
                    vg_name=vg,vg_uuid=oldpool['vg_uuid'],pv_uuid=oldpool['pv_uuid'],disk_serial=serial,max_volume_bytes=128*1024**2,max_managed_bytes=256*1024**2)
                req={k:ownership[k] for k in ['cluster_id','namespace_uid','claim_uid','pool_uid','volume_uid','operation_uid']}
                req.update(version=1,node_uid=cfg['node_uid'],capacity_bytes=requested_bytes)
                write(n,'pool.json',json.dumps(cfg));write(n,'request.json',json.dumps(req))
                prepared=invoke(n,'prepare');allocated[n['id']]=prepared['allocation']
                text(n,'sudo sh -c '+shlex.quote('umask 077; wg genkey > '+remote+'/wg.key; wg pubkey < '+remote+'/wg.key > '+remote+'/wg.pub'))
                ownership['public_keys'][str(n['id'])]=text(n,'sudo cat '+remote+'/wg.pub').strip();save_owner()
            else:
                previous=json.loads(text(n,'sudo cat /var/lib/royak/storage/pools/'+ownership['pool_uid']+'/'+ownership['volume_uid']+'.json'))
                allocated[n['id']]=previous['record']['allocation']
                assert text(n,'sudo cat '+remote+'/wg.pub').strip()==ownership['public_keys'][str(n['id'])]
        for n in inv['nodes']:
            if not previous_run:
                peers=[]
                for other in inv['nodes']:
                    peers.append(dict(node_uid=other['uuid'].replace('-',''),node_id=other['id']-1,hostname=other['name'],
                        address='10.246.75.'+str(other['id']),public_key=ownership['public_keys'][str(other['id'])],vg_name=pool_baselines[other['id']]['approved_pool']['vg_name']))
                plan={k:ownership[k] for k in ['cluster_id','pool_uid','volume_uid','operation_uid','minor','port','interface']}
                plan.update(version=1,shared_secret=secret,peers=peers);write(n,'plan.json',json.dumps(plan))
                peer_conf=''
                for other in inv['nodes']:
                    if other['id']!=n['id']:
                        peer_conf+='\n[Peer]\nPublicKey = '+ownership['public_keys'][str(other['id'])]+'\nAllowedIPs = 10.246.75.'+str(other['id'])+'/32\nEndpoint = '+other['ip']+':'+str(ownership['listen_port'])+'\nPersistentKeepalive = 5\n'
                write(n,'peers.conf',peer_conf)
                text(n,'sudo sh -c '+shlex.quote("umask 077; { printf '[Interface]\\nPrivateKey = '; cat "+remote+"/wg.key; printf 'ListenPort = "+str(ownership['listen_port'])+"\\n'; cat "+remote+"/peers.conf; } > "+remote+'/wg.conf'))
            text(n,'sudo ip link add '+iface+' type wireguard');transport_up.add(n['id'])
            text(n,'sudo wg setconf '+iface+' '+remote+'/wg.conf')
            text(n,'sudo ip address add 10.246.75.'+str(n['id'])+'/32 dev '+iface+' && sudo ip link set '+iface+' up')
            for other in inv['nodes']:
                if other['id']!=n['id']:text(n,'sudo ip route add 10.246.75.'+str(other['id'])+'/32 dev '+iface)
        for n in inv['nodes']:
            for other in inv['nodes']:
                if other['id']!=n['id']:text(n,'ping -c 1 -W 3 10.246.75.'+str(other['id']),timeout=10)
            if previous_run:
                phase_program="import json,pathlib; p=pathlib.Path("+repr('/var/lib/royak/storage/pools/'+ownership['pool_uid']+'/replica-'+ownership['volume_uid']+'.json')+"); print(json.dumps(json.loads(p.read_text())['record']['stage'] if p.exists() else None))"
                phase=json.loads(text(n,'sudo python3 -c '+shlex.quote(phase_program)))
                if phase in ['OnlineIntent','Online','OfflineIntent']:
                    invoke(n,'replica-offline')
            created=invoke(n,'replica-create');configured.add(n['id'])
            if previous_run and created['stage'] in ['OnlineIntent','Online','OfflineIntent']:
                # Ordinary product reconciliation after an exact failed
                # Secondary activation/teardown, never metadata recreation.
                invoke(n,'replica-offline');created=invoke(n,'replica-create')
            check('node '+str(n['id'])+' metadata binds the exact new LV without granting a writer',created['lv_uuid']==allocated[n['id']]['lv_uuid']
                and created['stage'] in ['MetadataReady','Offline'] and created['pod_access_granted'] is False and created['kernel'] is None
                and created['capacity_bytes']==requested_bytes and created['exposed_capacity_bytes']==exposed_bytes)
            repeated=invoke(n,'replica-create')
            check('node '+str(n['id'])+' create retry preserves backend identity',repeated==created)
            report['nodes'].append(dict(id=n['id'],uuid=n['uuid'],lv_uuid=created['lv_uuid'],device_uuid=created['device_uuid'],plan_sha256=created['plan_sha256']))
        check('three distinct backend identities share one exact replication plan',len({n['device_uuid'] for n in report['nodes']})==3 and len({n['plan_sha256'] for n in report['nodes']})==1)
        # Retain private original bytes only inside the root-private guest
        # directory (the replica journal/config contains the shared secret).
        # Exact fixture fault reversal is not automatic product recovery.
        one=inv['nodes'][0];vg=pool_baselines[one['id']]['approved_pool']['vg_name']
        metadata_before=extent(one,'/dev/'+vg+'/rkvol_'+ownership['volume_uid'])
        for kind,suffix,expected_error in [('journal','.json','corrupt replica journal'),('config','.conf','configuration changed')]:
            target='/var/lib/royak/storage/pools/'+ownership['pool_uid']+'/replica-'+ownership['volume_uid']+suffix
            backup=remote+'/fixture-'+kind+'-'+secrets.token_hex(6)+'.original'
            event(node=one['id'],fixture_private_fault_backup=backup,fixture_fault=kind)
            corrupt=('{broken owned replica journal' if kind=='journal' else '# deliberately changed owned config\n')
            program="""import os,pathlib
p=pathlib.Path(%r);backup=pathlib.Path(%r)
with backup.open('xb') as f:f.write(p.read_bytes());f.flush();os.fsync(f.fileno())
with p.open('wb') as f:f.write(%r.encode());f.flush();os.fsync(f.fileno())
"""%(target,backup,corrupt)
            text(one,'sudo python3 -c '+shlex.quote(program))
            try:
                code,_,err=invoke(one,'replica-create',negative=True)
                check('tampered '+kind+' cannot silently reinitialize the replica',code==2 and expected_error in err)
                check('tampered '+kind+' leaves every backing byte unchanged',extent(one,'/dev/'+vg+'/rkvol_'+ownership['volume_uid'])==metadata_before)
            finally:
                program="""import os,pathlib
p=pathlib.Path(%r);backup=pathlib.Path(%r);assert p.read_bytes()==%r.encode()
with p.open('wb') as f:f.write(backup.read_bytes());f.flush();os.fsync(f.fileno())
"""%(target,backup,corrupt)
                text(one,'sudo python3 -c '+shlex.quote(program));report['fixture_exact_fault_reversal']=True
        # A read-only device-mapper holder of the exact backing major/minor
        # must block all offline metadata/recovery entry points, regardless of
        # the planned DRBD minor. No metadata write or force command is used.
        alias='rksq_'+ownership['volume_uid'][:20];alias_uuid='ROYAK-QUALIFICATION-'+ownership['volume_uid']
        block='/dev/'+vg+'/rkvol_'+ownership['volume_uid'];before_alias=extent(one,block)
        text(one,shlex.join(['sudo','dmsetup','create',alias,'--readonly','--uuid',alias_uuid,'--table',
            '0 '+str(int(text(one,'sudo blockdev --getsz '+block)))+' linear '+block+' 0']))
        try:
            for action in ['replica-create','replica-online','replica-offline','replica-observe']:
                code,_,err=invoke(one,action,negative=True)
                check('read-only backing alias blocks '+action,code==2 and 'held by another layer' in err)
            check('held-device refusals do not alter any backing bytes',extent(one,block)==before_alias)
        finally:
            assert text(one,'sudo dmsetup info -c --noheadings -o uuid '+alias).strip()==alias_uuid
            text(one,'sudo dmsetup remove '+alias)
        # Simulate a foreign table colliding with the allocation-derived name.
        # The product must neither adopt/overwrite it nor remove it on an
        # offline retry. Only this fixture reverses its own exact table.
        journal='/var/lib/royak/storage/pools/'+ownership['pool_uid']+'/replica-'+ownership['volume_uid']+'.json'
        nonce=text(one,'sudo python3 -c '+shlex.quote('import json; print(json.load(open('+repr(journal)+'))["record"]["allocation_nonce"])')).strip()
        assert re.fullmatch('[0-9a-f]{32}',nonce)
        table='rks_'+ownership['volume_uid']+'_'+nonce[:16]
        foreign=dict(nftables=[dict(create=dict(table=dict(family='inet',name=table))),
            dict(add=dict(chain=dict(family='inet',table=table,name='foreign',type='filter',hook='output',prio=-150,policy='accept')))])
        command(one,'sudo nft --json --file /dev/stdin',input=json.dumps(foreign).encode())
        foreign_before=json.loads(text(one,'sudo nft --json list table inet '+table));backing_before=extent(one,block)
        try:
            for action in ['replica-online','replica-offline']:
                code,_,err=invoke(one,action,negative=True)
                check('foreign colliding guard is not adopted or removed by '+action,code==2 and 'never adopt, overwrite or remove' in err)
                actual=json.loads(text(one,'sudo nft --json list table inet '+table))
                assert actual==foreign_before and status(one)==[]
            check('foreign guard refusal does not replace backing identity or bytes',extent(one,block)==backing_before)
        finally:
            assert json.loads(text(one,'sudo nft --json list table inet '+table))==foreign_before
            text(one,'sudo nft delete table inet '+table)
        invoke(one,'replica-offline')
        for n in inv['nodes']:invoke(n,'replica-online')
        def connected():
            for n in inv['nodes']:
                values=status(n)
                if len(values)!=1 or values[0]['name']!=resource:return False
                s=values[0]
                if s['role']!='Secondary' or s['devices'][0]['open'] or s['devices'][0]['size']!=exposed_bytes//1024:return False
                if len(s['connections'])!=2 or any(p['connection-state']!='Connected' or p['peer-role']!='Secondary' for p in s['connections']):return False
            return True
        wait_for(connected,45)
        for n in inv['nodes']:
            observed=invoke(n,'replica-observe')
            raw_guard=guard(n)
            with (a.output_dir/('node-'+str(n['id'])+'-transport-guard.json')).open('x') as f:json.dump(raw_guard,f,indent=2);f.write('\n')
            check('node '+str(n['id'])+' has an exact persistent encrypted-only kernel guard',
                observed['encrypted_only_guard_table'] and any(v.get('table',{}).get('name')==observed['encrypted_only_guard_table'] for v in raw_guard['nftables']))
            check('node '+str(n['id'])+' has two real connected encrypted Secondary peers',observed['kernel']['role']=='Secondary'
                and all(p['connection-state']=='Connected' for p in observed['kernel']['connections']) and observed['pod_access_granted'] is False)
            again=invoke(n,'replica-online');check('node '+str(n['id'])+' online retry does not replace backend identity',again['device_uuid']==observed['device_uuid'])
        # Change one exact, fixture-owned rule while leaving transport intact.
        # The helper must detect a changed verdict, not silently repair it or
        # return an attestation. Rule bytes/counters are restored explicitly.
        one=inv['nodes'][0];original_guard=guard(one)
        original_rule=next(v['rule'] for v in original_guard['nftables'] if v.get('rule',{}).get('chain')=='output')
        changed_rule=json.loads(json.dumps(original_rule));assert changed_rule['expr'][-1]==dict(drop=None)
        changed_rule['expr'][-1]=dict(accept=None)
        command(one,'sudo nft --json --file /dev/stdin',input=json.dumps(dict(nftables=[dict(replace=dict(rule=changed_rule))])).encode())
        changed_guard=guard(one)
        try:
            for action in ['replica-observe','replica-online']:
                code,_,err=invoke(one,action,negative=True)
                check('changed kernel verdict is refused by '+action,code==2 and 'never adopt, overwrite or remove' in err)
            check('unsafe guard is not implicitly repaired or adopted',stable_nft(guard(one))==stable_nft(changed_guard))
        finally:
            command(one,'sudo nft --json --file /dev/stdin',input=json.dumps(dict(nftables=[dict(replace=dict(rule=original_rule))])).encode())
            assert stable_nft(guard(one))==stable_nft(original_guard)
        invoke(one,'replica-observe')
        # Only this VM's owned route is changed, never host routes/VPN.
        one=inv['nodes'][0];two=inv['nodes'][1];route='10.246.75.2/32'
        underlay=json.loads(text(one,'ip -j route get '+two['ip']))[0]['dev']
        assert re.fullmatch('[a-zA-Z0-9_-]{1,15}',underlay) and underlay!=iface
        # A root fixture can emit a raw Ethernet SYN without traversing its
        # own OUTPUT hook, modelling an untrusted underlay peer. The receiver's
        # INPUT guard must drop it before DRBD; there is no application payload.
        mac=text(one,'cat /sys/class/net/'+underlay+'/address').strip()
        assert re.fullmatch('[0-9a-f]{2}(:[0-9a-f]{2}){5}',mac)
        before_guard=guard(one);incoming=raw_inbound(two,one,mac);after_guard=guard(one)
        with (a.output_dir/'unencrypted-inbound-probe.json').open('x') as f:json.dump(dict(probe=incoming,before=before_guard,after=after_guard),f,indent=2);f.write('\n')
        check('real unencrypted underlay SYNs are dropped at the replica INPUT boundary',
            incoming['frames_sent']==3 and packets(after_guard,'input')-packets(before_guard,'input')>=3)
        text(one,'sudo ip route replace '+route+' via '+two['ip']+' dev '+underlay)
        try:
            code,_,err=invoke(one,'replica-online',negative=True)
            check('activation refuses a route that bypasses the pinned WireGuard interface',code==2 and 'route bypasses' in err)
            code,_,err=invoke(one,'replica-observe',negative=True)
            check('observation also refuses to attest a route outside WireGuard',code==2 and 'route bypasses' in err)
            before_guard=guard(one);probe=route_probe(one,underlay,'10.246.75.2',True);after_guard=guard(one)
            with (a.output_dir/'route-bypass-probe.json').open('x') as f:json.dump(dict(probe=probe,before=before_guard,after=after_guard),f,indent=2);f.write('\n')
            check('actual fallback packets are dropped before underlay egress while control SYNs remain visible',
                probe['protected_syn_out']==0 and probe['control_syn_out']>=1 and probe['errors']==[] and packets(after_guard,'output')>packets(before_guard,'output'))
            text(one,'sudo ip link delete '+iface);transport_up.remove(one['id'])
            before_guard=guard(one);probe=route_probe(one,underlay,'10.246.75.2',False);after_guard=guard(one)
            with (a.output_dir/'interface-loss-probe.json').open('x') as f:json.dump(dict(probe=probe,before=before_guard,after=after_guard),f,indent=2);f.write('\n')
            check('kernel guard survives complete WireGuard interface removal without plaintext fallback',
                probe['protected_syn_out']==0 and probe['control_syn_out']>=1 and probe['errors']==[] and packets(after_guard,'output')>packets(before_guard,'output'))
            code,_,err=invoke(one,'replica-observe',negative=True)
            check('missing WireGuard interface cannot be attested as safe',code==2)
        finally:
            if one['id'] not in transport_up:
                text(one,'sudo ip link add '+iface+' type wireguard');transport_up.add(one['id'])
                text(one,'sudo wg setconf '+iface+' '+remote+'/wg.conf')
                text(one,'sudo ip address add 10.246.75.1/32 dev '+iface+' && sudo ip link set '+iface+' up')
            for other in inv['nodes']:
                if other['id']!=one['id']:text(one,'sudo ip route replace 10.246.75.'+str(other['id'])+'/32 dev '+iface)
        wait_for(connected,45)
        check('DRBD reconnects over the restored exact encrypted transport',True)
        three=inv['nodes'][2]
        offline=invoke(three,'replica-offline');again=invoke(three,'replica-offline')
        check('closed Secondary offline operation is idempotent',offline==again and offline['kernel'] is None)
        online=invoke(three,'replica-online');wait_for(connected,45)
        check('ordinary activity-log replay/reactivation retains exact backend identity',online['device_uuid']==offline['device_uuid'])
        assert all(sha(REPO/f)==h for f,h in manifest['source_sha256'].items())
        report['passed']=True
    except Exception as error:report['error']=str(error)
    finally:
        for n in booted:
            try:
                current=status(n)
                if any(s['name']==resource for s in current):
                    # Keep the actual kernel schema/options for independent
                    # review, without exporting the authentication secret.
                    code,raw,_=command(n,shlex.join(['sudo','drbdsetup','show',resource,'--json']),allow_failure=True)
                    if code==0:
                        def scrub(value):
                            if isinstance(value,dict):return {k:('[redacted]' if 'secret' in k.lower() else scrub(v)) for k,v in value.items()}
                            if isinstance(value,list):return [scrub(v) for v in value]
                            return value
                        with (a.output_dir/('node-'+str(n['id'])+'-kernel-show.json')).open('x') as f:json.dump(scrub(json.loads(raw)),f,indent=2);f.write('\n')
                    try:invoke(n,'replica-offline')
                    except Exception:
                        # A failed guard/parser is NOT a pass. Safe teardown
                        # only of the exact new, unpromoted, closed resource.
                        s=next(s for s in current if s['name']==resource)
                        assert s['role']=='Secondary' and len(s['devices'])==1 and s['devices'][0]['minor']==ownership['minor'] and not s['devices'][0]['open']
                        conf='/var/lib/royak/storage/pools/'+ownership['pool_uid']+'/replica-'+ownership['volume_uid']+'.conf'
                        text(n,shlex.join(['sudo','drbdadm','-c',conf,'down',resource]));report['fixture_exact_secondary_teardown']=True
                assert status(n)==[]
                # Also reconcile an interrupted guard installation whose DRBD
                # activation never completed. Only the helper may remove it.
                if n['id'] in configured:invoke(n,'replica-offline')
                tables=json.loads(text(n,'sudo nft --json list tables'))['nftables']
                assert not any(v.get('table',{}).get('name','').startswith('rks_'+ownership['volume_uid']+'_') for v in tables)
                after_nft=json.loads(text(n,'sudo nft --json list ruleset'))
                with (a.output_dir/('node-'+str(n['id'])+'-firewall-after.json')).open('x') as f:json.dump(after_nft,f,indent=2);f.write('\n')
                assert stable_nft(after_nft)==stable_nft(nft_baselines[n['id']]),'non-owned guest firewall changed'
            except Exception as error:cleanup_errors.append(dict(node=n['id'],stage='exact Secondary teardown',error=str(error)))
            try:
                if n['id'] in transport_up:
                    assert text(n,'sudo wg show '+iface+' public-key').strip()==ownership['public_keys'][str(n['id'])]
                    text(n,'sudo ip link delete '+iface)
                assert text(n,'sudo wg show interfaces').strip()==''
                vg=pool_baselines[n['id']]['approved_pool']['vg_name']
                retained=extent(n,'/dev/'+vg+'/data')
                assert retained==before[n['id']],'old retained LV bytes changed'
                lvs=json.loads(text(n,'sudo lvs --reportformat json -o vg_name,lv_name,lv_uuid,lv_tags'))['report'][0]['lv']
                new=[v for v in lvs if v['vg_name']==vg and v['lv_name']=='rkvol_'+ownership['volume_uid']]
                if n['id'] in allocated:assert len(new)==1 and new[0]['lv_uuid']==allocated[n['id']]['lv_uuid']
                event(node=n['id'],retained_before=before[n['id']],retained_after=retained,retained_new_lv=new)
            except Exception as error:cleanup_errors.append(dict(node=n['id'],stage='transport/retained data verification',error=str(error)))
        report['cleanup_errors']=cleanup_errors;report['cleanup_complete']=len(booted)==3 and not cleanup_errors
        if report['cleanup_complete']:
            try:
                c=subprocess.run([sys.executable,str(Path(__file__).with_name('storage_closeout.py')),'--lab',str(root),
                    '--output',str(a.output_dir/'closeout.json'),'--extra-binary',guest+'/royak'],capture_output=True,text=True,timeout=180)
                assert c.returncode==0,c.stderr[-1000:]
                assert json.loads((a.output_dir/'closeout.json').read_text())['all_owned_vms_stopped']
                report['closeout_sha256']=sha(a.output_dir/'closeout.json')
            except Exception as error:report['cleanup_error']=str(error);report['cleanup_complete']=False
        report['passed']=report['passed'] and report['cleanup_complete'];save_owner();report['ownership_sha256']=sha(a.output_dir/'ownership.json')
        report['finished_at']=time.time()
        with (a.output_dir/'replica-report.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({k:report.get(k) for k in ['passed','error','cleanup_error','cleanup_complete','binary_sha256']},indent=2))
    return int(not report['passed'])


if __name__=='__main__':raise SystemExit(main())
