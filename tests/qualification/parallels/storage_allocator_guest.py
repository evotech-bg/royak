#!/usr/bin/env python3
"""Real root-driver allocation negatives on ONE exact pre-approved lab data PV.

Never creates/formats a PV/VG or modifies the retained predecessor LV. Only a
new UID-owned 192 MiB blank LV is written; deliberate test marker/journal/name
faults are reversed explicitly for cleanup, not presented as product recovery.
"""
import argparse
import hashlib
import json
import mmap
import os
import re
from pathlib import Path
import secrets
import subprocess
import time


def sha(data):return hashlib.sha256(data).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True);p.add_argument('--serial',required=True)
    p.add_argument('--device',required=True);p.add_argument('--vg',required=True)
    p.add_argument('--node-uid',required=True);p.add_argument('--pool-uid',required=True)
    p.add_argument('--volume-uid',required=True);p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--cluster-id',required=True);p.add_argument('--namespace-uid',required=True)
    p.add_argument('--claim-uid',required=True);p.add_argument('--operation-uid',required=True)
    a=p.parse_args();assert os.geteuid()==0;os.umask(0o077)
    assert a.device=='/dev/sdb' and re.fullmatch(r'rkqs[0-9a-f]{8}',a.vg) and len(a.pool_uid)==len(a.node_uid)==len(a.volume_uid)==32
    a.output_dir.mkdir(parents=True,mode=0o700,exist_ok=False)
    report=dict(kind='royak-lvm-allocator-component-v1',passed=False,checks=[],commands=[],
        binary_sha256=sha(a.binary.read_bytes()),fixture_sha256=sha(Path(__file__).read_bytes()),
        filesystem_formatted=False,drbd_configured=False,pod_access_granted=False,driver_controller_integrated=False,
        fault_reversal_by_fixture=False)
    cfg_path=a.output_dir/'pool.json';req_path=a.output_dir/'request.json'
    journal=Path('/var/lib/royak/storage/pools')/a.pool_uid/(a.volume_uid+'.json')
    old=Path('/dev')/a.vg/'data';new=Path('/dev')/a.vg/('rkvol_'+a.volume_uid)
    alias='rkvol_'+secrets.token_hex(16);renamed=False;marker_active=False;corrupt_active=False;original_journal=None
    allocation=None;baseline=None

    def command(*args,timeout=30,allowed=(0,)):
        completed=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=timeout)
        assert completed.returncode in allowed,(args[0:2],completed.returncode,completed.stderr[-500:])
        return completed.stdout
    def lvs():return json.loads(command('lvs','--reportformat','json','--units','b','--nosuffix','-o','vg_name,vg_uuid,lv_name,lv_uuid,lv_size,lv_tags'))['report'][0]['lv']
    def ours():return [r for r in lvs() if r['vg_name']==a.vg]
    def check(name,condition,**details):
        report['checks'].append(dict(name=name,passed=bool(condition),**details));assert condition,name
    def invoke(action,*extra,root=True):
        args=[str(a.binary),'storage-driver',action,'--config',str(cfg_path),*map(str,extra)]
        if not root:args=['sudo','-u','royak',*args]
        began=time.monotonic();c=subprocess.run(args,capture_output=True,text=True,timeout=180,
            env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL='C'))
        report['commands'].append(dict(action=action,exit_code=c.returncode,elapsed_s=time.monotonic()-began,
            stdout_sha256=sha(c.stdout.encode()),stderr_sha256=sha(c.stderr.encode()),unprivileged=not root))
        return c
    def read_extent(path,size=None):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECT);buf=mmap.mmap(-1,1024**2);view=memoryview(buf);h=hashlib.sha256()
        try:
            count=os.lseek(fd,0,os.SEEK_END) if size is None else size;os.lseek(fd,0,os.SEEK_SET);left=count
            while left:
                n=min(left,len(view));got=os.readv(fd,[view[:n]]);assert got==n
                h.update(view[:got]);left-=got
            return dict(bytes=count,sha256=h.hexdigest())
        finally:os.close(fd);view.release();buf.close()
    def first_block():
        fd=os.open(new,os.O_RDONLY|os.O_DIRECT);m=mmap.mmap(-1,4096);v=memoryview(m)
        try:assert os.readv(fd,[v])==4096;return bytes(v)
        finally:os.close(fd);v.release();m.close()
    marker=(b'owned Royak allocator negative fixture: not application data\n'+bytes([87])*4096)[:4096]
    def write_marker(data):
        assert len(data)==4096 and allocation is not None
        rows=[r for r in ours() if r['lv_name']=='rkvol_'+a.volume_uid]
        assert len(rows)==1 and rows[0]['lv_uuid']==allocation['lv_uuid']
        fd=os.open(new,os.O_WRONLY|os.O_DIRECT|os.O_SYNC);m=mmap.mmap(-1,4096);v=memoryview(m);v[:]=data
        try:assert os.writev(fd,[v])==4096;os.fsync(fd)
        finally:os.close(fd);v.release();m.close()
    def reverse_marker():
        nonlocal marker_active
        if marker_active:
            assert first_block()==marker,'refusing to overwrite an unexpected concurrent block value'
            write_marker(bytes(4096));marker_active=False;report['fault_reversal_by_fixture']=True
    def reverse_name():
        nonlocal renamed
        if renamed:
            r=[r for r in ours() if r['lv_name']==alias]
            assert len(r)==1 and r[0]['lv_uuid']==allocation['lv_uuid']
            command('lvrename','--devices',a.device,a.vg,alias,'rkvol_'+a.volume_uid)
            renamed=False;report['fault_reversal_by_fixture']=True
    def reverse_journal():
        nonlocal corrupt_active
        if corrupt_active:
            assert journal.read_bytes()==b'{malformed owned fixture journal'
            journal.write_bytes(original_journal);journal.chmod(0o600);corrupt_active=False
            report['fault_reversal_by_fixture']=True

    try:
        assert json.loads(command('drbdsetup','status','--json'))==[]
        assert command('docker','ps','-aq').strip()=='' and command('wg','show','interfaces').strip()==''
        assert command('systemctl','is-active','royak-qualification.service',allowed=(0,3)).strip()=='inactive'
        blocks=json.loads(command('lsblk','-b','-J','-o','PATH,TYPE,SERIAL,SIZE,MOUNTPOINTS'))['blockdevices']
        disks=[b for b in blocks if b['type']=='disk' and b.get('serial')==a.serial]
        assert len(disks)==1 and disks[0]['path']==a.device and disks[0]['size']==2*1024**3
        pv=json.loads(command('pvs','--reportformat','json','-o','pv_name,pv_uuid,vg_name,vg_uuid'))['report'][0]['pv']
        pv=[r for r in pv if r['pv_name']==a.device and r['vg_name']==a.vg];assert len(pv)==1;pv=pv[0]
        baseline=ours();assert len(baseline)==1 and baseline[0]['lv_name']=='data'
        report['baseline_lvs']=baseline;report['retained_before']=read_extent(old)
        assert not journal.exists() and not journal.parent.exists(),'new pool UID only'
        cfg=dict(version=1,cluster_id=a.cluster_id,node_uid=a.node_uid,pool_uid=a.pool_uid,
            vg_name=a.vg,vg_uuid=pv['vg_uuid'],pv_uuid=pv['pv_uuid'],disk_serial=a.serial,
            max_volume_bytes=128*1024**2,max_managed_bytes=256*1024**2)
        req=dict(version=1,cluster_id=cfg['cluster_id'],node_uid=a.node_uid,pool_uid=a.pool_uid,
            namespace_uid=a.namespace_uid,claim_uid=a.claim_uid,volume_uid=a.volume_uid,
            operation_uid=a.operation_uid,capacity_bytes=64*1024**2)
        cfg_path.write_text(json.dumps(cfg));req_path.write_text(json.dumps(req));cfg_path.chmod(0o600);req_path.chmod(0o600)
        c=invoke('inspect');assert c.returncode==0,c.stderr[-500:];pool=json.loads(c.stdout)
        check('driver independently fingerprints the exact data pool',c.returncode==0 and pool['vg_uuid']==cfg['vg_uuid']
            and pool['pv_uuid']==cfg['pv_uuid'] and pool['disk_serial']==a.serial and not pool['pod_access_granted'])
        report['approved_pool']=pool
        c=invoke('inspect',root=False);check('unprivileged helper invocation is refused before disk/config access',c.returncode!=0 and 'root operator' in c.stderr)
        for field,value in [('vg_uuid','CCCCCC-CCCC-CCCC-CCCC-CCCC-CCCC-CCCCCC'),('pv_uuid','DDDDDD-DDDD-DDDD-DDDD-DDDD-DDDD-DDDDDD'),('disk_serial','not-the-approved-disk')]:
            bad=dict(cfg);bad[field]=value;cfg_path.write_text(json.dumps(bad))
            c=invoke('prepare','--request',req_path)
            check('wrong '+field+' cannot allocate',c.returncode!=0 and ours()==baseline and not journal.exists())
        cfg_path.write_text(json.dumps(cfg));cfg_path.chmod(0o644);c=invoke('inspect')
        check('broad config permissions are refused',c.returncode!=0 and ours()==baseline);cfg_path.chmod(0o600)
        moved=cfg_path.with_suffix('.owned');cfg_path.rename(moved);cfg_path.symlink_to(moved)
        c=invoke('inspect');check('symlink config is refused',c.returncode!=0 and ours()==baseline)
        cfg_path.unlink();moved.rename(cfg_path)
        hard=a.output_dir/'hardlink.json';os.link(cfg_path,hard);c=invoke('inspect')
        check('multiply linked config is refused',c.returncode!=0 and ours()==baseline);hard.unlink()
        c=invoke('prepare','--request',req_path);assert c.returncode==0,c.stderr[-500:];prepared=json.loads(c.stdout)
        allocation=prepared['allocation']
        check('new backing LV is durable Prepared without pod authority',c.returncode==0 and prepared['stage']=='Prepared'
            and allocation['bytes']==192*1024**2 and prepared['high_epoch']==0 and not prepared['pod_access_granted'])
        observed=read_extent(new);expected=hashlib.sha256();zeroes=bytes(1024**2)
        for _ in range(192):expected.update(zeroes)
        check('independent full O_DIRECT read confirms every new byte is zero',observed['bytes']==192*1024**2
            and observed['sha256']==prepared['zero_sha256']==expected.hexdigest(),**observed)
        c=invoke('prepare','--request',req_path);check('exact retry preserves allocation UUID and journal',c.returncode==0 and json.loads(c.stdout)==prepared)
        altered=dict(req);altered['claim_uid']=secrets.token_hex(16);req_path.write_text(json.dumps(altered))
        c=invoke('prepare','--request',req_path);check('same volume UID cannot change claim ownership',c.returncode!=0 and journal.exists());req_path.write_text(json.dumps(req))
        extra=dict(req);extra['volume_uid']=secrets.token_hex(16);extra['operation_uid']=secrets.token_hex(16);req_path.write_text(json.dumps(extra));before=ours()
        c=invoke('prepare','--request',req_path);check('a second allocation cannot exceed the explicit pool quota',c.returncode!=0 and ours()==before);req_path.write_text(json.dumps(req))
        command('lvrename','--devices',a.device,a.vg,'rkvol_'+a.volume_uid,alias);renamed=True
        c=invoke('prepare','--request',req_path)
        check('missing prepared backing name never creates an empty replacement',c.returncode!=0 and not new.exists())
        unknown=dict(req);unknown['volume_uid']=alias.removeprefix('rkvol_');unknown['operation_uid']=secrets.token_hex(16);req_path.write_text(json.dumps(unknown))
        c=invoke('prepare','--request',req_path)
        check('an existing LV without its exact journal is never adopted',c.returncode!=0 and 'unknown existing LV' in c.stderr)
        req_path.write_text(json.dumps(req));reverse_name()
        original_journal=journal.read_bytes();(a.output_dir/'journal-original.json').write_bytes(original_journal)
        journal.write_bytes(b'{malformed owned fixture journal');corrupt_active=True
        (a.output_dir/'journal-corrupt.bin').write_bytes(journal.read_bytes())
        c=invoke('prepare','--request',req_path);check('corrupt journal is not treated as a new volume',c.returncode!=0)
        reverse_journal()
        write_marker(marker);marker_active=True;marker_hash=sha(marker)
        c=invoke('prepare','--request',req_path)
        check('retry never re-zeroes data written after allocation acknowledgement',c.returncode==0 and sha(first_block())==marker_hash)
        c=invoke('discard-unformatted','--volume-uid',a.volume_uid)
        check('destructive cleanup refuses nonzero data and preserves the exact marker',c.returncode!=0 and new.exists() and sha(first_block())==marker_hash,
            marker_sha256=marker_hash)
        reverse_marker()
        check('fixture reverses only its deliberate marker before cleanup',read_extent(new)==observed)
        c=invoke('discard-unformatted','--volume-uid',a.volume_uid);assert c.returncode==0,c.stderr[-500:];destroyed=json.loads(c.stdout)
        check('only independently zero, unformatted owned LV is removed',c.returncode==0 and destroyed['stage']=='Destroyed' and not new.exists())
        c=invoke('discard-unformatted','--volume-uid',a.volume_uid)
        check('discard acknowledgement is safely repeatable',c.returncode==0 and json.loads(c.stdout)==destroyed)
        c=invoke('prepare','--request',req_path)
        check('retired allocation UID cannot be reused',c.returncode!=0 and not new.exists())
        report['passed']=True
    except Exception as error:report['error']=str(error)
    finally:
        try:
            reverse_name();reverse_journal();reverse_marker()
            if allocation is not None and new.exists():
                c=invoke('discard-unformatted','--volume-uid',a.volume_uid)
                assert c.returncode==0,'exact blank-allocation cleanup refused; retain it for investigation'
            if baseline is not None:
                report['final_lvs']=ours();report['retained_after']=read_extent(old)
                assert report['final_lvs']==baseline,'LV inventory differs from retained baseline'
                assert report['retained_after']==report['retained_before'],'retained predecessor bytes changed'
            report['cleanup_complete']=True
        except Exception as error:report['cleanup_error']=str(error);report['passed']=False
        report['finished_at']=time.time()
        (a.output_dir/'component-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report.get(k) for k in ['passed','error','cleanup_error','cleanup_complete']},indent=2))
    return int(not report['passed'])


if __name__=='__main__':raise SystemExit(main())
