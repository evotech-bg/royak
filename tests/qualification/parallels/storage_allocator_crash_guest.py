#!/usr/bin/env python3
"""Kill the real new-LV helper mid-zeroing, then exercise journal recovery.

Only a fresh owned LV is touched. The old data LV is fully O_DIRECT hashed
before and after. This is process-crash recovery, not VM power-loss, DRBD,
filesystem or acknowledged-application-data durability qualification.
"""
import argparse
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def sha(data):return hashlib.sha256(data).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ['binary','output-dir']:p.add_argument('--'+arg,type=Path,required=True)
    for arg in ['serial','device','vg','node-uid','pool-uid','volume-uid','cluster-id','namespace-uid','claim-uid','operation-uid']:
        p.add_argument('--'+arg,required=True)
    a=p.parse_args();assert os.geteuid()==0;os.umask(0o077)
    assert a.device=='/dev/sdb' and re.fullmatch(r'rkqs[0-9a-f]{8}',a.vg)
    for uid in [a.node_uid,a.pool_uid,a.volume_uid,a.namespace_uid,a.claim_uid,a.operation_uid]:assert re.fullmatch('[0-9a-f]{32}',uid)
    a.output_dir.mkdir(parents=True,mode=0o700,exist_ok=False)
    report=dict(kind='royak-lvm-allocator-process-crash-v1',passed=False,checks=[],commands=[],
        binary_sha256=sha(a.binary.read_bytes()),fixture_sha256=sha(Path(__file__).read_bytes()),
        process_crash=True,vm_power_loss=False,filesystem_formatted=False,drbd_configured=False,
        pod_access_granted=False,driver_controller_integrated=False)
    cfg_path=a.output_dir/'pool.json';req_path=a.output_dir/'request.json'
    journal=Path('/var/lib/royak/storage/pools')/a.pool_uid/(a.volume_uid+'.json')
    old=Path('/dev')/a.vg/'data';new=Path('/dev')/a.vg/('rkvol_'+a.volume_uid)
    child=None;baseline=None;prepared=None;cfg=None;req=None
    env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL='C')

    def command(*args,allowed=(0,)):
        c=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=30)
        assert c.returncode in allowed,(args[0:2],c.returncode,c.stderr[-500:]);return c.stdout
    def ours():
        values=json.loads(command('lvs','--reportformat','json','--units','b','--nosuffix','-o',
            'vg_name,vg_uuid,lv_name,lv_uuid,lv_size,lv_tags'))['report'][0]['lv']
        return [r for r in values if r['vg_name']==a.vg]
    def extent(path):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECT);m=mmap.mmap(-1,1024**2);v=memoryview(m);h=hashlib.sha256()
        try:
            size=os.lseek(fd,0,os.SEEK_END);os.lseek(fd,0,os.SEEK_SET);left=size
            while left:
                n=min(left,len(v));assert os.readv(fd,[v[:n]])==n;h.update(v[:n]);left-=n
            return dict(bytes=size,sha256=h.hexdigest())
        finally:os.close(fd);v.release();m.close()
    def check(name,condition,**details):
        report['checks'].append(dict(name=name,passed=bool(condition),**details));assert condition,name
    def invoke(action,*extra):
        began=time.monotonic();c=subprocess.run([str(a.binary),'storage-driver',action,'--config',str(cfg_path),*map(str,extra)],
            capture_output=True,text=True,env=env,timeout=180)
        report['commands'].append(dict(action=action,exit_code=c.returncode,elapsed_s=time.monotonic()-began,
            stdout_sha256=sha(c.stdout.encode()),stderr_sha256=sha(c.stderr.encode())))
        return c
    def stop_exact_child():
        if child is not None and child.poll() is None:
            assert Path('/proc',str(child.pid),'exe').resolve()==a.binary.resolve()
            child.kill();child.wait(timeout=10)

    try:
        assert json.loads(command('drbdsetup','status','--json'))==[]
        assert command('docker','ps','-aq').strip()=='' and command('wg','show','interfaces').strip()==''
        assert command('systemctl','is-active','royak-qualification.service',allowed=(0,3)).strip()=='inactive'
        blocks=json.loads(command('lsblk','-b','-J','-o','PATH,TYPE,SERIAL,SIZE,MOUNTPOINTS'))['blockdevices']
        disks=[r for r in blocks if r['type']=='disk' and r.get('serial')==a.serial]
        assert len(disks)==1 and disks[0]['path']==a.device and disks[0]['size']==2*1024**3
        pvs=json.loads(command('pvs','--reportformat','json','-o','pv_name,pv_uuid,vg_name,vg_uuid'))['report'][0]['pv']
        pv=[r for r in pvs if r['pv_name']==a.device and r['vg_name']==a.vg];assert len(pv)==1;pv=pv[0]
        baseline=ours();assert len(baseline)==1 and baseline[0]['lv_name']=='data'
        report['baseline_lvs']=baseline;report['retained_before']=extent(old)
        assert not journal.parent.exists()
        cfg=dict(version=1,cluster_id=a.cluster_id,node_uid=a.node_uid,pool_uid=a.pool_uid,vg_name=a.vg,
            vg_uuid=pv['vg_uuid'],pv_uuid=pv['pv_uuid'],disk_serial=a.serial,
            max_volume_bytes=256*1024**2,max_managed_bytes=512*1024**2)
        req=dict(version=1,cluster_id=a.cluster_id,node_uid=a.node_uid,pool_uid=a.pool_uid,
            namespace_uid=a.namespace_uid,claim_uid=a.claim_uid,volume_uid=a.volume_uid,
            operation_uid=a.operation_uid,capacity_bytes=256*1024**2)
        cfg_path.write_text(json.dumps(cfg));req_path.write_text(json.dumps(req));cfg_path.chmod(0o600);req_path.chmod(0o600)
        with (a.output_dir/'interrupted.stdout').open('x') as out,(a.output_dir/'interrupted.stderr').open('x') as err:
            child=subprocess.Popen([str(a.binary),'storage-driver','prepare','--config',str(cfg_path),'--request',str(req_path)],
                stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=env,start_new_session=True)
            deadline=time.monotonic()+30;observed=None
            while time.monotonic()<deadline:
                if journal.exists():
                    value=json.loads(journal.read_bytes())
                    if value['record']['stage']=='Zeroing':
                        assert Path('/proc',str(child.pid),'exe').resolve()==a.binary.resolve()
                        os.kill(child.pid,signal.SIGSTOP)
                        # Confirm a genuine stopped helper, then pin the exact
                        # durable stage. A missed interruption is a failure,
                        # never relabelled as a crash-recovery success.
                        for _ in range(1000):
                            state=Path('/proc',str(child.pid),'status').read_text()
                            if re.search(r'^State:\s+T',state,re.M):break
                            time.sleep(.001)
                        else:raise RuntimeError('exact helper did not enter stopped state')
                        observed=json.loads(journal.read_bytes());break
                if child.poll() is not None:break
                time.sleep(.001)
            check('real helper stopped after durable Zeroing intent and before Prepared acknowledgement',
                observed is not None and observed['record']['stage']=='Zeroing' and child.poll() is None)
            interrupted=observed['record'];report['interrupted_record']=interrupted
            (a.output_dir/'interrupted-journal.json').write_text(json.dumps(observed,indent=2)+'\n')
            c=invoke('prepare','--request',req_path)
            check('another process cannot enter the pool while the interrupted writer holds its lock',
                c.returncode!=0 and 'operation in progress' in c.stderr)
            stop_exact_child()
            check('exact interrupted helper is killed and reaped',child.returncode==-signal.SIGKILL)
        # The original process never acknowledged Prepared. Ordinary replay
        # can finish ONLY this zeroing intent, using its original LV UUID.
        c=invoke('prepare','--request',req_path);assert c.returncode==0,c.stderr[-500:];prepared=json.loads(c.stdout)
        check('ordinary replay completes the original allocation, not an empty replacement',
            prepared['stage']=='Prepared' and prepared['allocation']==interrupted['allocation']
            and prepared['allocation_nonce']==interrupted['allocation_nonce'] and prepared['request']==req)
        actual=extent(new);expected=hashlib.sha256()
        for _ in range(384):expected.update(bytes(1024**2))
        check('independent direct read verifies the full recovered allocation',
            actual['bytes']==384*1024**2 and actual['sha256']==prepared['zero_sha256']==expected.hexdigest(),**actual)
        c=invoke('prepare','--request',req_path)
        check('post-recovery retry preserves the exact durable acknowledgement',c.returncode==0 and json.loads(c.stdout)==prepared)
        c=invoke('discard-unformatted','--volume-uid',a.volume_uid)
        check('recovered new blank allocation is safely discarded',c.returncode==0 and not new.exists()
            and json.loads(c.stdout)['stage']=='Destroyed')
        report['passed']=True
    except Exception as error:report['error']=str(error)
    finally:
        try:
            stop_exact_child()
            if new.exists() and req is not None:
                # Explicit normal product recovery of this brand-new owned
                # intent, followed by its independently verified blank-only
                # cleanup. Preserve FAILED if the assertion above failed.
                c=invoke('prepare','--request',req_path);assert c.returncode==0,'exact new intent recovery refused'
                c=invoke('discard-unformatted','--volume-uid',a.volume_uid);assert c.returncode==0,'blank-only cleanup refused'
                report['cleanup_replayed_interrupted_intent']=True
            if baseline is not None:
                report['final_lvs']=ours();report['retained_after']=extent(old)
                assert report['final_lvs']==baseline and report['retained_after']==report['retained_before']
            report['cleanup_complete']=True
        except Exception as error:report['cleanup_error']=str(error);report['passed']=False
        report['finished_at']=time.time()
        (a.output_dir/'component-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report.get(k) for k in ['passed','error','cleanup_error','cleanup_complete']},indent=2))
    return int(not report['passed'])


if __name__=='__main__':raise SystemExit(main())
