#!/usr/bin/env python3
"""Exact new mesh credential closeout; no signals, links or volume operations.

Probe all three nodes before any apply. Revalidate every leaf and evidence
hash before first unlink; keep raw runner/resource/log/H2 files unchanged.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

CASE=Path('/home/royak/.local/share/royak-qualification/linstor-footprint-20261102-v1/mesh-attempt2')


def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def targets(node):
    rows=['assets/config.json','assets/satellite.key','assets/satellite.p12','private/wg.key',
          'private/controller.trust.p12','satellite-config/linstor_satellite.toml']
    if node==1:rows+=['assets/controller.key','assets/controller.p12','assets/operator.key','assets/api-server.p12',
                     'private/operator.trust.p12','private/nodes.trust.p12','controller-config/linstor.toml']
    return sorted(rows)


def metadata(s):
    return dict(device=s.st_dev,inode=s.st_ino,mode=s.st_mode,uid=s.st_uid,gid=s.st_gid,nlink=s.st_nlink,
                size=s.st_size,mtime_ns=str(s.st_mtime_ns),ctime_ns=str(s.st_ctime_ns))


def quiescent():
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:comm=(p/'comm').read_text().strip()
        except (FileNotFoundError,ProcessLookupError):continue
        assert comm!='java','a Java process remains'
    worker=json.loads((CASE/'worker.json').read_bytes())
    p=Path('/proc')/str(worker['pid'])
    if p.exists():assert (p/'stat').read_text().rsplit(') ',1)[1].split()[19]!=worker['start_ticks']
    assert not Path('/sys/class/net/rklsmv1').exists()
    for p in Path('/proc').iterdir():
        if not p.name.isdigit() or int(p.name)==os.getpid():continue
        try:cwd=os.readlink(p/'cwd')
        except (FileNotFoundError,ProcessLookupError):continue
        assert cwd!=str(CASE),'another process still uses this exact test cwd'


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--action',choices=['probe','apply'],required=True)
    p.add_argument('--node',type=int,choices=[1,2,3],required=True);p.add_argument('--server-sha256',required=True)
    p.add_argument('--plan-sha256');a=p.parse_args();os.umask(0o077)
    assert os.getuid()==0 and Path('/etc/royak-lab-owner').read_text().strip()=='rkq-vm-20261028-royak'
    assert CASE.resolve()==CASE and CASE.stat().st_uid==1000 and stat.S_IMODE(CASE.stat().st_mode)==0o700
    assert sha(CASE/'server-report.json')==a.server_sha256
    report=json.loads((CASE/'server-report.json').read_bytes())
    assert report['node']['id']==a.node and report['all_original_roles_reaped'] and report['all_prerequisites_reaped']
    assert report['residual_original_sessions']==[] and report['network_cleanup']['exact_owned_interface_removed']
    quiescent();held=[]
    try:
        rows=[]
        for relative in targets(a.node):
            parent=CASE/relative.split('/')[0];leaf=relative.split('/')[1]
            assert parent.resolve()==parent and parent.stat().st_uid==1000 and stat.S_IMODE(parent.stat().st_mode)==0o700
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);held.append(fd)
            s=os.stat(leaf,dir_fd=fd,follow_symlinks=False)
            assert stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1
            assert s.st_uid==(0 if relative=='private/wg.key' else 1000)
            rows.append(dict(relative=relative,metadata=metadata(s),sha256=sha(CASE/relative),fd=fd,leaf=leaf))
        evidence={}
        for f in CASE.rglob('*'):
            if not f.is_file() or f.is_symlink() or str(f.relative_to(CASE)) in targets(a.node):continue
            if f.suffix in ['.log','.db'] or f.name in ['server-report.json','resources.jsonl','exercise-report.json','management-requests.jsonl','peer-negative-report.json'] or f.name.endswith('-redacted-tail.txt'):
                evidence[str(f.relative_to(CASE))]=sha(f)
        public_rows=[{k:v for k,v in r.items() if k not in ['fd','leaf']} for r in rows]
        plan=dict(kind='exact-mesh-credential-cleanup-plan',node=a.node,server_report_sha256=a.server_sha256,files=public_rows,evidence=evidence)
        if a.action=='probe':
            with (CASE/'credential-cleanup-plan.json').open('x') as f:json.dump(plan,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
            os.chown(CASE/'credential-cleanup-plan.json',1000,1000)
            print(json.dumps(dict(probed=True,files=len(rows),plan_sha256=sha(CASE/'credential-cleanup-plan.json'))));return
        assert a.plan_sha256 and sha(CASE/'credential-cleanup-plan.json')==a.plan_sha256
        original=json.loads((CASE/'credential-cleanup-plan.json').read_bytes());assert plan==original
        quiescent()
        for r in rows:
            assert metadata(os.stat(r['leaf'],dir_fd=r['fd'],follow_symlinks=False))==r['metadata'] and sha(CASE/r['relative'])==r['sha256']
        removed=[]
        for r in rows:
            assert metadata(os.stat(r['leaf'],dir_fd=r['fd'],follow_symlinks=False))==r['metadata']
            os.unlink(r['leaf'],dir_fd=r['fd']);os.fsync(r['fd']);assert not (CASE/r['relative']).exists()
            removed.append(dict(relative=r['relative'],prior_sha256=r['sha256']))
        assert all(sha(CASE/name)==digest for name,digest in evidence.items())
        quiescent()
        result=dict(kind='exact-mesh-credential-cleanup',node=a.node,removed=removed,evidence=evidence,
                    raw_reports_resources_logs_H2_unchanged=True,secure_erasure_claim=False,kernel_modules_unloaded=False)
        with (CASE/'credential-cleanup-report.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.chown(CASE/'credential-cleanup-report.json',1000,1000)
        print(json.dumps(dict(passed=True,removed=len(removed),report_sha256=sha(CASE/'credential-cleanup-report.json'))))
    finally:
        for fd in held:os.close(fd)


if __name__=='__main__':main()
