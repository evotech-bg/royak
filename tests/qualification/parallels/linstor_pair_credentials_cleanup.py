#!/usr/bin/env python3
"""Unlink exactly 36 ephemeral TLS/config files after ALL identity guards.

No process signal, namespace/device operation, recursive deletion, evidence or
database rewrite. The caller supplies hashes of the four original reports.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


ROOT=Path('/home/royak/.local/share/royak-qualification/linstor-footprint-20261102-v1')
CASES=['pair-attempt'+str(n) for n in range(1,5)]
NAMES=['private/ca.key','private/controller.key','private/satellite.key','private/client.key',
       'private/controller.p12','private/satellite.p12','private/trusted.p12',
       'controller-config/linstor.toml','satellite-config/linstor_satellite.toml']


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def identity(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def no_java():
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:comm=(p/'comm').read_text().strip()
        except (FileNotFoundError,ProcessLookupError):continue
        assert comm!='java','a Java process still exists; refuse all credential cleanup'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-reports',required=True)
    args=parser.parse_args()
    expected=json.loads(args.expected_reports)
    assert set(expected)==set(CASES)
    assert os.getuid()==0 and Path('/etc/royak-lab-owner').read_text().strip()=='rkq-vm-20261028-royak'
    assert ROOT.resolve()==ROOT and ROOT.stat().st_uid==1000 and stat.S_IMODE(ROOT.stat().st_mode)==0o700
    assert os.readlink('/proc/self/ns/mnt')==os.readlink('/proc/1/ns/mnt')
    assert os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net')
    no_java()
    held=[];guarded=[];evidence={};reports={}
    try:
        for name in CASES:
            case=ROOT/name
            assert case.resolve()==case and case.stat().st_uid==1000 and stat.S_IMODE(case.stat().st_mode)==0o700
            report=case/'pair-report.json'
            assert sha(report)==expected[name]
            original=json.loads(report.read_bytes());reports[name]=original
            assert original['all_roles_reaped'] and original['all_prerequisites_reaped']
            assert original['residual_original_session_processes']==[]
            for role in original['roles']:
                assert role['ended']['reaped']
                p=Path('/proc')/str(role['ended']['pid'])
                if p.exists():
                    start=(p/'stat').read_text().rsplit(') ',1)[1].split()[19]
                    assert start!=role['ended']['start_ticks'],'original process identity remains'
            for parent_name in ['private','controller-config','satellite-config']:
                parent=case/parent_name
                assert parent.resolve()==parent and parent.stat().st_uid==1000 and stat.S_IMODE(parent.stat().st_mode)==0o700
                fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                held.append(fd)
                for relative in [n for n in NAMES if n.split('/')[0]==parent_name]:
                    leaf=relative.split('/')[1]
                    s=os.stat(leaf,dir_fd=fd,follow_symlinks=False)
                    assert stat.S_ISREG(s.st_mode) and s.st_uid==1000 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600
                    path=case/relative
                    guarded.append(dict(parent_fd=fd,leaf=leaf,path=path,identity=identity(s),sha256=sha(path)))
            for path in case.rglob('*'):
                if path.is_file() and not path.is_symlink() and (path.name in ['pair-report.json','resources.jsonl'] or path.suffix in ['.log','.db'] or path.name.endswith('-redacted-tail.txt')):
                    evidence[str(path.relative_to(ROOT))]=sha(path)
        assert len(guarded)==36
        no_java()
        # Validate EVERY open-parent identity and file hash before first unlink.
        for row in guarded:
            assert identity(os.stat(row['leaf'],dir_fd=row['parent_fd'],follow_symlinks=False))==row['identity']
            assert sha(row['path'])==row['sha256']
        removed=[]
        for row in guarded:
            assert identity(os.stat(row['leaf'],dir_fd=row['parent_fd'],follow_symlinks=False))==row['identity']
            os.unlink(row['leaf'],dir_fd=row['parent_fd']);os.fsync(row['parent_fd'])
            assert not row['path'].exists() and not row['path'].is_symlink()
            removed.append(dict(path=str(row['path'].relative_to(ROOT)),prior_sha256=row['sha256']))
        assert all(sha(ROOT/name)==digest for name,digest in evidence.items())
        no_java()
        print(json.dumps(dict(kind='exact36-LINSTOR-pair-credentials-cleanup',removed=removed,
            retained_evidence_sha256=evidence,raw_reports_resources_logs_H2_unchanged=True,
            original_report_sha256=expected,secure_erasure_claim=False,private_JRE_archives_and_metadata_retained=True)))
    finally:
        for fd in held:os.close(fd)


if __name__=='__main__':main()
