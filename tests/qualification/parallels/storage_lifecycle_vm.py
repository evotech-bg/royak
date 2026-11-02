#!/usr/bin/env python3
"""Run current Linux metadata/lifecycle regressions on three owned kernels.

HTTPS tests run separately on each VM; the Raft subprocess test runs on node1
only and shares that node's kernel. NO claim of cross-host Raft/storage IO or
physical fencing follows from this gate. No containers/disks/routes are changed.
"""
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
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from bootstrap import run,ssh,verify_owner
from storage_disks import wait_for
from storage_preflight import UUIDS

REPO=Path(__file__).resolve().parents[3]
FIXTURES=['storage_identity_http.py','storage_identity_raft.py','backup_cli.py','storage_cli.py']

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,required=True);p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--old-binary',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
    a=p.parse_args();os.umask(0o077)
    root=a.lab.resolve();inv=json.loads((root/'inventory.json').read_text())
    assert inv['root']==str(root) and inv['kind']=='royak-parallels-lab-v1' and {n['uuid'] for n in inv['nodes']}==UUIDS
    if a.output_dir.exists():p.error('never overwrite previous qualification')
    build_path=a.binary.with_name(a.binary.name+'.build.json');build=json.loads(build_path.read_text())
    assert build['binary_sha256']==digest(a.binary) and build['source_unchanged_during_build']
    assert not build['debug_symbols'] and not build['symbols_only']
    expected=build['source_sha256']
    assert all(digest(REPO/name)==value for name,value in expected.items()),'build is not current source'
    assert shutil.disk_usage(root).free>=32*1024**3
    for n in inv['nodes']:assert verify_owner(root,n)['State']=='stopped'
    a.output_dir.mkdir(mode=0o700,parents=True)
    guest='/home/royak/.local/share/royak-qualification/lifecycle-'+secrets.token_hex(6)
    report=dict(kind='royak-lifecycle-linux-metadata-v1',passed=False,created_at=time.time(),nodes=[],
        guest_root=guest,binary_sha256=digest(a.binary),old_binary_sha256=digest(a.old_binary),
        build_manifest_sha256=digest(build_path),fixture_sha256=digest(Path(__file__)),
        scripts_sha256={f:digest(REPO/'tests/qualification'/f) for f in FIXTURES},
        source_sha256=expected,normal_release_flags=True,disks_changed=False,containers_created=False,
        cross_host_raft_test=False,driver_io_test=False,physical_fencing_test=False)
    booted=[];execution_done=False
    try:
        for n in inv['nodes']:
            verify_owner(root,n);run('prlctl','start',n['uuid'],timeout=90);booted.append(n)
        for n in inv['nodes']:
            wait_for(lambda:ssh(root,n,'printf ready',timeout=5).strip()=='ready',120)
            assert verify_owner(root,n)['State']=='running'
            ssh(root,n,'test ! -e '+shlex.quote(guest)+' && install -d -m 0700 '+shlex.quote(guest+'/tests/qualification'))
            # No shared folders: copy the exact source snapshot, scripts and
            # two pinned binaries into this new private guest directory.
            scp=['scp','-q','-i',str(root/'operator'),'-o','IdentitiesOnly=yes','-o','BatchMode=yes',
                 '-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile='+str(root/'known_hosts')]
            dest='royak@'+n['ip']+':'+guest+'/'
            run(*scp,'-r',REPO/'src',dest,timeout=60)
            run(*scp,a.binary,dest+'royak',timeout=60)
            run(*scp,a.old_binary,dest+'royak-old',timeout=60)
            for f in FIXTURES:run(*scp,REPO/'tests/qualification'/f,dest+'tests/qualification/'+f,timeout=30)
            manifest={'binary':digest(a.binary),'old':digest(a.old_binary),'src':{k[4:]:v for k,v in expected.items() if k.startswith('src/')},
                      'scripts':report['scripts_sha256']}
            program="""import hashlib,json,pathlib,subprocess,os
root=pathlib.Path(%r);manifest=json.loads(%r)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(root/'royak')==manifest['binary'] and sha(root/'royak-old')==manifest['old']
for name,value in manifest['src'].items():assert sha(root/'src'/name)==value,name
for name,value in manifest['scripts'].items():assert sha(root/'tests/qualification'/name)==value,name
(root/'royak').chmod(0o700);(root/'royak-old').chmod(0o700)
assert os.geteuid()!=0,'run metadata tests unprivileged'
assert not subprocess.check_output(['sudo','docker','ps','-aq'],text=True).strip()
assert json.loads(subprocess.check_output(['sudo','drbdsetup','status','--json'],text=True))==[]
rows=[]
for script,output in [('storage_identity_http.py','https.json'),('backup_cli.py','backup.json'),('storage_cli.py','storage.json')]+([('storage_identity_raft.py','raft.json')] if %r else []):
 args=['python3',str(root/'tests/qualification'/script),'--binary',str(root/'royak'),'--output',str(root/output)]
 if script in ['storage_identity_http.py','storage_identity_raft.py']:args+=['--old-binary',str(root/'royak-old')]
 completed=subprocess.run(args,capture_output=True,text=True,timeout=180,cwd=root)
 (root/(output+'.stdout')).write_text(completed.stdout)
 (root/(output+'.stderr')).write_text(completed.stderr)
 data=json.loads((root/output).read_text())
 assert data['binary_sha256']==manifest['binary'] and data['fixture_sha256']==manifest['scripts'][script]
 if 'source_sha256' in data:assert data['source_sha256']==manifest['src']
 rows.append(dict(file=output,exit_code=completed.returncode,report=data))
alive=[]
for proc in pathlib.Path('/proc').glob('[0-9]*'):
 try:
  if (proc/'exe').resolve() in [root/'royak',root/'royak-old']:alive.append(int(proc.name))
 except OSError:pass
print(json.dumps(dict(rows=rows,residual_exact_processes=alive)))
""" % (guest,json.dumps(manifest),n['id']==1)
            result=json.loads(ssh(root,n,'python3 -c '+shlex.quote(program),timeout=240))
            assert not result['residual_exact_processes'],'exact guest child leaked'
            node_dir=a.output_dir/('node-'+str(n['id']));node_dir.mkdir(mode=0o700)
            for row in result['rows']:
                with (node_dir/row['file']).open('x') as stream:json.dump(row['report'],stream,indent=2);stream.write('\n')
            report['nodes'].append(dict(id=n['id'],uuid=n['uuid'],results=[dict(file=r['file'],exit_code=r['exit_code'],
                passed=r['report']['passed'],checks=len(r['report']['checks']),report_sha256=digest(node_dir/r['file'])) for r in result['rows']],
                residual_exact_processes=result['residual_exact_processes']))
        assert all(digest(REPO/name)==value for name,value in expected.items()),'source changed during VM regression'
        execution_done=True
        report['passed']=all(r['passed'] and r['exit_code']==0 for n in report['nodes'] for r in n['results'])
    except Exception as error:report['error']=str(error)
    finally:
        try:
            # Never power off over an unexamined orphaned test process. On an
            # interrupted fixture, retain running guests for exact recovery.
            if len(booted)!=3:raise RuntimeError('partial boot: verify exact guest ownership before poweroff')
            completed=subprocess.run([sys.executable,str(Path(__file__).with_name('storage_closeout.py')),
                '--lab',str(root),'--output',str(a.output_dir/'closeout.json'),
                '--extra-binary',guest+'/royak','--extra-binary',guest+'/royak-old'],capture_output=True,text=True,timeout=180)
            assert completed.returncode==0,completed.stderr[-1200:]
            assert json.loads((a.output_dir/'closeout.json').read_text())['all_owned_vms_stopped']
            report['closeout_sha256']=digest(a.output_dir/'closeout.json')
        except Exception as error:report['cleanup_error']=str(error);report['passed']=False
        report['finished_at']=time.time()
        report['execution_done']=execution_done
        with (a.output_dir/'vm-report.json').open('x') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({k:report.get(k) for k in ['passed','error','cleanup_error','binary_sha256']},indent=2))
    return int(not report['passed'])


if __name__=='__main__':raise SystemExit(main())
