#!/usr/bin/env python3
"""Read-only raw-block/application-record diagnostics for the exact owned experiment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
from bootstrap import verify_owner,ssh
from storage_preflight import UUIDS


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('lab','parent','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--direct',action='store_true',help='bypass raw block-device page cache (Linux only)')
    a=p.parse_args();os.umask(0o077)
    if a.output.exists():p.error('never overwrite prior evidence')
    root=a.lab.resolve();inv=json.loads((root/'inventory.json').read_text())
    assert inv['kind']=='royak-parallels-lab-v1' and inv['root']==str(root) and {n['uuid'] for n in inv['nodes']}==UUIDS
    parent=json.loads((a.parent/'component-report.json').read_text())
    name=parent['resource'];assert re.fullmatch('rkqs[0-9a-f]{8}',name)
    expected=json.loads((a.parent/'acknowledged-0-100.json').read_text())+json.loads((a.parent/'acknowledged-100-200.json').read_text())
    expected={str(r['id']):r['sha256'] for r in expected};assert len(expected)==200
    size=next(c['bytes_per_replica'] for c in parent['checks'] if 'empty exposed extents' in c['name'])
    rows=[]
    for n in inv['nodes']:
        assert verify_owner(root,n)['State']=='running'
        program="""import hashlib,json,subprocess,os,mmap
device=%r
remaining=%d
direct=%r
chunks=[];h=hashlib.sha256()
fd=os.open(device,os.O_RDONLY | (os.O_DIRECT if direct else 0))
buffer=mmap.mmap(-1,1024**2);view=memoryview(buffer)
try:
 while remaining:
  count=min(1024**2,remaining)
  if direct:
   read=os.readv(fd,[view[:count]]);b=view[:read]
  else:b=os.read(fd,count);read=len(b)
  if not read:raise RuntimeError('short extent')
  chunks.append(hashlib.sha256(b).hexdigest());h.update(b);remaining-=read
finally:os.close(fd)
records={}
for i in range(200):
 r=subprocess.run(['debugfs',*(['-D'] if direct else []),'-R','cat /record-%%06d'%%i,device],capture_output=True)
 records[str(i)]=dict(bytes=len(r.stdout),sha256=hashlib.sha256(r.stdout).hexdigest(),exit_code=r.returncode,stderr=r.stderr.decode(errors='replace')[:250])
print(json.dumps(dict(raw_sha256=h.hexdigest(),chunk_sha256=chunks,record_hashes=records)))
""" % ('/dev/'+name+'/data',size,a.direct)
        before=ssh(root,n,'sudo drbdsetup status '+name+' --json',timeout=15)
        value=json.loads(ssh(root,n,'sudo python3 -c '+shlex.quote(program),timeout=120))
        value.update(node=n['id'],status_before=json.loads(before),sampled_at=time.time(),
            incorrect_record_ids=[int(k) for k,r in value['record_hashes'].items() if r['sha256']!=expected[k]])
        rows.append(value)
    chunks=rows[1]['chunk_sha256']
    report=dict(kind='royak-storage-readonly-diagnostics-v1',at=time.time(),resource=name,bytes_per_replica=size,
        io_mode='O_DIRECT/debugfs-D' if a.direct else 'buffered-raw-block-device',
        parent_sha256=hashlib.sha256((a.parent/'component-report.json').read_bytes()).hexdigest(),
        fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),nodes=rows,
        differing_mib_chunks_vs_node2={str(r['node']):[i for i,(x,y) in enumerate(zip(r['chunk_sha256'],chunks)) if x!=y] for r in rows},
        scope='read-only observation; no storage repair, promotion, filesystem mutation or production qualification')
    with a.output.open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps(dict(raw_hashes=[r['raw_sha256'] for r in rows],
        incorrect_records={str(r['node']):r['incorrect_record_ids'] for r in rows},
        differing_mib_chunks_vs_node2=report['differing_mib_chunks_vs_node2']),indent=2))


if __name__=='__main__':main()
