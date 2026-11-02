#!/usr/bin/env python3
"""New cold-attached disks for the measured LINSTOR candidate, no old adoption.

Only the three pinned lab VMs. All guests pass quiescence before any shutdown.
Original Popen handles/receipts use the existing exact-operation owner. A
timeout is not permission to kill/retry. An incomplete run is never resumed
automatically. This creates blank disks, NOT pools or storage qualification.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import sys
import time
import xml.etree.ElementTree as ET

REPO=Path(__file__).resolve().parents[3]
BASE=REPO/'tests/qualification/.runs/rkq-storage-20261030'
LAB=REPO/'tests/qualification/.runs/rkq-vm-20261028-royak'
OUT=BASE/'root-linstor-data-v1/disks-attempt2'
HELPERS=BASE/'agent-normal-main-n2-server-recipes-v1'
UUIDS=['29cbe522-6829-412f-a480-ab52283a1158','1752e81e-a541-4099-a054-842f71f3cc64','12422c3b-1e89-444b-8faf-426d2da0b15e']
SIZE=2*1024**3


def event_name(node_id,phase):
    return 'n'+str(node_id)+'-event-'+phase+'.json'


def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def validate_vm(info,node):
    assert node['id'] in [1,2,3] and UUIDS[node['id']-1]==node['uuid']
    assert info['ID'].strip('{}')==node['uuid'] and info['Name']==node['name']
    assert Path(info['Home']).resolve()==(LAB/'vms'/(node['name']+'.pvm')).resolve()
    assert info['Hardware']['memory']['size']=='2048Mb' and info['Hardware']['cpu']['cpus']==2


def validate_new_disk(before,after):
    old={d['serial'] for d in before if d['type']=='disk'}
    assert '' not in old and None not in old
    new=[d for d in after if d['type']=='disk' and d.get('serial') not in old]
    assert len(new)==1
    d=new[0]
    assert d['serial'] and d['size']==SIZE and not d.get('children')
    assert d['path'].startswith('/dev/sd') and d['path'] not in {v['path'] for v in before}
    assert d['mountpoints'] and all(m is None for m in d['mountpoints'])
    assert {v['serial'] for v in after if v['type']=='disk'}==old|{d['serial']}
    for prior in before:
        if prior['type']=='disk':
            current=next(v for v in after if v.get('serial')==prior['serial'])
            assert all(current[k]==prior[k] for k in ['path','size','type','model','uuid','mountpoints'])
    return d


PROBE=r'''import pathlib,json,os,subprocess,hashlib
def run(args,allow=False):
 p=subprocess.run(args,capture_output=True,text=True,check=False)
 assert allow or p.returncode==0,(args,p.returncode,p.stderr)
 return p.stdout.strip()
assert os.getuid()==0 and pathlib.Path('/etc/royak-lab-owner').read_text().strip()=='rkq-vm-20261028-royak'
assert run(['docker','ps','-aq'])==''
assert json.loads(run(['drbdsetup','status','--json']))==[]
assert run(['wg','show','interfaces'])==''
assert run(['systemctl','is-active','royak-qualification.service'],True)=='inactive'
assert run(['systemctl','is-enabled','royak-qualification.service'],True) in ['disabled','not-found']
visible=[]
for p in pathlib.Path('/proc').iterdir():
 if not p.name.isdigit():continue
 try:comm=(p/'comm').read_text().strip()
 except (FileNotFoundError,ProcessLookupError):continue
 assert comm!='java' and 'royak' not in comm and comm not in ['postgres','restic'],(p.name,comm)
 if comm.startswith('python') and int(p.name)!=os.getpid():visible.append(dict(pid=int(p.name),comm=comm))
assert visible==[],('other Python test owners still visible',visible)
configs={}
for parent in [pathlib.Path('/etc/drbd.d'),pathlib.Path('/etc/drbd.conf')]:
 for p in sorted(parent.rglob('*')) if parent.is_dir() else [parent]:
  assert not p.is_symlink()
  if p.is_file():configs[str(p)]=hashlib.sha256(p.read_bytes()).hexdigest()
out=dict(boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),lab=os.path.realpath('/lab'),
 packages_sha256=hashlib.sha256(run(['dpkg-query','-W']).encode()).hexdigest(),configs=configs,
 blocks=json.loads(run(['lsblk','-b','-J','-o','NAME,PATH,SIZE,TYPE,MOUNTPOINTS,SERIAL,MODEL,UUID,MAJ:MIN']))['blockdevices'],
 lvs=json.loads(run(['lvs','--reportformat','json','--units','b','--nosuffix','-o','vg_name,lv_name,lv_uuid,lv_size,lv_attr'])),
 pvs=json.loads(run(['pvs','--reportformat','json','--units','b','--nosuffix','-o','pv_name,pv_uuid,vg_name,vg_uuid,pv_size'])))
print(json.dumps(out))
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--action',choices=['preflight','execute'],required=True);a=p.parse_args()
    assert sha(LAB/'inventory.json')=='bcce839c84eaf624cc16da06381a9cec0971292f25a4e0da837def005db2ce56'
    for name,pin in {'safe_server_build.py':'788bdfab19a1b9898efe1330d67fcaf9b988f7c905f214edba9d20d38a30ff74',
        'owner_registry.py':'b53206032ba86a2c9bf10478d35dcbe7313f2ac2a6de31582cc6a4ef5cff3404',
        'normal_server_descriptor_equality.py':'046e13b1c520010bf875d14d886af9824522c9208b5dd3b0fca424bcb5664c32'}.items():assert sha(HELPERS/name)==pin
    assert shutil.disk_usage(BASE).free>=40*1024**3
    os.umask(0o077)
    out=OUT if a.action=='execute' else OUT.parent/'disks-preflight2'
    assert not out.exists() and not out.is_symlink();out.mkdir(parents=True,mode=0o700)
    sys.path.insert(0,str(HELPERS));spec=importlib.util.spec_from_file_location('data_disk_original_operations',HELPERS/'safe_server_build.py')
    b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
    nodes=json.loads((LAB/'inventory.json').read_bytes())['nodes'];assert [n['uuid'] for n in nodes]==UUIDS
    options=['-F','/dev/null','-i',str(LAB/'operator'),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
        '-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+str(LAB/'known_hosts'),'-o','ConnectTimeout=3','-o','ControlMaster=no','-o','ControlPath=none']
    report=dict(kind='new-LINSTOR-candidate-data-disks-v1',passed=False,action=a.action,fixture_sha256=sha(Path(__file__)),
                size_bytes_per_disk=SIZE,maximum_total_bytes=3*SIZE,nodes=[],compiler_operation=False,storage_qualified=False)
    def vm(n,tag):
        value=json.loads(b.command(out,'n'+str(n['id'])+'-'+tag,['prlctl','list','-i',n['uuid'],'--json']))[0]
        validate_vm(value,n);return value
    def remote(n,tag,code=PROBE):
        return b.command(out,'n'+str(n['id'])+'-'+tag,['ssh',*options,'royak@'+n['ip'],'sudo -n python3 -B -c '+shlex.quote(code)],timeout=40)
    def event(n,phase,**value):
        b.put(out/event_name(n['id'],phase),dict(node=n['id'],uuid=n['uuid'],phase=phase,**value))
    try:
        # ALL initial checks precede the first guest shutdown or new disk.
        for n in nodes:
            info=vm(n,'owner-before');assert info['State']=='running'
            assert {k for k in info['Hardware'] if k.startswith('hdd')}=={'hdd0','hdd1','hdd2'}
            before=json.loads(remote(n,'before'))
            report['nodes'].append(dict(node=n,before=before,vm_before=info))
        if a.action=='execute':
            for row in report['nodes']:
                n=row['node'];assert shutil.disk_usage(BASE).free>=32*1024**3
                info=vm(n,'owner-before-shutdown');assert info['State']=='running'
                fresh=json.loads(remote(n,'quiescence-before-shutdown'))
                assert all(fresh[k]==row['before'][k] for k in ['boot','lab','packages_sha256','configs','blocks','lvs','pvs'])
                event(n,'shutdown-intent',old_boot=fresh['boot'])
                code,_,_=b.operation(out,'n'+str(n['id'])+'-shutdown',['ssh',*options,'royak@'+n['ip'],'sudo -n shutdown -h now'],40)
                assert code in [0,255],('unexpected shutdown client status',code)
                end=time.monotonic()+75;number=0
                while True:
                    number+=1;stopped=vm(n,'stopped-check'+str(number))
                    if stopped['State']=='stopped':break
                    assert time.monotonic()<end,'normal shutdown did not complete; no force-stop'
                    time.sleep(1)
                oldhw={k:v for k,v in row['vm_before']['Hardware'].items() if k.startswith('hdd')}
                assert {k:v for k,v in stopped['Hardware'].items() if k.startswith('hdd')}==oldhw
                disk=out/('new-owned-n'+str(n['id'])+'.hdd');assert not disk.exists() and not disk.is_symlink()
                event(n,'disk-create-intent',host_disk=str(disk),size_bytes=SIZE)
                b.command(out,'n'+str(n['id'])+'-create-disk',['prl_disk_tool','create','--hdd',str(disk),'--size','2G','--alloc-policy','sparse'],timeout=90)
                assert disk.is_dir() and disk.resolve()==disk and disk.stat().st_uid==os.getuid()
                descriptor=disk/'DiskDescriptor.xml';tree=ET.parse(descriptor)
                backing=disk/tree.find('.//StorageData/Storage/Image/File').text
                assert backing.resolve().parent==disk and backing.stat().st_size==SIZE and stat.S_ISREG(backing.stat().st_mode)
                assert backing.stat().st_nlink==1
                identity=dict(host_disk=str(disk),descriptor_sha256=sha(descriptor),backing_name=backing.name,backing_inode=backing.stat().st_ino,backing_dev=backing.stat().st_dev,backing_size=SIZE)
                event(n,'disk-created',**identity)
                recheck=vm(n,'owner-before-attach');assert recheck['State']=='stopped' and recheck['Hardware']==stopped['Hardware']
                b.command(out,'n'+str(n['id'])+'-attach',['prlctl','set',n['uuid'],'--device-add','hdd','--image',str(disk),'--iface','sata'],timeout=60)
                attached=vm(n,'attached')
                assert attached['State']=='stopped' and all(attached['Hardware'][k]==v for k,v in oldhw.items())
                new={k:v for k,v in attached['Hardware'].items() if k.startswith('hdd') and k not in oldhw}
                assert set(new)=={'hdd3'} and Path(new['hdd3']['image']).resolve()==disk and new['hdd3']['size']=='2048Mb'
                event(n,'disk-attached',**identity,hardware=new)
                b.command(out,'n'+str(n['id'])+'-start',['prlctl','start',n['uuid']],timeout=90)
                end=time.monotonic()+120;number=0
                while True:
                    number+=1
                    code,stdout,stderr=b.operation(out,'n'+str(n['id'])+'-boot-check'+str(number),['ssh',*options,'royak@'+n['ip'],'test -f /var/lib/royak-lab-ready'],15)
                    if code==0:break
                    assert time.monotonic()<end,'guest boot did not complete; no restart'
                    time.sleep(1)
                after=json.loads(remote(n,'after'));assert after['boot']!=fresh['boot']
                assert all(after[k]==fresh[k] for k in ['lab','packages_sha256','configs','lvs','pvs'])
                guest=validate_new_disk(fresh['blocks'],after['blocks'])
                signatures=json.loads(remote(n,'blank-proof',"import json,subprocess;print(subprocess.check_output(['wipefs','--no-act','--json',"+repr(guest['path'])+"],text=True))"))
                assert signatures['signatures']==[]
                final=vm(n,'owner-final');assert final['State']=='running' and final['Hardware']==attached['Hardware']
                row.update(identity=identity,guest_disk=guest,blank_signatures=signatures,after=after,vm_after=final)
                event(n,'identified-blank',**identity,guest_disk=guest)
                print(json.dumps(dict(node=n['id'],new_disk_serial=guest['serial'],new_disk_path=guest['path'],bytes=SIZE,blank=True)),flush=True)
        report['passed']=True
    except BaseException as error:report['failure']=type(error).__name__+': '+str(error)
    report['original_owner']=b.OWNERS.snapshot();b.put(out/'report.json',report)
    print(json.dumps({k:report.get(k) for k in ['passed','action','failure','original_owner']}),flush=True)
    return int(not report['passed'])


if __name__=='__main__':raise SystemExit(main())
