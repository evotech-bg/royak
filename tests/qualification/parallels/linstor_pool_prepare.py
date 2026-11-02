#!/usr/bin/env python3
"""Initialize only the three NEW blank disks, recording durable PV/VG identity.

This is preparation for real LINSTOR replica I/O, not a replica or production
gate. Never retry/adopt an existing PV, VG, case directory or incomplete run.
Guest commands retain their original Popen/log owner on timeout, no force kill.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

RUN='linstor-data-pool-20261102-v2'
GUEST=Path('/var/lib/royak-storage-qualification')/RUN
STAGED=Path('/home/royak/.local/share/royak-qualification/linstor-footprint-20261102-v1/linstor_pool_prepare_v2.py')
SIZE=2*1024**3
UUIDS=['29cbe522-6829-412f-a480-ab52283a1158','1752e81e-a541-4099-a054-842f71f3cc64','12422c3b-1e89-444b-8faf-426d2da0b15e']


def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()


def put(p,v):
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:json.dump(v,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())


def validate_config(c):
    assert set(c)=={'run','node','uuid','device','serial','size','major_minor','vg','tag'}
    assert c['run']==RUN and c['node'] in [1,2,3] and UUIDS[c['node']-1]==c['uuid']
    assert c['device']=='/dev/sdd' and c['serial'] and re.fullmatch('[A-Za-z0-9]+',c['serial'])
    assert c['size']==SIZE and re.fullmatch('[0-9]+:[0-9]+',c['major_minor'])
    assert c['vg']=='rklsd_20261102_n'+str(c['node']) and c['tag']=='rklsd_20261102_n'+str(c['node'])


def descriptor_guard(disk,identity):
    # Descriptor XML is hypervisor-maintained metadata, not the backing-file
    # identity. Do not silently rebaseline it or claim historical equality.
    assert disk.resolve()==disk and str(disk)==identity['host_disk'] and disk.stat().st_uid==os.getuid()
    backing=disk/identity['backing_name'];s=backing.stat()
    assert not backing.is_symlink() and backing.resolve().parent==disk and s.st_ino==identity['backing_inode']
    assert s.st_dev==identity['backing_dev'] and s.st_size==identity['backing_size']==SIZE and s.st_nlink==1
    expected=identity['descriptor_sha256'];current=disk/'DiskDescriptor.xml';current_sha=sha(current)
    backup=disk/'DiskDescriptor.xml.Backup'
    assert not current.is_symlink() and not backup.is_symlink()
    old=ET.parse(backup).getroot();new=ET.parse(current).getroot()
    for tree in [old,new]:
        assert tree.tag=='Parallels_disk_image' and int(tree.findtext('./Disk_Parameters/Disk_size'))*512==SIZE
        assert len(tree.findall('./StorageData/Storage'))==1 and len(tree.findall('./StorageData/Storage/Image'))==1
        image=tree.find('./StorageData/Storage/Image')
        assert image.findtext('Type')=='Plain' and image.findtext('File')==identity['backing_name']
        guid=image.findtext('GUID');assert guid and identity['backing_name'].endswith('.'+guid+'.hds')
        assert tree.findtext('./StorageData/Storage/Start')=='0' and int(tree.findtext('./StorageData/Storage/End'))*512==SIZE
        shots=tree.findall('./Snapshots/Shot');assert len(shots)==1 and shots[0].findtext('GUID')==guid
        assert shots[0].findtext('ParentGUID')=='{00000000-0000-0000-0000-000000000000}'
    path='./Disk_Parameters/Miscellaneous/Bootable'
    assert not old.findall(path)
    found=new.findall(path);assert len(found)==1 and found[0].text=='0' and found[0].attrib=={} and len(found[0])==0
    new.find('./Disk_Parameters/Miscellaneous').remove(found[0])
    def canonical(e):return (e.tag,sorted(e.attrib.items()),(e.text or '').strip(),tuple(canonical(x) for x in e))
    assert canonical(old)==canonical(new),'unexplained descriptor modification'
    return dict(original_creation_sha256=expected,current_sha256=current_sha,backup_sha256=sha(backup),
        current_to_backup_delta='only added Disk_Parameters/Miscellaneous/Bootable=0',
        historical_creation_bytes_recovered=False,historical_creation_descriptor_equal=current_sha==expected,
        disposition='retain creation hash mismatch as finding; new blank backing identity proven independently by creation inode/dev/size, exact VM attachment and fresh unique guest serial/signature checks')


def read_command(argv,allow=False):
    p=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
    try:out,err=p.communicate(timeout=30)
    except BaseException:
        while p.poll() is None:time.sleep(1)
        p.communicate();raise
    assert allow or p.returncode==0,(argv,p.returncode,err.decode(errors='replace'))
    return out.decode().strip()


def creation_commands(c):
    validate_config(c)
    return [('pv-create',['pvcreate','--yes','--devices',c['device'],c['device']]),
            ('vg-create',['vgcreate','--devices',c['device'],'--addtag',c['tag'],c['vg'],c['device']]),
            ('pv-tag',['pvchange','--devices',c['device'],'--addtag',c['tag'],c['device']])]


def probe(c):
    validate_config(c)
    assert os.getuid()==0 and Path('/etc/royak-lab-owner').read_text().strip()=='rkq-vm-20261028-royak'
    assert not GUEST.exists() and not GUEST.is_symlink()
    assert GUEST.parent.resolve()==GUEST.parent and GUEST.parent.stat().st_uid==0
    assert not STAGED.exists() or (STAGED.is_file() and not STAGED.is_symlink() and STAGED.stat().st_uid==1000)
    assert read_command(['docker','ps','-aq'])=='' and json.loads(read_command(['drbdsetup','status','--json']))==[]
    blocks=json.loads(read_command(['lsblk','-b','-J','-o','NAME,PATH,SIZE,TYPE,MOUNTPOINTS,SERIAL,MODEL,UUID,MAJ:MIN']))['blockdevices']
    matching=[v for v in blocks if v.get('serial')==c['serial']];assert len(matching)==1
    d=matching[0]
    assert d['path']==c['device'] and d['size']==SIZE and d['type']=='disk' and d['maj:min']==c['major_minor']
    assert not d.get('children') and all(x is None for x in d['mountpoints'])
    st=os.stat(c['device']);assert stat.S_ISBLK(st.st_mode) and f'{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}'==c['major_minor']
    assert Path(c['device']).resolve()==Path(c['device'])
    signatures=json.loads(read_command(['wipefs','--no-act','--json',c['device']]))
    assert signatures['signatures']==[]
    pv=json.loads(read_command(['pvs','--reportformat','json','--units','b','--nosuffix','-o','pv_name,pv_uuid,vg_name,vg_uuid,pv_size,pv_tags']))
    vg=json.loads(read_command(['vgs','--reportformat','json','--units','b','--nosuffix','-o','vg_name,vg_uuid,vg_size,vg_free,vg_tags']))
    lv=json.loads(read_command(['lvs','--reportformat','json','--units','b','--nosuffix','-o','vg_name,lv_name,lv_uuid,lv_size,lv_attr']))
    assert all(x['pv_name']!=c['device'] for x in pv['report'][0]['pv'])
    assert all(x['vg_name']!=c['vg'] for x in vg['report'][0]['vg'])
    help_text={name:read_command([name,'--help']) for name in ['pvcreate','pvchange','vgcreate']}
    assert '--addtag' not in help_text['pvcreate'] and all('--addtag' in help_text[n] for n in ['pvchange','vgcreate'])
    assert all('--devices' in text for text in help_text.values())
    return dict(passed=True,config=c,block=d,pvs=pv,vgs=vg,lvs=lv,cli_help_sha256={k:hashlib.sha256(v.encode()).hexdigest() for k,v in help_text.items()},
                postgres_binary=Path('/usr/lib/postgresql/16/bin/postgres').is_file(),restic_binary=shutil.which('restic'))


def guest_apply(c):
    before=probe(c);GUEST.mkdir(mode=0o700);put(GUEST/'config.json',c);put(GUEST/'before.json',before)
    roles=[];report=dict(kind='new-owned-LVM-pool-preparation',passed=False,storage_qualified=False,config=c)
    def command(tag,argv):
        put(GUEST/(tag+'-intent.json'),dict(argv=argv))
        out=(GUEST/(tag+'.stdout')).open('xb');err=(GUEST/(tag+'.stderr')).open('xb')
        child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=out,stderr=err,close_fds=True);roles.append(child)
        try:
            put(GUEST/(tag+'-launched.json'),dict(pid=child.pid))
            child.wait(timeout=40)
        except BaseException as error:
            put(GUEST/(tag+'-UNKNOWN.json'),dict(pid=child.pid,error=type(error).__name__,no_signal=True,no_retry=True))
            while child.poll() is None:time.sleep(1)
            raise
        finally:
            if child.poll() is not None:
                for f in [out,err]:f.flush();os.fsync(f.fileno());f.close()
        put(GUEST/(tag+'-finished.json'),dict(pid=child.pid,exit=child.returncode))
        assert child.returncode==0,tag
    try:
        for tag,argv in creation_commands(c):command(tag,argv)
        pv=json.loads(read_command(['pvs','--reportformat','json','--units','b','--nosuffix','-o','pv_name,pv_uuid,vg_name,vg_uuid,pv_size,pv_tags']))
        vg=json.loads(read_command(['vgs','--reportformat','json','--units','b','--nosuffix','-o','vg_name,vg_uuid,vg_size,vg_free,vg_tags']))
        lv=json.loads(read_command(['lvs','--reportformat','json','--units','b','--nosuffix','-o','vg_name,lv_name,lv_uuid,lv_size,lv_attr']))
        newpv=[v for v in pv['report'][0]['pv'] if v['pv_name']==c['device']];assert len(newpv)==1
        newvg=[v for v in vg['report'][0]['vg'] if v['vg_name']==c['vg']];assert len(newvg)==1
        p,v=newpv[0],newvg[0]
        assert p['vg_name']==c['vg'] and p['vg_uuid']==v['vg_uuid'] and p['pv_uuid'] and v['vg_uuid']
        assert c['tag'] in p['pv_tags'].split(',') and c['tag'] in v['vg_tags'].split(',')
        assert int(v['vg_size'])==int(v['vg_free']) and int(v['vg_size'])>SIZE-16*1024**2
        assert [x for x in pv['report'][0]['pv'] if x['pv_name']!=c['device']]==before['pvs']['report'][0]['pv']
        assert [x for x in vg['report'][0]['vg'] if x['vg_name']!=c['vg']]==before['vgs']['report'][0]['vg']
        assert lv==before['lvs']
        report.update(passed=True,pv=p,vg=v,all_old_PVs_VGs_LVs_unchanged=True)
    except BaseException as error:report['failure']=type(error).__name__+': '+str(error)
    report['all_original_children_reaped']=all(p.poll() is not None for p in roles)
    put(GUEST/'report.json',report)
    print(json.dumps(report),flush=True);return int(not report['passed'])


def host_main():
    repo=Path(__file__).resolve().parents[3];base=repo/'tests/qualification/.runs/rkq-storage-20261030'
    lab=repo/'tests/qualification/.runs/rkq-vm-20261028-royak';helpers=base/'agent-normal-main-n2-server-recipes-v1'
    disks=base/'root-linstor-data-v1/disks-attempt2/report.json';d=json.loads(disks.read_bytes())
    assert d['passed'] and d['action']=='execute' and len(d['nodes'])==3
    assert shutil.disk_usage(base).free>=40*1024**3
    out=base/'root-linstor-data-v1/pools-attempt4';assert not out.exists();os.umask(0o077);out.mkdir(mode=0o700)
    for name,pin in {'safe_server_build.py':'788bdfab19a1b9898efe1330d67fcaf9b988f7c905f214edba9d20d38a30ff74',
        'owner_registry.py':'b53206032ba86a2c9bf10478d35dcbe7313f2ac2a6de31582cc6a4ef5cff3404',
        'normal_server_descriptor_equality.py':'046e13b1c520010bf875d14d886af9824522c9208b5dd3b0fca424bcb5664c32'}.items():assert sha(helpers/name)==pin
    sys.path.insert(0,str(helpers));spec=importlib.util.spec_from_file_location('pool_preparation_owner',helpers/'safe_server_build.py')
    b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
    options=['-F','/dev/null','-i',str(lab/'operator'),'-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
        '-o','UpdateHostKeys=no','-o','UserKnownHostsFile='+str(lab/'known_hosts'),'-o','ConnectTimeout=3','-o','ControlMaster=no','-o','ControlPath=none']
    report=dict(kind='new-three-guest-LVM-pool-preparation',passed=False,disk_report_sha256=sha(disks),fixture_sha256=sha(Path(__file__)),nodes=[],compiler_operation=False,storage_qualified=False)
    def invoke(n,tag,code):
        return b.command(out,'n'+str(n['id'])+'-'+tag,['ssh',*options,'royak@'+n['ip'],'sudo -n python3 -B -c '+shlex.quote(code)],timeout=120)
    try:
        configs=[]
        for row in d['nodes']:
            n=row['node'];ident=row['identity'];guest=row['guest_disk']
            info=json.loads(b.command(out,'n'+str(n['id'])+'-owner',['prlctl','list','-i',n['uuid'],'--json']))[0]
            assert n['uuid']==UUIDS[n['id']-1] and info['ID'].strip('{}')==n['uuid'] and info['State']=='running' and info['Name']==n['name']
            assert Path(info['Home']).resolve()==(lab/'vms'/(n['name']+'.pvm')).resolve()
            assert info['Hardware']['cpu']['cpus']==2 and info['Hardware']['memory']['size']=='2048Mb'
            assert Path(info['Hardware']['hdd3']['image']).resolve()==Path(ident['host_disk'])
            disk=Path(ident['host_disk']);descriptor=descriptor_guard(disk,ident)
            backing=disk/ident['backing_name'];st=backing.stat();assert st.st_ino==ident['backing_inode'] and st.st_dev==ident['backing_dev'] and st.st_size==SIZE
            cfg=dict(run=RUN,node=n['id'],uuid=n['uuid'],device=guest['path'],serial=guest['serial'],size=SIZE,major_minor=guest['maj:min'],vg='rklsd_20261102_n'+str(n['id']),tag='rklsd_20261102_n'+str(n['id']))
            validate_config(cfg);configs.append((n,cfg))
            invoke(n,'stage-absent',"from pathlib import Path;p=Path("+repr(str(STAGED))+");assert not p.exists() and not p.is_symlink()")
            b.command(out,'n'+str(n['id'])+'-stage',['scp',*options,str(Path(__file__)),'royak@'+n['ip']+':'+str(STAGED)],timeout=30)
            code="import pathlib,hashlib,runpy,sys;p=pathlib.Path("+repr(str(STAGED))+");assert hashlib.sha256(p.read_bytes()).hexdigest()=="+repr(report['fixture_sha256'])+";sys.argv=[str(p),'--guest-action','probe','--config',"+repr(json.dumps(cfg))+ "];runpy.run_path(str(p),run_name='__main__')"
            value=json.loads(invoke(n,'preflight',code));assert value['passed'];report['nodes'].append(dict(node=n,config=cfg,descriptor=descriptor,preflight=value))
        # No PV/VG operation until all three exact disk probes passed.
        for row in report['nodes']:
            n=row['node'];cfg=row['config']
            code="import pathlib,hashlib,runpy,sys;p=pathlib.Path("+repr(str(STAGED))+");assert hashlib.sha256(p.read_bytes()).hexdigest()=="+repr(report['fixture_sha256'])+";sys.argv=[str(p),'--guest-action','apply','--config',"+repr(json.dumps(cfg))+ "];runpy.run_path(str(p),run_name='__main__')"
            value=json.loads(invoke(n,'apply',code));row['result']=value
            assert value['passed'] and value['all_original_children_reaped']
            print(json.dumps(dict(node=n['id'],vg=value['vg']['vg_name'],pv_uuid=value['pv']['pv_uuid'],vg_uuid=value['vg']['vg_uuid'])),flush=True)
        report['passed']=True
    except BaseException as error:report['failure']=type(error).__name__+': '+str(error)
    report['original_owner']=b.OWNERS.snapshot();b.put(out/'report.json',report)
    print(json.dumps({k:report.get(k) for k in ['passed','failure','original_owner']}),flush=True)
    return int(not report['passed'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--guest-action',choices=['probe','apply']);parser.add_argument('--config');a=parser.parse_args()
    if a.guest_action:
        os.umask(0o077);cfg=json.loads(a.config)
        if a.guest_action=='probe':print(json.dumps(probe(cfg)),flush=True)
        else:raise SystemExit(guest_apply(cfg))
    else:raise SystemExit(host_main())
