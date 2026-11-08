"""Actual new-pool replicated I/O/PG actions; never an old-volume authority.

Called only by the pinned data fixture on the three dedicated test guests.
All commands use the fixture's original Popen/log owner. No force promotion,
system install, public port, old pool, broad Docker cleanup or host network.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import re
import stat
import subprocess
import tarfile
import time

RESOURCE='rkls_data_20261102_a3'
POOL='rkls_data_20261102_a3'
MINOR=433
PORT=7801
VOLUME_BYTES=512*1024**2
LV=RESOURCE+'_00000'
IMAGE='postgres@sha256:7a8050e52090c5f77effbe7e0cbed4a0587306776c3f26dc99933a63c619eaf1'
IMAGE_ID='sha256:7a8050e52090c5f77effbe7e0cbed4a0587306776c3f26dc99933a63c619eaf1'
IDENTITIES={
 1:dict(serial='CYP46EGV5A7MZFM20NR4',pv='hbwcou-E9Pp-bWkk-g3fZ-ryRN-LDKi-8T0COz',vg='ckC6sy-iVAt-xG8b-MXwA-Sndr-0OTb-ZdfJod'),
 2:dict(serial='KG5MGPEKTJQM3A08B052',pv='gmDa5W-vmD2-WhkZ-SwsK-3zTk-Twpc-8kiz7p',vg='Sfis8f-VTrJ-ozAS-8iQW-0t7V-D57Y-4N2Mt6'),
 3:dict(serial='8AQYCJX538MM17XSMA6M',pv='oAfyaP-UXUK-FuxH-Jxqt-YWHx-3vaN-5VCOYK',vg='bypOqe-WKaq-xgIi-Srgy-OJ6K-72GR-gd91vJ')}


def vg_name(node):return 'rklsd_20261102_n'+str(node)


def mount_path(node):
    return Path('/var/lib/royak-storage-qualification')/('linstor-data-20261102-v3-n'+str(node)+'-mount')


def command(owner,tag,argv,seconds=30):
    owner.last_data_tag='data-'+str(os.getpid())+'-'+str(time.monotonic_ns())+'-'+tag
    return owner.command(owner.last_data_tag,argv,seconds=seconds)


def drain_failed_child(child):
    # Continue consuming BOTH original pipes after a parser failure so a child
    # cannot be parked forever behind a full stdout/stderr pipe. Never signal.
    try:child.communicate(timeout=30)
    except subprocess.TimeoutExpired:child.communicate()


def payload_audit(m,cfg):
    assert m.sha(m.ROOT/'package-plan.json')=='fd96fe48124ed4833664d975210d89309245b6f5c650a1dbb245e5fd193ecb1b'
    owner=m.Owner(cfg);rows=[]
    for package in json.loads((m.ROOT/'package-plan.json').read_bytes())['packages']:
        archive=m.ROOT/'downloads'/package['filename']
        assert m.sha(archive)==package['sha256'] and archive.stat().st_size==package['bytes']
        child=subprocess.Popen(['dpkg-deb','--fsys-tarfile',str(archive)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,close_fds=True)
        owner.children.append(child);m.put(m.CASE/('payload-audit-'+package['package']+'-launched.json'),dict(pid=child.pid))
        files=0;size=0;rolling=hashlib.sha256()
        try:
            with tarfile.open(fileobj=child.stdout,mode='r|') as stream:
                for member in stream:
                    name=member.name.removeprefix('./');relative=Path(name)
                    assert not relative.is_absolute() and '..' not in relative.parts
                    staged=m.ROOT/'payloads'/package['package']/relative
                    if member.issym():assert staged.is_symlink() and os.readlink(staged)==member.linkname
                    elif member.isdir():assert staged.is_dir() and not staged.is_symlink()
                    elif member.isfile():
                        h=hashlib.sha256()
                        with stream.extractfile(member) as f:
                            while True:
                                part=f.read(1024**2)
                                if not part:break
                                h.update(part)
                        digest=h.hexdigest();assert staged.is_file() and not staged.is_symlink() and m.sha(staged)==digest
                        projected=[]
                        prefix='usr/share/linstor-server/'
                        if package['package'].startswith('linstor-') and name.startswith(prefix):projected.append(m.CASE/'app'/name[len(prefix):])
                        if package['package']=='openjdk-21-jre-headless':projected.append(m.CASE/'jre'/relative)
                        for path in projected:assert path.is_file() and m.sha(path)==digest
                        files+=1;size+=member.size;rolling.update(name.encode()+b'\0'+digest.encode()+b'\n')
                    else:raise AssertionError('unexpected package member class: '+name)
            child.wait(timeout=30);error=child.stderr.read();assert child.returncode==0 and not error
        except BaseException:
            m.put(m.CASE/('payload-audit-'+package['package']+'-FAILED.json'),dict(pid=child.pid,retained_until_terminal=True))
            drain_failed_child(child)
            raise
        finally:
            if child.poll() is not None:child.stdout.close();child.stderr.close()
        rows.append(dict(package=package['package'],archive_sha256=package['sha256'],regular_files=files,regular_bytes=size,ordered_regular_content_sha256=rolling.hexdigest(),extract_process_exit=child.returncode))
    result=dict(passed=True,packages=rows,all_original_children_reaped=all(p.poll() is not None for p in owner.children),
                java_binary_sha256=m.sha(m.CASE/'jre/usr/lib/jvm/java-21-openjdk-arm64/bin/java'))
    m.put(m.CASE/'payload-byte-audit.json',result);return result


def pool_guard(m,owner,cfg,empty=False):
    node=cfg['node']['id'];expected=IDENTITIES[node];vg=vg_name(node)
    block=json.loads(command(owner,'blocks',['lsblk','-b','-J','-o','PATH,SIZE,TYPE,SERIAL,MOUNTPOINTS']))['blockdevices']
    disk=[d for d in block if d.get('serial')==expected['serial']];assert len(disk)==1
    assert disk[0]['path']=='/dev/sdd' and disk[0]['size']==2*1024**3 and disk[0]['type']=='disk'
    pvs=json.loads(command(owner,'pvs',['pvs','--reportformat','json','-o','pv_name,pv_uuid,vg_name,vg_uuid,pv_tags']))['report'][0]['pv']
    matches=[p for p in pvs if p['pv_name']=='/dev/sdd'];assert len(matches)==1
    p=matches[0];assert p['pv_uuid']==expected['pv'] and p['vg_uuid']==expected['vg'] and p['vg_name']==vg and vg in p['pv_tags'].split(',')
    vgs=json.loads(command(owner,'vgs',['vgs','--reportformat','json','-o','vg_name,vg_uuid,vg_tags']))['report'][0]['vg']
    matches=[v for v in vgs if v['vg_name']==vg];assert len(matches)==1 and matches[0]['vg_uuid']==expected['vg'] and vg in matches[0]['vg_tags'].split(',')
    lvs=json.loads(command(owner,'lvs',['lvs','--reportformat','json','--units','b','--nosuffix','-o','vg_name,lv_name,lv_uuid,lv_size,lv_kernel_major,lv_kernel_minor']))['report'][0]['lv']
    own=[v for v in lvs if v['vg_name']==vg]
    assert own==[] if empty else len(own)<=1 and all(v['lv_name']==LV for v in own)
    return dict(pv=p,vg=matches[0],lvs=own)


def kernel(owner):
    values=json.loads(command(owner,'status',['drbdsetup','status','--json']))
    assert len(values)<=1 and all(r['name']==RESOURCE for r in values),'foreign/unexpected DRBD resource'
    if values:
        assert len(values[0]['devices'])==1 and values[0]['devices'][0]['minor']==MINOR
    return values


def healthy(value):
    return bool(value and len(value['devices'])==1 and value['devices'][0]['disk-state']=='UpToDate'
        and value['devices'][0].get('quorum') is True and len(value['connections'])==2
        and all(c['connection-state']=='Connected' and len(c['peer_devices'])==1
            and c['peer_devices'][0]['peer-disk-state']=='UpToDate'
            and c['peer_devices'][0].get('out-of-sync',1)==0 for c in value['connections']))


def inspect(m,owner,cfg):
    pool=pool_guard(m,owner,cfg);values=kernel(owner)
    result=dict(pool=pool,status=values[0] if values else None,healthy=healthy(values[0]) if values else False)
    if values:
        assert len(pool['lvs'])==1
        identity=dict(node=cfg['node']['id'],resource=RESOURCE,minor=MINOR,vg_uuid=IDENTITIES[cfg['node']['id']]['vg'],lv_uuid=pool['lvs'][0]['lv_uuid'],device='/dev/drbd'+str(MINOR),bytes=values[0]['devices'][0]['size']*1024)
        assert identity['bytes']==VOLUME_BYTES
        path=m.CASE/'volume-identity.json'
        if path.exists():assert json.loads(path.read_bytes())==identity
        else:m.put(path,identity)
        result['identity']=identity
    return result


def api_result(m,method,path,data=None):
    connection=http.client.HTTPSConnection('127.0.0.1',38370,context=m.context('api-server-ca.pem','operator'),timeout=10)
    try:
        connection.request(method,path,None if data is None else json.dumps(data),{'Content-Type':'application/json'})
        response=connection.getresponse();body=response.read(1024**2+1);assert len(body)<=1024**2
        value=json.loads(body)
        def redacted(v):
            if isinstance(v,dict):return {k:('[REDACTED]' if any(word in k.lower() for word in ['secret','password']) else redacted(x)) for k,x in v.items()}
            if isinstance(v,list):return [redacted(x) for x in v]
            if isinstance(v,str):return re.sub(r'(shared-secret\s+)[^\s;]+',r'\1[REDACTED]',v)
            return v
        m.put(m.CASE/('data-api-'+str(time.monotonic_ns())+'.json'),dict(method=method,path=path,status=response.status,body_sha256=hashlib.sha256(body).hexdigest(),response=redacted(value),redacted_semantic_response=True))
        assert 200<=response.status<300,'LINSTOR HTTP '+str(response.status)+' '+method+' '+path
    finally:connection.close()
    if isinstance(value,list):
        assert all(not isinstance(row,dict) or not isinstance(row.get('ret_code'),int) or row['ret_code']>=0 for row in value), 'LINSTOR error return code'
    return value


def validate_storage_pool(value,node):
    assert value['storage_pool_name']==POOL and value['provider_kind']=='LVM'
    # The pinned server canonicalizes legacy LvmVg input to StorPoolName.
    # Use its canonical API contract, while the independent PV/VG UUID guard
    # continues to constrain the physical target; never accept arbitrary pools.
    assert value['props']['StorDriver/StorPoolName']==vg_name(node)


def trusted_initialize(m,owner,cfg):
    assert cfg['node']['id']==1 and api_result(m,'GET','/v1/nodes')==[]
    created=[]
    for node in m.NODES:
        created.append(api_result(m,'POST','/v1/nodes',dict(name=node['hostname'],type='SATELLITE',net_interfaces=[dict(name='wireguard',address=node['wg_ip'],satellite_port=3367,satellite_encryption_type='SSL')])))
    deadline=time.monotonic()+90
    while True:
        values=api_result(m,'GET','/v1/nodes')
        if len(values)==3 and all(x['connection_status']=='ONLINE' for x in values):break
        assert time.monotonic()<deadline,'trusted native TLS FullSync90s';time.sleep(.5)
    assert api_result(m,'GET','/v1/resource-definitions')==[]
    return dict(native_nodes=values,creation_results=created)


def fresh_control_health(m,owner,cfg):
    assert cfg['node']['id']==1
    nodes=api_result(m,'GET','/v1/nodes');assert len(nodes)==3 and all(x['connection_status']=='ONLINE' for x in nodes)
    pools=[]
    for node in m.NODES:
        value=api_result(m,'GET','/v1/nodes/'+node['hostname']+'/storage-pools/'+POOL+'?cached=false')
        validate_storage_pool(value,node['id'])
        pools.append(value)
    return dict(nodes=nodes,fresh_storage_pool_reads=pools)


def provision(m,owner,cfg):
    assert cfg['node']['id']==1 and api_result(m,'GET','/v1/resource-definitions')==[]
    result=dict(pool_results=[])
    for node in m.NODES:
        value=api_result(m,'POST','/v1/nodes/'+node['hostname']+'/storage-pools',dict(storage_pool_name=POOL,provider_kind='LVM',props={'StorDriver/StorPoolName':vg_name(node['id'])}))
        result['pool_results'].append(value)
        actual=api_result(m,'GET','/v1/nodes/'+node['hostname']+'/storage-pools/'+POOL)
        validate_storage_pool(actual,node['id'])
    props={'StorPoolName':POOL,'DrbdOptions/Net/protocol':'C','DrbdOptions/Net/allow-two-primaries':'no',
           'DrbdOptions/auto-quorum':'io-error','DrbdOptions/Resource/auto-promote':'no','DrbdOptions/Resource/on-no-data-accessible':'io-error',
           'BalanceResourcesEnabled':'false'}
    result['definition_result']=api_result(m,'POST','/v1/resource-definitions',dict(resource_definition=dict(name=RESOURCE,props=props),drbd_port=PORT))
    result['volume_result']=api_result(m,'POST','/v1/resource-definitions/'+RESOURCE+'/volume-definitions',dict(volume_definition=dict(volume_number=0,size_kib=VOLUME_BYTES//1024),drbd_minor_number=MINOR))
    result['assignment_results']=[]
    for node in m.NODES:
        result['assignment_results'].append(api_result(m,'POST','/v1/resource-definitions/'+RESOURCE+'/resources/'+node['hostname'],dict(resource=dict(node_name=node['hostname'],props={'StorPoolName':POOL,'PrefNic':'wireguard'}),layer_list=['DRBD','STORAGE'])))
    definitions=api_result(m,'GET','/v1/resource-definitions');assert len(definitions)==1 and definitions[0]['name']==RESOURCE
    result['resource_definition_uuid']=definitions[0]['uuid']
    m.put(m.CASE/'resource-definition-identity.json',dict(name=RESOURCE,uuid=result['resource_definition_uuid']))
    return result


def device(m,owner,cfg,require_primary=True):
    result=inspect(m,owner,cfg);assert result['healthy']
    assert not require_primary or result['status']['role']=='Primary'
    p=Path('/dev/drbd'+str(MINOR));s=p.stat();assert p.resolve()==p and stat.S_ISBLK(s.st_mode) and os.minor(s.st_rdev)==MINOR
    return p,result


def digest_device(path):
    h=hashlib.sha256();total=0
    with path.open('rb',buffering=0) as f:
        while total<VOLUME_BYTES:
            data=f.read(min(1024**2,VOLUME_BYTES-total));assert data;h.update(data);total+=len(data)
    return dict(bytes=total,sha256=h.hexdigest())


def raw_write(m,owner,cfg):
    assert cfg['node']['id']==1
    path,state=device(m,owner,cfg);records=[]
    fd=os.open(path,os.O_WRONLY|os.O_CLOEXEC)
    try:
        for i in range(128):
            payload=hashlib.sha256(('royak-new-replica-record-'+str(i)).encode()).digest()*2048
            offset=i*len(payload);assert os.pwrite(fd,payload,offset)==len(payload);os.fsync(fd)
            records.append(dict(id=i,offset=offset,bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest()))
        trailer=hashlib.sha256(b'royak-replica-end').digest()*128
        assert os.pwrite(fd,trailer,VOLUME_BYTES-len(trailer))==len(trailer);os.fsync(fd)
        records.append(dict(id='trailer',offset=VOLUME_BYTES-len(trailer),bytes=len(trailer),sha256=hashlib.sha256(trailer).hexdigest()))
    finally:os.close(fd)
    result=dict(acknowledged_records=records,whole_device=digest_device(path),identity=state['identity'])
    m.put(m.CASE/'raw-acknowledgements.json',result);return result


def container_record(m):
    p=m.CASE/'pg-container.json';return json.loads(p.read_bytes()) if p.exists() else None


def container_guard(m,owner,cfg):
    r=container_record(m);assert r and not (m.CASE/'pg-removed.json').exists()
    value=json.loads(command(owner,'pg-inspect',['docker','container','inspect',r['id']]))[0]
    assert value['Id']==r['id'] and value['Image']==IMAGE_ID and value['Name']=='/'+r['name']
    assert value['Config']['Labels']['royak.qualification']==m.RUN and value['Config']['Labels']['royak.node']==str(cfg['node']['id'])
    assert value['HostConfig']['NetworkMode']=='none' and value['HostConfig']['Memory']==256*1024**2
    assert value['HostConfig']['NanoCpus']==1000000000 and value['HostConfig']['PidsLimit']==96
    assert value['HostConfig']['ReadonlyRootfs'] and not value['NetworkSettings']['Ports']
    mounts=[x for x in value['Mounts'] if x['Destination']=='/var/lib/postgresql/data']
    assert len(mounts)==1 and mounts[0]['Source']==str(mount_path(cfg['node']['id'])) and mounts[0]['Type']=='bind'
    return r,value


def mount_volume(m,owner,cfg):
    path,state=device(m,owner,cfg);target=mount_path(cfg['node']['id'])
    assert not target.exists() and not target.is_symlink()
    assert target.parent.resolve()==target.parent and target.parent.stat().st_uid==0
    target.mkdir(mode=0o700);s=target.stat()
    m.put(m.CASE/'pg-mount-identity.json',dict(path=str(target),dev=s.st_dev,inode=s.st_ino))
    command(owner,'mount',['mount','-o','nosuid,nodev,noexec',str(path),str(target)])
    found=json.loads(command(owner,'findmnt',['findmnt','--json','--mountpoint',str(target)]))['filesystems']
    assert len(found)==1 and found[0]['source']==str(path) and found[0]['target']==str(target) and found[0]['fstype']=='ext4'
    return target


def pg_start(m,owner,cfg):
    assert not (m.CASE/'pg-container.json').exists()
    assert command(owner,'containers-before',['docker','ps','-aq']).strip()==''
    target=mount_volume(m,owner,cfg)
    # Keep lost+found outside PGDATA by using a child directory of the fresh FS.
    (target/'pgdata').mkdir(mode=0o700,exist_ok=True)
    password=m.CASE/'private/pg-password';assert not password.exists()
    fd=os.open(password,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:f.write(secrets.token_hex(32)+'\n');f.flush();os.fsync(f.fileno())
    name='rkq-lsdata-a3-n'+str(cfg['node']['id'])
    argv=['docker','run','-d','--name',name,'--label','royak.qualification='+m.RUN,'--label','royak.node='+str(cfg['node']['id']),
          '--network','none','--memory','256m','--memory-swap','256m','--cpus','1','--pids-limit','96','--read-only','--security-opt','no-new-privileges',
          '--log-opt','max-size=10m','--log-opt','max-file=1','--tmpfs','/tmp:rw,noexec,nosuid,size=64m',
          '--tmpfs','/var/run/postgresql:rw,noexec,nosuid,size=4m',
          '--mount','type=bind,src='+str(target)+',dst=/var/lib/postgresql/data',
          '--mount','type=bind,src='+str(password)+',dst=/run/secrets/pg-password,readonly',
          '-e','PGDATA=/var/lib/postgresql/data/pgdata','-e','POSTGRES_PASSWORD_FILE=/run/secrets/pg-password',
          IMAGE,'postgres','-c','shared_buffers=32MB','-c','max_connections=12','-c','fsync=on','-c','synchronous_commit=on',
          '-c','full_page_writes=on','-c','listen_addresses=']
    cidfile=m.CASE/'pg-cid';assert not cidfile.exists() and not cidfile.is_symlink()
    argv[2:2]=['--cidfile',str(cidfile)]
    try:command(owner,'pg-run',argv,seconds=60)
    finally:
        if cidfile.exists():
            assert not cidfile.is_symlink() and cidfile.stat().st_uid==0
            cid=cidfile.read_text().strip();assert len(cid)==64 and all(c in '0123456789abcdef' for c in cid)
            m.put(m.CASE/'pg-container.json',dict(id=cid,name=name,image=IMAGE_ID,mount=str(target)))
    assert (m.CASE/'pg-container.json').exists(),'no exact Docker creation receipt'
    deadline=time.monotonic()+60
    while True:
        r,value=container_guard(m,owner,cfg);assert value['State']['Running'] and not value['State']['OOMKilled']
        try:
            version=sql(m,owner,cfg,"SELECT current_setting('server_version'),system_identifier FROM pg_control_system();")
            if version.strip():break
        except AssertionError:
            assert time.monotonic()<deadline,'PostgreSQL readiness60s';time.sleep(.2)
    return dict(container_id=cid,version_and_system_identifier=version.strip())


def sql(m,owner,cfg,text):
    r,value=container_guard(m,owner,cfg)
    return command(owner,'psql',['docker','exec','--user','postgres',r['id'],'psql','-X','-v','ON_ERROR_STOP=1','-U','postgres','-d','postgres','-A','-t','-F','\t','-c',text])


def expected_rows(count):
    return '\n'.join(str(i)+'\t'+(hashlib.md5(str(i).encode()).hexdigest()*32).encode().hex() for i in range(1,count+1))+'\n'


def pg_check(m,owner,cfg,count):
    raw=sql(m,owner,cfg,'COPY (SELECT id,encode(convert_to(payload,\'UTF8\'),\'hex\') FROM ledger ORDER BY id) TO STDOUT;')
    expected=expected_rows(count)
    assert raw==expected, 'PostgreSQL exact acknowledged row identity/payload mismatch'
    settings=sql(m,owner,cfg,"SELECT current_setting('fsync'),current_setting('synchronous_commit'),current_setting('full_page_writes'),system_identifier FROM pg_control_system();").strip()
    assert settings.startswith('on\ton\ton\t')
    return dict(rows=count,canonical_rows_sha256=hashlib.sha256(raw.encode()).hexdigest(),settings_and_system_identifier=settings)


def pg_write(m,owner,cfg,first,last):
    if first==1:sql(m,owner,cfg,'CREATE TABLE ledger (id integer PRIMARY KEY,payload text NOT NULL);')
    acknowledged=[]
    for low in range(first,last+1,100):
        high=min(last,low+99)
        value=sql(m,owner,cfg,'BEGIN; INSERT INTO ledger SELECT i,repeat(md5(i::text),32) FROM generate_series('+str(low)+','+str(high)+') AS i; COMMIT;')
        assert 'COMMIT' in value,'no successful COMMIT response'
        receipt=dict(first=low,last=high,commit_reply_sha256=hashlib.sha256(value.encode()).hexdigest())
        m.put(m.CASE/('pg-ack-'+str(low)+'-'+str(high)+'.json'),receipt);acknowledged.append(receipt)
    return dict(acknowledged_transactions=acknowledged,verification=pg_check(m,owner,cfg,last))


def pg_clean(m,owner,cfg):
    r=container_record(m);target=mount_path(cfg['node']['id']);result=dict(container_removed=False,mount_removed=False,clean_shutdown=True)
    if r and not (m.CASE/'pg-removed.json').exists():
        r,value=container_guard(m,owner,cfg)
        command(owner,'pg-logs',['docker','logs',r['id']])
        if value['State']['Running']:
            command(owner,'pg-TERM',['docker','kill','--signal=SIGTERM',r['id']])
            deadline=time.monotonic()+30
            while True:
                r,value=container_guard(m,owner,cfg)
                if not value['State']['Running']:break
                assert time.monotonic()<deadline,'PG graceful TERM30s; no forced kill'
                time.sleep(.2)
        r,value=container_guard(m,owner,cfg);assert not value['State']['Running']
        result['clean_shutdown']=value['State']['ExitCode']==0 and not value['State']['OOMKilled']
        result['exit_code']=value['State']['ExitCode'];result['OOMKilled']=value['State']['OOMKilled']
        command(owner,'pg-rm',['docker','rm',r['id']]);m.put(m.CASE/'pg-removed.json',dict(id=r['id'],exit_code=value['State']['ExitCode'],clean_shutdown=result['clean_shutdown']))
        result['container_removed']=True
    if r:
        assert command(owner,'pg-absence',['docker','ps','-aq','--no-trunc','--filter','id='+r['id']]).strip()==''
    record=m.CASE/'pg-mount-identity.json'
    if record.exists() and target.exists():
        info=json.loads(record.read_bytes());assert info['path']==str(target) and not target.is_symlink()
        command(owner,'umount',['umount',str(target)])
        s=target.stat();assert s.st_dev==info['dev'] and s.st_ino==info['inode'] and s.st_uid==0
        target.rmdir();result['mount_removed']=True
    password=m.CASE/'private/pg-password'
    if password.exists():
        s=password.stat();assert password.resolve()==password and stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1
        password.unlink();result['temporary_password_removed']=True
    values=kernel(owner)
    if values:
        assert not values[0]['devices'][0].get('open',False)
        if values[0]['role']=='Primary':command(owner,'secondary',['drbdsetup','secondary',RESOURCE])
    return result


def down(m,owner,cfg):
    values=kernel(owner)
    if not values:return dict(resource_down=True,already_absent=True)
    pool_guard(m,owner,cfg)
    assert not mount_path(cfg['node']['id']).exists(),'owned mount not released before resource teardown'
    assert command(owner,'containers-down',['docker','ps','-aq']).strip()==''
    assert values[0]['role']=='Secondary' and not values[0]['devices'][0].get('open',False)
    command(owner,'resource-down',['drbdsetup','down',RESOURCE])
    assert kernel(owner)==[]
    return dict(resource_down=True,retained_backing_LV=True)


def run(m,cfg,action):
    owner=m.Owner(cfg);result=dict(kind='real-LINSTOR-replica-PG-action',action=action,node=cfg['node']['id'],passed=False,storage_or_production_qualified=False)
    try:
        if action=='data-trusted-init':result['value']=trusted_initialize(m,owner,cfg)
        elif action=='data-control-health':result['value']=fresh_control_health(m,owner,cfg)
        elif action=='data-provision':result['value']=provision(m,owner,cfg)
        elif action=='data-inspect':result['value']=inspect(m,owner,cfg)
        elif action=='data-primary':
            assert inspect(m,owner,cfg)['healthy'];command(owner,'primary',['drbdsetup','primary',RESOURCE]);result['value']=inspect(m,owner,cfg);assert result['value']['status']['role']=='Primary'
        elif action=='data-deny-primary':
            assert cfg['node']['id']==2
            try:command(owner,'second-primary',['drbdsetup','primary',RESOURCE])
            except AssertionError:
                assert owner.children[-1].poll() not in [None,0]
                reason=(m.CASE/'logs'/(owner.last_data_tag+'.log')).read_text().lower()
                assert 'multiple primaries' in reason or 'peer is primary' in reason,'refusal was not actually the single-writer gate'
                result['value']=inspect(m,owner,cfg);assert result['value']['status']['role']=='Secondary'
                result['second_primary_rejected']=True
            else:raise AssertionError('second Primary unexpectedly accepted')
        elif action=='data-secondary':
            command(owner,'secondary',['drbdsetup','secondary',RESOURCE]);result['value']=inspect(m,owner,cfg);assert result['value']['status']['role']=='Secondary'
        elif action=='data-write':result['value']=raw_write(m,owner,cfg)
        elif action=='data-read':
            path,state=device(m,owner,cfg);result['value']=dict(whole_device=digest_device(path),identity=state['identity'])
        elif action=='data-filesystem':
            assert cfg['node']['id']==1 and (m.CASE/'raw-acknowledgements.json').exists()
            path,state=device(m,owner,cfg);command(owner,'mkfs',['mkfs.ext4','-q','-m','0',str(path)],seconds=40)
            result['value']=dict(filesystem_uuid=command(owner,'fs-uuid',['blkid','-s','UUID','-o','value',str(path)]).strip())
        elif action=='pg-start':result['value']=pg_start(m,owner,cfg)
        elif action=='pg-write-first':assert cfg['node']['id']==1;result['value']=pg_write(m,owner,cfg,1,1000)
        elif action=='pg-write-second':assert cfg['node']['id']==2;result['value']=pg_write(m,owner,cfg,1001,1100)
        elif action=='pg-check':assert cfg['node']['id'] in [2,3];result['value']=pg_check(m,owner,cfg,1000 if cfg['node']['id']==2 else 1100)
        elif action=='pg-clean':
            result['value']=pg_clean(m,owner,cfg);assert result['value']['clean_shutdown'],'PG exited abnormally; resources cleaned but test stays FAILED'
        elif action=='data-delete':
            assert cfg['node']['id']==1
            saved=json.loads((m.CASE/'resource-definition-identity.json').read_bytes())
            definitions=api_result(m,'GET','/v1/resource-definitions');assert len(definitions)==1 and definitions[0]['name']==saved['name']==RESOURCE and definitions[0]['uuid']==saved['uuid']
            result['value']=api_result(m,'DELETE','/v1/resource-definitions/'+RESOURCE)
        else:raise AssertionError('unknown exact data action')
        result['passed']=True
    except BaseException as error:result['failure']=(type(error).__name__+': '+str(error)).replace(cfg['password'],'[REDACTED]')
    result['all_original_children_reaped']=all(c.poll() is not None for c in owner.children)
    m.put(m.CASE/('data-result-'+action+'-'+str(time.monotonic_ns())+'.json'),result)
    return result
