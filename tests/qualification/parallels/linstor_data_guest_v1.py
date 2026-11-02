#!/usr/bin/env python3
"""Owned three-VM LINSTOR data and PostgreSQL assessment.

Each original worker owns its new WireGuard interface and Java Popen objects
until verified shutdown. Mount isolation applies only inside the new worker
namespace. No default route, firewall, system service or prior sdb/sdc LV is changed.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import resource
import shutil
import socket
import ssl
import stat
import subprocess
import time
import sys
import linstor_data_actions_v1 as data_actions

RUN='linstor-data-20261102-v1'
ROOT=Path('/home/royak/.local/share/royak-qualification/linstor-footprint-20261102-v1')
CASE=ROOT/'data-attempt1'
IFACE='rklsdv1'
NODES=[dict(id=n,ip='10.37.129.'+str(210+n),wg_ip='10.254.77.'+str(10+n),wg_port=51910+n,
            hostname='rkq-vm-20261028-royak-n'+str(n)) for n in range(1,4)]


def sha(p):
    with p.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def put(p,value):
    with p.open('x') as stream:
        json.dump(value,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    os.chown(p,1000,1000)


def proc(pid):
    p=Path('/proc')/str(pid);f=(p/'stat').read_text().rsplit(') ',1)[1].split()
    s=dict(line.split(':',1) for line in (p/'status').read_text().splitlines() if ':' in line)
    return dict(pid=pid,start_ticks=f[19],rss_bytes=int(s['VmRSS'].split()[0])*1024,
        fd=len(list((p/'fd').iterdir())),threads=int(s['Threads']),tasks=len(list((p/'task').iterdir())),
        utime_ticks=int(f[11]),stime_ticks=int(f[12]),clock_hz=os.sysconf('SC_CLK_TCK'),uid=int(s['Uid'].split()[0]))


def decode_tcp_address(value):
    raw=bytes.fromhex(value)
    if len(raw)==4:return socket.inet_ntop(socket.AF_INET,raw[::-1])
    address=ipaddress.ip_address(socket.inet_ntop(socket.AF_INET6,b''.join(raw[i:i+4][::-1] for i in range(0,16,4))))
    return str(address.ipv4_mapped or address)


def tcp_snapshot(node_id):
    rows=[];mesh_ips={'10.254.77.'+str(10+n) for n in range(1,4)}
    for table in ['/proc/net/tcp','/proc/net/tcp6']:
        for line in Path(table).read_text().splitlines()[1:]:
            f=line.split();local_hex,local_port=f[1].split(':');remote_hex,remote_port=f[2].split(':')
            local=decode_tcp_address(local_hex);remote=decode_tcp_address(remote_hex);local_port=int(local_port,16);remote_port=int(remote_port,16)
            listener=f[3]=='0A' and local_port in [3367,38370,38371,7799]
            mesh=local in mesh_ips and remote in mesh_ips and any(p in [3367,7799] for p in [local_port,remote_port])
            api=node_id==1 and local==remote=='127.0.0.1' and any(p in [38370,38371] for p in [local_port,remote_port])
            if listener or mesh or api:rows.append(dict(table=table,local=local,remote=remote,local_port=local_port,remote_port=remote_port,state=f[3],inode=f[9],timer=f[5]))
    return rows


def closed_tcp_rows(rows):
    return all(row['state']=='06' and row['inode']=='0' for row in rows)


def validate(cfg,node):
    assert cfg['run']==RUN and cfg['node']==NODES[node-1] and cfg['node']['id']==node
    assert set(cfg)=={'run','node','password','stage_sha256'}
    assert len(cfg['password'])==64 and all(c in '0123456789abcdef' for c in cfg['password'])
    assert len(cfg['stage_sha256'])==64


class Owner:
    def __init__(self,cfg):
        self.cfg=cfg;self.children=[];self.roles=[];self.created_link=None;self.key_applied=False;self.alias_applied=False;self.peer_keys=set()
        self.env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME=str(CASE/'home'),LANG='C.UTF-8',LC_ALL='C.UTF-8',
                      TMPDIR=str(CASE/'tmp'),RKQ_STORE_PASSWORD=cfg['password'])
    def command(self,tag,argv,seconds=30,stdin=None,output=None,user=None):
        log=(output or CASE/'logs'/(tag+'.log')).open('xb')
        incoming=None if stdin is None else stdin.open('rb')
        extra=dict(user=1000,group=1000,extra_groups=[]) if user==1000 else {}
        child=subprocess.Popen(argv,cwd=CASE,env=self.env,stdin=incoming or subprocess.DEVNULL,stdout=log,
            stderr=subprocess.PIPE if output else subprocess.STDOUT,close_fds=True,start_new_session=True,**extra)
        self.children.append(child)
        put(CASE/(tag+'-launched.json'),dict(pid=child.pid,argv=argv))
        try:
            if output:
                _,error=child.communicate(timeout=seconds)
                assert not error,'bounded command wrote stderr: '+tag
            else:child.wait(timeout=seconds)
        except BaseException as error:
            put(CASE/(tag+'-UNKNOWN.json'),dict(pid=child.pid,error=type(error).__name__,no_signal=True))
            while child.poll() is None:time.sleep(1)
            raise
        finally:
            if child.poll() is not None:
                log.flush();os.fsync(log.fileno());log.close()
                if incoming:incoming.close()
                if child.stderr:child.stderr.close()
        assert child.returncode==0,'known terminal command failed: '+tag
        return (output or CASE/'logs'/(tag+'.log')).read_text()
    def launch(self,tag,name,user):
        def no_core():resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        log=(CASE/(tag+'.log')).open('xb')
        argv=[str(CASE/'app/bin'/name),'--config-directory='+str(CASE/('controller-config' if name=='Controller' else 'satellite-config')),
              '--logs='+str(CASE/'logs'/('controller' if name=='Controller' else 'satellite'))]
        extra=dict(user=1000,group=1000,extra_groups=[]) if user==1000 else {}
        child=subprocess.Popen(argv,cwd=CASE,env=self.env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
            close_fds=True,start_new_session=True,preexec_fn=no_core,**extra)
        role=dict(tag=tag,child=child,log=log);self.roles.append(role);role['identity']=proc(child.pid)
        put(CASE/(tag+'-launched.json'),dict(argv=argv,identity=role['identity']))
        return role
    def stop(self,role):
        child=role['child']
        if child.poll() is None:
            assert proc(child.pid)['start_ticks']==role['identity']['start_ticks']
            child.terminate()
            try:child.wait(timeout=30)
            except BaseException as error:
                put(CASE/(role['tag']+'-UNKNOWN.json'),dict(pid=child.pid,error=type(error).__name__,no_force_kill=True))
                while child.poll() is None:time.sleep(1)
                raise
        role['log'].flush();os.fsync(role['log'].fileno());role['log'].close()
        role['ended']=dict(pid=child.pid,start_ticks=role['identity']['start_ticks'],exit=child.returncode,reaped=True)
    def link(self):
        return json.loads(self.command('link-observe-'+str(time.monotonic_ns()),['ip','-j','-d','link','show','dev',IFACE]))[0]
    def network_up(self,peers):
        assert len(peers)==3 and {p['node']['id'] for p in peers}=={1,2,3}
        current=json.loads(self.command('all-links-before',['ip','-j','link','show']))
        assert IFACE not in {v['ifname'] for v in current}
        self.command('wg-create',['ip','link','add','dev',IFACE,'type','wireguard'])
        self.created_link=self.link()['ifindex']
        self.command('wg-alias',['ip','link','set','dev',IFACE,'alias',RUN+':n'+str(self.cfg['node']['id'])])
        self.alias_applied=True
        self.command('wg-key',['wg','set',IFACE,'listen-port',str(self.cfg['node']['wg_port']),'private-key',str(CASE/'private/wg.key')])
        self.key_applied=True
        for row in peers:
            peer=row['node']
            if peer['id']==self.cfg['node']['id']:continue
            assert peer==NODES[peer['id']-1]
            self.command('peer-'+str(peer['id']),['wg','set',IFACE,'peer',row['public_key'],'allowed-ips',peer['wg_ip']+'/32',
                'endpoint',peer['ip']+':'+str(peer['wg_port']),'persistent-keepalive','1'])
            self.peer_keys.add(row['public_key'])
        self.command('wg-address',['ip','address','add',self.cfg['node']['wg_ip']+'/32','dev',IFACE])
        self.command('wg-up',['ip','link','set','dev',IFACE,'up'])
        for peer in NODES:
            if peer['id']!=self.cfg['node']['id']:
                self.command('route-'+str(peer['id']),['ip','route','add',peer['wg_ip']+'/32','dev',IFACE,'proto','static'])
    def network_down(self):
        if self.created_link is None:return None
        value=self.link();assert value['ifindex']==self.created_link and value['linkinfo']['info_kind']=='wireguard'
        alias=RUN+':n'+str(self.cfg['node']['id'])
        assert value.get('ifalias','')==alias if self.alias_applied else value.get('ifalias','') in ['',alias]
        if self.key_applied:
            public=self.command('cleanup-public-key',['wg','show',IFACE,'public-key']).strip()
            assert public==json.loads((CASE/'prepared.json').read_bytes())['public_key']
            peers=set(self.command('cleanup-peer-keys',['wg','show',IFACE,'peers']).split())
            assert peers==self.peer_keys
        self.command('wg-delete',['ip','link','delete','dev',IFACE])
        self.created_link=None
        links=json.loads(self.command('all-links-after',['ip','-j','link','show']))
        assert IFACE not in {v['ifname'] for v in links}
        return dict(exact_owned_interface_removed=True)


def context(ca,client=None):
    ctx=ssl.create_default_context(cafile=str(CASE/'assets'/ca))
    if client:ctx.load_cert_chain(str(CASE/'assets'/(client+'.pem')),str(CASE/'assets'/(client+'.key')))
    return ctx


def api(method,path,data=None,ctx=None):
    conn=http.client.HTTPSConnection('127.0.0.1',38370,context=ctx or context('api-server-ca.pem','operator'),timeout=10)
    try:
        conn.request(method,path,None if data is None else json.dumps(data),{'Content-Type':'application/json'})
        response=conn.getresponse();body=response.read(1024*1024+1)
        assert len(body)<=1024*1024 and 200<=response.status<300,'API status '+str(response.status)
        return json.loads(body)
    finally:conn.close()


def prepare(cfg):
    assert not (CASE/'prepared.json').exists()
    for name in ['private','logs','logs/controller','logs/satellite','tmp','home','db','app','controller-config','satellite-config','owned-var-lib','owned-drbd-d']:
        (CASE/name).mkdir(mode=0o700);os.chown(CASE/name,1000,1000)
    owner=Owner(cfg)
    portable=CASE/'jre';shutil.copytree(ROOT/'payloads/openjdk-21-jre-headless',portable,symlinks=True)
    for p in portable.rglob('*'):
        if p.is_symlink() and os.readlink(p).startswith('/'):
            target=portable/os.readlink(p).lstrip('/');p.unlink();p.symlink_to(os.path.relpath(target,p.parent))
    java=portable/'usr/lib/jvm/java-21-openjdk-arm64';owner.env['JAVA_HOME']=str(java)
    for package in ['linstor-common','linstor-controller','linstor-satellite']:
        source=ROOT/'payloads'/package/'usr/share/linstor-server'
        for p in source.rglob('*'):
            dst=CASE/'app'/p.relative_to(source)
            if p.is_dir():dst.mkdir(parents=True,exist_ok=True,mode=0o700);os.chown(dst,1000,1000)
            elif p.is_file():
                dst.parent.mkdir(parents=True,exist_ok=True,mode=0o700);os.chown(dst.parent,1000,1000)
                if dst.exists():assert sha(dst)==sha(p)
                elif p.name in ['Controller','Satellite']:shutil.copy2(p,dst)
                else:dst.symlink_to(p)
    assert sha(CASE/'app/bin/Controller')=='8309d34cdf86d91e14805a7cd39617ff385a8a1ed365c0b270ce76a81ea92ec4'
    assert sha(CASE/'app/bin/Satellite')=='8acc2ab842a0ac8855276bec4bbafd3ea96762b2450d387af6c16c667b39640a'
    owner.command('wg-genkey',['wg','genkey'],output=CASE/'private/wg.key')
    public=owner.command('wg-pubkey',['wg','pubkey'],stdin=CASE/'private/wg.key').strip()
    for name,ca in [('controller','controller-ca.pem'),*([('operator','operator-ca.pem'),('nodes','nodes-ca.pem')] if cfg['node']['id']==1 else [])]:
        owner.command('trust-'+name,[str(java/'bin/keytool'),'-importcert','-noprompt','-alias','trusted-ca','-file',str(CASE/'assets'/ca),
            '-storetype','PKCS12','-keystore',str(CASE/'private'/(name+'.trust.p12')),'-storepass:env','RKQ_STORE_PASSWORD'])
        os.chown(CASE/'private'/(name+'.trust.p12'),1000,1000)
    password=cfg['password'];assets=CASE/'assets';private=CASE/'private'
    stlt=CASE/'satellite-config/linstor_satellite.toml'
    stlt.write_text('[netcom]\ntype="ssl"\nbind_address="'+cfg['node']['wg_ip']+'"\nport=3367\nserver_certificate="'+str(assets/'satellite.p12')+'"\n'
        'trusted_certificates="'+str(private/'controller.trust.p12')+'"\nkey_password="'+password+'"\nkeystore_password="'+password+'"\ntruststore_password="'+password+'"\nssl_protocol="TLSv1.2"\n')
    os.chown(stlt,1000,1000)
    if cfg['node']['id']==1:
        p=CASE/'controller-config/linstor.toml'
        p.write_text('[db]\nuser="linstor"\npassword="'+password+'"\nconnection_url="jdbc:h2:'+str(CASE/'db/linstordb')+'"\n'
            '[http]\nenabled=true\nlisten_addr="127.0.0.1"\nport=38371\n[https]\nenabled=true\nlisten_addr="127.0.0.1"\nport=38370\n'
            'keystore="'+str(assets/'api-server.p12')+'"\nkeystore_password="'+password+'"\ntruststore="'+str(private/'operator.trust.p12')+'"\ntruststore_password="'+password+'"\n')
        os.chown(p,1000,1000)
    assert all(c.poll() is not None for c in owner.children)
    value=dict(node=cfg['node'],public_key=public,prepared=True,config_sha256=sha(assets/'config.json'))
    put(CASE/'prepared.json',value);return value


def serve(cfg):
    assert os.readlink('/proc/self/ns/mnt')!=os.readlink('/proc/1/ns/mnt')
    assert os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net')
    mounts=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    assert not any(x.startswith(('shared:','master:','propagate_from:')) for row in mounts for x in row[6:row.index('-')])
    assert not (CASE/'worker.json').exists()
    owner=Owner(cfg);owner.env['JAVA_HOME']=str(CASE/'jre/usr/lib/jvm/java-21-openjdk-arm64')
    owner.env['JAVA_OPTS']='-Xms64M -Xmx512M -Djava.io.tmpdir='+str(CASE/'tmp')
    report=dict(kind='owned-three-VM-LINSTOR-worker',passed=False,node=cfg['node'],heap_profile=dict(initial_mib=64,maximum_mib=512),
        backend_selected=False,storage_or_production_or_endurance_qualified=False,pools_or_volumes_created=None)
    worker=proc(os.getpid());put(CASE/'worker.json',worker)
    began=time.monotonic()
    try:
        for target,source in [('/var/lib',CASE/'owned-var-lib'),('/etc/drbd.d',CASE/'owned-drbd-d')]:
            p=Path(target);assert p.resolve()==p and p.is_dir() and p.stat().st_uid==0
            owner.command('mount-'+source.name,['mount','--bind',str(source),target])
            assert (p.stat().st_dev,p.stat().st_ino)==(source.stat().st_dev,source.stat().st_ino)
        p=Path('/var/lib/linstor');p.mkdir(mode=0o700);os.chown(p,1000,1000)
        peers=json.loads((CASE/'peers.json').read_bytes());owner.network_up(peers)
        def ready(role):
            deadline=time.monotonic()+120
            while True:
                assert role['child'].poll() is None
                try:return api('GET','/v1/controller/version')
                except (OSError,ssl.SSLError):
                    assert time.monotonic()<deadline,'Controller startup deadline120s'
                    time.sleep(.2)
        if cfg['node']['id']==1:
            seed=owner.launch('controller-bootstrap','Controller',1000);report['version']=ready(seed)
            prefix='NetCom/SslConnector/';props=api('GET','/v1/controller/properties')
            keys={k[len(prefix):].lower():k for k in props if k.startswith(prefix)}
            assert set(keys)=={'keystore','keystorepasswd','keypasswd','truststore','truststorepasswd','sslprotocol','bindaddress','port','enabled','type'}
            password=cfg['password'];private=CASE/'private';assets=CASE/'assets'
            update={keys[k]:v for k,v in dict(keystore=str(assets/'controller.p12'),keystorepasswd=password,keypasswd=password,
                truststore=str(private/'nodes.trust.p12'),truststorepasswd=password,sslprotocol='TLSv1.2',bindaddress='',port='0',enabled='true',type='SSL').items()}
            update.update({'NetCom/PlainConnector/Enabled':'false','NetCom/DebugSslConnector/Enabled':'false'})
            report['connector_update_rc']=api('POST','/v1/controller/properties',dict(override_props=update));owner.stop(seed)
            ctl=owner.launch('controller','Controller',1000);assert ready(ctl)==report['version']
        stlt=owner.launch('satellite','Satellite',0)
        # For node2/3 a local socket connect proves the exact listener exists;
        # the coordinator separately requires TLS chain, role and native ONLINE.
        deadline=time.monotonic()+120
        while True:
            assert stlt['child'].poll() is None
            try:
                with socket.create_connection((cfg['node']['wg_ip'],3367),timeout=2):pass
                break
            except OSError:
                assert time.monotonic()<deadline,'Satellite startup deadline120s'
                time.sleep(.2)
        put(CASE/'ready.json',dict(worker=worker,ready=True,wireguard_public_key=json.loads((CASE/'prepared.json').read_bytes())['public_key']))
        with (CASE/'resources.jsonl').open('x') as stream:
            while not (CASE/'stop.json').exists():
                assert time.monotonic()-began<600,'bounded worker600s deadline reached'
                live=[r for r in owner.roles if 'ended' not in r]
                assert all(r['child'].poll() is None for r in live),'a real Java role exited'
                row=dict(elapsed_s=time.monotonic()-began,roles={r['tag']:proc(r['child'].pid) for r in live})
                assert sum(x['rss_bytes'] for x in row['roles'].values())<1400*1024**2
                stream.write(json.dumps(row)+'\n');stream.flush();time.sleep(2)
            stream.flush();os.fsync(stream.fileno())
        assert json.loads((CASE/'stop.json').read_bytes())==dict(run=RUN,kind='normal-stop',worker_start_ticks=worker['start_ticks'])
        report['network_before_shutdown']={name:owner.command('wg-'+name,['wg','show',IFACE,name]).strip() for name in ['public-key','peers','allowed-ips','endpoints','latest-handshakes','transfer']}
        for role in reversed(owner.roles):
            if 'ended' not in role:owner.stop(role)
        report['data_resource_teardown']=data_actions.down(sys.modules[__name__],owner,cfg)
        put(CASE/'roles-stopped.json',dict(worker=worker,roles=[r['ended'] for r in owner.roles],initial_TCP=tcp_snapshot(cfg['node']['id'])))
        deadline=time.monotonic()+30
        while not (CASE/'network-stop.json').exists():
            assert time.monotonic()<deadline,'global transport drain barrier30s deadline'
            time.sleep(.1)
        assert json.loads((CASE/'network-stop.json').read_bytes())==dict(run=RUN,kind='network-stop',worker_start_ticks=worker['start_ticks'])
        report['transport_drain']=tcp_snapshot(cfg['node']['id'])
        put(CASE/'transport-drain.json',dict(rows=report['transport_drain']))
        assert closed_tcp_rows(report['transport_drain']),'non-closed TCP remains before WG removal'
        report['passed']=True
    except BaseException as error:report['failure']=(type(error).__name__+': '+str(error)).replace(cfg['password'],'[REDACTED]')
    finally:
        for role in reversed(owner.roles):
            if 'ended' not in role:owner.stop(role)
        if 'data_resource_teardown' not in report:
            try:report['data_resource_teardown']=data_actions.down(sys.modules[__name__],owner,cfg)
            except BaseException as error:
                put(CASE/'data-teardown-UNKNOWN.json',dict(error=type(error).__name__,no_signal=True,no_network_cleanup=True))
                # Preserve this exact owner and interface for explicit recovery.
                while True:time.sleep(1)
        report['roles']=[dict(tag=r['tag'],initial=r['identity'],ended=r.get('ended')) for r in owner.roles]
        report['all_original_roles_reaped']=all(r['child'].poll() is not None for r in owner.roles)
        report['all_prerequisites_reaped']=all(c.poll() is not None for c in owner.children)
        report['network_cleanup']=owner.network_down()
        report['all_prerequisites_reaped']=all(c.poll() is not None for c in owner.children)
        sessions={r['child'].pid for r in owner.roles};residual=[]
        for p in Path('/proc').iterdir():
            if not p.name.isdigit():continue
            try:
                f=(p/'stat').read_text().rsplit(') ',1)[1].split()
                if int(f[3]) in sessions:residual.append(dict(pid=int(p.name),session=int(f[3]),start_ticks=f[19],state=f[0]))
            except (FileNotFoundError,ProcessLookupError):continue
        report['residual_original_sessions']=residual
        if residual:report['passed']=False
        for role in owner.roles:
            path=CASE/(role['tag']+'.log')
            (CASE/(role['tag']+'-redacted-tail.txt')).write_text(path.read_text(errors='replace')[-24000:].replace(cfg['password'],'[REDACTED]'))
        report['credentials_retained_pending_exact_cleanup']=True
        report=json.loads(json.dumps(report).replace(cfg['password'],'[REDACTED]'))
        put(CASE/'server-report.json',report)
        for path in [CASE/'resources.jsonl',*CASE.glob('*-redacted-tail.txt')]:
            if path.exists():path.chmod(0o600);os.chown(path,1000,1000)
    return report


def exercise(cfg):
    assert cfg['node']['id']==1
    report=dict(kind='real-three-VM-SSL-WireGuard-management',passed=False,negatives={},nodes=[],requests=0,
                backend_selected=False,storage_or_production_or_endurance_qualified=False)
    def deny_tls(name,host,ctx):
        try:
            with socket.create_connection((host,3367),timeout=3) as raw:
                with ctx.wrap_socket(raw,server_hostname=host) as connection:
                    data=connection.recv(1)
                    assert data==b'','unauthorized application data: '+name
                    report['negatives'][name]='EOF before application data'
        except ssl.SSLError as error:report['negatives'][name]=dict(error=type(error).__name__,reason=str(error))
        assert name in report['negatives'],'denial was not observed: '+name
    try:
        for client in [None,'satellite','controller']:
            name='REST_'+('no-certificate' if client is None else 'wrong-role-'+client)
            try:api('GET','/v1/controller/version',ctx=context('api-server-ca.pem',client))
            except (OSError,ssl.SSLError) as error:report['negatives'][name]=type(error).__name__
            else:raise AssertionError('REST accepted '+name)
        for node in NODES:
            host=node['wg_ip'];good=context('nodes-ca.pem','controller')
            with socket.create_connection((host,3367),timeout=3) as raw:
                with good.wrap_socket(raw,server_hostname=host) as connection:
                    report['nodes'].append(dict(node=node,certificate_sha256=hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest(),TLS=connection.version()))
            for client in [None,'operator','satellite']:
                deny_tls('satellite'+str(node['id'])+'_'+('no-certificate' if client is None else 'wrong-role-'+client),host,context('nodes-ca.pem',client))
            deny_tls('satellite'+str(node['id'])+'_untrusted-server',host,ssl.create_default_context())
            if node['id']!=1:
                with socket.socket() as underlay:
                    underlay.settimeout(3)
                    assert underlay.connect_ex((node['ip'],3367))!=0,'raw underlay listener was reachable'
            report.setdefault('node_create_rc',[]).append(api('POST','/v1/nodes',dict(name=node['hostname'],type='SATELLITE',net_interfaces=[dict(name='wireguard',address=host,satellite_port=3367,satellite_encryption_type='SSL')])) )
        deadline=time.monotonic()+90
        while True:
            nodes=api('GET','/v1/nodes')
            if len(nodes)==3 and all(n['connection_status']=='ONLINE' for n in nodes):break
            assert time.monotonic()<deadline,'not all real SSL nodes ONLINE'
            time.sleep(.5)
        assert api('GET','/v1/resource-definitions')==[]
        report['initial_online_nodes']=nodes
        began=time.monotonic();last_phase=None;report['phases']=[]
        with (CASE/'management-requests.jsonl').open('x') as stream:
            while time.monotonic()-began<180:
                now=time.monotonic();phase='warmup' if now-began<30 else 'workload' if now-began<150 else 'idle'
                if phase!=last_phase:report['phases'].append(dict(phase=phase,elapsed_s=now-began));last_phase=phase
                if phase=='workload':
                    started=time.monotonic();current=api('GET','/v1/nodes')
                    assert len(current)==3 and all(n['connection_status']=='ONLINE' for n in current)
                    row=dict(elapsed_s=time.monotonic()-began,seconds=time.monotonic()-started,node_UUIDs=sorted(n['uuid'] for n in current))
                    stream.write(json.dumps(row)+'\n');stream.flush();report['requests']+=1;time.sleep(.2)
                else:time.sleep(.05)
            stream.flush();os.fsync(stream.fileno())
        report['observed_seconds']=time.monotonic()-began
        report['final_nodes']=api('GET','/v1/nodes');assert all(n['connection_status']=='ONLINE' for n in report['final_nodes'])
        assert api('GET','/v1/resource-definitions')==[]
        report['passed']=True
    except BaseException as error:report['failure']=(type(error).__name__+': '+str(error)).replace(cfg['password'],'[REDACTED]')
    for p in [CASE/'management-requests.jsonl']:
        if p.exists():p.chmod(0o600);os.chown(p,1000,1000)
    put(CASE/'exercise-report.json',report);return report


def peer_negative(cfg):
    report=dict(passed=False,negatives={})
    try:
        for node in NODES:
            if node['id']==cfg['node']['id']:continue
            ctx=context('nodes-ca.pem','satellite')
            try:
                with socket.create_connection((node['wg_ip'],3367),timeout=3) as raw:
                    with ctx.wrap_socket(raw,server_hostname=node['wg_ip']) as tls:
                        assert tls.recv(1)==b'','a node certificate received application data as Controller'
                        report['negatives'][str(node['id'])]='EOF before application data'
            except ssl.SSLError as error:report['negatives'][str(node['id'])]=dict(error=type(error).__name__,reason=str(error))
            assert str(node['id']) in report['negatives']
        report['passed']=True
    except BaseException as error:report['failure']=type(error).__name__+': '+str(error)
    put(CASE/'peer-negative-report.json',report);return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action',choices=['prepare','serve','status','stop','exercise','peer-negative','network-stop',
        'data-provision','data-inspect','data-primary','data-secondary','data-deny-primary','data-write','data-read','data-filesystem','data-delete',
        'pg-start','pg-write-first','pg-write-second','pg-check','pg-clean'],required=True)
    parser.add_argument('--node',type=int,choices=[1,2,3],required=True)
    parser.add_argument('--config-sha256',required=True)
    a=parser.parse_args();os.umask(0o077)
    assert os.getuid()==0 and Path('/etc/royak-lab-owner').read_text().strip()=='rkq-vm-20261028-royak'
    assert CASE.resolve()==CASE and CASE.stat().st_uid==1000 and stat.S_IMODE(CASE.stat().st_mode)==0o700
    assert sha(CASE/'assets/config.json')==a.config_sha256
    cfg=json.loads((CASE/'assets/config.json').read_bytes());validate(cfg,a.node)
    assert sha(ROOT/'stage-report.json')==cfg['stage_sha256']
    if a.action=='prepare':
        result=prepare(cfg);result['payload_audit']=data_actions.payload_audit(sys.modules[__name__],cfg)
        result['new_pool_preflight']=data_actions.pool_guard(sys.modules[__name__],Owner(cfg),cfg,empty=True)
    elif a.action=='serve':result=serve(cfg)
    elif a.action=='exercise':result=exercise(cfg)
    elif a.action=='peer-negative':result=peer_negative(cfg)
    elif a.action.startswith(('data-','pg-')):result=data_actions.run(sys.modules[__name__],cfg,a.action)
    else:
        worker=json.loads((CASE/'worker.json').read_bytes()) if (CASE/'worker.json').exists() else None
        if a.action=='status' and (worker is None or not (Path('/proc')/str(worker['pid'])).exists()):
            result=dict(worker_live=False,ready=False,terminal_report=(CASE/'server-report.json').exists())
        else:
            current=proc(worker['pid'])
            assert current['start_ticks']==worker['start_ticks'] and os.readlink('/proc/'+str(worker['pid'])+'/cwd')==str(CASE)
        if a.action=='status' and worker is not None and (Path('/proc')/str(worker['pid'])).exists():
            stopped=(CASE/'roles-stopped.json').exists()
            if stopped:
                for ended in json.loads((CASE/'roles-stopped.json').read_bytes())['roles']:
                    p=Path('/proc')/str(ended['pid'])
                    if p.exists():assert (p/'stat').read_text().rsplit(') ',1)[1].split()[19]!=ended['start_ticks']
            tcp=tcp_snapshot(a.node)
            result=dict(worker_live=True,worker=current,ready=(CASE/'ready.json').exists(),roles_stopped=stopped,TCP=tcp,TCP_closed_only=closed_tcp_rows(tcp))
        elif a.action=='network-stop':
            put(CASE/'network-stop.json',dict(run=RUN,kind='network-stop',worker_start_ticks=worker['start_ticks']))
            result=dict(network_stop_requested=True,worker=current)
        elif a.action=='stop':
            put(CASE/'stop.json',dict(run=RUN,kind='normal-stop',worker_start_ticks=worker['start_ticks']))
            result=dict(normal_stop_requested=True,worker=current)
    print(json.dumps(result if a.action.startswith(('data-','pg-')) else {k:v for k,v in result.items() if k in ['prepared','node','public_key','config_sha256','worker_live','worker','ready','normal_stop_requested','network_stop_requested','roles_stopped','TCP','TCP_closed_only','passed','failure','requests']}),flush=True)
    return int(result.get('passed') is False)


if __name__=='__main__':raise SystemExit(main())
