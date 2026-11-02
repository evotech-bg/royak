#!/usr/bin/env python3
"""Real Controller/Satellite TLS pair, no pools or resource definitions.

Run ONLY inside new private guest mount+network namespaces. Two bind mounts
redirect Satellite's automatic metadata/config writes into this new case.
This is backend assessment, not replicated-volume or production acceptance.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import resource
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import time


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def put(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def proc(pid):
    root = Path('/proc') / str(pid)
    fields = (root / 'stat').read_text().rsplit(') ', 1)[1].split()
    status = dict(line.split(':', 1) for line in (root / 'status').read_text().splitlines() if ':' in line)
    return dict(pid=pid, start_ticks=fields[19], rss_bytes=int(status['VmRSS'].split()[0])*1024,
                fd=len(list((root/'fd').iterdir())), threads=int(status['Threads']),
                tasks=len(list((root/'task').iterdir())), utime_ticks=int(fields[11]),
                stime_ticks=int(fields[12]), clock_hz=os.sysconf('SC_CLK_TCK'),
                uid=int(status['Uid'].split()[0]), capabilities=status['CapEff'].strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--stage-sha256', required=True)
    args = parser.parse_args()
    assert os.getuid() == 0
    assert Path('/etc/royak-lab-owner').read_text().strip() == 'rkq-vm-20261028-royak'
    namespaces = {kind:dict(initial=os.readlink('/proc/1/ns/'+kind), own=os.readlink('/proc/self/ns/'+kind)) for kind in ['net','mnt']}
    assert all(v['initial'] != v['own'] for v in namespaces.values())
    root = args.root
    assert root == Path('/home/royak/.local/share/royak-qualification/linstor-footprint-20261102-v1')
    assert root.resolve() == root and root.stat().st_uid == 1000
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert sha(root/'stage-report.json') == args.stage_sha256
    assert json.loads((root/'stage-report.json').read_bytes())['passed']
    case = root/'pair-attempt2'
    assert not case.exists() and not case.is_symlink()
    os.umask(0o077)
    case.mkdir(mode=0o700)
    os.chown(case,1000,1000)
    for name in ['private','logs','db','tmp','home','app','controller-config','satellite-config','owned-var-lib','owned-drbd-d']:
        (case/name).mkdir(mode=0o700)
        os.chown(case/name,1000,1000)
    env = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME=str(case/'home'),LANG='C.UTF-8',LC_ALL='C.UTF-8',TMPDIR=str(case/'tmp'))
    password = secrets.token_hex(32)
    env['RKQ_STORE_PASSWORD'] = password
    children=[]
    roles=[]
    report=dict(kind='real-private-Controller-Satellite-TLS-pair',passed=False,namespaces=namespaces,
                backend_selected=False,production_or_replication_or_endurance_qualified=False,
                heap_profile_per_role=dict(initial_mib=64,maximum_mib=512),vendor_default_footprint=False,
                package_installation=False,system_service=False,pools_or_resource_definitions_created=False,
                bind_mounts=[],requests=0,negatives={},samples=0)

    def command(tag,argv,budget=30,user=None):
        log=(case/'logs'/(tag+'.log')).open('xb')
        extra=dict(user=1000,group=1000,extra_groups=[]) if user==1000 else {}
        child=subprocess.Popen(argv,cwd=case,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                               close_fds=True,start_new_session=True,**extra)
        children.append((child,log))
        put(case/(tag+'-launched.json'),dict(pid=child.pid,argv=argv))
        try:
            code=child.wait(timeout=budget)
        except BaseException as error:
            put(case/(tag+'-UNKNOWN.json'),dict(pid=child.pid,error=type(error).__name__,no_signal=True))
            while child.poll() is None: time.sleep(1)
            raise
        log.flush();os.fsync(log.fileno());log.close()
        assert code==0,'known terminal prerequisite failed: '+tag

    def stop(role):
        child,log=role['child'],role['log']
        if child.poll() is None:
            assert proc(child.pid)['start_ticks']==role['identity']['start_ticks']
            child.terminate()
            try: child.wait(timeout=30)
            except BaseException as error:
                put(case/(role['tag']+'-UNKNOWN.json'),dict(pid=child.pid,error=type(error).__name__,no_force_kill=True))
                while child.poll() is None:time.sleep(1)
                report['passed']=False
        log.flush();os.fsync(log.fileno());log.close()
        role['ended']=dict(pid=child.pid,start_ticks=role['identity']['start_ticks'],exit=child.returncode,reaped=child.poll() is not None)

    def launch(tag,name,user):
        def no_core(): resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        log=(case/(tag+'.log')).open('xb')
        argv=[str(case/'app/bin'/name),'--config-directory='+str(case/('controller-config' if name=='Controller' else 'satellite-config')),
              '--logs='+str(case/'logs')]
        extra=dict(user=1000,group=1000,extra_groups=[]) if user==1000 else {}
        child=subprocess.Popen(argv,cwd=case,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                               close_fds=True,start_new_session=True,preexec_fn=no_core,**extra)
        role=dict(tag=tag,child=child,log=log)
        roles.append(role)
        role['identity']=proc(child.pid)
        put(case/(tag+'-launched.json'),dict(argv=argv,identity=role['identity']))
        return role

    try:
        # No initial-namespace mount or route is changed. The caller already
        # made propagation private when creating this new mount namespace.
        mount_rows=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
        assert not any(token.startswith(('shared:','master:','propagate_from:')) for row in mount_rows for token in row[6:row.index('-')]),'mount propagation is not recursively private'
        for target,source in [('/var/lib',case/'owned-var-lib'),('/etc/drbd.d',case/'owned-drbd-d')]:
            original=Path(target)
            assert original.resolve()==original and original.is_dir() and original.stat().st_uid==0
            command('mount-'+source.name,['/usr/bin/mount','--bind',str(source),target])
            assert original.stat().st_ino==source.stat().st_ino and original.stat().st_dev==source.stat().st_dev
            report['bind_mounts'].append(dict(source=str(source),target=target,device=source.stat().st_dev,inode=source.stat().st_ino))
        command('loopback',['/usr/sbin/ip','link','set','lo','up'])
        (Path('/var/lib')/'linstor').mkdir(mode=0o700)
        os.chown('/var/lib/linstor',1000,1000)
        portable=case/'jre'
        shutil.copytree(root/'payloads/openjdk-21-jre-headless',portable,symlinks=True)
        for path in portable.rglob('*'):
            if path.is_symlink() and os.readlink(path).startswith('/'):
                target=portable/os.readlink(path).lstrip('/')
                path.unlink();path.symlink_to(os.path.relpath(target,path.parent))
        java_home=portable/'usr/lib/jvm/java-21-openjdk-arm64'
        env['JAVA_HOME']=str(java_home)
        env['JAVA_OPTS']='-Xms64M -Xmx512M -Djava.io.tmpdir='+str(case/'tmp')
        for package in ['linstor-common','linstor-controller','linstor-satellite']:
            source=root/'payloads'/package/'usr/share/linstor-server'
            for path in source.rglob('*'):
                destination=case/'app'/path.relative_to(source)
                if path.is_dir():destination.mkdir(parents=True,exist_ok=True,mode=0o755)
                elif path.is_file():
                    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
                    if destination.exists():assert sha(destination)==sha(path)
                    elif path.name in ['Controller','Satellite']:shutil.copy2(path,destination)
                    else:destination.symlink_to(path)
        # umask077 made new app directories root0700; transfer ONLY this
        # new projection to the Controller UID before any credentials exist.
        for directory in (case/'app').rglob('*'):
            if directory.is_dir() and not directory.is_symlink():os.chown(directory,1000,1000)
        access_code='import os,sys;assert os.getuid()==1000;assert all(os.access(p,os.R_OK|os.X_OK) for p in sys.argv[1:]);print("new projection traversable as Controller UID")'
        command('controller-read-access',['/usr/bin/python3','-B','-c',access_code,str(case/'app/bin/Controller'),str(case/'app/bin/Satellite'),str(java_home/'bin/java')],user=1000)
        assert sha(case/'app/bin/Controller')=='8309d34cdf86d91e14805a7cd39617ff385a8a1ed365c0b270ce76a81ea92ec4'
        assert sha(case/'app/bin/Satellite')=='8acc2ab842a0ac8855276bec4bbafd3ea96762b2450d387af6c16c667b39640a'
        private=case/'private'
        command('ca',['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=Royak-private-pair-CA',
                      '-keyout',str(private/'ca.key'),'-out',str(private/'ca.pem')])
        for serial,(name,usage) in enumerate([('controller','serverAuth,clientAuth'),('satellite','serverAuth,clientAuth'),('client','clientAuth')],1):
            command(name+'-csr',['openssl','req','-newkey','rsa:2048','-nodes','-subj','/CN='+name,
                                  '-keyout',str(private/(name+'.key')),'-out',str(private/(name+'.csr'))])
            ext=private/(name+'.ext')
            ext.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
            command(name+'-sign',['openssl','x509','-req','-in',str(private/(name+'.csr')),'-CA',str(private/'ca.pem'),'-CAkey',str(private/'ca.key'),
                                   '-set_serial',str(serial),'-days','1','-sha256','-extfile',str(ext),'-out',str(private/(name+'.pem'))])
            if name!='client':
                command(name+'-store',['openssl','pkcs12','-export','-in',str(private/(name+'.pem')),'-inkey',str(private/(name+'.key')),
                                      '-certfile',str(private/'ca.pem'),'-name',name,'-out',str(private/(name+'.p12')),'-passout','env:RKQ_STORE_PASSWORD'])
        command('truststore',[str(java_home/'bin/keytool'),'-importcert','-noprompt','-alias','test-ca','-file',str(private/'ca.pem'),
                              '-storetype','PKCS12','-keystore',str(private/'trusted.p12'),'-storepass:env','RKQ_STORE_PASSWORD'])
        reservations=[socket.socket() for _ in range(3)]
        for sock in reservations:sock.bind(('127.0.0.1',0))
        api_port,http_port,stlt_port=[sock.getsockname()[1] for sock in reservations]
        for sock in reservations:sock.close()
        ctrl_config=case/'controller-config/linstor.toml'
        ctrl_config.write_text('[db]\nuser="linstor"\npassword="'+password+'"\nconnection_url="jdbc:h2:'+str(case/'db/linstordb')+'"\n'
            '[http]\nenabled=true\nlisten_addr="127.0.0.1"\nport='+str(http_port)+'\n[https]\nenabled=true\nlisten_addr="127.0.0.1"\nport='+str(api_port)+'\n'
            'keystore="'+str(private/'controller.p12')+'"\nkeystore_password="'+password+'"\ntruststore="'+str(private/'trusted.p12')+'"\ntruststore_password="'+password+'"\n')
        stlt_config=case/'satellite-config/linstor_satellite.toml'
        stlt_config.write_text('[netcom]\ntype="ssl"\nbind_address="127.0.0.1"\nport='+str(stlt_port)+'\nserver_certificate="'+str(private/'satellite.p12')+'"\n'
            'trusted_certificates="'+str(private/'trusted.p12')+'"\nkey_password="'+password+'"\nkeystore_password="'+password+'"\ntruststore_password="'+password+'"\nssl_protocol="TLSv1.2"\n')
        for path in [*private.iterdir(),ctrl_config,stlt_config]:
            if path.is_file():path.chmod(0o600);os.chown(path,1000,1000)
        good=ssl.create_default_context(cafile=str(private/'ca.pem'))
        good.load_cert_chain(str(private/'client.pem'),str(private/'client.key'))
        def api(method,path,data=None,context=good):
            conn=http.client.HTTPSConnection('127.0.0.1',api_port,context=context,timeout=10)
            try:
                conn.request(method,path,None if data is None else json.dumps(data),{'Content-Type':'application/json'})
                response=conn.getresponse();body=response.read(1024*1024+1)
                assert len(body)<=1024*1024 and 200<=response.status<300,(response.status,body[:2048].decode().replace(password,'[REDACTED]'))
                return json.loads(body)
            finally:conn.close()
        def ready(role):
            deadline=time.monotonic()+120
            while True:
                assert role['child'].poll() is None,'controller exited during startup'
                try:return api('GET','/v1/controller/version')
                except (OSError,ssl.SSLError):
                    assert time.monotonic()<deadline,'unchanged 120 s startup deadline'
                    time.sleep(.2)
        # Planned bootstrap writes only NEW Controller metadata. The exact
        # source requires restart to apply changed internal netcom properties.
        seed=launch('controller-bootstrap','Controller',1000)
        report['version']=ready(seed)
        props=api('GET','/v1/controller/properties')
        prefix='netcom/SslConnector/'
        keys={k[len(prefix):].lower():k for k in props if k.startswith(prefix)}
        required={'keystore','keystorepasswd','keypasswd','truststore','truststorepasswd','sslprotocol','bindaddress','port','enabled','type'}
        report['observed_connector_property_keys']=sorted(keys)
        assert set(keys)==required,sorted(keys)
        update={keys[k]:v for k,v in dict(keystore=str(private/'controller.p12'),keystorepasswd=password,keypasswd=password,
            truststore=str(private/'trusted.p12'),truststorepasswd=password,sslprotocol='TLSv1.2',bindaddress='127.0.0.1',port='0',enabled='true',type='ssl').items()}
        report['connector_update_rc']=api('POST','/v1/controller/properties',dict(override_props=update))
        stop(seed)
        controller=launch('controller','Controller',1000)
        assert ready(controller)==report['version']
        no_client=ssl.create_default_context(cafile=str(private/'ca.pem'))
        for name,context in [('REST_no_client_certificate',no_client),('REST_untrusted_server_CA',ssl.create_default_context())]:
            try:api('GET','/v1/controller/version',context=context)
            except (OSError,ssl.SSLError) as error:report['negatives'][name]=type(error).__name__
            else:raise AssertionError('REST accepted '+name)
        satellite=launch('satellite','Satellite',0)
        # Validate real Satellite server identity, then the actual protobuf
        # Controller->Satellite connection. No fake protocol responder.
        deadline=time.monotonic()+120
        while True:
            assert satellite['child'].poll() is None,'Satellite exited during startup'
            try:
                with socket.create_connection(('127.0.0.1',stlt_port),timeout=2) as raw:
                    with good.wrap_socket(raw,server_hostname='localhost') as connection:
                        report['satellite_tls_version']=connection.version()
                        report['satellite_peer_certificate_sha256']=hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest()
                break
            except (OSError,ssl.SSLError):
                assert time.monotonic()<deadline,'Satellite 120 s startup deadline'
                time.sleep(.2)
        for name,context in [('Satellite_no_client_certificate',no_client),('Satellite_untrusted_server_CA',ssl.create_default_context())]:
            try:
                with socket.create_connection(('127.0.0.1',stlt_port),timeout=2) as raw:
                    with context.wrap_socket(raw,server_hostname='localhost'):
                        pass
            except ssl.SSLError as error:report['negatives'][name]=type(error).__name__
            else:raise AssertionError('Satellite TLS handshake accepted '+name)
        node_name='rkq-pair-node2'
        report['node_create_rc']=api('POST','/v1/nodes',dict(name=node_name,type='SATELLITE',net_interfaces=[dict(name='local',address='127.0.0.1',satellite_port=stlt_port,satellite_encryption_type='SSL')]))
        deadline=time.monotonic()+90
        while True:
            nodes=api('GET','/v1/nodes')
            if len(nodes)==1 and nodes[0].get('connection_status')=='ONLINE':break
            assert time.monotonic()<deadline,'actual SSL node never became ONLINE'
            time.sleep(.5)
        report['online_node']=nodes[0]
        assert api('GET','/v1/resource-definitions')==[]
        report['empty_resource_definitions_verified']=True
        report['actual_roles']={}
        for role in [controller,satellite]:
            p=Path('/proc')/str(role['child'].pid)
            exe=Path(os.readlink(p/'exe'))
            assert exe==java_home/'bin/java'
            report['actual_roles'][role['tag']]=dict(executable=str(exe),executable_sha256=sha(exe),cmdline=(p/'cmdline').read_bytes().decode().split('\0')[:-1],identity=proc(role['child'].pid))
        assert report['actual_roles']['controller']['identity']['uid']==1000 and int(report['actual_roles']['controller']['identity']['capabilities'],16)==0
        assert report['actual_roles']['satellite']['identity']['uid']==0
        began=time.monotonic();next_sample=began
        report['requested_phase_seconds']=dict(warmup=30,workload=120,idle=30)
        with (case/'resources.jsonl').open('x') as out:
            while time.monotonic()-began<180:
                now=time.monotonic();elapsed=now-began
                phase='warmup' if elapsed<30 else 'workload' if elapsed<150 else 'idle'
                if now>=next_sample:
                    row=dict(elapsed_s=elapsed,phase=phase,roles={role['tag']:proc(role['child'].pid) for role in [controller,satellite]})
                    assert all(v['start_ticks']==role['identity']['start_ticks'] for role,v in [(controller,row['roles']['controller']),(satellite,row['roles']['satellite'])])
                    assert sum(v['rss_bytes'] for v in row['roles'].values())<1400*1024**2,'pair safety RSS ceiling'
                    out.write(json.dumps(row)+'\n');out.flush();report['samples']+=1;next_sample=now+2
                if phase=='workload':
                    current=api('GET','/v1/nodes')
                    assert len(current)==1 and current[0]['connection_status']=='ONLINE'
                    report['requests']+=1
                    time.sleep(.2)
                else:time.sleep(.05)
            out.flush();os.fsync(out.fileno())
        report['observed_phase_seconds']=time.monotonic()-began
        report['final_nodes']=api('GET','/v1/nodes')
        assert api('GET','/v1/resource-definitions')==[]
        report['passed']=True
    except BaseException as error:
        report['failure']=(type(error).__name__+': '+str(error)).replace(password,'[REDACTED]')
    finally:
        for role in reversed(roles):
            if 'ended' not in role:stop(role)
        report['roles']=[dict(tag=r['tag'],initial=r['identity'],ended=r.get('ended')) for r in roles]
        report['all_roles_reaped']=all(r['child'].poll() is not None for r in roles)
        report['all_prerequisites_reaped']=all(c.poll() is not None for c,_ in children)
        original_sessions={role['child'].pid for role in roles}
        residual=[]
        for p in Path('/proc').iterdir():
            if not p.name.isdigit():continue
            try:
                fields=(p/'stat').read_text().rsplit(') ',1)[1].split()
                if int(fields[3]) in original_sessions:
                    residual.append(dict(pid=int(p.name),session=int(fields[3]),start_ticks=fields[19],state=fields[0],comm=(p/'comm').read_text().strip()))
            except (FileNotFoundError,ProcessLookupError):continue
        report['residual_original_session_processes']=residual
        if residual:report['passed']=False
        for role in roles:
            path=case/(role['tag']+'.log')
            if path.exists():(case/(role['tag']+'-redacted-tail.txt')).write_text(path.read_text(errors='replace')[-20000:].replace(password,'[REDACTED]'))
        report['private_credentials_retained_pending_exact_cleanup']=True
        report=json.loads(json.dumps(report).replace(password,'[REDACTED]'))
        put(case/'pair-report.json',report)
        for name in ['pair-report.json','resources.jsonl',*[r['tag']+'-redacted-tail.txt' for r in roles]]:
            path=case/name
            if path.exists():path.chmod(0o600);os.chown(path,1000,1000)
    print(json.dumps({k:report.get(k) for k in ['passed','failure','requests','samples','all_roles_reaped','all_prerequisites_reaped']}),flush=True)
    return int(not report['passed'])


if __name__=='__main__':raise SystemExit(main())
