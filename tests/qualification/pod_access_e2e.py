#!/usr/bin/env python3
"""Root-only, owned Linux Docker runtime-access regression (no storage IO).

Uses only a fresh scratch directory and new fixture containers. Does not adopt
or delete existing containers, volumes, images, disks, or historical evidence.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import re
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


def command(*args, timeout=30):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f'{args[:3]} failed: {p.stderr[-1000:]}')
    return p.stdout.strip()


def wait(predicate, timeout=40):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(.2)
    raise AssertionError('runtime condition did not converge')


def docker_api(method, path, value=None):
    """Exact local-daemon fixture calls; never a user-selected remote socket."""
    address=os.environ.get('DOCKER_HOST','unix:///var/run/docker.sock')
    assert address.startswith('unix://') and path.startswith('/')
    connection=http.client.HTTPConnection('localhost',timeout=6)
    connection.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    connection.sock.settimeout(6)
    connection.sock.connect(address[7:])
    try:
        connection.request(method,path,None if value is None else json.dumps(value),{'Content-Type':'application/json'})
        response=connection.getresponse()
        raw=response.read(65537)
        assert len(raw)<=65536,'bounded fixture Docker response'
        return response.status,json.loads(raw) if raw else {}
    finally:
        connection.close()


def inspected_containers(ids,inspect,vanished):
    """A list is not an atomic inspect snapshot. Only exact404 means vanished."""
    assert len(ids)==len(set(ids)) and all(re.fullmatch('[0-9a-f]{64}',cid) for cid in ids)
    values=[]
    for cid in ids:
        status,value=inspect(cid)
        if status==404:
            vanished(cid)
            continue
        assert status==200 and isinstance(value,dict) and value.get('Id')==cid,'unknown or mismatched container census'
        values.append(value)
    return values

def removable_fixture_network(info,run,names):
    """A newly seen name alone never authorizes deleting a network."""
    return bool(isinstance(info,dict) and re.fullmatch('[0-9a-f]{64}',info.get('Id',''))
        and info.get('Name') in names and info.get('Labels',{}).get('royak.qualification')==run
        and info.get('Containers')=={})

def tcp_listener_present(tables,port):
    assert type(port) is int and 0<port<65536
    suffix=':'+format(port,'04X')
    return any(len(fields:=line.split())>3 and fields[1].upper().endswith(suffix) and fields[3]=='0A'
        for table in tables for line in table.splitlines()[1:])


def exercise_stale_forward(*,root,run,ns,image,viewer,initial_networks,
                          api,pod,running,websocket,check,command,docker_api,wait,result):
    owner='pf-stale'
    receiver=None
    forward=None
    assert result=={}
    result.update(kind='royak-pinned-pod-forward-ip-reuse-v1',passed=False)
    evidence=root/'pf-ip-reuse.json'
    assert not evidence.exists()
    try:
        check('create exact stale-forward target',api(f'/api/v1/namespaces/{ns}/pods','POST',pod(owner))[0]==201)
        old=wait(lambda:running(owner))
        cid=old['Id'];pod_name=old['Config']['Labels']['royak.pod']
        name='rk-'+ns
        net=old['NetworkSettings']['Networks'].get(name)
        assert net and net.get('IPAddress'),'no actual namespace IPv4 endpoint; do not fake IP reuse coverage'
        network=net['NetworkID'];address=net['IPAddress']
        assert re.fullmatch('[0-9a-f]{64}',cid) and re.fullmatch('[0-9a-f]{64}',network)
        assert isinstance(ipaddress.ip_address(address),ipaddress.IPv4Address)
        assert not any(network.startswith(old_id) for old_id in initial_networks),'only the newly owned fixture network'
        network_info=json.loads(command('docker','network','inspect',network))[0]
        assert network_info['Id']==network and network_info['Name']==name and network_info['Labels'].get('royak.qualification')==run
        result['original']={'container_id':cid,'pod':pod_name,'network':network,'network_name':name,'ip':address,
                            'started_at':old['State']['StartedAt']}
        forward=websocket(pod_name,'portforward',viewer,'ports=8080')
        assert forward.status==101
        for _ in range(2):
            opcode,data=forward.frame();assert opcode==2 and data[1:]==(8080).to_bytes(2,'little')
        # No first application byte has yet opened this lazy port.
        check('retire desired stale target before lazy port first use',api(f'/apis/apps/v1/namespaces/{ns}/deployments/{owner}','DELETE')[0]==200)
        wait(lambda:docker_api('GET',f'/containers/{cid}/json')[0]==404)
        assert running(owner) is None,'do not compete with a newly reconciled target'
        receiver=command('docker','create','--name',run+'-pf-receiver','--label','royak.qualification='+run,
            '--label','royak.qualification-purpose=pf-ip-reuse','--network',network,'--ip',address,
            image,'sh','-c','mkdir -p /capture; exec nc -l -p 8080 > /capture/received')
        assert re.fullmatch('[0-9a-f]{64}',receiver) and receiver!=cid
        result['receiver_id']=receiver
        command('docker','start',receiver)
        def listening():
            code,current=docker_api('GET',f'/containers/{receiver}/json')
            if code!=200 or not current['State']['Running']:
                return False
            assert current['Config']['Labels']['royak.qualification']==run
            assert current['NetworkSettings']['Networks'][name]['IPAddress']==address
            assert current['NetworkSettings']['Networks'][name]['NetworkID']==network
            # Metadata observation, not a TCP probe that consumes nc's listener.
            tables={name:command('docker','exec',receiver,'cat','/proc/net/'+name) for name in ('tcp','tcp6')}
            assert all(len(raw)<=65536 for raw in tables.values()),'bounded receiver socket census'
            result['listener_observation']=dict(at=time.time(),container_id=receiver,
                running=current['State']['Running'],network_id=network,ip=address,tables=tables)
            return tcp_listener_present(list(tables.values()),8080)
        wait(listening)
        marker=('FORWARD-MUST-NOT-REACH-'+run).encode()
        payload=b'GET /'+marker+b' HTTP/1.0\r\n\r\n'
        result['attempt_payload_sha256']=hashlib.sha256(payload).hexdigest()
        try:
            forward.send(0,payload)
        except (OSError,EOFError):
            pass # a correctly rejected old handle may already have closed
        try:
            server_closed=forward.closed()
        except (OSError,EOFError):
            server_closed=False # a timeout is not successful server-side rejection
        result['server_closed_before_client_cleanup']=server_closed
        forward.close()
        wait(lambda:api('/royak/v1/pod-access/usage')[1]['active_or_closing']==0,10)
        # Retain a bounded observation interval and then copy the actual receiver
        # bytes, not merely a client-side closed flag or an API boolean.
        time.sleep(1)
        first=root/'pf-reuse-before-direct-control.bin'
        assert not first.exists();command('docker','cp',receiver+':/capture/received',str(first))
        received=first.read_bytes()
        result['forward_received_bytes']=len(received)
        result['forward_received_sha256']=hashlib.sha256(received).hexdigest()
        check('stale Pod forward sends ZERO application bytes to reused IP',received==b'',observed_bytes=len(received),receiver=receiver)
        check('stale Pod handle closes before fixture closes client',server_closed)
        # Positive control proves this exact reused-IP receiver really accepts
        # bytes; zero above must not result from a dead listener or wrong route.
        control=('DIRECT-CONTROL-'+run).encode()
        with socket.create_connection((address,8080),3) as direct:
            direct.sendall(control)
            direct.shutdown(socket.SHUT_WR)
        wait(lambda:docker_api('GET',f'/containers/{receiver}/json')[1]['State']['Running'] is False)
        final=root/'pf-reuse-direct-control.bin'
        assert not final.exists();command('docker','cp',receiver+':/capture/received',str(final))
        direct_bytes=final.read_bytes()
        check('reused IP positive control reaches exact receiver',direct_bytes==control,observed_bytes=len(direct_bytes))
        result['direct_control_sha256']=hashlib.sha256(direct_bytes).hexdigest()
        result['passed']=True
    except Exception as error:
        result['error']=type(error).__name__+': '+str(error)
        raise
    finally:
        if forward is not None:
            forward.close()
        if receiver is not None:
            code,current=docker_api('GET',f'/containers/{receiver}/json')
            if code==200:
                assert current['Id']==receiver and current['Config']['Labels'].get('royak.qualification')==run
                command('docker','rm','-f',receiver)
            assert docker_api('GET',f'/containers/{receiver}/json')[0]==404
        result['receiver_cleaned']=receiver is None or docker_api('GET',f'/containers/{receiver}/json')[0]==404
        evidence.write_text(json.dumps(result,indent=2)+'\n')
    return result


class WebSocket:
    def __init__(self, port, context, path, token):
        started=time.monotonic()
        self.sock = context.wrap_socket(socket.create_connection(('127.0.0.1', port), 6), server_hostname='localhost')
        self.sock.settimeout(6)
        key = __import__('base64').b64encode(secrets.token_bytes(16)).decode()
        self.sock.sendall((f'GET {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\n'
            f'Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n'
            'Sec-WebSocket-Protocol: v5.channel.k8s.io, v4.channel.k8s.io\r\n\r\n').encode())
        head = bytearray()
        while not head.endswith(b'\r\n\r\n'):
            byte = self.sock.recv(1)
            if not byte:
                raise AssertionError('websocket handshake EOF')
            head.extend(byte)
            assert len(head) < 16384
        self.status = int(head.split()[1])
        self.handshake_ms=(time.monotonic()-started)*1000
        self.headers={k.lower():v.strip() for line in head.decode().split('\r\n')[1:] if ':' in line for k,v in [line.split(':',1)]}

    def exact(self, size):
        out = bytearray()
        while len(out) < size:
            data = self.sock.recv(size - len(out))
            if not data:
                raise EOFError()
            out.extend(data)
        return bytes(out)

    def send(self, channel, data):
        payload = bytes([channel]) + data
        mask = secrets.token_bytes(4)
        n = len(payload)
        head = bytes([0x82, 0x80 | n]) if n < 126 else bytes([0x82, 0xfe]) + struct.pack('!H', n)
        self.sock.sendall(head + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))

    def frame(self):
        first, second = self.exact(2)
        n = second & 127
        if n == 126:
            n = struct.unpack('!H', self.exact(2))[0]
        elif n == 127:
            n = struct.unpack('!Q', self.exact(8))[0]
        assert n <= 1024 * 1024 and not second & 128
        return first & 15, self.exact(n)

    def echo(self, text):
        self.send(0, text + b'\n')
        data = bytearray()
        for _ in range(20):
            opcode, payload = self.frame()
            assert opcode != 8
            if payload and payload[0] == 1:
                data.extend(payload[1:])
                if text in data:
                    return True
        return False

    def closed(self):
        try:
            for _ in range(20):
                if self.frame()[0] == 8:
                    return True
        except (EOFError, ConnectionError, ssl.SSLEOFError):
            return True
        return False

    def close(self):
        self.sock.close()


def collect(binary, output, resource_cycles=0):
    assert resource_cycles in (0,12)
    assert os.geteuid() == 0 and __import__('sys').platform == 'linux'
    assert not command('docker', 'ps', '-aq'), 'refuse a nonempty Docker lab'
    os.umask(0o077)
    root = Path(tempfile.mkdtemp(prefix='runtime-access-', dir='/var/lib/royak-storage-qualification'))
    run = 'rkq-access-' + secrets.token_hex(5)
    ns, other = 'access-' + secrets.token_hex(3), 'access-' + secrets.token_hex(3)
    checks, streams, created, mounts = [], [], [], []
    report = dict(kind='royak-pod-access-runtime-e2e-v1', passed=False, started_at=time.time(), run=run,
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), checks=checks,
        scratch=str(root), storage_replication_qualified=False, physical_fencing_qualified=False,
        cross_host_forwarding_test=False, mount_race_qualified=False)
    server = log = None
    admin, viewer, peer = secrets.token_hex(24), secrets.token_hex(24), secrets.token_hex(24)
    tokens = root / 'tokens.csv'
    tokens.write_text(f'{viewer},viewer,viewer,"readers"\n{peer},peer-viewer,viewer,"readers"\n')
    tokens.chmod(0o600)
    (root / 'home').mkdir()
    (root / 'public').mkdir()
    (root / 'runtime').mkdir()
    (root / 'public' / 'sentinel').write_text('retained-public-data\n')
    (root / 'runtime' / 'synthetic-secret').write_text('synthetic-not-a-real-credential\n')
    initial_networks = set(command('docker', 'network', 'ls', '-q').split())
    cluster = node = None
    resource_stop=threading.Event()
    resource_thread=None

    def check(name, passed, **details):
        checks.append(dict(name=name, passed=bool(passed), **details))
        assert passed, name

    def api(path, method='GET', body=None, token=None, stream=False):
        req = urllib.request.Request(base + path, None if body is None else json.dumps(body).encode(),
            {'Authorization': 'Bearer ' + (token or admin), 'Content-Type': 'application/json'}, method=method)
        try:
            response = opener.open(req, timeout=7)
        except urllib.error.HTTPError as e:
            response = e
        if stream:
            return response
        with response:
            data = response.read()
            try:
                data = json.loads(data)
            except ValueError:
                data = data.decode(errors='replace')
            return response.code, data

    def pod(name, host=None, capability=False):
        c = dict(name='main', image=image, command=['sh', '-c',
            'mkdir -p /www; echo runtime-fixture > /www/index.html; echo runtime-started; exec httpd -f -p 8080 -h /www'])
        spec = dict(containers=[c])
        if host:
            c['volumeMounts'] = [dict(name='data', mountPath='/data')]
            spec['volumes'] = [dict(name='data', hostPath=dict(path=host))]
        if capability:
            c['securityContext'] = dict(capabilities=dict(add=['NET_RAW']))
        return dict(apiVersion='v1', kind='Pod', metadata=dict(name=name, namespace=ns,
            labels={'royak.runtime-access': '{"version":1,"host_access":false}'}), spec=spec)

    def containers():
        ids = command('docker', 'ps', '-aq','--no-trunc').split()
        def vanished(cid):
            rows=report.setdefault('container_census_vanished',[])
            assert len(rows)<256,'excessively volatile fixture container census'
            rows.append(dict(at=time.time(),container_id=cid,inspect_status=404))
        return inspected_containers(ids,lambda cid:docker_api('GET','/containers/'+cid+'/json'),vanished)

    def running(owner):
        return next((c for c in containers() if c['Config']['Labels'].get('royak.deployment') == owner
            and c['Config']['Labels'].get('royak.namespace') == ns and c['State']['Running']), None)

    def websocket(pod_name, sub, token, query):
        ws = WebSocket(port, context, f'/api/v1/namespaces/{ns}/pods/{pod_name}/{sub}?' + query, token)
        streams.append(ws)
        return ws

    try:
        image_tag='busybox:1.36.1'
        existing=subprocess.run(['docker','image','inspect',image_tag],capture_output=True,text=True)
        if existing.returncode:
            command('docker','pull',image_tag,timeout=120)
        image_info=json.loads(command('docker','image','inspect',image_tag))[0]
        image=image_info['Id']
        report['image_tag']=image_tag
        report['image_repo_digests']=image_info['RepoDigests']
        report['fixture_image_pulled']=existing.returncode!=0
        report['image_id'] = image
        # Controlled user-defined subnets make same-IP reuse deterministic.
        # Only NEW namespace networks are created, before the server can race
        # their creation; no pre-existing bridge or guest/host route is edited.
        previous=json.loads(command('docker','network','inspect',*sorted(initial_networks))) if initial_networks else []
        occupied=[ipaddress.ip_network(item['Subnet']) for value in previous for item in (value.get('IPAM',{}).get('Config') or []) if item.get('Subnet')]
        occupied.extend(ipaddress.ip_network(value['dst'],strict=False) for value in json.loads(command('ip','-j','-4','route')) if value.get('dst') not in (None,'default'))
        report['fixture_networks']=[]
        existing_names={value['Name'] for value in previous}
        for name in ('royak','rk-default','rk-'+ns,'rk-'+other):
            if name in existing_names:
                assert name in ('royak','rk-default'),'random namespace fixture name collided with an existing network'
                continue # preserve the existing global/default network unchanged
            subnet=next((ipaddress.ip_network(f'10.234.{i}.0/24') for i in range(1,255)
                if not any(ipaddress.ip_network(f'10.234.{i}.0/24').overlaps(old) for old in occupied)),None)
            assert subnet is not None,'no non-overlapping new fixture subnet'
            net_id=command('docker','network','create','--driver','bridge','--label','royak.qualification='+run,
                '--label','royak.managed=true','--subnet',str(subnet),name)
            observed=json.loads(command('docker','network','inspect',net_id))[0]
            assert re.fullmatch('[0-9a-f]{64}',net_id) and observed['Id']==net_id and observed['Name']==name and observed['Labels'].get('royak.qualification')==run
            report['fixture_networks'].append(dict(id=net_id,name=name,subnet=str(subnet)))
            occupied.append(subnet)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        base = f'https://localhost:{port}'
        env = dict(PATH=os.environ['PATH'], HOME=str(root / 'home'), ROYAK_STATE=str(root / 'state.json'),
            ROYAK_DATA_DIR=str(root / 'runtime'), ROYAK_TOKEN=admin, ROYAK_TOKEN_FILE=str(tokens),
            DOCKER_HOST='unix:///var/run/docker.sock')
        log = (root / 'server.log').open('wb')
        server = subprocess.Popen([str(binary), 'watch', '--tls', '--port', str(port), '--ingress-port', '0', '--interval', '1'],
            cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
        ca = root / 'home' / '.kube' / 'royak-ca.pem'
        wait(lambda: ca.exists() or server.poll() is not None, 20)
        assert server.poll() is None
        context = ssl.create_default_context(cafile=str(ca))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        wait(lambda: api('/healthz')[0] == 200)
        for namespace in (ns, other):
            check('create namespace ' + namespace, api('/api/v1/namespaces', 'POST', dict(kind='Namespace', metadata=dict(name=namespace)))[0] == 201)
        rbac = '/apis/rbac.authorization.k8s.io/v1'
        role = dict(kind='Role', metadata=dict(name='reader', namespace=ns), rules=[
            dict(resources=['pods'], verbs=['get', 'list', 'create']),
            dict(resources=['pods/log'], verbs=['get']), dict(resources=['pods/exec', 'pods/portforward'], verbs=['create'])])
        check('namespace role', api(f'{rbac}/namespaces/{ns}/roles', 'POST', role)[0] == 201)
        binding = dict(kind='RoleBinding', metadata=dict(name='reader', namespace=ns),
            roleRef=dict(kind='Role', name='reader'), subjects=[dict(kind='Group', name='readers')])
        check('namespace binding', api(f'{rbac}/namespaces/{ns}/rolebindings', 'POST', binding)[0] == 201)
        check('host manifest rejected for namespace caller', api(f'/api/v1/namespaces/{ns}/pods', 'POST', pod('denied', str(root/'public')), viewer)[0] == 403)
        check('capability rejected for namespace caller', api(f'/api/v1/namespaces/{ns}/pods', 'POST', pod('denied-cap', capability=True), viewer)[0] == 403)
        for name, host, cap in [('ordinary', None, False), ('host', str(root/'public'), False), ('cap', None, True)]:
            check('create actual ' + name, api(f'/api/v1/namespaces/{ns}/pods', 'POST', pod(name, host, cap))[0] == 201)
            if name=='ordinary':
                # Establish exact ownership before any later workload can
                # fail; cleanup must not depend on ALL Pods having started.
                first=wait(lambda:running('ordinary'))
                cluster=first['Config']['Labels']['royak.cluster']
                node=first['Config']['Labels']['royak.node']
        ordinary, host, cap = [wait(lambda n=name: running(n)) for name in ('ordinary', 'host', 'cap')]
        report['docker_server']=json.loads(command('docker','version','--format','{{json .Server}}'))
        # Observe the ACTUAL daemon protocol used by the exec cleanup fix.
        # This is one harmless true process in an exact fixture-owned runtime,
        # not a Royak authorization test or fabricated successful response.
        code,value=docker_api('POST','/containers/'+ordinary['Id']+'/exec',dict(Cmd=['true']))
        check('create exact fixture daemon exec',code==201 and len(value.get('Id',''))==64)
        direct_exec=value['Id']
        code,before_start=docker_api('GET','/exec/'+direct_exec+'/json')
        check('actual daemon unstarted exec is false with null exit code',code==200 and before_start.get('ContainerID')==ordinary['Id']
            and before_start.get('Running') is False and 'ExitCode' in before_start and before_start['ExitCode'] is None,
            observed={key:before_start.get(key) for key in ('Running','ExitCode','Pid')})
        code,_=docker_api('POST','/exec/'+direct_exec+'/start',dict(Detach=True,Tty=False))
        assert code==200
        def terminal_exec():
            status,value=docker_api('GET','/exec/'+direct_exec+'/json')
            return value if status==200 and value.get('ContainerID')==ordinary['Id'] and value.get('Running') is False and type(value.get('ExitCode')) is int else None
        after_start=wait(terminal_exec,10)
        check('actual daemon fast exec has numeric terminal witness',after_start['ExitCode']==0,
            observed={key:after_start.get(key) for key in ('Running','ExitCode','Pid')})
        cluster = ordinary['Config']['Labels']['royak.cluster']
        node = ordinary['Config']['Labels']['royak.node']
        names = {name: value['Config']['Labels']['royak.pod'] for name, value in [('ordinary', ordinary), ('host', host), ('cap', cap)]}
        report['runtime_contracts'] = {name: json.loads(c['Config']['Labels']['royak.runtime-access']) for name,c in [('ordinary',ordinary),('host',host),('cap',cap)]}
        check('manifest cannot forge ordinary runtime label', report['runtime_contracts']['ordinary']['host_access'] is False)
        check('actual host and capability labels privileged', all(report['runtime_contracts'][name]['host_access'] for name in ('host','cap')))
        for name in ('host', 'cap'):
            path = f'/api/v1/namespaces/{ns}/pods/{names[name]}'
            for sub, method in [('log', 'GET'), ('exec?command=true', 'POST')]:
                check('deny actual ' + name + '/' + sub, api(path+'/'+sub, method, token=viewer)[0] == 403)
            ws = websocket(names[name], 'exec', viewer, 'command=cat&stdin=true')
            check('deny actual websocket ' + name, ws.status == 403)
            ws.close()
            ws = websocket(names[name], 'portforward', viewer, 'ports=8080')
            check('deny actual portforward ' + name, ws.status == 403)
            ws.close()
            response = api(path+'/log?follow=true', token=viewer, stream=True)
            check('deny actual log-follow ' + name, response.code == 403)
            response.close()
        ordinary_path = f'/api/v1/namespaces/{ns}/pods/{names["ordinary"]}'
        check('ordinary logs accessible', api(ordinary_path+'/log', token=viewer)[0] == 200)
        code,result=api(ordinary_path+'/exec?command=true', 'POST', token=viewer)
        check('ordinary JSON exec accessible',code==200 and result.get('exitCode')==0,observed_status=code,exit_code=result.get('exitCode'))
        check('other namespace cannot be addressed', api(f'/api/v1/namespaces/{other}/pods/{names["ordinary"]}/log', token=viewer)[0] == 403)
        host_role = dict(kind='ClusterRole', metadata=dict(name=run), rules=[dict(resources=['hostaccess'], verbs=['use'])])
        check('host role', api(rbac+'/clusterroles', 'POST', host_role)[0] == 201)
        host_binding = dict(kind='ClusterRoleBinding', metadata=dict(name=run), roleRef=dict(kind='ClusterRole', name=run), subjects=[dict(kind='User', name='viewer')])
        check('host grant', api(rbac+'/clusterrolebindings', 'POST', host_binding)[0] == 201)
        host_path = f'/api/v1/namespaces/{ns}/pods/{names["host"]}'
        code, result = api(host_path+'/exec?command=cat&command=/data/sentinel', 'POST', token=viewer)
        check('authorized actual benign host mount', code == 200 and result.get('exitCode')==0 and 'retained-public-data' in result.get('output',''),
            observed_status=code,exit_code=result.get('exitCode'),output_sha256=hashlib.sha256(result.get('output','').encode()).hexdigest())
        def resources():
            proc=Path('/proc')/str(server.pid)
            tasks=[]
            vanished=[]
            for task in sorted((proc/'task').iterdir()):
                try:
                    raw=(task/'stat').read_text();fields=raw[raw.rfind(')')+2:].split()
                    tasks.append(dict(tid=int(task.name),comm=(task/'comm').read_text().strip(),state=fields[0],
                        utime=int(fields[11]),stime=int(fields[12]),starttime=int(fields[19]),wchan=(task/'wchan').read_text().strip()))
                except (FileNotFoundError,ProcessLookupError):
                    vanished.append(int(task.name))
            fds={}
            vanished_fds=[]
            for fd in (proc/'fd').iterdir():
                try:
                    fds[fd.name]=os.readlink(fd)
                except (FileNotFoundError,ProcessLookupError):
                    vanished_fds.append(fd.name)
            status=dict(line.split(':',1) for line in (proc/'status').read_text().splitlines() if ':' in line)
            stat=(proc/'stat').read_text();stat=stat[stat.rfind(')')+2:].split()
            return dict(at=time.time(),fds=len(fds),fd_targets=fds,vanished_fds=vanished_fds,threads=int(status['Threads']),observed_threads=len(tasks),vanished_tasks=vanished,tasks=tasks,
                rss_kib=int(status['VmRSS'].split()[0]),hwm_kib=int(status['VmHWM'].split()[0]),
                utime=int(stat[11]),stime=int(stat[12]),incarnation=int(stat[19]))

        if resource_cycles:
            first_resource_stream=len(streams)
            sampler_errors=[]
            def sampler():
                with (root/'resources.jsonl').open('w') as stream:
                    while not resource_stop.is_set():
                        try:
                            stream.write(json.dumps(resources())+'\n');stream.flush()
                        except FileNotFoundError:
                            sampler_errors.append('server process disappeared during resource collection')
                            return
                        except OSError as error:
                            sampler_errors.append(type(error).__name__+': '+str(error))
                            return
                        resource_stop.wait(.25)
            resource_thread=threading.Thread(target=sampler,name='fixture-resource-sampler')
            resource_thread.start()
            phase=dict(requested_cycles=resource_cycles,started_at=time.time(),cold=resources(),cycles=[])
            report['resource_phase']=phase
            phase['sampler_errors']=sampler_errors
            def docker_census():
                return {name:command('docker','top',value['Id'],'-eo','pid,ppid,stat,comm').splitlines()[1:]
                    for name,value in [('ordinary',ordinary),('host',host),('cap',cap)]}
            phase['docker_census_before']=docker_census()
            def no_exec_workers():
                return not any(t['comm'] in ('rk-exec-rd','rk-exec-wr') for t in resources()['tasks'])
            def usage():
                code,body=api('/royak/v1/pod-access/usage')
                assert code==200
                return body
            def exec_observation():
                # Diagnostic evidence only: never start, retry or kill an exec
                # to make an uncertain lifecycle appear complete.
                values=[]
                for current in containers():
                    if current['Id'] not in (ordinary['Id'],host['Id'],cap['Id']):
                        continue
                    exec_ids=current.get('ExecIDs') or []
                    assert len(exec_ids)<=256,'bounded fixture exec inventory'
                    entries=[]
                    for exec_id in exec_ids:
                        assert re.fullmatch('[0-9a-f]{64}',exec_id)
                        status,value=docker_api('GET','/exec/'+exec_id+'/json')
                        entries.append(dict(id=exec_id,status=status,observed={k:value.get(k) for k in ('ContainerID','Running','ExitCode','Pid','ProcessConfig')}))
                    values.append(dict(container_id=current['Id'],execs=entries,
                        processes=command('docker','top',current['Id'],'-eo','pid,ppid,stat,comm').splitlines()))
                return dict(at=time.time(),usage=usage(),containers=values,resources=resources())
            check('session usage requires cluster rights',api('/royak/v1/pod-access/usage',token=viewer)[0]==403)
            def clear_clients(clients):
                for client in clients:
                    client.close()
                wait(lambda:no_exec_workers() and usage()['active_or_closing']==0,10)
            def open_cat(token):
                ws=websocket(names['ordinary'],'exec',token,'command=cat&stdin=true')
                assert ws.status==101 and ws.echo(b'capacity-ack')
                return ws
            def capacity(label):
                active=[]
                try:
                    for token in (viewer,peer):
                        for _ in range(6):
                            active.append(open_cat(token))
                        forward=websocket(names['ordinary'],'portforward',token,'ports=8080')
                        assert forward.status==101
                        forward.frame();forward.frame();forward.send(0,b'GET / HTTP/1.0\r\n')
                        active.append(forward)
                        logs=api(ordinary_path+'/log?follow=true',token=token,stream=True)
                        streams.append(logs)
                        assert logs.code==200 and b'runtime-started' in logs.readline()
                        active.append(logs)
                    check(label+' admits 16 mixed sessions, eight per identity',len(active)==16)
                    current=usage()
                    check(label+' exact active or closing accounting',current['active_or_closing']==16 and current['node_limit']==16 and current['user_limit']==8,
                        observed=current)
                    denied=websocket(names['ordinary'],'exec',viewer,'command=cat&stdin=true')
                    check(label+' ninth identity session rejected',denied.status==429 and denied.headers.get('retry-after')=='1')
                    denied.close()
                    denied=websocket(names['ordinary'],'exec',admin,'command=cat&stdin=true')
                    check(label+' seventeenth node session rejected',denied.status==503 and denied.headers.get('retry-after')=='1')
                    denied.close()
                    check(label+' finite diagnostic shares admission',api(ordinary_path+'/log',token=viewer)[0]==429)
                    check(label+' health remains reachable',api('/healthz')[0]==200)
                    # Every accepted exec still carries data, not merely a
                    # successful upgrade followed by premature revocation.
                    for index,client in enumerate(active):
                        if isinstance(client,WebSocket) and index not in (6,14):
                            assert client.echo(b'all-sixteen-still-live')
                    return resources()
                finally:
                    clear_clients(active)
            phase['capacity_before']=capacity('initial capacity')
            # Observe the existing runtime pool's actual idle lifecycle; no
            # product keepalive/timeout or old endurance bound is changed.
            phase['first_drain']=[]
            for _ in range(15):
                time.sleep(1);phase['first_drain'].append(resources())
            for cycle in range(resource_cycles):
                active=[];started=time.monotonic()
                try:
                    cat=open_cat(viewer);active.append(cat)
                    forward=websocket(names['ordinary'],'portforward',viewer,'ports=8080')
                    assert forward.status==101;forward.frame();forward.frame()
                    forward.send(0,b'GET / HTTP/1.0\r\n')
                    active.append(forward)
                    logs=api(ordinary_path+'/log?follow=true',token=viewer,stream=True);streams.append(logs)
                    assert logs.code==200 and b'runtime-started' in logs.readline();active.append(logs)
                    check('cycle '+str(cycle+1)+' mixed streams live',cat.echo(('cycle-'+str(cycle+1)).encode()))
                    sample=resources()
                finally:
                    clear_clients(active)
                phase['cycles'].append(dict(cycle=cycle+1,elapsed=time.monotonic()-started,open=sample,drained=resources()))
            # A slow/unread client must backpressure, not grow an unbounded
            # host-side queue. Closing its transport must also release workers.
            flood=websocket(names['ordinary'],'exec',viewer,'command=yes&stdin=true')
            assert flood.status==101 and flood.frame()[1][0]==1
            time.sleep(3)
            phase['slow_reader']=resources();flood.close();wait(no_exec_workers,10)
            check('slow reader releases named workers',no_exec_workers())
            wait(lambda:usage()['active_or_closing']==0,10)
            sleeper=websocket(names['ordinary'],'exec',viewer,'command=sleep&command=60&stdin=true')
            check('foreground ignoring stdin starts',sleeper.status==101)
            wait(lambda:usage()['active_or_closing']==1,10)
            # Preserve the original immediate-close regression: no extra
            # Docker observation or artificial sleep before closing this one.
            sleeper.close();wait(lambda:usage()['active_or_closing']==0,10)
            check('closed foreground ignoring stdin releases actual process reservation',usage()['active_or_closing']==0)
            confirmed=websocket(names['ordinary'],'exec',viewer,'command=sleep&command=60&stdin=true')
            check('confirmed-running foreground accepts stream',confirmed.status==101)
            def actual_foreground_started():
                status,current=docker_api('GET','/containers/'+ordinary['Id']+'/json')
                assert status==200 and current['Id']==ordinary['Id']
                entries=current.get('ExecIDs') or []
                assert len(entries)<=256
                for exec_id in entries:
                    assert re.fullmatch('[0-9a-f]{64}',exec_id)
                    code,value=docker_api('GET','/exec/'+exec_id+'/json')
                    config=value.get('ProcessConfig') or {}
                    if code==200 and value.get('ContainerID')==ordinary['Id'] and value.get('Running') is True and value.get('Pid',0)>1 and config.get('entrypoint')=='sleep' and config.get('arguments')==['60']:
                        return dict(exec_id=exec_id,pid=value['Pid'],running=True,exit_code=value.get('ExitCode'))
                return None
            phase['confirmed_foreground_witness']=wait(actual_foreground_started,10)
            confirmed.close();wait(lambda:usage()['active_or_closing']==0,10)
            check('confirmed-running foreground releases actual process reservation',usage()['active_or_closing']==0,
                witness=phase['confirmed_foreground_witness'])
            eof_cat=open_cat(viewer)
            check('stdin EOF control negotiates v5',eof_cat.headers.get('sec-websocket-protocol')=='v5.channel.k8s.io')
            eof_cat.send(255,b'\0')
            eof_status=None;eof_closed=False
            for _ in range(20):
                opcode,payload=eof_cat.frame()
                if opcode==8:
                    eof_closed=True
                    break
                if payload and payload[0]==3:
                    eof_status=json.loads(payload[1:])
            check('active v5 stdin EOF completes cat without closing client first',
                eof_closed and eof_status is not None and eof_status.get('status')=='Success',observed_status=eof_status)
            eof_cat.close();wait(lambda:usage()['active_or_closing']==0,10)
            check('v5 stdin EOF releases actual reservation',usage()['active_or_closing']==0)
            ephemeral=pod('ephemeral')
            ephemeral['spec']['containers'][0]['command']=['sh','-c',"trap 'exit 0' TERM; while :; do sleep 1; done"]
            check('create process-deletion fixture',api(f'/api/v1/namespaces/{ns}/pods','POST',ephemeral)[0]==201)
            old=wait(lambda:running('ephemeral'))
            old_name=old['Config']['Labels']['royak.pod']
            deleted=websocket(old_name,'exec',viewer,'command=sleep&command=60&stdin=true')
            check('open exec on soon-deleted runtime',deleted.status==101)
            wait(lambda:usage()['active_or_closing']==1,10)
            check('delete exact runtime while exec active',api(f'/api/v1/namespaces/{ns}/pods/{old_name}','DELETE')[0]==200)
            check('deleted runtime closes its stream',deleted.closed());deleted.close()
            wait(lambda:usage()['active_or_closing']==0,10)
            replacement=wait(lambda: (c if (c:=running('ephemeral')) and c['Id']!=old['Id'] else None))
            check('cleanup cannot retarget same-name replacement',replacement['State']['Running'] and replacement['Id']!=old['Id'])
            check('remove only ephemeral desired fixture',api(f'/apis/apps/v1/namespaces/{ns}/deployments/ephemeral','DELETE')[0]==200)
            wait(lambda:running('ephemeral') is None)
            query=urllib.parse.urlencode([('command','head'),('command','-c'),('command','5000000'),('command','/dev/zero')])
            code,body=api(ordinary_path+'/exec?'+query,'POST',token=viewer)
            check('buffered exec fails above 4 MiB without truncation',code==413 and body.get('status')=='Failure',observed_status=code)
            denied=websocket(names['ordinary'],'portforward',viewer,'ports=1,2,3,4,5,6,7,8,9')
            check('forward port fanout bounded before upgrade',denied.status==400);denied.close()
            wait(lambda:usage()['active_or_closing']==0,10)
            phase['capacity_after']=capacity('post-cycle capacity')
            phase['final_drain']=[]
            for _ in range(15):
                time.sleep(1);phase['final_drain'].append(resources())
            cold=phase['cold'];last=phase['final_drain'][-5:]
            check('named session workers fully drain after 12 cycles',all(not any(t['comm'] in ('rk-exec-rd','rk-exec-wr') for t in s['tasks']) for s in last))
            check('post-cycle fd median remains bounded',sorted(s['fds'] for s in last)[2]<=cold['fds']+1)
            check('post-idle threads remain within cold plus two',all(s['threads']<=cold['threads']+2 for s in last),cold=cold['threads'],final=[s['threads'] for s in last])
            phase['docker_census_final']=docker_census()
            check('workload processes return to one httpd per container',all(len(rows)==1 and rows[0].split()[-1]=='httpd' and 'Z' not in rows[0].split()[-2] for rows in phase['docker_census_final'].values()),
                observed=phase['docker_census_final'])
            phase['finished_at']=time.time()
            resource_stop.set();resource_thread.join(timeout=3);assert not resource_thread.is_alive();resource_thread=None
            check('resource sampler completed without missing process data',not sampler_errors,observed=sampler_errors)
            samples=[json.loads(line) for line in (root/'resources.jsonl').read_text().splitlines()]
            phase['samples']=len(samples)
            phase['peak_rss_kib']=max(s['rss_kib'] for s in samples)
            phase['peak_hwm_kib']=max(s['hwm_kib'] for s in samples)
            check('kernel host rss high-water growth within fixed 128 MiB bound',phase['peak_hwm_kib']-cold['rss_kib']<=128*1024,
                baseline_rss_kib=cold['rss_kib'],peak_rss_kib=phase['peak_rss_kib'],peak_hwm_kib=phase['peak_hwm_kib'])
            latency=sorted(s.handshake_ms for s in streams[first_resource_stream:] if isinstance(s,WebSocket) and s.status==101)
            phase['handshake_latency_ms']=dict(samples=len(latency),p50=latency[(len(latency)-1)//2],
                p95=latency[int((len(latency)-1)*.95)],p99=latency[int((len(latency)-1)*.99)],maximum=latency[-1])
            phase['royak_cpu_percent']=((samples[-1]['utime']+samples[-1]['stime'])-(cold['utime']+cold['stime']))/os.sysconf('SC_CLK_TCK')/(phase['finished_at']-phase['started_at'])*100
            phase['resources_sha256']=hashlib.sha256((root/'resources.jsonl').read_bytes()).hexdigest()
            phase['passed']=True
        report['pf_ip_reuse']={}
        exercise_stale_forward(root=root,run=run,ns=ns,image=image,viewer=viewer,
            initial_networks=initial_networks,api=api,pod=pod,running=running,websocket=websocket,
            check=check,command=command,docker_api=docker_api,wait=wait,result=report['pf_ip_reuse'])
        report['session_resources']=[dict(stage='before',**resources())]
        sessions = []
        for name in ('ordinary','host'):
            ws = websocket(names[name], 'exec', viewer, 'command=cat&stdin=true')
            check('open interactive ' + name, ws.status == 101 and ws.echo(b'before-revoke'))
            forward = websocket(names[name], 'portforward', viewer, 'ports=8080')
            check('open portforward ' + name, forward.status == 101)
            for _ in range(2):
                opcode, payload = forward.frame()
                assert opcode == 2 and payload[1:] == (8080).to_bytes(2,'little')
            forward.send(0, b'GET / HTTP/1.0\r\n')  # backend open, request deliberately incomplete
            sessions.append((name, ws, forward))
        response = api(host_path+'/log?follow=true', token=viewer, stream=True)
        streams.append(response)
        check('open real host log stream', response.code == 200 and b'runtime-started' in response.readline())
        report['session_resources'].append(dict(stage='open',**resources()))
        started = time.monotonic()
        check('revoke host rights', api(rbac+'/clusterrolebindings/'+run, 'DELETE')[0] == 200)
        _, host_ws, host_forward = sessions[1]
        check('already-open host exec closes', host_ws.closed(), elapsed=time.monotonic()-started)
        check('already-open host portforward closes', host_forward.closed(), elapsed=time.monotonic()-started)
        check('already-open idle host log closes', response.read(1) == b'', elapsed=time.monotonic()-started)
        _, ordinary_ws, ordinary_forward = sessions[0]
        check('ordinary session survives host-only revoke', ordinary_ws.echo(b'ordinary-still-authorized'))
        ordinary_forward.send(0, b'Host: localhost\r\n\r\n')
        received = bytearray()
        for _ in range(20):
            _, payload = ordinary_forward.frame()
            if payload and payload[0] == 0:
                received.extend(payload[1:])
                if b'runtime-fixture' in received:
                    break
        check('ordinary forward still carries data', b'runtime-fixture' in received)
        check('revoke namespace rights', api(f'{rbac}/namespaces/{ns}/rolebindings/reader', 'DELETE')[0] == 200)
        check('already-open ordinary exec closes', ordinary_ws.closed())
        check('already-open ordinary forward closes', ordinary_forward.closed())
        for stream in streams:
            stream.close()
        streams.clear()
        def cats():
            # Docker needs the host PID column to map ps rows into a
            # container. Preserve it rather than asking only for comm.
            return [c['Id'] for c in (ordinary,host) if any(
                len(parts:=line.split())==2 and parts[1]=='cat'
                for line in command('docker','top',c['Id'],'-eo','pid,comm').splitlines()[1:])]
        wait(lambda:not cats(),10)
        check('interactive cat processes exit after stdin/socket revocation',not cats())
        if resource_cycles:
            wait(lambda:usage()['active_or_closing']==0,10)
            check('final authorization revoke releases all actual reservations',usage()['active_or_closing']==0)
        for _ in range(15 if resource_cycles else 3):
            time.sleep(1)
            report['session_resources'].append(dict(stage='drained',**resources()))
        if resource_cycles:
            final=report['session_resources'][-5:]
            check('final authorization drain has no named exec worker',all(not any(t['comm'] in ('rk-exec-rd','rk-exec-wr') for t in s['tasks']) for s in final))
            check('final authorization drain preserves unchanged thread bound',all(s['threads']<=report['resource_phase']['cold']['threads']+2 for s in final))
            check('final authorization drain returns fd median',sorted(s['fds'] for s in final)[2]<=report['resource_phase']['cold']['fds']+1)
        # Real symlink and bind aliases of synthetic private data must not be
        # mounted, even for an operator with explicit host-access authority.
        (root/'public'/'link').symlink_to(root/'runtime', target_is_directory=True)
        (root/'public'/'bind').mkdir()
        command('mount', '--bind', str(root/'runtime'), str(root/'public'/'bind'))
        mounts.append(root/'public'/'bind')
        for name in ('link','bind'):
            check('admit alias metadata ' + name, api(f'/api/v1/namespaces/{ns}/pods', 'POST', pod(name, str(root/'public'/name)))[0] == 201)
        def alias_refusals():
            lines=(root/'server.log').read_text(errors='replace').splitlines()
            return {name:next((line for line in lines if f'create rk-{ns}_{name}-1:' in line and 'reserved' in line),None) for name in ('link','bind')}
        wait(lambda:all(alias_refusals().values()))
        check('real symlink and bind aliases refused before container start',not running('link') and not running('bind'),observed_refusals=alias_refusals())
        # A fixture-owned simulation of a legacy Pod and a foreign cluster.
        for foreign in (False, True):
            labels = dict(ordinary['Config']['Labels'])
            labels.pop('royak.runtime-access')
            labels['royak.pod'] = run + ('-foreign' if foreign else '-legacy')
            labels['royak.qualification'] = run
            if foreign:
                labels['royak.cluster'] = run + '-foreign-cluster'
            args = ['docker','run','-d','--name',labels['royak.pod']]
            for key,value in labels.items():
                args += ['--label',key+'='+value]
            cid = command(*args,image,'sleep','3600')
            created.append(cid)
        legacy, foreign = created
        wait(lambda: legacy not in command('docker','ps','-aq','--no-trunc').split(), 30)
        check('legacy owned container retired', legacy not in command('docker','ps','-aq','--no-trunc').split())
        check('foreign cluster container untouched', command('docker','inspect',foreign,'--format','{{.State.Running}}') == 'true')
        check('retirement retains public volume data', (root/'public'/'sentinel').read_text() == 'retained-public-data\n')
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        report['error_traceback']=__import__('traceback').format_exc()[-8000:]
        if resource_cycles and server and server.poll() is None:
            try:
                report['failure_exec_observation']=exec_observation()
            except Exception as observation_error:
                report['failure_observation_error']=type(observation_error).__name__+': '+str(observation_error)
    finally:
        resource_stop.set()
        if resource_thread:
            resource_thread.join(timeout=3)
        if (root/'resources.jsonl').exists():
            report['resource_samples_sha256']=hashlib.sha256((root/'resources.jsonl').read_bytes()).hexdigest()
        for stream in streams:
            try:
                stream.close()
            except OSError:
                pass
        if server:
            server.terminate()
            try:
                server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
            report['server_reaped'] = server.poll() is not None
        if log:
            log.close()
        cleanup_errors = []
        try:
            for c in containers():
                labels = c['Config']['Labels'] or {}
                if labels.get('royak.qualification') == run or (cluster and labels.get('royak.cluster') == cluster
                    and labels.get('royak.node') == node and labels.get('royak.namespace') == ns):
                    command('docker','rm','-f',c['Id'])
            for mount in mounts:
                assert mount == root/'public'/'bind' and os.stat(mount).st_ino == os.stat(root/'runtime').st_ino
                command('umount',str(mount))
            for net in set(command('docker','network','ls','-q').split()) - initial_networks:
                info = json.loads(command('docker','network','inspect',net))[0]
                if removable_fixture_network(info,run,('royak','rk-default','rk-'+ns,'rk-'+other)):
                    command('docker','network','rm',net)
            report['residual_containers'] = command('docker','ps','-aq').split()
            report['owned_mounts_released'] = not any(os.path.ismount(p) for p in mounts)
            report['public_data_sha256'] = hashlib.sha256((root/'public'/'sentinel').read_bytes()).hexdigest()
        except Exception as error:
            cleanup_errors.append(type(error).__name__+': '+str(error))
        report['cleanup_errors'] = cleanup_errors
        report['server_log_sha256'] = hashlib.sha256((root/'server.log').read_bytes()).hexdigest() if (root/'server.log').exists() else None
        report['passed'] = bool(report['passed'] and not cleanup_errors and report.get('residual_containers') == []
            and report.get('owned_mounts_released') and report.get('server_reaped'))
        report['finished_at'] = time.time()
        output.write_text(json.dumps(report,indent=2)+'\n')
        # Scratch, synthetic state, exact server log and fixture evidence are
        # retained; no old volume, image, or evidence tree is deleted.
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--resource-cycles',type=int,choices=[0,12],default=0)
    a = p.parse_args()
    assert not a.output.exists(), 'never overwrite qualification evidence'
    result = collect(a.binary.resolve(),a.output.resolve(),a.resource_cycles)
    print(json.dumps(dict(passed=result['passed'],checks=len(result['checks']),error=result.get('error'))))
    raise SystemExit(0 if result['passed'] else 1)
