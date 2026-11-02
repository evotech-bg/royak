"""Exact watchdog/control experiments inside one owned Linux VM."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
from pathlib import Path
import socket
import subprocess
import time

CASES=('idle','traffic','direct-exec','direct-detached-exec','watchdog-success','watchdog-failure',
       'watchdog-timeout','watchdog-success-init','watchdog-timeout-init','watchdog-nested-timeout-init',
       'watchdog-background-init','watchdog-concurrent-init')
TRAFFIC='''import http.client
for mode in ("persistent","churn"):
 c=None
 for i in range(100):
  if c is None:c=http.client.HTTPConnection("127.0.0.1",8000,timeout=3)
  c.request("GET","/health");r=c.getresponse();assert r.status==200;r.read()
  if mode=="churn":c.close();c=None
 if c:c.close()
print("200 valid direct HTTP health responses")
'''


def command(*args,timeout=15):
    result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if result.returncode: raise RuntimeError(str(args[:3])+': '+result.stderr[-1500:])
    return result.stdout.strip()


def sample(name):
    value=json.loads(command('docker','exec',name,'python3','/pid-census.py'))
    value['docker_stats']=json.loads(command('docker','stats','--no-stream','--format','{{json .}}',name))
    return value


class DockerConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(2)
        self.sock.connect('/var/run/docker.sock')  # owned guest daemon, never host socket


def api(method,path,body=None):
    connection=DockerConnection('localhost',timeout=2)
    try:
        connection.request(method,path,None if body is None else json.dumps(body),{'Content-Type':'application/json'})
        reply=connection.getresponse();data=reply.read()
        if not 200<=reply.status<300:raise RuntimeError('guest Docker API status '+str(reply.status))
        return json.loads(data) if data else None
    finally:connection.close()


def detached_exec(name,cmd):
    # Match docker::probe_exec's exact create/start/poll contract, not just a
    # foreground shell approximation of the watchdog.
    ident=api('POST','/containers/'+name+'/exec',dict(AttachStdout=False,AttachStderr=False,Cmd=cmd))['Id']
    api('POST','/exec/'+ident+'/start',dict(Detach=True,Tty=False))
    end=time.monotonic()+3
    while time.monotonic()<end:
        info=api('GET','/exec/'+ident+'/json')
        if not info['Running']:return info['ExitCode']
        time.sleep(.05)
    raise TimeoutError('same three-second probe completion deadline exceeded')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--iterations',type=int,default=40)
    args=parser.parse_args()
    script=(args.directory/'watchdog.sh').read_text()
    report=dict(run=args.run_id,watchdog_sha256=hashlib.sha256(script.encode()).hexdigest(),cases=[],cleanup_errors=[])
    for case in CASES:
        name=args.run_id+'-'+case
        row=dict(case=case,name=name,init=case.endswith('-init'),samples=[],exit_codes=[])
        created=False
        try:
            options=['docker','run','-d','--name',name,'--label','royak.qualification='+args.run_id,
                     '--label','royak.diagnostic=pid','--network','none','--memory','64m','--cpus','0.25',
                     '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges','--user','10001:10001',
                     '-e','PYTHONDONTWRITEBYTECODE=1','--tmpfs','/probe-result:rw,noexec,nosuid,size=64k,uid=10001,gid=10001',
                     '-v',str(args.directory/'app.py')+':/app.py:ro',
                     '-v',str(args.directory/'pid_census.py')+':/pid-census.py:ro']
            if row['init']:options.append('--init')
            command(*options,'python:3.13-alpine','python3','-u','/app.py')
            created=True
            for attempt in range(10):
                try:
                    command('docker','exec',name,'python3','-c','import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/health",timeout=3).read()')
                    break
                except RuntimeError:
                    if attempt==9:raise
                    time.sleep(.2)
            time.sleep(.3)
            row['samples'].append(dict(after=0,**sample(name)))
            count=3 if 'timeout' in case or case=='watchdog-concurrent-init' else args.iterations
            if case=='idle':time.sleep(3)
            elif case=='traffic':row['traffic']=command('docker','exec',name,'python3','-c',TRAFFIC,timeout=30)
            else:
                for i in range(count):
                    cmd=['docker','exec',name]
                    if case=='direct-exec':
                        result=subprocess.run(cmd+['true'],capture_output=True,text=True,timeout=8)
                        code=result.returncode
                    else:
                        workload=['true']
                        if case=='watchdog-failure':workload=['false']
                        elif 'nested-timeout' in case:workload=['sh','-c','(sleep 2; echo late > /probe-result/late) & wait']
                        elif 'timeout' in case:workload=['sleep','3']
                        elif case=='watchdog-background-init':workload=['sh','-c','(trap "" TERM; sleep 2; echo late > /probe-result/late) & exit 0']
                        probe=['true'] if case=='direct-detached-exec' else ['/bin/sh','-c',script,'royak-probe','1',*workload]
                        if case=='watchdog-concurrent-init':
                            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                                long=pool.submit(detached_exec,name,['/bin/sh','-c',script,'royak-probe','1','sleep','3'])
                                short=pool.submit(detached_exec,name,['/bin/sh','-c',script,'royak-probe','1','sleep','.3'])
                                if (short.result(),long.result())!=(0,137):raise RuntimeError('probe process groups are not isolated')
                            code=0
                        else:code=detached_exec(name,probe)
                    row['exit_codes'].append(code)
                    expected=137 if 'timeout' in case else 1 if case=='watchdog-failure' else 0
                    if code!=expected:raise RuntimeError('Unexpected probe/control exit '+str(code))
                    if (i+1)%10==0:row['samples'].append(dict(after=i+1,**sample(name)))
            time.sleep(2)
            row['samples'].append(dict(after=count if case not in ('idle','traffic') else case,**sample(name)))
            row['zombie_delta']=len(row['samples'][-1]['zombies'])-len(row['samples'][0]['zombies'])
            row['task_delta']=row['samples'][-1]['tasks']-row['samples'][0]['tasks']
            row['late_write_absent']=command('docker','exec',name,'sh','-c','test ! -e /probe-result/late; echo $?')=='0'
            row['application_healthy']=command('docker','exec',name,'python3','-c','import urllib.request; print(urllib.request.urlopen("http://127.0.0.1:8000/health",timeout=3).status)')=='200'
            row['state']=json.loads(command('docker','inspect','-f','{{json .State}}',name))
            row['completed']=row['state']['Running'] and not row['state']['OOMKilled']
            # The no-init hard-kill case deliberately proves why an application
            # PID 1 is insufficient. It is a negative control, never a release pass.
            row['negative_control']=case=='watchdog-timeout'
            row['regression_passed']=(row['completed'] and row['application_healthy'] and row['late_write_absent'] and
                (row['zombie_delta']>0 if row['negative_control'] else row['zombie_delta']==0 and row['task_delta']==0))
        except Exception as error:
            row.update(completed=False,error=type(error).__name__+': '+str(error))
        finally:
            if created:
                try:
                    owner=command('docker','inspect','-f','{{index .Config.Labels "royak.qualification"}}',name)
                    if owner!=args.run_id:raise RuntimeError('Container ownership changed')
                    command('docker','rm','-f',name)
                except Exception as error:report['cleanup_errors'].append(str(error))
        report['cases'].append(row)
    report['completed']=all(r['completed'] for r in report['cases']) and not report['cleanup_errors']
    report['regression_passed']=report['completed'] and all(r.get('regression_passed') for r in report['cases'])
    print(json.dumps(report))


if __name__=='__main__':main()
