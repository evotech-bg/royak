"""Real BusyBox/Dash watchdog matrix in exact owned, isolated containers."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]


def run(*args,check=True):
    return subprocess.run(['docker',*args],capture_output=True,text=True,check=check,timeout=15)


def census(name):
    # Builtins only; exclude the collector itself. Fixture comm names have no
    # whitespace. No argv/environment/output from the application is captured.
    script='''count=0; zombies=0
for f in /proc/[0-9]*/stat; do
 read -r pid comm state rest < "$f" 2>/dev/null || continue
 [ "$pid" = "$$" ] && continue
 count=$((count+1))
 [ "$state" != Z ] || zombies=$((zombies+1))
done
printf "%s %s\\n" "$count" "$zombies"
'''
    processes,zombies=map(int,run('exec',name,'/bin/sh','-c',script).stdout.split())
    return dict(processes=processes,zombies=zombies)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',action='append',choices=['alpine:3.22','python:3.13-slim'])
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    watchdog=ROOT/'src/probe-watchdog.sh'
    digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
    before=digest(watchdog)
    ident='rkq-watchdog-'+secrets.token_hex(5)
    report=dict(run=ident,watchdog_sha256=before,fixture_sha256=digest(Path(__file__)),cases=[],cleanup_errors=[],
                scope='real container shell/process cleanup, not full Debian cluster qualification')
    for image in args.image or ['alpine:3.22','python:3.13-slim']:
        for init in (False,True):
            name=ident+'-'+str(len(report['cases']))
            row=dict(image=image,init=init,passed=False,command_durations_s=[])
            created=False
            try:
                row['image_id']=run('image','inspect','-f','{{.Id}}',image).stdout.strip()
                run('create','--name',name,'--label','royak.qualification='+ident,'--init='+str(init).lower(),
                    '--network','none','--memory','64m','--cpus','0.25','--user','10001:10001','--read-only',
                    '--cap-drop','ALL','--security-opt','no-new-privileges:true','--tmpfs','/tmp:rw,mode=1777',
                    '-v',str(watchdog)+':/watchdog.sh:ro',image,'sleep','3600')
                created=True
                run('start',name)
                row['shell']=run('exec',name,'readlink','-f','/bin/sh').stdout.strip()
                row['baseline']=census(name)
                def probe(seconds,*cmd):
                    return run('exec',name,'/bin/sh','/watchdog.sh',str(seconds),*cmd,check=False)
                for expected in (0,7):
                    for _ in range(40):
                        start=time.monotonic();result=probe(2,'sh','-c','exit '+str(expected));elapsed=time.monotonic()-start
                        row['command_durations_s'].append(elapsed)
                        assert result.returncode==expected,(result.returncode,result.stderr)
                        assert elapsed<1.5,'successful/failed probe waited for its two-second timer'
                    assert census(name)==row['baseline'],'timer descendants accumulated without init'
                assert probe(2,'does-not-exist-royak').returncode==127
                if init:
                    durations=[]
                    for command in ('sleep 3; touch /tmp/late-write','(sleep 3; touch /tmp/grandchild-write) & wait'):
                        start=time.monotonic();result=probe(1,'sh','-c',command);elapsed=time.monotonic()-start
                        assert result.returncode==137 and elapsed<3,(result.returncode,elapsed,result.stderr)
                        durations.append(elapsed)
                    row['timeout_durations_s']=durations
                    time.sleep(3.2)
                    run('exec',name,'sh','-c','test ! -e /tmp/late-write && test ! -e /tmp/grandchild-write')
                result=run('exec','-e','PATH=/nonexistent',name,'/bin/sh','/watchdog.sh','1','/bin/touch','/tmp/unsafe-fallback',check=False)
                assert result.returncode==125
                run('exec',name,'test','!','-e','/tmp/unsafe-fallback')
                row['final']=census(name)
                assert row['final']==row['baseline'] and row['final']['zombies']==0
                assert run('inspect','-f','{{.State.Running}}',name).stdout.strip()=='true'
                row['passed']=True
            except Exception as error:row['failure']=type(error).__name__+': '+str(error)
            finally:
                if created:
                    try:
                        assert run('inspect','-f','{{index .Config.Labels "royak.qualification"}}',name).stdout.strip()==ident
                        run('rm','-f',name)
                    except Exception as error:report['cleanup_errors'].append(str(error))
            report['cases'].append(row)
            print(('PASS ' if row['passed'] else 'FAIL ')+image+' init='+str(init),flush=True)
    report['source_unchanged']=before==digest(watchdog)
    report['passed']=all(r['passed'] for r in report['cases']) and not report['cleanup_errors'] and report['source_unchanged']
    if args.output:args.output.write_text(json.dumps(report,indent=2))
    print('PASS portable watchdog matrix' if report['passed'] else 'FAIL portable watchdog matrix',flush=True)
    return int(not report['passed'])


if __name__=='__main__':raise SystemExit(main())
