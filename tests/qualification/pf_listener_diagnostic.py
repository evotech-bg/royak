"""One owned network-none BusyBox listener observation; no application server."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time

from pod_access_e2e import tcp_listener_present

IMAGE='busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'
EXPECTED='sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    assert not args.output.exists()
    def call(*command):return subprocess.run(command,capture_output=True,text=True,timeout=30)
    inspected=call('docker','image','inspect',IMAGE)
    if inspected.returncode:
        pulled=call('docker','pull',IMAGE)
        assert pulled.returncode==0,pulled.stderr
        inspected=call('docker','image','inspect',IMAGE)
    image=json.loads(inspected.stdout)[0]
    assert image['Id']==EXPECTED
    owner='rkq-listener-'+secrets.token_hex(6)
    result=dict(passed=False,owner=owner,image=image['Id'],tables={},cleanup_verified=False,
        scope='one fresh owned network-none container; TCP listener predicate diagnostic, not stale-forward acceptance')
    created=None
    try:
        process=call('docker','run','-d','--name',owner,'--label','royak.qualification='+owner,
            '--network','none',IMAGE,'sh','-c','mkdir -p /capture; exec nc -l -p 8080 > /capture/received')
        assert process.returncode==0,process.stderr
        created=process.stdout.strip()
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            info=json.loads(call('docker','container','inspect',created).stdout)[0]
            assert info['Config']['Labels'].get('royak.qualification')==owner and info['Image']==EXPECTED
            result['state']=info['State']
            for filename in ('tcp','tcp6'):
                value=call('docker','exec',created,'cat','/proc/net/'+filename)
                assert value.returncode==0,value.stderr
                result['tables'][filename]=value.stdout
            result['old_ipv4_only_observed']=tcp_listener_present([result['tables']['tcp']],8080)
            result['both_families_observed']=tcp_listener_present(list(result['tables'].values()),8080)
            if result['both_families_observed']:break
            time.sleep(.05)
        result['processes']=call('docker','top',created,'-eo','pid,ppid,comm').stdout
        result['passed']=info['State']['Running'] and result['both_families_observed']
    finally:
        if created:
            value=call('docker','container','inspect',created)
            info=json.loads(value.stdout)[0]
            assert info['Id']==created and info['Config']['Labels'].get('royak.qualification')==owner
            removed=call('docker','container','rm','-f',created)
            absent=call('docker','container','inspect',created)
            result['cleanup_verified']=removed.returncode==0 and absent.returncode!=0 and 'No such container' in absent.stderr
        result['passed']=bool(result['passed'] and result['cleanup_verified'])
        result['fixture_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        with args.output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(result,indent=2))
    return int(not result['passed'])

if __name__=='__main__':raise SystemExit(main())
