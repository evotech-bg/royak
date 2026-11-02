"""Real CLI exit status checks with no Docker daemon, credentials or network."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():parser.error('refusing to overwrite earlier evidence')
    rows=[]
    with tempfile.TemporaryDirectory(prefix='rkq-cli-exit-') as root:
        env=dict(PATH=os.environ.get('PATH',''),HOME=root,ROYAK_NO_DOCKER='1',
                 ROYAK_STATE=str(Path(root)/'state.json'),ROYAK_DATA_DIR=str(Path(root)/'data'),
                 DOCKER_HOST='unix://'+str(Path(root)/'missing-docker.sock'))
        no_docker_flag={k:v for k,v in env.items() if k!='ROYAK_NO_DOCKER'}
        no_docker_flag['PATH']=''  # no curl/registry call is possible
        cases=[
            ('help succeeds',['--help'],lambda r:r.returncode==0,env),
            ('invalid command fails',['invalid-qualification-command'],lambda r:r.returncode!=0,env),
            ('unknown runtime is rejected',['pull','--runtime','unknown-runtime','rkq-invalid:qualification'],
             lambda r:r.returncode==2,env),
            ('failed pull is not acknowledged as success',['pull','--runtime','docker','rkq-invalid:qualification'],
             lambda r:r.returncode!=0 and 'pull failed' in r.stderr,env),
        ]
        for runtime in ('neuropod','light','cri'):
            cases.append((runtime+' pull does not require Docker or hide failure',
                          ['pull','--runtime',runtime,'rkq-invalid:qualification'],
                          lambda r:r.returncode!=0 and 'pull failed' in r.stderr and 'Docker is not running' not in r.stderr,
                          no_docker_flag))
        for name,command,ok,environment in cases:
            result=subprocess.run([str(args.binary.resolve()),*command],env=environment,capture_output=True,text=True,timeout=10)
            rows.append(dict(name=name,passed=ok(result),exit_code=result.returncode))
    report=dict(passed=all(r['passed'] for r in rows),checks=rows,
                binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                fixture_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                scope='real CLI processes against a missing private socket; no Docker daemon, credentials or network')
    args.output.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return int(not report['passed'])


if __name__=='__main__':raise SystemExit(main())
