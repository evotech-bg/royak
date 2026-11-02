"""Run Rust tests on Linux in a disposable owned container, with zero ignores."""
import argparse
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import time

from run import HERE, ROOT, LABEL, docker, digest, source_inventory, cleanup_build_resources

def test_counts(log):
    # A failed parent test can print a child's captured summary. Preserve the
    # FINAL cargo/test-harness summary, including failures, never a child PASS.
    matches=re.findall(r'^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored',log,re.MULTILINE)
    return dict(zip(('passed','failed','ignored'),map(int,matches[-1]))) if matches else None

def test_binary_path(log):
    paths=set(re.findall(r'^\s*(?:Running|Executable) unittests src/main\.rs \((/target/(?:release|debug)/deps/royak-[0-9a-f]+)\)\s*$',log,re.MULTILINE))
    return next(iter(paths)) if len(paths)==1 else None

def full_test_summary(log):
    matches=re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',log,re.MULTILINE)
    if not matches:return None
    status,*numbers=matches[-1]
    return dict(status=status,**dict(zip(('passed','failed','ignored','measured','filtered_out'),map(int,numbers))))

def full_suite_passed(summary):
    return bool(summary and summary['status']=='ok' and summary['passed']>0 and
        all(summary[key]==0 for key in ('failed','ignored','measured','filtered_out')))

def container_evidence(name, owner):
    value=json.loads(docker('container','inspect','-f',
        '{{json .}}',name))
    assert value['Config'].get('Labels',{}).get(LABEL)==owner,'refusing non-owned test container'
    return dict(id=value['Id'],image=value['Image'],exit_code=value['State']['ExitCode'],
        oom_killed=value['State']['OOMKilled'],memory_bytes=value['HostConfig']['Memory'],
        memory_swap_bytes=value['HostConfig']['MemorySwap'],nano_cpus=value['HostConfig']['NanoCpus'],
        running=value['State']['Running'],restarting=value['State']['Restarting'],dead=value['State']['Dead'])

def phase_finished(state,code,memory_gib):
    return bool(state and code==0 and state['exit_code']==code and
        state['oom_killed'] is False and state['running'] is False and
        state['restarting'] is False and state['dead'] is False and
        state['memory_bytes']==memory_gib*1024**3 and state['nano_cpus']==3*10**9 and
        re.fullmatch(r'sha256:[0-9a-f]{64}',state['image']))

def execution_args(run, volumes, executable, restic, image):
    assert re.fullmatch(r'sha256:[0-9a-f]{64}',image),'exact compiler image ID required before test execution'
    return ['docker','run','--name',run+'-execute','--label',LABEL+'='+run,
        '--cpus','3','--memory','3g',
        '-v',volumes[0]+':/target:ro','-v',volumes[2]+':/work',
        *(['-e','ROYAK_STAGE_RESTIC=/work/restic-tool/restic'] if restic else []),
        '-w','/work',image,executable]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release',action='store_true',help='Use the unchanged normal release profile, not debug')
    parser.add_argument('--output-dir',type=Path,help='New evidence directory; never overwrite an earlier run')
    parser.add_argument('--restic-manifest',type=Path,help='Previously signature-verified pinned restic build manifest; required by real backup adapter tests')
    parser.add_argument('--compile-memory-gib',type=int,choices=(3,4,6,8),default=3,
        help='Compiler-only memory budget; execution remains in a separate unchanged 3GiB container')
    args=parser.parse_args()
    restic=None
    if args.restic_manifest:
        manifest=args.restic_manifest.resolve()
        pin=json.loads(manifest.read_text())
        assert pin['version']=='0.19.1' and pin['signature_fingerprint']=='CF8F18F2844575973F79D4E191A6868BD3F7A907'
        arch=docker('info','--format','{{.Architecture}}').strip()
        platform={'aarch64':'linux_arm64','arm64':'linux_arm64','x86_64':'linux_amd64','amd64':'linux_amd64'}.get(arch)
        assert platform,'unsupported qualification Docker architecture'
        selected=[b for b in pin['builds'] if b['platform']==platform]
        assert len(selected)==1,'manifest must pin the actual Docker architecture'
        binary=Path(selected[0]['path'])
        assert binary.is_absolute() and not binary.is_symlink() and binary.is_file() and os.access(binary,os.X_OK)
        assert digest(binary)==selected[0]['sha256']
        assert digest(manifest.parent/'SHA256SUMS')==pin['checksums_sha256']
        restic=dict(binary=str(binary),binary_sha256=digest(binary),manifest=str(manifest),manifest_sha256=digest(manifest),platform=platform)
    elif (ROOT/'src/backup_engine.rs').exists():
        parser.error('real backup tests require --restic-manifest; missing tool is not a skipped/pass result')
    run="rkq-unit-"+time.strftime("%Y%m%d-%H%M%S")+"-"+secrets.token_hex(3)
    out=args.output_dir.resolve() if args.output_dir else HERE/".runs"/run;out.mkdir(mode=0o700)
    sources={str(p.relative_to(ROOT)):digest(p) for p in source_inventory()}
    volumes=[run+"-target",run+"-cargo",run+"-work"];failure=None;code=None;counts=None;test_binary=None
    compile_code=None;build_state=None;execution_state=None;execution_attempted=False;build_attempted=False;summary=None
    cleanup_verified=False
    compile_args=None;execute_args=None;execution_log=None
    print("Evidence: "+str(out),flush=True)
    (out/'fixture.py').write_bytes(Path(__file__).read_bytes())
    started=time.monotonic()
    try:
        for volume in volumes:
            docker("volume","create","--label",LABEL+"="+run,volume)
            assert docker('volume','inspect','-f','{{index .Labels "'+LABEL+'"}}',volume).strip()==run,'refusing a non-owned unit-test volume'
        tool_args=[]
        tool_setup=''
        if restic:
            tool_args=['-v',restic['binary']+':/qualification-input/restic:ro','-e','ROYAK_STAGE_RESTIC=/work/restic-tool/restic']
            # Copy only the exact read-only pinned artifact into this owned
            # container. Its private executable must be owned by container root.
            tool_setup='mkdir -m 0700 /work/restic-tool; cp /qualification-input/restic /work/restic-tool/restic; chmod 0700 /work/restic-tool/restic; '
        with (out/"cargo-test.log").open("w") as log:
            compile_args=["docker","run","--name",run,"--label",LABEL+"="+run,"--cpus","3","--memory",str(args.compile_memory_gib)+'g',
                "-e","CARGO_BUILD_JOBS=3","-e","CARGO_TARGET_DIR=/target",
                "-v",str(ROOT)+":/src:ro","-v",volumes[0]+":/target","-v",volumes[1]+":/usr/local/cargo","-v",volumes[2]+":/work",
                *tool_args,
                "-w","/work","rust:1.90-alpine","sh","-ec",
                "rustc -Vv\ncargo -V\napk add --no-cache musl-dev build-base cmake perl linux-headers git >/dev/null; cp /src/Cargo.toml /src/Cargo.lock /work/; cp -a /src/src /src/examples /work/; "+tool_setup+"cargo test --locked "+("--release " if args.release else "")+"--bin royak --no-run"]
            build_attempted=True
            result=subprocess.run(compile_args,stdout=log,stderr=subprocess.STDOUT,timeout=900)
            compile_code=result.returncode
        build_state=container_evidence(run,run)
        text=(out/"cargo-test.log").read_text()
        assert phase_finished(build_state,compile_code,args.compile_memory_gib),'Linux test compilation/terminal/resource validation failed before execution; raw log and compiler state retained'
        executed=test_binary_path(text)
        assert executed and executed.startswith('/target/'+('release' if args.release else 'debug')+'/deps/'),'compiled test artifact does not match requested profile'
        if executed:
            assert docker('container','inspect','-f','{{index .Config.Labels "'+LABEL+'"}}',run).strip()==run,'refusing test artifact from non-owned container'
            retained=out/'royak-rust-tests'
            assert not retained.exists()
            docker('cp',run+':'+executed,str(retained))
            assert retained.is_file() and not retained.is_symlink() and retained.stat().st_size<=128*1024**2
            with retained.open('rb') as stream:assert stream.read(4)==b'\x7fELF'
            test_binary=dict(container_path=executed,path=str(retained),sha256=digest(retained),bytes=retained.stat().st_size)
        assert test_binary is not None,'exact executed Linux test binary is unavailable; no complete qualification evidence'
        execute_args=execution_args(run,volumes,executed,restic,build_state['image'])
        execution_log=out/'test-execution.log'
        execution_attempted=True
        with execution_log.open('x') as log:
            result=subprocess.run(execute_args,stdout=log,stderr=subprocess.STDOUT,timeout=900)
            code=result.returncode
        execution_state=container_evidence(run+'-execute',run)
        counts=test_counts(execution_log.read_text())
        summary=full_test_summary(execution_log.read_text())
        assert execution_state['image']==build_state['image'],'compiler and test runner resolved different images'
        assert phase_finished(execution_state,code,3),'unit execution terminal/resource validation failed'
        assert full_suite_passed(summary),"Linux Rust tests failed, omitted checks or did not execute the complete suite"
        assert sources=={str(p.relative_to(ROOT)):digest(p) for p in source_inventory()},"sources changed during Linux unit tests"
        if restic:
            assert digest(Path(restic['binary']))==restic['binary_sha256'] and digest(Path(restic['manifest']))==restic['manifest_sha256'],'pinned restic inputs changed'
    except BaseException as error:failure=type(error).__name__+": "+str(error)
    finally:
        # A subprocess timeout is not a terminal container observation. Capture
        # exact owned phase state before removing it; never turn unknown into0.
        if build_attempted and build_state is None:
            try:build_state=container_evidence(run,run)
            except Exception:pass
        if execution_attempted and execution_state is None:
            try:execution_state=container_evidence(run+'-execute',run)
            except Exception:pass
        if execution_log and execution_log.exists() and counts is None:
            counts=test_counts(execution_log.read_text())
            summary=full_test_summary(execution_log.read_text())
        cleanup_errors=[]
        try:
            if execution_attempted:
                container_evidence(run+'-execute',run)
                docker('container','rm','-f',run+'-execute')
        except Exception as error:
            cleanup_errors.append(str(error))
            failure=(failure+'; ' if failure else '')+'execution cleanup failed: '+str(error)
        try:
            cleanup_build_resources(run,volumes,compile_code is not None)
        except Exception as error:
            cleanup_errors.append(str(error))
            failure=(failure+'; ' if failure else '')+'owned cleanup failed: '+str(error)
        # The shared legacy helper is intentionally best-effort when no exit
        # code exists. A skipped inspect error is not absence or cleanup proof.
        cleanup_verified=not cleanup_errors and compile_code is not None
        report=dict(passed=failure is None,failure=failure,exit_code=code,counts=counts,source_sha256=sources,
            release_profile=args.release,profile_overrides=False,fixture_sha256=digest(out/'fixture.py'),raw_log_sha256=digest(out/'cargo-test.log') if (out/'cargo-test.log').exists() else None,
            owned_resource_prefix=run,
            test_binary=test_binary,
            compile_exit_code=compile_code,compile_memory_gib=args.compile_memory_gib,
            full_test_summary=summary,
            compile_command=compile_args,execution_command=execute_args,
            build_state=build_state,execution_state=execution_state,
            execution_log_sha256=digest(execution_log) if execution_log and execution_log.exists() else None,
            runtime_memory_limit_bytes=3*1024**3,
            owned_cleanup_verified=cleanup_verified,
            restic=restic,
            duration_s=round(time.monotonic()-started,3),scope="Linux Rust tests in owned isolated container; no host Docker socket")
        (out/"unit-report.json").write_text(json.dumps(report,indent=2))
    print(("PASS " if report["passed"] else "FAIL ")+str(counts or failure),flush=True)
    return int(not report["passed"])

if __name__=="__main__":raise SystemExit(main())
