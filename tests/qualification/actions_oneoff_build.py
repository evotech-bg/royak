"""One approved12GiB Linux build via Actions on the existing owned Mac lab.

Reuses the immutable original-owner-safe local builder; never stops foreign
containers, retries, changes fat-LTO/CPU/deadline/size or claims the6GiB gate.
This intentionally refuses on a runner without the pinned lab harness.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib

LAB = Path('/Users/ivogergov/Projects/orinetes/tests/qualification/.runs/rkq-storage-20261030')
HELPERS = LAB / 'agent-normal-main-n2-server-recipes-v1'
BUILDER = LAB / 'root-approved12g-release116-v1/safe_server_build_12g.py'
PINS = {BUILDER: 'aa31effe3f4b787685d63746287566322fdcb76f9cdd328d1bd4e9bd68b856c1',
        HELPERS/'owner_registry.py': 'b53206032ba86a2c9bf10478d35dcbe7313f2ac2a6de31582cc6a4ef5cff3404',
        HELPERS/'normal_server_descriptor_equality.py': '046e13b1c520010bf875d14d886af9824522c9208b5dd3b0fca424bcb5664c32',
        LAB/'owned-mounted-v10-source-50ef2af10f2e4d048ec446a95d45c6b0/tests/qualification/host_capacity.py':
        '3ee1621887b9ccb2b8648982aefa34825709ead70a2f1263d05c9219937586db'}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream,'sha256').hexdigest()


def inventory(root):
    files=[root/'Cargo.toml',root/'Cargo.lock',*sorted(p for p in (root/'src').rglob('*')
           if p.is_file() and p.suffix in {'.rs','.html','.js','.css','.sh'})]
    assert all(p.resolve()==p for p in files)
    return {str(p.relative_to(root)):sha(p) for p in files}


def main():
    assert sys.argv[1:]==['--one-approved-actions-build']
    assert os.environ['GITHUB_REPOSITORY']=='evotech-bg/royak'
    assert os.environ['GITHUB_REF']=='refs/heads/fix/cluster-census-federation'
    assert os.environ['RUNNER_OS']=='macOS' and os.environ['RUNNER_ARCH']=='ARM64'
    root=Path.cwd();assert root.resolve()==root
    actual=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    assert actual==os.environ['GITHUB_SHA']
    out=root/'.oneoff-build';out.mkdir(mode=0o700)
    report=dict(passed=False,commit=actual,compiler_started=False,original6GiB_gate_passed=False,
                compiler_exception_gib=12,CPU=3,deadline_s=1800,size_limit_bytes=10*1024**2,
                production_or_endurance_qualified=False,one_attempt_only=True)
    builder=None;began=time.monotonic()
    try:
        # No resources or compiler are created until these read-only gates pass.
        daemon=subprocess.check_output(['docker','info','--format','{{.ID}}'],text=True).strip()
        assert daemon=='01bc68c9-23e4-49d7-87fc-9f6314e8a949','Not the approved owned build daemon.'
        memory=int(subprocess.check_output(['docker','info','--format','{{.MemTotal}}'],text=True))
        active=subprocess.check_output(['docker','ps','-q'],text=True).split()
        report.update(daemon_memory_bytes=memory,foreign_running_container_count=len(active))
        assert memory>=13*1024**3,'Docker requires13GiB capacity for the approved12GiB compiler.'
        assert not active,'PRELAUNCH REFUSED: other running containers; nothing stopped or created.'
        assert subprocess.check_output(['docker','info','--format','{{.Architecture}}'],text=True).strip() in ['aarch64','arm64']
        assert shutil.disk_usage(root).free>=40*1024**3,'Original40GiB build reserve required.'
        assert tomllib.loads((root/'Cargo.toml').read_text())['profile']['release']==dict(
            **{'opt-level':3,'lto':True,'codegen-units':1,'strip':True})
        for path,pin in PINS.items():assert sha(path)==pin,str(path)
        sys.path.insert(0,str(HELPERS))
        spec=importlib.util.spec_from_file_location('oneoff_original_builder',BUILDER)
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        sources=inventory(root);report['source_sha256']=sources
        # Durable one-attempt intent. An earlier preflight refusal did NOT launch
        # the compiler; this new Actions intent must never overwrite prior proof.
        intent=LAB/'root-approved12g-release116-v1/ACTIONS-ONE-ATTEMPT-INTENT.json'
        with intent.open('x') as stream:
            json.dump(dict(commit=actual,run_id=os.environ['GITHUB_RUN_ID'],
                           run_attempt=os.environ['GITHUB_RUN_ATTEMPT'],compiler_memory_gib=12),stream)
            stream.flush();os.fsync(stream.fileno())
        binary=out/'royak-linux-aarch64'
        value=builder.build_normal(out,root,binary,sources)
        report['build']=value
        report['compiler_started']=bool(builder.RESOURCE_OWNER and builder.RESOURCE_OWNER.compiler_launch_may_have_started)
        assert inventory(root)==sources,'Source changed during build.'
        assert value['build_completed'] and value['owned_build_cleanup_verified']
        raw=binary.read_bytes()[:20]
        assert raw[:6]==b'\x7fELF\x02\x01' and int.from_bytes(raw[18:20],'little')==183
        report.update(binary_sha256=sha(binary),binary_bytes=binary.stat().st_size)
        assert binary.stat().st_size<=10*1024**2,'Compiled binary exceeds original10MiB gate.'
        (out/'SHA256SUMS').write_text(report['binary_sha256']+'  '+binary.name+'\n')
        report['passed']=True
    except BaseException as error:
        report['failure']=type(error).__name__+': '+str(error)
        if builder is not None:
            report['compiler_started']=bool(builder.RESOURCE_OWNER and builder.RESOURCE_OWNER.compiler_launch_may_have_started)
            if builder.OWNERS.unknown or (builder.RESOURCE_OWNER is not None and
                    builder.RESOURCE_OWNER.effects_started and not builder.RESOURCE_OWNER.all_absent):
                builder.hold_unknown(error,out,'actions-build')
    report['elapsed_seconds']=time.monotonic()-began
    with (out/'report.json').open('x') as stream:json.dump(report,stream,indent=2)
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as stream:
        stream.write('## One approved12GiB Linux build\n\n'+json.dumps({k:v for k,v in report.items()
            if k in ['passed','failure','compiler_started','binary_bytes','elapsed_seconds']})+'\n\n')
        stream.write('Not the original6GiB build gate, Linux test suite, storage/endurance or production qualification.\n')
    print(json.dumps({k:v for k,v in report.items() if k!='source_sha256' and k!='build'}))
    return int(not report['passed'])


if __name__=='__main__':
    raise SystemExit(main())
