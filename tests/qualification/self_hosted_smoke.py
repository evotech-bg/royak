"""Small trusted-branch runner smoke; explicitly NOT build/release qualification."""
import argparse
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def binding(root, env):
    workspace = Path(env['GITHUB_WORKSPACE'])
    assert workspace.is_absolute() and workspace.resolve() == workspace
    name = 'royak-smoke-' + env['GITHUB_RUN_ID'] + '-' + env['GITHUB_RUN_ATTEMPT']
    assert env['GITHUB_RUN_ID'].isdigit() and env['GITHUB_RUN_ATTEMPT'].isdigit()
    assert root == workspace / name and root.resolve() == root and not root.is_symlink()
    assert (root / '.git').is_dir() and not (root / '.git').is_symlink()
    return dict(run_id=env['GITHUB_RUN_ID'], attempt=env['GITHUB_RUN_ATTEMPT'],
                sha=env['GITHUB_SHA'], root=str(root))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--cleanup', action='store_true')
    args = p.parse_args()
    root = args.root
    expected = binding(root, os.environ)
    marker = root / '.royak-smoke-owner.json'
    if args.cleanup:
        # A failed/partial checkout without our marker is retained, not deleted.
        if not marker.exists():
            print('No ownership marker: no cleanup performed.')
            return
        assert not marker.is_symlink() and marker.stat().st_nlink == 1
        assert json.loads(marker.read_text()) == expected
        shutil.rmtree(root)
        print('Removed only the exact marked smoke checkout.')
        return
    assert sys.version_info >= (3, 11)
    assert shutil.disk_usage(root).free >= 1024**3, 'Need1GiB for lightweight checks; no build allowed.'
    actual = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    assert actual == expected['sha'], 'Checkout must match the exact workflow commit.'
    with marker.open('x') as stream:
        json.dump(expected, stream)
    files = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z'], text=True).split('\0')
    py = [root / f for f in files if f.endswith('.py')]
    shells = [root / f for f in files if f.endswith('.sh')]
    for path in py:
        ast.parse(path.read_text(), filename=str(path))
    for path in shells:
        subprocess.run(['bash', '-n', str(path)], check=True)
    subprocess.run(['node', '--check', str(root / 'src/dashboard-topology.js')], check=True)
    subprocess.run(['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'],
                   cwd=root, check=True, stdout=subprocess.DEVNULL)
    # Pure local scope/capacity guards; no guest, Docker, network, restic or raw device.
    subprocess.run([sys.executable, '-B', '-m', 'unittest', '-q',
                    'test_linstor_data_disks', 'test_linstor_pool_prepare',
                    'test_linstor_data_capacity'], cwd=root / 'tests/qualification/parallels', check=True)
    subprocess.run([sys.executable, '-B', '-m', 'unittest', '-q', 'test_self_hosted_smoke'],
                   cwd=root / 'tests/qualification', check=True)
    result = dict(passed=True, sha=actual, python_files=len(py), shell_files=len(shells),
                  build_started=False, Docker_or_VM_operation=False, release_qualified=False)
    print(json.dumps(result))
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as stream:
        stream.write('## Self-hosted runner smoke only\n\n')
        stream.write('Exact commit: `' + actual + '`\n\n')
        stream.write('Syntax, manifest and pure local guards passed. No compilation, Docker/VM tests, '
                     'deployment or full release qualification was performed.\n')


if __name__ == '__main__':
    main()
