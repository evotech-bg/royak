import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import actions_oneoff_build as build


class PrelaunchSafety(unittest.TestCase):
    def refused(self, memory, active, daemon='01bc68c9-23e4-49d7-87fc-9f6314e8a949'):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();old=Path.cwd()
            env=dict(GITHUB_REPOSITORY='evotech-bg/royak',
                     GITHUB_REF='refs/heads/fix/cluster-census-federation',
                     GITHUB_SHA='a'*40,RUNNER_OS='macOS',RUNNER_ARCH='ARM64',
                     GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',
                     GITHUB_STEP_SUMMARY=str(root/'summary.md'))
            calls=[]
            def command(args,**kwargs):
                calls.append(args)
                if args[0]=='git':return 'a'*40+'\n'
                if args[-1]=='{{.ID}}':return daemon+'\n'
                if args[-1]=='{{.MemTotal}}':return str(memory)+'\n'
                if args==['docker','ps','-q']:return active
                raise AssertionError('Unexpected command beyond refused preflight')
            try:
                os.chdir(root)
                with patch.dict(os.environ,env,clear=True),patch('sys.argv',['build','--one-approved-actions-build']),patch.object(build.subprocess,'check_output',side_effect=command),contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(build.main(),1)
                report=json.loads((root/'.oneoff-build/report.json').read_text())
                self.assertFalse(report['compiler_started'])
                self.assertFalse(report['passed'])
                self.assertFalse(any('run' in args or 'create' in args or 'rm' in args for args in calls))
                return report
            finally:os.chdir(old)

    def test_foreign_containers_refuse_without_creation(self):
        r=self.refused(16*1024**3,'foreign-a\nforeign-b\n')
        self.assertEqual(r['foreign_running_container_count'],2)
        self.assertIn('PRELAUNCH REFUSED',r['failure'])

    def test_insufficient_daemon_memory_refuses(self):
        self.assertIn('13GiB',self.refused(12*1024**3,'')['failure'])

    def test_wrong_daemon_refuses(self):
        self.assertIn('approved owned build daemon',self.refused(16*1024**3,'','other')['failure'])


if __name__=='__main__':unittest.main()
