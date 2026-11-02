import os
from pathlib import Path
import tempfile
import unittest
import self_hosted_smoke as s


class SmokeOwnership(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name).resolve()
        self.root = self.workspace / 'royak-smoke-123-1'
        self.root.mkdir()
        (self.root / '.git').mkdir()
        self.env = dict(GITHUB_WORKSPACE=str(self.workspace), GITHUB_RUN_ID='123',
                        GITHUB_RUN_ATTEMPT='1', GITHUB_SHA='a'*40)

    def test_exact_checkout(self):
        self.assertEqual(s.binding(self.root,self.env)['run_id'],'123')

    def test_repository_root_never_authorized(self):
        with self.assertRaises(AssertionError):
            s.binding(self.workspace,self.env)

    def test_other_run_refused(self):
        env=dict(self.env,GITHUB_RUN_ID='124')
        with self.assertRaises(AssertionError):
            s.binding(self.root,env)

    def test_path_injection_refused(self):
        env=dict(self.env,GITHUB_RUN_ID='../123')
        with self.assertRaises(AssertionError):
            s.binding(self.root,env)

    def test_symlinked_root_refused(self):
        actual=self.workspace/'other';self.root.rename(actual);self.root.symlink_to(actual)
        with self.assertRaises(AssertionError):
            s.binding(self.root,self.env)

    def test_symlinked_git_refused(self):
        (self.root/'.git').rmdir();(self.workspace/'foreign-git').mkdir()
        (self.root/'.git').symlink_to(self.workspace/'foreign-git')
        with self.assertRaises(AssertionError):
            s.binding(self.root,self.env)


if __name__=='__main__':
    unittest.main()
