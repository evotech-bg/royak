"""Pure result parsing only; does not build, start Docker or change resources."""
import unittest
from linux_unit import test_counts,test_binary_path,execution_args,full_test_summary,full_suite_passed,phase_finished


class LinuxUnitCounts(unittest.TestCase):
    def test_success_is_explicit(self):
        self.assertEqual(test_counts('test result: ok. 376 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n'),
                         dict(passed=376,failed=0,ignored=0))

    def test_final_failure_cannot_be_replaced_by_embedded_child_success(self):
        raw='test result: ok. 1 passed; 0 failed; 0 ignored; 99 filtered out\nnoise\ntest result: FAILED. 374 passed; 2 failed; 0 ignored; 0 filtered out\n'
        self.assertEqual(test_counts(raw),dict(passed=374,failed=2,ignored=0))

    def test_missing_summary_is_unknown_and_ignored_count_is_preserved(self):
        self.assertIsNone(test_counts('compiler failed before any test ran'))
        self.assertEqual(test_counts('test result: ok. 1 passed; 0 failed; 3 ignored;'),dict(passed=1,failed=0,ignored=3))

    def test_exact_cargo_test_executable_is_pinned(self):
        self.assertEqual(test_binary_path('     Running unittests src/main.rs (/target/release/deps/royak-ab19)\n'),'/target/release/deps/royak-ab19')
        self.assertEqual(test_binary_path(' Running unittests src/main.rs (/target/debug/deps/royak-ab19)\n'),'/target/debug/deps/royak-ab19')
        self.assertEqual(test_binary_path(' Executable unittests src/main.rs (/target/release/deps/royak-ab19)\n'),'/target/release/deps/royak-ab19')

    def test_missing_foreign_or_ambiguous_test_binary_is_not_evidence(self):
        self.assertIsNone(test_binary_path('compiler failed'))
        self.assertIsNone(test_binary_path('Running unittests src/main.rs (/etc/passwd)\n'))
        self.assertIsNone(test_binary_path('Running unittests src/main.rs (/target/release/deps/royak-ab19)\nRunning unittests src/main.rs (/target/release/deps/royak-cd29)\n'))

    def test_separate_execution_retains_cpu_memory_and_readonly_binary(self):
        image='sha256:'+'a'*64
        args=execution_args('rkq-unit-exact',['owned-target','owned-cargo','owned-work'],
            '/target/release/deps/royak-ab19',True,image)
        self.assertEqual(args[args.index('--memory')+1],'3g')
        self.assertEqual(args[args.index('--cpus')+1],'3')
        self.assertIn('owned-target:/target:ro',args)
        self.assertIn('owned-work:/work',args)
        self.assertNotIn('owned-cargo:/usr/local/cargo',args)
        self.assertNotIn('/var/run/docker.sock',str(args))
        self.assertEqual(args[-1],'/target/release/deps/royak-ab19')
        self.assertEqual(args[-2],image)
        with self.assertRaises(AssertionError):
            execution_args('run',['a','b','c'],'/target/release/deps/royak-ab19',True,'rust:1.90-alpine')

    def test_full_suite_rejects_zero_filtered_measured_failed_or_ignored(self):
        good='test result: ok. 460 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 43s\n'
        self.assertTrue(full_suite_passed(full_test_summary(good)))
        for bad in (good.replace('460 passed','0 passed'),good.replace('0 failed','1 failed'),
                    good.replace('0 ignored','1 ignored'),good.replace('0 measured','1 measured'),
                    good.replace('0 filtered out','1 filtered out'),good.replace('ok.','FAILED.'),'missing'):
            self.assertFalse(full_suite_passed(full_test_summary(bad)))

    def test_terminal_phase_requires_exact_resources_and_actual_success(self):
        state=dict(exit_code=0,oom_killed=False,running=False,restarting=False,dead=False,
            memory_bytes=6*1024**3,nano_cpus=3*10**9,image='sha256:'+'a'*64)
        self.assertTrue(phase_finished(state,0,6))
        self.assertFalse(phase_finished(state,0,3))
        for key,bad in [('exit_code',101),('oom_killed',True),('running',True),('restarting',True),
                        ('dead',True),('memory_bytes',0),('nano_cpus',0),('image','rust:1.90-alpine')]:
            self.assertFalse(phase_finished(dict(state,**{key:bad}),0,6),key)
        self.assertFalse(phase_finished(state,101,6))


if __name__=='__main__':
    unittest.main()
