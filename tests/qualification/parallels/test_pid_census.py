import tempfile
import unittest
from pathlib import Path
from unittest import mock
import hashlib
import importlib.util

import pid_census as subject
from pid_census import census, thread_census


class CensusTests(unittest.TestCase):
    def test_thread_id_lifetime_cpu_and_wait_channel_without_payload_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            process=Path(directory);(process/'task').mkdir()
            for tid, start, cpu, comm, state, wait in [(21, '100', 2, 'tokio-rt-worker', 'S', 'futex_wait_queue'),
                                                       (22, '200', 10, 'pool (worker)', 'R', '0')]:
                p=process/'task'/str(tid);p.mkdir()
                fields=[state,'1','9','9',*(['0']*7),str(cpu),'1',*(['0']*6),start]
                (p/'stat').write_text(f'{tid} ({comm}) '+ ' '.join(fields))
                (p/'wchan').write_text(wait)
            (process/'task'/'23').mkdir()  # exited during this sample
            data=thread_census(process)
            self.assertEqual(data['observed'],2)
            self.assertEqual(data['exited_during_sample'],[23])
            self.assertEqual(data['errors'],[])
            self.assertEqual(data['threads'][1],dict(tid=22,start_ticks='200',cpu_ticks=11,utime_ticks=10,stime_ticks=1,comm='pool (worker)',state='R',wait_channel='0'))
            self.assertNotIn('argv',data['threads'][0])

    def test_process_state_parent_identity_and_threads_without_argv_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for pid,state,threads in ((1,'S',2),(9,'Z',1),(10,'R',1)):
                process=root/str(pid);process.mkdir();(process/'task').mkdir()
                for tid in range(threads):(process/'task'/str(pid+tid)).mkdir()
                # Linux stat fields after comm: state, PPID, PGRP, session,
                # ... field 22 (starttime). Comm may itself contain parentheses.
                fields=[state,'1','9','9',*(['0']*15),'123']
                (process/'stat').write_text(f'{pid} (sh (probe)) '+ ' '.join(fields))
            (root/'11').mkdir()  # exited midway through this sample
            value=census(root,exclude_pid=10)
            self.assertEqual(value['tasks'],3)
            self.assertEqual(value['states'],{'S':1,'Z':1})
            self.assertEqual(value['zombies'][0],dict(pid=9,comm='sh (probe)',state='Z',ppid=1,pgrp=9,session=9,start_ticks='123',threads=1))
            self.assertNotIn('argv',value['processes'][0])


def stat_data(tid=21, start='100', user=2, kernel=1, comm='probe (worker)', state='S'):
    fields=[state,'1','9','9',*(['0']*7),str(user),str(kernel),*(['0']*6),start]
    return f'{tid} ({comm}) ' + ' '.join(fields)


class PinnedCensusTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.process=Path(self.directory.name)
        (self.process/'task').mkdir()
        (self.process/'stat').write_text(stat_data())
        for tid,start in ((21,'100'),(22,'200')):
            task=self.process/'task'/str(tid);task.mkdir()
            (task/'stat').write_text(stat_data(tid,start))
            (task/'wchan').write_text('futex_wait_queue')

    def collect(self):
        return thread_census(self.process,expected_pid=21,expected_start_ticks='100')

    def categories(self,value):
        return {row['error'] for row in value['errors']}

    def test_pinned_complete_records_both_process_and_task_boundaries(self):
        value=self.collect()
        self.assertTrue(value['process_identity_consistent'])
        self.assertTrue(value['task_set_consistent'])
        self.assertEqual(value['observed'],2)
        self.assertEqual(value['errors'],[])
        self.assertEqual(value['task_ids_before'],[21,22])
        self.assertFalse(value['atomic_continuous_coverage_proven'])

    def test_old_unpinned_call_is_explicitly_not_identity_proof(self):
        value=thread_census(self.process)
        self.assertFalse(value['process_identity_pinned'])
        self.assertIsNone(value['process_identity_consistent'])

    def test_invalid_expected_pair_and_bool_pid_refuse(self):
        for kwargs in ({'expected_pid':True,'expected_start_ticks':'100'},
                       {'expected_pid':21}, {'expected_start_ticks':'100'}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                thread_census(self.process,**kwargs)

    def test_missing_process_is_unavailable_not_zero_total(self):
        (self.process/'stat').unlink()
        value=self.collect()
        self.assertIn('FileNotFoundError',self.categories(value))
        self.assertIsNone(value['process_before'])
        self.assertIsNone(value['task_ids_before'])
        self.assertTrue(value['observed_is_recorded_rows_not_total'])

    def test_wrong_original_process_start_refuses_before_tasks(self):
        (self.process/'stat').write_text(stat_data(start='300'))
        value=self.collect()
        self.assertIn('ProcessIdentityBeforeMismatch',self.categories(value))
        self.assertIsNone(value['task_ids_before'])

    def test_process_reuse_after_collection_retains_rows_and_error(self):
        original=subject._bounded_text;reads=0
        def read(path,maximum):
            nonlocal reads
            if path==self.process/'stat':
                reads+=1
                if reads==2:return stat_data(start='300')
            return original(path,maximum)
        with mock.patch.object(subject,'_bounded_text',side_effect=read):value=self.collect()
        self.assertEqual(value['observed'],2)
        self.assertIn('ProcessIncarnationChanged',self.categories(value))
        self.assertFalse(value['process_identity_consistent'])

    def test_tid_reuse_after_wait_channel_is_not_same_incarnation(self):
        original=subject._bounded_text;reads=0
        def read(path,maximum):
            nonlocal reads
            if path==self.process/'task/22/stat':
                reads+=1
                if reads==2:return stat_data(22,'201')
            return original(path,maximum)
        with mock.patch.object(subject,'_bounded_text',side_effect=read):value=self.collect()
        self.assertIn('ThreadIncarnationChanged',self.categories(value))
        self.assertEqual(value['threads'][1]['start_ticks'],'200')

    def test_task_set_change_is_explicit_not_a_complete_empty_census(self):
        with mock.patch.object(subject,'_task_ids',side_effect=[[21,22],[21]]):value=self.collect()
        self.assertIn('TaskSetChanged',self.categories(value))
        self.assertFalse(value['task_set_consistent'])
        self.assertEqual(value['observed'],2)

    def test_missing_main_task_is_explicit(self):
        with mock.patch.object(subject,'_task_ids',return_value=[22]):value=self.collect()
        self.assertIn('MainTaskMissingFromDirectory',self.categories(value))

    def test_missing_wait_channel_retains_first_actual_stat_and_race(self):
        (self.process/'task/22/wchan').unlink()
        value=self.collect()
        self.assertEqual(value['observed'],2)
        self.assertEqual(value['exited_during_sample'],[])
        self.assertIsNone(value['threads'][1]['wait_channel'])
        self.assertEqual(value['threads'][1]['wait_channel_error'],'FileNotFoundError')

    def test_stat_symlink_is_not_followed(self):
        path=self.process/'task/22/stat';path.unlink();path.symlink_to(self.process/'stat')
        value=self.collect()
        self.assertTrue(value['errors'])
        self.assertEqual(value['observed'],1)

    def test_oversized_stat_is_explicit_not_truncated(self):
        (self.process/'task/22/stat').write_bytes(b'x'*(subject.MAX_STAT_BYTES+1))
        value=self.collect()
        self.assertIn('CensusBoundExceeded',self.categories(value))
        self.assertEqual(value['observed'],1)

    def test_task_bound_refuses_without_partial_success(self):
        with mock.patch.object(subject,'MAX_TASKS',1):value=self.collect()
        self.assertIn('CensusBoundExceeded',self.categories(value))
        self.assertIsNone(value['task_ids_before'])

    def test_nonnumeric_task_entry_is_not_silently_skipped(self):
        (self.process/'task/unexpected').mkdir()
        value=self.collect()
        self.assertIn('ValueError',self.categories(value))


class StatParserTests(unittest.TestCase):
    def test_separate_cpu_counters_preserve_asymmetry_and_u64_boundaries(self):
        for user, kernel in ((7,19),(0,0),(2**64-1,0),(0,2**64-1)):
            with self.subTest(user=user,kernel=kernel):
                value=subject.parse_task_stat(stat_data(user=user,kernel=kernel),21)
                self.assertEqual(value['utime_ticks'],user)
                self.assertEqual(value['stime_ticks'],kernel)
                self.assertEqual(value['cpu_ticks'],user+kernel)

    def test_each_cpu_counter_refuses_negative_unicode_and_individual_overflow(self):
        for key in ('user','kernel'):
            for counter in (-1,'１２',2**64):
                with self.subTest(key=key,counter=counter),self.assertRaises(ValueError):
                    subject.parse_task_stat(stat_data(**{key:counter}),21)

    def test_comm_with_spaces_and_closing_parentheses(self):
        value=subject.parse_task_stat(stat_data(comm='pool ) (worker)'),21)
        self.assertEqual(value['comm'],'pool ) (worker)')
        self.assertEqual(value['cpu_ticks'],3)

    def test_wrong_tid_and_short_fields_refuse(self):
        for raw in (stat_data(22), '21 (x) S 1 2'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):subject.parse_task_stat(raw,21)

    def test_negative_oversized_and_combined_cpu_counters_refuse(self):
        for raw in (stat_data(user=-1),stat_data(user=2**64),stat_data(user=2**64-1,kernel=1)):
            with self.subTest(raw=raw),self.assertRaises(ValueError):subject.parse_task_stat(raw,21)

    def test_control_text_and_bad_start_refuse(self):
        for raw in (stat_data(comm='bad\nname'),stat_data(start='-1')):
            with self.subTest(raw=raw),self.assertRaises(ValueError):subject.parse_task_stat(raw,21)


class ReviewerJoinTests(unittest.TestCase):
    setUp=PinnedCensusTests.setUp
    collect=PinnedCensusTests.collect

    def reviewer(self):
        path=Path(__file__).resolve().with_name('thread_review.py')
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),'5e0c627caceb8c9e1a08c0209173120081b97f4641a240bea7c2bb30b84257fa')
        spec=importlib.util.spec_from_file_location('held_thread_reviewer_v3',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def review(self,value):
        return self.reviewer().review_samples([dict(node=1,elapsed_s=1.0,phase='steady',metrics=dict(
            schema_version=2,boot_id='fixture-boot',clock_ticks=100,process=dict(
                pid=21,start_ticks='100',threads=2,thread_census=value)))])

    def test_actual_collector_shape_joins_unchanged_v3_data_reviewer(self):
        result=self.review(self.collect())
        self.assertEqual(result['review_state'],'OBSERVATIONS_REVIEWED')
        self.assertEqual(result['observed_thread_identity_count'],2)
        self.assertIn('leak-free',result['claims_excluded'])

    def test_identity_error_cannot_become_complete_in_old_reviewer(self):
        value=self.collect();value['errors'].append(dict(tid=21,error='ProcessIncarnationChanged'))
        result=self.review(value)
        self.assertEqual(result['review_state'],'INCOMPLETE_OBSERVATIONS')
        self.assertIn('CENSUS_ERRORS',result['overlapping_category_counts'])

    def test_cpu_split_keeps_first_actual_task_stat_when_tid_is_reused(self):
        (self.process/'task/22/stat').write_text(stat_data(22,'200',user=7,kernel=19))
        original=subject._bounded_text;reads=0
        def read(path,maximum):
            nonlocal reads
            if path==self.process/'task/22/stat':
                reads+=1
                if reads==2:return stat_data(22,'201',user=13,kernel=23)
            return original(path,maximum)
        with mock.patch.object(subject,'_bounded_text',side_effect=read):value=self.collect()
        row=value['threads'][1]
        self.assertEqual((row['start_ticks'],row['utime_ticks'],row['stime_ticks'],row['cpu_ticks']),('200',7,19,26))
        self.assertIn('ThreadIncarnationChanged',{item['error'] for item in value['errors']})
        self.assertEqual(self.review(value)['review_state'],'INCOMPLETE_OBSERVATIONS')


if __name__=='__main__':unittest.main()
