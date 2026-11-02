import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from soak_checks import resource_report, traffic_gate, continuity, guest_cleanup_passed, MIB
from soak import SoakLab
from soak_metrics import path_usage


def samples():
    return [dict(node=node,elapsed_s=i*60,phase='soak',metrics=dict(schema_version=2,clock_ticks=100,boot_id="boot",root_free_bytes=5*1024**3,
        process=dict(pid=10,start_ticks="100",rss_bytes=20*MIB,fds=24,threads=8,cpu_ticks=i*10),
        containers=[dict(id='container',started_at='start',init=True,running=True,oom=False,census=dict(tasks=3,zombies=[]))],
        paths={p:dict(present=True,kind='directory' if p.endswith('.raft') else 'file',bytes=1000) for p in
               ('/lab/state.json.raft','/lab/royak.log','/lab/data/connect-audit.jsonl')}))
        for node in (1,2,3) for i in range(12)]


class ResourceTests(unittest.TestCase):
    def test_stopped_vm_is_not_a_substitute_for_disabled_service_and_empty_runtime(self):
        clean=dict(service_active='inactive',service_enabled='disabled',royak_process_alive=False,
                   containers=[],all_container_count=0,wireguard_present=False,owned_firewall_rules=0)
        self.assertTrue(guest_cleanup_passed(clean))
        for key,bad in (('service_active','active'),('service_enabled','enabled'),('royak_process_alive',True),
                        ('containers',['owned']),('all_container_count',6),('wireguard_present',True),('owned_firewall_rules',1)):
            with self.subTest(key=key):self.assertFalse(guest_cleanup_passed(dict(clean,**{key:bad})))
        self.assertFalse(guest_cleanup_passed({}))
    def test_stable_three_node_resources_pass(self):
        self.assertTrue(resource_report(samples())["passed"])

    def test_growth_oom_and_disk_exhaustion_each_fail(self):
        for field in ("rss_bytes","fds","threads","oom","disk"):
            rows=samples()
            for row in rows:
                if row["elapsed_s"]<300: continue
                m=row["metrics"]
                if field=="oom": m["containers"][0]["oom"]=True
                elif field=="disk": m["root_free_bytes"]=100
                else: m["process"][field]+=100*MIB if field=="rss_bytes" else 100
            with self.subTest(field=field): self.assertFalse(resource_report(rows)["passed"])

    def test_restarts_do_not_merge_incarnation_memory(self):
        rows=samples()
        for row in rows:
            if row["elapsed_s"]>=300:
                row["metrics"]["process"]["pid"]=11
                row["metrics"]["process"]["rss_bytes"]=90*MIB
        self.assertFalse(resource_report(rows)["passed"])  # neither lifetime has eight samples

    def test_missing_telemetry_is_not_zero_or_sufficient_coverage(self):
        rows=[r for r in samples() if r["node"]!=3]+[dict(node=3,elapsed_s=20,error="SSH unavailable")]
        result=resource_report(rows)
        self.assertFalse(result["passed"])
        self.assertEqual(result["missing_samples"],1)

    def test_original_pid_growth_is_rejected_even_with_flat_royak_rss(self):
        rows=samples()
        for r in rows:r['metrics']['containers'][0]['census']['tasks']=3+int(r['elapsed_s']/60)*48
        result=resource_report(rows)
        self.assertFalse(result['passed'])
        self.assertTrue(any('task growth' in e['reason'] for e in result['errors']))

    def test_same_pid_in_different_container_incarnations_does_not_merge(self):
        rows=samples()
        for r in rows:
            if r['elapsed_s']>=300:r['metrics']['containers'][0]['started_at']='restart'
        self.assertFalse(resource_report(rows)['passed'])  # no eight-sample lifetime

    def test_persistent_and_drain_zombies_fail_even_below_task_gain_bound(self):
        for mode in ('persistent','drain'):
            rows=samples()
            for r in rows:
                if r['elapsed_s']>=600 or mode=='persistent':
                    r['metrics']['containers'][0]['census']['zombies']=[dict(pid=9,start_ticks='123')]
                    if mode=='drain':r['phase']='drain'
            self.assertFalse(resource_report(rows)['passed'])

    def test_one_transient_zombie_not_in_drain_does_not_prove_leak(self):
        rows=samples();rows[3]['metrics']['containers'][0]['census']['zombies']=[dict(pid=9,start_ticks='123')]
        self.assertTrue(resource_report(rows)['passed'])

    def test_missing_census_reaper_or_raft_path_cannot_pass(self):
        for field in ('census','init','raft','schema'):
            rows=samples()
            m=rows[3]['metrics']
            if field=='census':m['containers'][0].pop('census')
            elif field=='init':m['containers'][0]['init']=False
            elif field=='schema':m.pop('schema_version')
            else:m['paths']['/lab/state.json.raft']=dict(present=False,bytes=None)
            with self.subTest(field=field):self.assertFalse(resource_report(rows)['passed'])

    def test_real_raft_and_log_growth_is_not_hidden_by_missing_state_json(self):
        for path in ('/lab/state.json.raft','/lab/royak.log','/lab/data/connect-audit.jsonl'):
            rows=samples()
            for r in rows:
                if r['elapsed_s']>=300:r['metrics']['paths'][path]['bytes']+=40*MIB
            self.assertFalse(resource_report(rows)['passed'])

    def test_audit_is_required_after_real_issuer_use_not_before_lazy_creation(self):
        rows=samples()
        for r in rows:
            if r['node']!=1 or r['elapsed_s']<300:
                r['metrics']['paths']['/lab/data/connect-audit.jsonl']=dict(present=False,bytes=None)
        report=resource_report(rows,audit_first_use={1:300})
        self.assertTrue(report['passed'])
        self.assertEqual(report['audit_required_nodes'],[1])
        self.assertTrue(all(r['bytes'] is None for r in report['audit_absences']))
        self.assertFalse(resource_report(rows,audit_first_use={1:0})['passed'])

    def test_audit_cannot_disappear_after_it_was_observed(self):
        rows=samples();rows[3]['metrics']['paths']['/lab/data/connect-audit.jsonl']=dict(present=False,bytes=None)
        self.assertFalse(resource_report(rows,audit_first_use={1:600})['passed'])

    def test_cpu_report_is_royak_ticks_not_docker_container_cpu(self):
        report=resource_report(samples())
        for t in report['trends']:
            self.assertAlmostEqual(t['cpu_one_core_percent']['mean'],1/6)


class PathUsageTests(unittest.TestCase):
    def test_missing_path_is_explicitly_unavailable(self):
        with tempfile.TemporaryDirectory() as root:
            value=path_usage(Path(root)/'missing')
            self.assertFalse(value['present']);self.assertIsNone(value['bytes'])

    def test_nested_raft_files_measured_without_following_external_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            base=Path(root);raft=base/'state.json.raft';raft.mkdir()
            (raft/'log').write_bytes(b'123');(raft/'snapshots').mkdir();(raft/'snapshots'/'s').write_bytes(b'4567')
            (base/'secret').write_bytes(b'x'*100);(raft/'link').symlink_to(base/'secret')
            value=path_usage(raft)
            self.assertEqual((value['kind'],value['bytes'],value['files']),('directory',7,2))


class TrafficTests(unittest.TestCase):
    def events(self):
        return [dict(kind="app_complete",phase=p,elapsed_s=i,status=200) for p in ("baseline","soak") for i in range(60)]

    def test_steady_traffic_passes(self):
        self.assertTrue(traffic_gate(self.events(),1,1)["passed"])

    def test_silent_worker_or_empty_phase_cannot_pass(self):
        self.assertFalse(traffic_gate(self.events(),5,1)["passed"])
        self.assertFalse(traffic_gate([],1,1)["passed"])

    def test_failed_responses_remain_visible(self):
        events=self.events(); events[20]["status"]=0
        self.assertFalse(traffic_gate(events,1,1)["passed"])

    def test_empty_middle_minute_cannot_hide_behind_healthy_edges(self):
        rows=[dict(kind="app_complete",elapsed_s=i,status=200) for i in range(180) if not 60<=i<120]
        self.assertFalse(continuity(rows,[],0,180,1)["passed"])

    def test_only_declared_fault_and_recovery_windows_are_exempt(self):
        rows=[dict(kind="app_complete",elapsed_s=i,status=200) for i in range(180) if not 60<=i<120]
        faults=[dict(kind="fault_start",fault="node",elapsed_s=65),dict(kind="fault_end",fault="node",elapsed_s=100)]
        self.assertTrue(continuity(rows,faults,0,180,1)["passed"])
        self.assertFalse(continuity(rows,faults[:1],0,180,1)["passed"])

    def test_fault_names_do_not_overwrite_acknowledged_control_state(self):
        lab=SoakLab.__new__(SoakLab); lab.fault_count=6
        with patch("qualify.original.Lab.control_write") as write:
            lab.control_write("leader-sigkill")
        write.assert_called_once_with("cycle-6-leader-sigkill")


class FixtureTests(unittest.TestCase):
    def test_failed_assertion_still_collects_drain_and_resources_then_fails(self):
        lab=SoakLab.__new__(SoakLab);lab.checks=[];seen=[]
        def traffic():
            lab.check('continuity',False)
            seen.append('traffic-continued')
        lab.verify_traffic=traffic
        lab.verify_drain=lambda:seen.append('drain')
        lab.verify_resources=lambda:seen.append('resources')
        with self.assertRaisesRegex(AssertionError,'continuity'):lab.verify()
        self.assertEqual(seen,['traffic-continued','drain','resources'])
        self.assertFalse(lab.collecting_closeout)
        with self.assertRaises(AssertionError):lab.check('provision still fails fast',False)

    def test_unexpected_traffic_or_drain_exception_does_not_hide_resource_evidence(self):
        for stage in ('traffic','drain'):
            lab=SoakLab.__new__(SoakLab);lab.checks=[];seen=[]
            def action(name):
                seen.append(name)
                if name==stage:raise ValueError('original error')
            lab.verify_traffic=lambda:action('traffic')
            lab.verify_drain=lambda:action('drain')
            lab.verify_resources=lambda:action('resources')
            with self.assertRaisesRegex(ValueError,'original error'):lab.verify()
            self.assertEqual(seen,['traffic','drain','resources'])
            self.assertTrue(any(not c['passed'] for c in lab.checks))

    def test_resource_sampling_cadence_includes_collection_time(self):
        lab=SoakLab.__new__(SoakLab);lab.metrics_stop=Mock();lab.metrics_stop.is_set.side_effect=[False,True]
        lab.args=Mock(sample_interval=10);lab.sample_resources=Mock()
        with patch('soak.time.monotonic',side_effect=[100,103]):lab.metrics_loop()
        lab.metrics_stop.wait.assert_called_once_with(7)

    def test_soak_credentials_are_in_private_file_not_process_arguments(self):
        lab=SoakLab.__new__(SoakLab); lab.user="secret-not-in-argv"
        with patch("qualify.VMMixin.write_remote") as write:
            lab.write_remote({},"/lab/environment","HOME=\"/root\"\n")
        calls=write.call_args_list
        self.assertEqual(calls[0].args[1],"/lab/connect-tokens.csv")
        self.assertIn("secret-not-in-argv",calls[0].args[2])
        self.assertNotIn("secret-not-in-argv",calls[1].args[2])

    def test_only_soak_workload_enables_keepalive(self):
        lab=SoakLab.__new__(SoakLab)
        with patch("qualify.VMMixin.write_remote") as write:
            lab.write_remote({},"/lab/build/workload.py",b"class Handler(BaseHTTPRequestHandler):\n    pass\n","644")
        self.assertIn('protocol_version = "HTTP/1.1"',write.call_args.args[2])

    def test_unexpected_workload_shape_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError,"fixture shape"):
            SoakLab.__new__(SoakLab).write_remote({},"/lab/build/workload.py",b"unrelated")


if __name__=="__main__": unittest.main()
