import copy
import unittest
from soak_acceptance import completed, resource_contract, drain_contract
from soak_checks import resource_report
from test_soak import samples


def report():
    return dict(passed=True,long_soak_qualified=True,profile="full",source_and_fixtures_unchanged=True,powered_off=True,cleanup_completed=True,
                checks=[dict(name="requested workload duration actually completed",passed=True,observed_seconds=7200)])


class LongSoakAcceptanceTests(unittest.TestCase):
    def test_raw_pid_and_raft_contract_is_required_not_legacy_boolean(self):
        self.assertFalse(resource_contract(dict(passed=True)))
        value=resource_report(samples())
        self.assertFalse(resource_contract(value))  # raw bounds alone do not prove drain
        value.update(drain_complete=True,drain_samples_per_node={'1':3,'2':3,'3':3})
        self.assertTrue(resource_contract(value))
        value['container_trends']=[]
        self.assertFalse(resource_contract(value))

    def test_missing_or_active_session_or_unbounded_cache_fails_drain(self):
        clean=[dict(node=n,status=200,active=0,open=0,retained=8) for n in (1,2,3)]
        self.assertTrue(drain_contract(clean))
        for key,bad in [('status',503),('active',1),('open',1),('retained',257),('retained',-1)]:
            rows=copy.deepcopy(clean);rows[0][key]=bad
            with self.subTest(key=key,bad=bad):self.assertFalse(drain_contract(rows))
        self.assertFalse(drain_contract(clean[:2]))

    def test_complete_full_duration_is_required(self):
        self.assertTrue(completed(report(),dict(profile="full",requested_seconds=7200)))

    def test_short_pass_cannot_substitute_for_long_soak(self):
        self.assertFalse(completed(report(),dict(profile="smoke",requested_seconds=360)))
        value=report(); value["checks"][0]["observed_seconds"]=7199
        self.assertFalse(completed(value,dict(profile="full",requested_seconds=7200)))
        self.assertFalse(completed(report(),dict(profile='full',requested_seconds=7200,negative_closeout_control=True)))

    def test_any_failed_or_skipped_check_stale_source_or_cleanup_fails(self):
        for key in ("passed","long_soak_qualified","source_and_fixtures_unchanged","powered_off","cleanup_completed"):
            value=report(); value[key]=False
            with self.subTest(key=key): self.assertFalse(completed(value,dict(profile="full",requested_seconds=7200)))
        value=report(); value["checks"].append(dict(name="gap",passed=True,skipped=True))
        self.assertFalse(completed(value,dict(profile="full",requested_seconds=7200)))


if __name__=="__main__": unittest.main()
