import unittest

from connect_acceptance import consecutive_gate, matches


class ConnectAcceptanceTests(unittest.TestCase):
    def test_one_pass_is_not_a_stability_gate(self):
        self.assertFalse(consecutive_gate([dict(run_id="1", passed=True)])[0])

    def test_latest_failure_cannot_be_replaced_by_older_green_runs(self):
        attempts = [dict(run_id=str(i), passed=i != 4) for i in range(1, 5)]
        self.assertFalse(consecutive_gate(attempts)[0])
        attempts.extend(dict(run_id=str(i), passed=True) for i in range(5, 8))
        self.assertTrue(consecutive_gate(attempts)[0])

    def test_debug_or_stale_fixtures_are_not_release_acceptance(self):
        manifest = dict(source_sha256={"src/x.rs": "source"}, harness_sha256={"run.py": "helper"})
        report = dict(binary_sha256="binary", client_sha256="client", fixture_sha256="fixture")
        build = dict(binary_sha256="binary", source_sha256=manifest["source_sha256"], source_unchanged_during_build=True, debug_symbols=False)
        args = ("binary", "client", manifest["source_sha256"], "fixture", {"run.py": "helper"})
        self.assertTrue(matches(manifest, report, build, *args))
        self.assertFalse(matches(manifest, report, dict(build, debug_symbols=True), *args))
        self.assertFalse(matches(manifest, dict(report, fixture_sha256="old"), build, *args))
        self.assertFalse(matches(dict(manifest, source_sha256={}), report, build, *args))


if __name__ == "__main__":
    unittest.main()
