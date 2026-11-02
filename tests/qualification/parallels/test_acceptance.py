import unittest
import json
from pathlib import Path
import tempfile
from acceptance import REQUIRED, acceptable, choose, capacity_attempt


def report(mode="connect"):
    return dict(passed=True, checks=[dict(name=name, passed=True) for name in REQUIRED[mode]])


class AcceptanceTests(unittest.TestCase):
    def test_pass_without_required_real_checks_is_refused(self):
        self.assertFalse(acceptable(dict(passed=True, checks=[]), "connect"))

    def test_any_failed_or_skipped_check_is_refused(self):
        for extra in (dict(name="extra", passed=False), dict(name="extra", passed=True, skipped=True)):
            value = report()
            value["checks"].append(extra)
            self.assertFalse(acceptable(value, "connect"))

    def test_one_pass_is_not_three_consecutive_passes(self):
        row = dict(run="001", report=report(), clean=True)
        self.assertFalse(choose([row], "connect", 3)["passed"])

    def test_latest_failure_cannot_be_replaced_by_an_old_pass(self):
        rows = [dict(run=str(i), report=report(), clean=True) for i in range(4)]
        rows[-1]["report"]["passed"] = False
        self.assertFalse(choose(rows, "connect", 3)["passed"])

    def test_cleanup_error_fails_acceptance(self):
        rows = [dict(run=str(i), report=report(), clean=True) for i in range(3)]
        rows[-1]["clean"] = False
        self.assertFalse(choose(rows, "connect", 3)["passed"])

    def test_complete_clean_repeats_pass(self):
        rows = [dict(run=str(i), report=report(), clean=True) for i in range(3)]
        self.assertTrue(choose(rows, "connect", 3)["passed"])

    def test_capacity_requires_every_one_of_twelve_real_cycles(self):
        value = report("capacity")
        self.assertTrue(acceptable(value, "capacity"))
        value["checks"] = [c for c in value["checks"] if c["name"] != "cycle 11: one revoke closes all eight streams"]
        self.assertFalse(acceptable(value, "capacity"))

    def test_latest_capacity_failure_is_not_hidden_by_an_older_pass(self):
        rows = [dict(run="001", report=report("capacity"), clean=True),
                dict(run="002", report={"passed": False, "checks": []}, clean=True)]
        self.assertFalse(choose(rows, "capacity", 1)["passed"])

    def test_focused_capacity_is_separate_and_binds_fixture_client_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.assertIsNone(capacity_attempt(directory, "fixture", "client"))
            value = dict(report("capacity"), focused_reproducer=True,
                         vm_fixture_sha256="fixture", client_sha256="client")
            (directory / "capacity-report.json").write_text(json.dumps(value))
            row = capacity_attempt(directory, "fixture", "client")
            self.assertTrue(choose([row], "capacity", 1)["passed"])
            self.assertFalse(acceptable(row["report"], "connect"))
            self.assertFalse(capacity_attempt(directory, "wrong", "client")["report"]["passed"])
            self.assertFalse(capacity_attempt(directory, "fixture", "wrong")["report"]["passed"])
            (directory / "cleanup.jsonl").touch()
            self.assertFalse(choose([capacity_attempt(directory, "fixture", "client")], "capacity", 1)["passed"])

    def test_malformed_capacity_report_is_a_failure_not_an_ignored_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for invalid in ("not json", "[]", "null"):
                (directory / "capacity-report.json").write_text(invalid)
                row = capacity_attempt(directory, "fixture", "client")
                self.assertFalse(choose([row], "capacity", 1)["passed"])


if __name__ == "__main__":
    unittest.main()
