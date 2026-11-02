import unittest
from coverage_report import latest_suite
from run import source_inventory, ROOT


class CoverageTests(unittest.TestCase):
    def test_embedded_assets_are_part_of_current_source_evidence(self):
        names = {str(p.relative_to(ROOT)) for p in source_inventory()}
        self.assertIn("src/dashboard.html", names)
        self.assertIn("src/probe-watchdog.sh", names)
    def attempt(self, run_id, sha, passed):
        return ({"run_id": run_id, "source_sha256": {"test.sh": sha}},
                {"suites": [{"suite": "test.sh", "passed": passed}]})

    def test_latest_failure_cannot_be_hidden_by_an_earlier_pass(self):
        attempts = [self.attempt("1", "current", True), self.attempt("2", "current", False)]
        self.assertFalse(latest_suite(attempts, "test.sh", "current")["passed"])

    def test_a_zero_exit_with_a_skip_is_not_accepted(self):
        attempt=self.attempt("1","current",True)
        attempt[1]["suites"][0]["skip_lines"]=["omitted actual runtime check"]
        self.assertFalse(latest_suite([attempt],"test.sh","current")["passed"])

    def test_different_fixture_is_not_current_evidence(self):
        self.assertIsNone(latest_suite([self.attempt("1", "old", True)], "test.sh", "new"))

    def test_changed_dependent_fixture_invalidates_evidence(self):
        attempt = self.attempt("1", "current", True)
        attempt[0]["source_sha256"]["helper.py"] = "old"
        self.assertIsNone(latest_suite([attempt], "test.sh", "current", {"helper.py":"new"}))


if __name__ == "__main__":
    unittest.main()
