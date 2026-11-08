import unittest
from checker import check_history, summarize


class CheckerTests(unittest.TestCase):
    def event(self, **changes):
        return dict(kind="app_complete", status=200, id="a", value="v",
                    returned_id="a", returned_value="v", **changes)

    def test_valid(self):
        self.assertTrue(check_history([self.event()], {"a": "v"})["passed"])

    def test_lost_ack_is_failure(self):
        self.assertFalse(check_history([self.event()], {})["passed"])

    def test_corruption_is_failure(self):
        self.assertFalse(check_history([self.event()], {"a": "wrong"})["passed"])

    def test_wrong_response_is_failure(self):
        event = self.event()
        event["returned_id"] = "other"
        self.assertFalse(check_history([event], {"a": "v"})["passed"])

    def test_no_success_is_not_green(self):
        self.assertFalse(check_history([], {})["passed"])

    def test_timeout_can_have_committed(self):
        event = self.event()
        event["status"] = 0
        result = check_history([self.event(), event], {"a": "v"})
        self.assertTrue(result["passed"])
        self.assertEqual(result["ambiguous_or_failed"], 1)

    def test_phase_measurements_include_failed_requests(self):
        events = [dict(kind="app_complete", phase="baseline", node=1, status=200, latency_ms=10),
                  dict(kind="app_complete", phase="baseline", node=2, status=503, latency_ms=100)]
        baseline = summarize(events)["baseline"]
        self.assertEqual(baseline["availability"], 0.5)
        self.assertEqual(baseline["successful_ingress_nodes"], [1])
        self.assertEqual(baseline["requests"], 2)
        self.assertEqual(baseline["latency_ms"]["p95"], 100)

    def test_empty_measurements_are_not_fabricated(self):
        self.assertEqual(summarize([]), {})


if __name__ == "__main__":
    unittest.main()
