import unittest
from dataset import build_rows


class DatasetTests(unittest.TestCase):
    def sample(self, now=10):
        return dict(elapsed_s=now, phase="secret-fault-label", nodes=[], cpu_percent=None)

    def event(self, now, latency=5):
        return dict(kind="app_complete", elapsed_s=now, status=200, latency_ms=latency)

    def test_future_observations_do_not_leak(self):
        row = next(build_rows([self.sample()], [self.event(9), self.event(11, 999)], "run"))
        self.assertEqual(row["features"]["completed_requests"], 1)
        self.assertEqual(row["features"]["latency_p95_ms"], 5)

    def test_labels_are_separate_from_features(self):
        row = next(build_rows([self.sample()], [], "run"))
        self.assertNotIn("secret-fault-label", str(row["features"]))
        self.assertEqual(row["labels"]["injector_phase"], "secret-fault-label")

    def test_missing_data_is_not_zero(self):
        row = next(build_rows([self.sample()], [], "run"))
        self.assertIsNone(row["features"]["cpu_percent"])
        self.assertIsNone(row["features"]["latency_p95_ms"])
        self.assertIsNone(row["features"]["error_fraction"])

    def test_window_discards_old_observations(self):
        rows = list(build_rows([self.sample(10), self.sample(30)], [self.event(5), self.event(25)], "run"))
        self.assertEqual([r["features"]["completed_requests"] for r in rows], [1, 1])


if __name__ == "__main__":
    unittest.main()
