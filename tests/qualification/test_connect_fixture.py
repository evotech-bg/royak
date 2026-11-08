import unittest
from unittest.mock import Mock, patch

from connect_e2e import ConnectLab


class ConnectObservationTests(unittest.TestCase):
    def lab(self):
        lab = ConnectLab.__new__(ConnectLab)
        lab.gateway = {"api": "https://127.0.0.1:6443", "name": "owned-test-node"}
        lab.user = "test-credential-not-for-output"
        return lab

    def test_unavailable_control_transport_is_not_a_secondary_none_error(self):
        with patch("connect_e2e.request", return_value=(0, None)):
            with self.assertRaisesRegex(RuntimeError, "gateway transport unavailable: GET") as failure:
                self.lab().call("GET", "/royak/v1/connect/namespaces/a/audit")
        self.assertNotIn("test-credential", str(failure.exception))

    def test_http_denial_is_preserved_for_negative_security_checks(self):
        with patch("connect_e2e.request", return_value=(403, {"error": "denied"})):
            self.assertEqual(self.lab().call("POST", "/sessions"), (403, {"error": "denied"}))

    def test_unavailable_pod_observation_is_explicitly_failed(self):
        lab = self.lab()
        lab.api = Mock(return_value=(0, None))
        with self.assertRaisesRegex(AssertionError, "pod observation failed"):
            lab.pods("team-a")

    def test_successful_empty_pod_observation_is_not_a_transport_failure(self):
        lab = self.lab()
        lab.api = Mock(return_value=(200, {"items": []}))
        self.assertEqual(lab.pods("team-a"), [])

    def test_capacity_setup_waits_for_service_configuration_not_just_quorum_ack(self):
        lab=self.lab();lab.nodes=[{"id":1},{"id":2}]
        lab.api=Mock(side_effect=[(200,{"spec":{"selector":{"app":"new"}}}),(200,{"spec":{"selector":{"app":"old"}}})])
        self.assertFalse(lab.service_converged("new"))
        lab.api=Mock(return_value=(200,{"spec":{"selector":{"app":"new"}}}))
        self.assertTrue(lab.service_converged("new"))

    def test_service_convergence_does_not_silently_retry_a_transport_outage(self):
        lab=self.lab();lab.nodes=[{"id":1}];lab.api=Mock(return_value=(0,None))
        with self.assertRaisesRegex(AssertionError,"Service observation failed"):
            lab.service_converged("new")


if __name__ == "__main__":
    unittest.main()
