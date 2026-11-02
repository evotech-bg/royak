import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock

from load_balancer import LBVMFaultLab


class LiveBackendSelectionTests(unittest.TestCase):
    def test_vm_fault_requires_recent_success_from_that_occupied_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            lab = LBVMFaultLab.__new__(LBVMFaultLab)
            lab.out = Path(tmp)
            lab.started = time.monotonic() - 100
            lab.lock = threading.Lock()
            lab.random = Mock()
            lab.random.choice.side_effect = lambda values: values[0]
            lab.check = Mock()
            events = [
                dict(status=200, selected_backend="10.37.129.211:8080", elapsed_s=90),
                dict(status=503, selected_backend="10.37.129.212:8080", elapsed_s=99),
                dict(status=200, selected_backend="10.37.129.213:8080", elapsed_s=99),
            ]
            (lab.out / "lb-history.jsonl").write_text("\n".join(json.dumps(e) for e in events))
            candidates = [({"id": i, "ip": "10.37.129." + str(210 + i)}, ["actual-container"]) for i in range(1, 4)]
            selected = lab.select_vm_outage_target(candidates)
            self.assertEqual(selected[0]["id"], 3)
            self.assertEqual([n[0]["id"] for n in lab.random.choice.call_args.args[0]], [3])


if __name__ == "__main__":
    unittest.main()
