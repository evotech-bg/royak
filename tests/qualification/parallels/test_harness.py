import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

import bootstrap
import qualify


class OwnershipTests(unittest.TestCase):
    def test_foreign_vm_home_is_refused(self):
        with patch.object(bootstrap, "run", return_value=json.dumps([{"Home": "/tmp/unrelated.pvm"}])):
            with self.assertRaisesRegex(RuntimeError, "ownership/path mismatch"):
                bootstrap.verify_owner(Path("/tmp/our-lab"), {"uuid": "only-this-uuid"})

    def test_owned_vm_home_is_accepted(self):
        info = {"Home": "/tmp/our-lab/vms/owned.pvm"}
        with patch.object(bootstrap, "run", return_value=json.dumps([info])):
            self.assertEqual(bootstrap.verify_owner(Path("/tmp/our-lab"), {"uuid": "owned"}), info)

    def test_management_ssh_pins_host_key_without_fallback(self):
        with patch.object(bootstrap, "run", return_value="ok") as command:
            bootstrap.ssh(Path("/tmp/owned"), {"ip": "10.37.129.211"}, "true")
        args = command.call_args.args
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("UserKnownHostsFile=/tmp/owned/known_hosts", args)
        self.assertNotIn("StrictHostKeyChecking=no", args)


class TransportTests(unittest.TestCase):
    def test_all_node_idle_preflight_precedes_any_parallel_preparation(self):
        lab=self.lab();lab.inventory=dict(nodes=[dict(id=1),dict(id=2),dict(id=3)])
        lab.remote=Mock(side_effect=['inactive','active'])
        with patch.object(qualify,'verify_owner') as owner:
            with self.assertRaisesRegex(RuntimeError,'exact recovery is required'):
                lab.preflight_idle()
        self.assertEqual(owner.call_count,2)
        self.assertTrue(all(c.args[1][:2]==['sh','-ec'] for c in lab.remote.call_args_list))

    def test_idle_service_does_not_hide_stopped_containers(self):
        lab=self.lab();lab.inventory=dict(nodes=[dict(id=1),dict(id=2),dict(id=3)])
        lab.remote=Mock(side_effect=['inactive']*3+['','stopped-container'])
        with patch.object(qualify,'verify_owner'):
            with self.assertRaisesRegex(RuntimeError,'residual containers'):lab.preflight_idle()
        self.assertEqual(lab.remote.call_args_list[-1].args[1],['docker','ps','-aq'])

    def lab(self):
        lab = qualify.VMMixin.__new__(qualify.VMMixin)
        lab.vmroot = Path("/tmp/owned")
        lab.vm_by_name = {"owned-vm": {"ip": "10.37.129.211"}}
        return lab

    def test_unknown_vm_is_never_sent_an_ssh_command(self):
        with patch.object(qualify, "ssh") as command:
            with self.assertRaises(KeyError):
                self.lab().transport("exec", "foreign-vm", "true")
            command.assert_not_called()

    def test_host_docker_operations_are_never_run(self):
        for action in ("run", "stop", "rm", "volume", "network", "system"):
            with self.subTest(action=action), patch.object(qualify, "run") as command:
                with self.assertRaisesRegex(RuntimeError, "host Docker operation refused"):
                    self.lab().transport(action, "anything")
                command.assert_not_called()

    def test_guest_arguments_are_shell_quoted(self):
        with patch.object(qualify, "ssh", return_value="ok") as command:
            self.lab().transport("exec", "owned-vm", "printf", "%s", "$(not-a-command)")
        self.assertIn("'$(not-a-command)'", command.call_args.args[2])

    def test_secrets_are_streamed_not_added_to_ssh_argv(self):
        lab = self.lab()
        with patch.object(qualify, "run", return_value="") as command:
            lab.write_remote(lab.vm_by_name["owned-vm"], "/lab/secret", "not-for-argv")
        self.assertNotIn("not-for-argv", repr(command.call_args.args))
        self.assertEqual(command.call_args.kwargs["input"], b"not-for-argv")

    def test_copied_public_ca_stays_private_on_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ca.pem"
            with patch.object(qualify, "ssh", return_value="public certificate"):
                self.lab().transport("cp", "owned-vm:/root/.kube/royak-ca.pem", str(path))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
