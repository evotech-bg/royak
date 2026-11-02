import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from storage_replication import Experiment


class EmptyInitializationTests(unittest.TestCase):
    def test_activation_replays_offline_activity_log_before_up(self):
        e=Experiment.__new__(Experiment);e.config='/owned/drbd.conf';e.name='rkqs00000000';e.command=Mock(return_value='')
        n=dict(id=1);e.adm(n,'up')
        self.assertIn(' apply-al ',e.command.call_args_list[0].args[1])
        self.assertIn(' up ',e.command.call_args_list[1].args[1])

    def experiment(self):
        e=Experiment.__new__(Experiment)
        e.nodes=[dict(id=i) for i in (1,2,3)]
        e.name='rkqs00000000'
        e.status=Mock(return_value=dict(role='Secondary',devices=[dict(size=1,open=False,disk_state='Inconsistent')],
                    connections=[{'connection-state':'Connected'}]*2))
        e.status.return_value['devices'][0]['disk-state']='Inconsistent'
        e.command=Mock(return_value=json.dumps(dict(bytes=1024,sha256=hashlib.sha256(bytes(1024)).hexdigest())))
        def check(name,passed,**kw):
            if not passed:raise RuntimeError('not equal empty replicas')
        e.check=check;e.adm=Mock()
        return e

    def test_only_identically_verified_zero_extents_can_initialize(self):
        e=self.experiment();e.initialize_empty_extent()
        self.assertEqual(e.command.call_count,3)
        e.adm.assert_called_once_with(e.nodes[0],'new-current-uuid','--clear-bitmap')

    def test_nonzero_or_wrong_size_data_never_clears_bitmap(self):
        for bad in [dict(bytes=1024,sha256=hashlib.sha256(b'x'*1024).hexdigest()),
                    dict(bytes=1023,sha256=hashlib.sha256(bytes(1024)).hexdigest())]:
            e=self.experiment();e.command.side_effect=[e.command.return_value,json.dumps(bad),e.command.return_value]
            with self.assertRaises((AssertionError,RuntimeError)):e.initialize_empty_extent()
            e.adm.assert_not_called()

    def test_active_open_consistent_or_disconnected_resource_is_never_reinitialized(self):
        for change in ('role','open','disk','connection'):
            e=self.experiment();s=e.status.return_value
            if change=='role':s['role']='Primary'
            if change=='open':s['devices'][0]['open']=True
            if change=='disk':s['devices'][0]['disk-state']='UpToDate'
            if change=='connection':s['connections'][0]['connection-state']='Connecting'
            with self.assertRaises(AssertionError):e.initialize_empty_extent()
            e.adm.assert_not_called()

    def test_backend_abbreviated_credential_error_is_redacted_before_journal(self):
        e=Experiment.__new__(Experiment);e.root=Path('/owned-test');e.sensitive=['abcde012'*6];e.event=Mock()
        result=SimpleNamespace(returncode=10,stdout=b'',stderr=b"Parse error value 'abcde012abcde012abcd...' is too long")
        with patch('storage_replication.verify_owner'),patch('storage_replication.subprocess.run',return_value=result):
            with self.assertRaises(RuntimeError):e.command(dict(id=1,ip='127.0.0.1'),'owned-component-command')
        logged=e.event.call_args.kwargs['stderr']
        self.assertIn('[redacted]',logged)
        self.assertNotIn('abcde012',logged)

    def test_successful_ssh_readiness_is_not_confused_with_empty_stdout(self):
        e=Experiment.__new__(Experiment);e.root=Path('/owned-test');n=dict(id=1,uuid='owned-node')
        e.started=[n];e.drbd=[];e.mounted=set();e.cleanup_errors=[];e.iface='rkstore0';e.name='rkqs00000000'
        e.command=Mock(return_value='[]')
        with patch('storage_replication.verify_owner',return_value={'State':'stopped'}), \
             patch('storage_replication.run'),patch('storage_replication.ssh',return_value='ready') as ssh, \
             patch('storage_replication.wait_for',side_effect=lambda predicate,seconds:self.assertTrue(predicate())):
            e.cleanup()
        self.assertEqual(e.cleanup_errors,[])
        self.assertEqual(ssh.call_args.args[2],'printf ready')


if __name__=='__main__':unittest.main()
