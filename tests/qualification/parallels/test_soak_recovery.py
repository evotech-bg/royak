import unittest
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
import recover
from recover import validate_run_id


class RecoveryIdentityTests(unittest.TestCase):
    def test_every_selected_pointer_is_validated_before_first_cleanup(self):
        ident='rkq-soak-20261028-235542-adc0c9'
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'inventory.json';p.write_text(json.dumps(dict(nodes=[dict(id=1),dict(id=2)])))
            with patch.object(recover,'verify_owner'),patch.object(recover,'ssh',side_effect=['/var/lib/royak-qualification/'+ident,'/foreign']) as ssh:
                with self.assertRaisesRegex(RuntimeError,'refusing cleanup'):recover.recover(p,ident)
            self.assertEqual([c.args[2] for c in ssh.call_args_list],['sudo readlink -f /lab']*2)

    def test_partial_recovery_preserves_other_nodes_and_rejects_unknown_selection(self):
        ident='rkq-soak-20261028-235542-adc0c9'
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'inventory.json';p.write_text(json.dumps(dict(nodes=[dict(id=1,ip='one'),dict(id=2,ip='two')])))
            with patch.object(recover,'verify_owner') as owner,patch.object(recover,'ssh') as ssh,patch.object(recover,'save'),patch.object(recover.subprocess,'check_output',return_value=''):
                ssh.side_effect=lambda root,node,command:'/var/lib/royak-qualification/'+ident if command=='sudo readlink -f /lab' else ''
                recover.recover(p,ident,[2])
                self.assertEqual([c.args[1]['id'] for c in owner.call_args_list],[2])
                self.assertEqual({c.args[1]['id'] for c in ssh.call_args_list},{2})
                for selection in ([99],[2,2],[]):
                    with self.subTest(selection=selection),self.assertRaises(ValueError):recover.recover(p,ident,selection)

    def test_exact_short_and_soak_run_ids_are_accepted(self):
        for value in ("rkq-20261028-231403-d8c3fc","rkq-soak-20261028-235542-adc0c9"):
            validate_run_id(value)

    def test_paths_shell_text_and_partial_ids_are_refused(self):
        for value in ("rkq-../foreign","rkq-soak-","rkq-20261028-231403-d8c3fc;id",
                      "rkq-20261028-231403-d8c3fc/../foreign","rkq-soak-20261028-235542-adc0c9\n"):
            with self.subTest(value=value),self.assertRaises(ValueError): validate_run_id(value)


if __name__=="__main__": unittest.main()
