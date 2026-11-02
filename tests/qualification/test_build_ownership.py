"""Pure build-cleanup contracts; never calls Docker or changes resources."""
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from run import cleanup_build_resources


class BuildOwnership(unittest.TestCase):
    def exercise(self, owners, completed=True, remove_code=0):
        calls=[]
        def fake(args,**_):
            calls.append(args)
            if 'inspect' in args:
                owner=owners.get(args[-1])
                return SimpleNamespace(returncode=1 if owner is None else 0,stdout=owner or '')
            return SimpleNamespace(returncode=remove_code,stdout='')
        with patch('run.subprocess.run',side_effect=fake):
            try:
                cleanup_build_resources('owned',['a','b'],completed)
            except RuntimeError as error:
                return calls,str(error)
        return calls,None

    def test_only_exact_owned_labels_are_removed(self):
        calls,error=self.exercise(dict(owned='owned',a='owned',b='owned'))
        self.assertIsNone(error)
        self.assertEqual([c[-1] for c in calls if 'rm' in c],['owned','a','b'])

    def test_foreign_collision_is_preserved_even_on_failed_build(self):
        calls,error=self.exercise(dict(owned='foreign',a='owned',b='foreign'),False)
        self.assertIn('non-owned',error)
        self.assertEqual([c[-1] for c in calls if 'rm' in c],['a'])

    def test_unknown_cleanup_prevents_qualified_completion(self):
        calls,error=self.exercise({})
        self.assertIn('observation unavailable',error)
        self.assertFalse(any('rm' in c for c in calls))
        self.assertIsNone(self.exercise({},False)[1])

    def test_failed_owned_removal_is_not_success(self):
        self.assertIn('cleanup failed',self.exercise(dict(owned='owned',a='owned',b='owned'),remove_code=1)[1])


if __name__=='__main__':
    unittest.main()
