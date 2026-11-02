from pathlib import Path
import unittest
from unittest.mock import patch

import pod_access_vm


class VMCapacityPreflightTests(unittest.TestCase):
    def test_every_owned_home_output_and_tmp_is_observed_without_summing(self):
        homes=[dict(Home='/owned/n1.pvm'),dict(home='/owned/n2.pvm')]
        with patch.object(pod_access_vm,'measure',return_value=dict(allocation_available_bytes=50*1024**3)) as measure:
            report=pod_access_vm.capacity_preflight(Path('/owned/lab'),Path('/evidence/new-run'),homes)
        self.assertEqual([call.args[0] for call in measure.call_args_list][:2],
                         [Path('/owned/lab'),Path('/evidence')])
        self.assertEqual([call.args[0] for call in measure.call_args_list][-2:],
                         [Path('/owned/n1.pvm'),Path('/owned/n2.pvm')])
        self.assertEqual(len(measure.call_args_list),5)
        self.assertEqual(report['minimum_allocation_available_bytes'],50*1024**3)
        self.assertFalse(report['raw_free_floor_verified'])

    def test_insufficient_location_prevents_admission_even_if_other_pool_is_large(self):
        with patch.object(pod_access_vm,'measure',side_effect=[
                dict(allocation_available_bytes=200*1024**3),
                dict(allocation_available_bytes=39*1024**3),
                dict(allocation_available_bytes=200*1024**3)]):
            with self.assertRaisesRegex(AssertionError,'insufficient allocation'):
                pod_access_vm.capacity_preflight(Path('/owned/lab'),Path('/evidence/run'),[])


if __name__=='__main__':unittest.main()
