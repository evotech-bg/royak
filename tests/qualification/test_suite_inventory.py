from pathlib import Path
import unittest

from suites import ROOT, SUITES


class SuiteInventoryTests(unittest.TestCase):
    def test_all_linux_integration_entrypoints_are_in_the_runner(self):
        entrypoints = {p.name for p in ROOT.glob("test-*.sh")}
        # This file is a macOS-to-Linux adapter, not another feature suite. The
        # mesh suite it wraps runs directly in the isolated Linux test daemon.
        entrypoints.remove("test-mesh-macos.sh")
        self.assertEqual(entrypoints, set(SUITES))
        self.assertEqual(len(SUITES), len(set(SUITES)))


if __name__ == "__main__":
    unittest.main()
