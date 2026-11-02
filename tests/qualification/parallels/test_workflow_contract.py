"""Static workflow contracts only; this does not execute/validate GitHub Actions."""
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
# Staged fixture snapshots carry the proposed YAML beside this test. Once
# installed under tests/qualification/parallels, inspect the actual workflows.
# Missing files remain errors, not skipped/passing tests.
WORKFLOWS = HERE if (HERE / "ci.yml").exists() else HERE.parents[2] / ".github/workflows"


def job(text, name):
    content = text.split("\n  " + name + ":\n", 1)[1]
    return re.split(r"\n  [a-z][a-z0-9-]*:\n", content, maxsplit=1)[0]


class WorkflowContract(unittest.TestCase):
    def setUp(self):
        self.ci = (WORKFLOWS / "ci.yml").read_text()
        self.qualification = (WORKFLOWS / "qualification.yml").read_text()
        self.build = job(self.ci, "build")

    def test_existing_hosted_matrix_and_read_only_build_token(self):
        self.assertIn("os: [ubuntu-latest, macos-latest]", self.build)
        self.assertIn("runs-on: ${{ matrix.os }}", self.build)
        self.assertIn("permissions:\n      contents: read", self.build)
        for text in (self.ci, self.qualification):
            self.assertNotIn("self-hosted", text)
            self.assertNotIn("pull_request_target", text)

    def test_pinned_host_setup_uses_fresh_signature_verified_output_not_path_install(self):
        self.assertIn('get_restic.py --host --root "$TOOL_ROOT" --github-env "$GITHUB_ENV"', self.build)
        self.assertIn("gpg --version >/dev/null", self.build)
        for token in ("${GITHUB_RUN_ID}", "${GITHUB_RUN_ATTEMPT}", "${RUNNER_OS}", "${RUNNER_ARCH}"):
            self.assertIn(token, self.build)
        for forbidden in ("GITHUB_PATH", "export PATH", "brew install", "apt-get", "curl |", "--insecure", "--skip", "--ignored", "continue-on-error"):
            self.assertNotIn(forbidden, self.build)

    def test_mandatory_actual_cargo_tests_precede_unchanged_size_gate(self):
        self.assertEqual(self.build.count("run: cargo test --locked --bin royak"), 1)
        self.assertLess(self.build.index("Pin signature-verified restic"), self.build.index("Unit tests (cargo test"))
        self.assertLess(self.build.index("Unit tests (cargo test"), self.build.index("Check binary size"))
        self.assertIn('if [ "$SIZE" -gt 10485760 ]; then', self.build)
        self.assertNotIn("|| true", self.build)

    def test_qualification_stays_opt_in_hosted_and_joins_exact_manifest(self):
        self.assertIn("workflow_dispatch:", self.qualification)
        self.assertIn("runs-on: ubuntu-latest", self.qualification)
        self.assertIn("timeout-minutes: 45", self.qualification)
        self.assertIn('--platform linux_arm64 --platform linux_amd64 --root "$TOOL_ROOT"', self.qualification)
        self.assertIn('linux_unit.py --release --restic-manifest "$ROYAK_QUAL_RESTIC_MANIFEST"', self.qualification)
        self.assertLess(self.qualification.index("Pin signature-verified restic"), self.qualification.index("Mandatory Linux Rust tests"))
        self.assertIn("tests/qualification/.runs/**/restic-build.json", self.qualification)
        self.assertIn("tests/qualification/.runs/**/SHA256SUMS.asc", self.qualification)
        self.assertIn("tests/qualification/.runs/**/key.asc", self.qualification)


if __name__ == "__main__": unittest.main(verbosity=2)
