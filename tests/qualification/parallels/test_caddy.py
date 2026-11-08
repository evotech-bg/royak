import hashlib
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import get_caddy


class DownloadTests(unittest.TestCase):
    def fixture(self, root, algorithm):
        source = root / "test-binary"
        source.write_bytes(b"not an executable; extraction fixture only")
        archive = root / f"caddy_{get_caddy.VERSION}_mac_arm64.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(source, arcname="caddy")
        with archive.open("rb") as stream:
            expected = hashlib.file_digest(stream, algorithm).hexdigest()
        sums = root / f"caddy_{get_caddy.VERSION}_checksums.txt"
        sums.write_text(expected + "  " + archive.name + "\n")
        return sums

    def test_official_sha512_format_is_checked_before_use(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.fixture(root, "sha512")
            with patch.object(get_caddy, "run", return_value="fixture-version"):
                get_caddy.fetch(root)
            self.assertEqual((root / "caddy").read_bytes(), b"not an executable; extraction fixture only")

    def test_corrupt_download_is_not_extracted_or_executed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sums = self.fixture(root, "sha512")
            sums.write_text("0" * 128 + "  " + f"caddy_{get_caddy.VERSION}_mac_arm64.tar.gz\n")
            with patch.object(get_caddy, "run") as command:
                with self.assertRaisesRegex(RuntimeError, "checksum mismatch"):
                    get_caddy.fetch(root)
                command.assert_not_called()
            self.assertFalse((root / "caddy").exists())


if __name__ == "__main__":
    unittest.main()
