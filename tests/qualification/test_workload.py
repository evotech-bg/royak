import json
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from workload import Handler


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.db = str(Path(self.directory.name) / "ledger.db")
        with closing(sqlite3.connect(self.db)) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE entries(id TEXT PRIMARY KEY,value TEXT NOT NULL)")
        self.env = patch.dict(os.environ, MODE="ledger", DB=self.db)
        self.env.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.env.stop()
        self.directory.cleanup()

    def write(self, ident, value):
        req = urllib.request.Request(self.url + "/write", json.dumps(dict(id=ident, value=value)).encode(),
                                     {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_duplicate_is_idempotent(self):
        self.assertEqual(self.write("a", "v")[0], 200)
        self.assertEqual(self.write("a", "v")[0], 200)
        with urllib.request.urlopen(self.url + "/entries") as response:
            self.assertEqual(json.load(response), {"a": "v"})

    def test_idempotency_conflict_cannot_overwrite(self):
        self.write("a", "first")
        self.assertEqual(self.write("a", "second")[0], 409)
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(db.execute("SELECT value FROM entries WHERE id='a'").fetchone()[0], "first")

    def test_acknowledgement_is_readable_from_separate_connection(self):
        status, response = self.write("a", "durable")
        self.assertEqual((status, response), (200, {"id": "a", "value": "durable"}))
        with closing(sqlite3.connect(self.db)) as db, db:
            self.assertEqual(db.execute("SELECT value FROM entries WHERE id='a'").fetchone()[0], "durable")

    def test_invalid_schema_rejected(self):
        self.assertEqual(self.write(123, "v")[0], 400)


if __name__ == "__main__":
    unittest.main()
