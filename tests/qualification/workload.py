"""Small stateless application and independent durable oracle for qualification.

The ledger is deliberately OUTSIDE Royak. This tests routing and orchestrator
recovery, not distributed volume durability. No third-party Python dependencies.
"""
import json
from contextlib import closing
import os
import socket
import sqlite3
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            return self.send(200, {"ok": True, "instance": socket.gethostname()})
        if os.environ.get("MODE") == "ledger" and self.path == "/entries":
            with closing(sqlite3.connect(os.environ["DB"])) as db, db:
                return self.send(200, dict(db.execute("SELECT id,value FROM entries")))
        return self.send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/write":
            return self.send(404, {"error": "not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096:
                return self.send(400, {"error": "invalid size"})
            raw = self.rfile.read(length)
            item = json.loads(raw)
            if not isinstance(item.get("id"), str) or not isinstance(item.get("value"), str):
                return self.send(400, {"error": "id and value must be strings"})
            if os.environ.get("MODE") == "ledger":
                with closing(sqlite3.connect(os.environ["DB"], timeout=10)) as db, db:
                    db.execute("PRAGMA synchronous=FULL")
                    db.execute("INSERT OR IGNORE INTO entries VALUES (?,?)", (item["id"], item["value"]))
                    old = db.execute("SELECT value FROM entries WHERE id=?", (item["id"],)).fetchone()[0]
                    if old != item["value"]:
                        return self.send(409, {"error": "idempotency conflict"})
                return self.send(200, item)
            req = urllib.request.Request(os.environ["LEDGER_URL"] + "/write", raw,
                                         {"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as response:
                result = json.load(response)
            result["instance"] = socket.gethostname()
            return self.send(200, result)
        except urllib.error.HTTPError as error:
            with error:
                return self.send(error.code, {"error": "upstream rejected"})
        except (ValueError, KeyError):
            return self.send(400, {"error": "invalid request"})
        except Exception as error:
            return self.send(503, {"error": type(error).__name__})


if __name__ == "__main__":
    if os.environ.get("MODE") == "ledger":
        with closing(sqlite3.connect(os.environ["DB"])) as db, db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("CREATE TABLE IF NOT EXISTS entries(id TEXT PRIMARY KEY,value TEXT NOT NULL)")
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
