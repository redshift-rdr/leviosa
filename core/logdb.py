import json
import sqlite3
from datetime import datetime, timezone

from core.models import LeviosaResponse

_SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                TEXT    NOT NULL,
    module            TEXT,
    proxy             TEXT,
    method            TEXT    NOT NULL,
    url               TEXT    NOT NULL,
    request_headers   TEXT    NOT NULL,
    request_params    TEXT    NOT NULL,
    status            INTEGER NOT NULL,
    response_headers  TEXT    NOT NULL,
    response_body     BLOB,
    response_bytes    INTEGER NOT NULL,
    error             INTEGER NOT NULL
);
"""

# Commit in batches so a long scan does not fsync on every request; the final
# flush happens in close().
_COMMIT_EVERY = 50


class TrafficLogger:
    """
    Append-only sqlite log of every request/response the tool sends.

    Writes are synchronous sqlite calls made from the (single-threaded) asyncio
    loop. At this tool's request volume the brief per-write block is acceptable,
    and it keeps the logger simple and dependency-free.
    """

    def __init__(self, path: str):
        # check_same_thread stays default: the whole app runs on one thread.
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()
        self._pending = 0

    def log(
        self,
        response: LeviosaResponse,
        module: str | None = None,
        proxy: str | None = None,
    ) -> None:
        req = response.request
        params = [
            {"type": p.type, "name": p.name, "value": p.value} for p in req.params
        ]
        # status == 0 is the sentinel _send_one returns for a network error.
        error = 1 if response.status == 0 else 0
        self.conn.execute(
            "INSERT INTO traffic ("
            "ts, module, proxy, method, url, request_headers, request_params, "
            "status, response_headers, response_body, response_bytes, error"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                module,
                proxy,
                req.method,
                req.url,
                json.dumps(req.headers),
                json.dumps(params),
                response.status,
                json.dumps(response.headers),
                response.body or None,
                len(response.body),
                error,
            ),
        )
        self._pending += 1
        if self._pending >= _COMMIT_EVERY:
            self.conn.commit()
            self._pending = 0

    def close(self) -> None:
        self.conn.commit()
        self.conn.close()
