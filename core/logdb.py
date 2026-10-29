"""Traffic-only SQLite output compatible with Burp's Log Requests to SQLite."""
import sqlite3
from pathlib import Path

from core.models import LeviosaResponse
from core.tooltags import BurpTool

_COLUMNS = (
    "LOCAL_SOURCE_IP", "TARGET_URL", "HTTP_METHOD", "BURP_TOOL", "REQUEST_RAW",
    "SEND_DATETIME", "HTTP_STATUS_CODE", "RESPONSE_RAW",
)
_SCHEMA = "CREATE TABLE ACTIVITY (" + ", ".join(f"{name} TEXT" for name in _COLUMNS) + ")"


def _check_schema(conn, create=False):
    tables = {row[0].upper() for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    )}
    if tables - {"ACTIVITY"}:
        raise ValueError("Traffic output requires an ACTIVITY-only database; "
                         "choose a new --log-db path. Existing logs remain readable with leviosa-traffic.")
    if not tables:
        if not create:
            return
        conn.execute(_SCHEMA)
    columns = conn.execute("PRAGMA table_info(ACTIVITY)").fetchall()
    if [(row[1], row[2].upper(), row[3], row[4], row[5]) for row in columns] != [
        (name, "TEXT", 0, None, 0) for name in _COLUMNS
    ]:
        raise ValueError("Incompatible ACTIVITY schema: expected the eight Burp TEXT columns "
                         "without defaults, constraints or extra columns; choose a new --log-db path.")


def validate_database(path: str) -> None:
    """Check an existing output database without creating or modifying it."""
    file = Path(path)
    if file.exists():
        conn = sqlite3.connect(file.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            _check_schema(conn)
        finally:
            conn.close()


def _text(raw: bytes, encoding: str | None = None) -> str:
    """Retain valid UTF-8/declared text; map other bytes one-to-one with Latin-1."""
    try:
        return raw.decode(encoding or "utf-8")
    except (UnicodeDecodeError, LookupError):
        return raw.decode("latin-1")


class TrafficLogger:
    """Append only ACTIVITY rows, with no findings or execution metadata tables.

    Each insert commits immediately so human-paced runs do not hold a write lock
    while idle, and another process can inspect the database during a scan.
    """

    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, isolation_level=None)
        try:
            _check_schema(self.conn, create=True)
        except BaseException:
            self.conn.close()
            raise

    def log(self, response: LeviosaResponse, *, tool: BurpTool | str = BurpTool.REPEATER) -> None:
        tool = BurpTool(tool)
        if not response.traffic:
            raise ValueError("Traffic logging requires transport-captured HTTP exchanges")
        for record in response.traffic:
            self.conn.execute(
                "INSERT INTO ACTIVITY (" + ", ".join(_COLUMNS) + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.local_source_ip, record.target_url, record.method, str(tool),
                    _text(record.request_raw), record.sent_at.strftime("%Y-%m-%d %H:%M:%S"),
                    str(record.status), _text(record.response_body, record.response_encoding),
                ),
            )

    def close(self) -> None:
        self.conn.close()
