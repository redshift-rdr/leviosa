import json
import sqlite3

import pytest

from core.logdb import TrafficLogger
from core.models import LeviosaRequest, LeviosaResponse, Param


def make_response(url="http://example.com", status=200, body=b"hello", params=None):
    req = LeviosaRequest(
        method="GET",
        url=url,
        headers=["Host: example.com"],
        params=params or [],
    )
    return LeviosaResponse(
        status=status,
        headers={"Content-Type": "text/html"},
        body=body,
        request=req,
    )


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "traffic.db")


def read_rows(path):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM traffic ORDER BY id")]
    finally:
        conn.close()


class TestTrafficLogger:
    def test_creates_table(self, db_path):
        logger = TrafficLogger(db_path)
        logger.close()
        conn = sqlite3.connect(db_path)
        try:
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
        finally:
            conn.close()
        assert "traffic" in tables

    def test_logs_a_row(self, db_path):
        logger = TrafficLogger(db_path)
        logger.log(make_response(), module="AdminFinder", proxy="http://127.0.0.1:8080")
        logger.close()

        rows = read_rows(db_path)
        assert len(rows) == 1
        row = rows[0]
        assert row["module"] == "AdminFinder"
        assert row["proxy"] == "http://127.0.0.1:8080"
        assert row["method"] == "GET"
        assert row["url"] == "http://example.com"
        assert row["status"] == 200
        assert row["response_body"] == b"hello"
        assert row["response_bytes"] == 5
        assert row["error"] == 0
        assert row["ts"]

    def test_headers_and_params_stored_as_json(self, db_path):
        logger = TrafficLogger(db_path)
        params = [Param(type="cookie", name="session", value="abc")]
        logger.log(make_response(params=params))
        logger.close()

        row = read_rows(db_path)[0]
        assert json.loads(row["request_headers"]) == ["Host: example.com"]
        assert json.loads(row["request_params"]) == [
            {"type": "cookie", "name": "session", "value": "abc"}
        ]
        assert json.loads(row["response_headers"]) == {"Content-Type": "text/html"}

    def test_network_error_flagged(self, db_path):
        logger = TrafficLogger(db_path)
        # status == 0 is the network-error sentinel from _send_one.
        logger.log(make_response(status=0, body=b""))
        logger.close()

        row = read_rows(db_path)[0]
        assert row["error"] == 1
        assert row["response_body"] is None
        assert row["response_bytes"] == 0

    def test_batch_commit_then_close_persists_all(self, db_path):
        logger = TrafficLogger(db_path)
        for i in range(120):
            logger.log(make_response(url=f"http://example.com/{i}"))
        logger.close()
        assert len(read_rows(db_path)) == 120

    def test_none_module_and_proxy(self, db_path):
        logger = TrafficLogger(db_path)
        logger.log(make_response())
        logger.close()
        row = read_rows(db_path)[0]
        assert row["module"] is None
        assert row["proxy"] is None
