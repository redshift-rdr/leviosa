import hashlib
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path

import pytest

from core.logdb import TrafficLogger, _COLUMNS, _text
from core.models import LeviosaRequest, LeviosaResponse, TrafficRecord

EXAMPLE = Path(__file__).resolve().parent.parent / 'example_db_log.sqlite'


def make_response(status=200, body=b'hello'):
    req = LeviosaRequest('POST', 'http://example.com/api?q=one&q=two', [], [])
    record = TrafficRecord(req.url, req.method, datetime(2026, 10, 29, 11, 35, 30),
                           '192.0.2.2', b'POST /api?q=one&q=two HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\na=1',
                           status, body)
    return LeviosaResponse(status, {}, body, req, traffic=[record])


def rows(path):
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute('SELECT * FROM ACTIVITY ORDER BY rowid')]


def schema(path):
    with sqlite3.connect(path) as conn:
        return conn.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall(), conn.execute('PRAGMA table_info(ACTIVITY)').fetchall()


def test_schema_exactly_matches_burp_example(tmp_path):
    path = tmp_path / 'output.sqlite'
    logger = TrafficLogger(str(path))
    logger.close()
    tables, columns = schema(path)
    assert [name for name, _ in tables] == ['ACTIVITY']
    assert columns == schema(EXAMPLE)[1]
    assert [row[1] for row in columns] == list(_COLUMNS)


def test_log_stores_only_compatible_text_values(tmp_path):
    path = tmp_path / 'output.sqlite'
    logger = TrafficLogger(str(path))
    logger.log(make_response())
    logger.close()
    record, = rows(path)
    assert record == {
        'LOCAL_SOURCE_IP': '192.0.2.2', 'TARGET_URL': 'http://example.com/api?q=one&q=two',
        'HTTP_METHOD': 'POST', 'BURP_TOOL': 'Repeater',
        'REQUEST_RAW': 'POST /api?q=one&q=two HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\na=1',
        'SEND_DATETIME': '2026-10-29 11:35:30', 'HTTP_STATUS_CODE': '200', 'RESPONSE_RAW': 'hello',
    }
    assert all(isinstance(value, str) for value in record.values())


def test_append_to_burp_copy_preserves_schema_and_existing_rows(tmp_path):
    original_digest = hashlib.sha256(EXAMPLE.read_bytes()).hexdigest()
    path = tmp_path / 'burp.sqlite'
    shutil.copy2(EXAMPLE, path)
    before = rows(path)
    before_schema = schema(path)
    logger = TrafficLogger(str(path))
    logger.log(make_response(), tool='Scanner')
    logger.close()
    assert rows(path)[:-1] == before
    assert rows(path)[-1]['BURP_TOOL'] == 'Scanner'
    assert schema(path) == before_schema
    assert hashlib.sha256(EXAMPLE.read_bytes()).hexdigest() == original_digest


def test_network_failure_is_status_zero_with_empty_response(tmp_path):
    path = tmp_path / 'output.sqlite'
    response = make_response(0, b'')
    response.traffic[0].request_raw = b''
    response.traffic[0].local_source_ip = ''
    logger = TrafficLogger(str(path))
    logger.log(response)
    logger.close()
    record, = rows(path)
    assert record['HTTP_STATUS_CODE'] == '0'
    assert record['RESPONSE_RAW'] == record['REQUEST_RAW'] == record['LOCAL_SOURCE_IP'] == ''


def test_each_write_visible_without_close(tmp_path):
    path = tmp_path / 'output.sqlite'
    logger = TrafficLogger(str(path))
    for _ in range(60):
        logger.log(make_response())
    assert len(rows(path)) == 60
    # A second writer is not blocked by the first logger's idle connection.
    other = TrafficLogger(str(path))
    other.log(make_response())
    other.close()
    logger.close()
    assert len(rows(path)) == 61


@pytest.mark.parametrize('ddl', [
    'CREATE TABLE traffic (id INTEGER)',
    'CREATE TABLE ACTIVITY (TARGET_URL TEXT)',
])
def test_reject_incompatible_database_without_schema_changes(tmp_path, ddl):
    path = tmp_path / 'old.sqlite'
    with sqlite3.connect(path) as conn:
        conn.execute(ddl)
    before = path.read_bytes()
    with pytest.raises(ValueError, match='choose a new'):
        TrafficLogger(str(path))
    assert path.read_bytes() == before


def test_logger_requires_real_transport_capture(tmp_path):
    logger = TrafficLogger(str(tmp_path / 'output.sqlite'))
    response = make_response()
    response.traffic = []
    try:
        with pytest.raises(ValueError, match='transport-captured'):
            logger.log(response)
    finally:
        logger.close()


def test_text_and_binary_decode_without_replacement_characters():
    assert _text('caf\u00e9'.encode()) == 'caf\u00e9'
    assert _text(b'caf\xe9', 'iso-8859-1') == 'caf\u00e9'
    assert _text(b'\x00\xff').encode('latin-1') == b'\x00\xff'


def test_invalid_output_tag_is_rejected_before_insert(tmp_path):
    path = tmp_path / 'output.sqlite'
    logger = TrafficLogger(str(path))
    try:
        with pytest.raises(ValueError):
            logger.log(make_response(), tool='Requester')
        assert not rows(path)
    finally:
        logger.close()
