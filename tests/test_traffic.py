import sqlite3
import subprocess
import sys

import pytest

from traffic import _fmt_dt, _path_of, build_parser, build_where

PROJECT_ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def seed_db(path, rows):
    """rows: list of (ts, module, method, url, status, bytes, error)."""
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE traffic (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL, module TEXT, proxy TEXT,
            method TEXT NOT NULL, url TEXT NOT NULL,
            request_headers TEXT NOT NULL DEFAULT '[]',
            request_params TEXT NOT NULL DEFAULT '[]',
            status INTEGER NOT NULL,
            response_headers TEXT NOT NULL DEFAULT '{}',
            response_body BLOB, response_bytes INTEGER NOT NULL, error INTEGER NOT NULL
        );
        """
    )
    conn.executemany(
        "INSERT INTO traffic (ts, module, method, url, status, response_bytes, error) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()
    conn.close()


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "traffic.db"
    seed_db(str(path), [
        ("2026-07-08T09:00:00+00:00", "passthrough", "GET", "http://t/app/home", 200, 10, 0),
        ("2026-07-08T09:05:00+00:00", "errorpages", "POST", "http://t/api/login", 500, 30, 0),
        ("2026-07-09T15:00:00+00:00", "adminfinder", "GET", "http://t/api/users?id=1", 404, 5, 0),
        ("2026-07-09T15:30:00+00:00", "errorpages", "POST", "http://t/api/pay", 500, 0, 0),
        ("2026-07-09T16:00:00+00:00", None, "GET", "http://t/x", 0, 0, 1),
    ])
    return str(path)


def run_where(db, argv):
    """Apply build_where(parsed argv) against the db and return matched urls."""
    args = build_parser().parse_args([db, *argv])
    where, params = build_where(args)
    conn = sqlite3.connect(db)
    try:
        return [r[0] for r in conn.execute(
            f"SELECT url FROM traffic{where} ORDER BY id", params)]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

class TestFilters:
    def test_no_filters_returns_all(self, db):
        assert len(run_where(db, [])) == 5

    def test_status(self, db):
        urls = run_where(db, ["--status", "500"])
        assert urls == ["http://t/api/login", "http://t/api/pay"]

    def test_multiple_status(self, db):
        assert len(run_where(db, ["--status", "200", "--status", "404"])) == 2

    def test_status_class(self, db):
        assert set(run_where(db, ["--status-class", "5xx"])) == {
            "http://t/api/login", "http://t/api/pay"}

    def test_method_case_insensitive(self, db):
        urls = run_where(db, ["--method", "post"])
        assert urls == ["http://t/api/login", "http://t/api/pay"]

    def test_module(self, db):
        assert set(run_where(db, ["--module", "errorpages"])) == {
            "http://t/api/login", "http://t/api/pay"}

    def test_module_empty_matches_raw_dispatch(self, db):
        # NULL module (raw dispatch) is matched with --module ''
        assert run_where(db, ["--module", ""]) == ["http://t/x"]

    def test_path_substring(self, db):
        assert len(run_where(db, ["--path", "/api"])) == 3

    def test_errors_only(self, db):
        assert run_where(db, ["--errors-only"]) == ["http://t/x"]

    def test_after(self, db):
        assert len(run_where(db, ["--after", "2026-07-09"])) == 3

    def test_before(self, db):
        assert len(run_where(db, ["--before", "2026-07-08T23:59:59+00:00"])) == 2

    def test_time_range(self, db):
        urls = run_where(db, ["--after", "2026-07-09", "--before", "2026-07-09T15:15:00+00:00"])
        assert urls == ["http://t/api/users?id=1"]

    def test_bad_status_class_raises(self, db):
        args = build_parser().parse_args([db, "--status-class", "xyz"])
        with pytest.raises(ValueError):
            build_where(args)


# ---------------------------------------------------------------------------
# Stacking — the headline requirement
# ---------------------------------------------------------------------------

class TestStacking:
    def test_time_and_status(self, db):
        urls = run_where(db, ["--after", "2026-07-09", "--status", "500"])
        assert urls == ["http://t/api/pay"]

    def test_method_and_path(self, db):
        urls = run_where(db, ["--method", "GET", "--path", "/api"])
        assert urls == ["http://t/api/users?id=1"]

    def test_three_filters(self, db):
        urls = run_where(db, ["--status-class", "5xx", "--method", "POST", "--path", "pay"])
        assert urls == ["http://t/api/pay"]


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

class TestFormatting:
    def test_fmt_dt(self):
        assert _fmt_dt("2026-07-09T15:30:00+00:00") == "2026-07-09 15:30:00"

    def test_fmt_dt_bad_input_passthrough(self):
        assert _fmt_dt("not-a-date") == "not-a-date"

    def test_path_with_query(self):
        assert _path_of("http://t/api/users?id=1", 60) == "/api/users?id=1"

    def test_path_root(self):
        assert _path_of("http://t", 60) == "/"

    def test_path_truncated(self):
        out = _path_of("http://t/" + "a" * 100, 20)
        assert len(out) == 20
        assert out.endswith("...")


# ---------------------------------------------------------------------------
# End-to-end CLI
# ---------------------------------------------------------------------------

class TestCli:
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "traffic.py", *args],
            capture_output=True, text=True, cwd=PROJECT_ROOT,
        )

    def test_table_output(self, db):
        r = self._run(db, "--status", "500")
        assert r.returncode == 0
        assert "DATETIME (UTC)" in r.stdout
        assert "/api/login" in r.stdout
        assert "2 row(s)" in r.stdout

    def test_count(self, db):
        r = self._run(db, "--module", "errorpages", "--count")
        assert r.stdout.strip() == "2"

    def test_no_match(self, db):
        r = self._run(db, "--status", "418")
        assert "no matching traffic." in r.stdout

    def test_missing_db_errors(self, tmp_path):
        r = self._run(str(tmp_path / "nope.db"), "--count")
        assert r.returncode == 1
        assert "cannot open" in r.stderr

    def test_limit_note(self, db):
        r = self._run(db, "--limit", "1")
        assert "limited to 1" in r.stdout


@pytest.fixture
def activity_db(tmp_path):
    from core.logdb import _SCHEMA
    path = tmp_path / 'burp.sqlite'
    with sqlite3.connect(path) as conn:
        conn.execute(_SCHEMA)
        conn.executemany('INSERT INTO ACTIVITY VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [
            ('127.0.0.1', 'http://t/home', 'GET', 'Repeater', 'GET /home HTTP/1.1\r\n\r\n', '2026-10-29 10:00:00', '200', 'ok'),
            ('127.0.0.1', 'http://t/api/login', 'POST', 'Scanner', '', '2026-10-29 11:00:00', '500', 'error'),
            ('127.0.0.1', 'http://t/missing', 'GET', 'Intruder', '', '2026-10-29 12:00:00', '404', ''),
            ('', 'http://t/failed', 'GET', 'Repeater', '', '2026-10-29 13:00:00', '0', ''),
        ])
    return str(path)


class TestActivityCli:
    _run = TestCli._run
    def test_activity_table(self, activity_db):
        result = self._run(activity_db)
        assert result.returncode == 0, result.stderr
        assert 'DATETIME (LOCAL)' in result.stdout
        assert 'TOOL' in result.stdout and 'Repeater' in result.stdout
        assert '4 row(s)' in result.stdout

    @pytest.mark.parametrize('flags,count', [
        (['--status', '500'], '1'),
        (['--status-class', '4xx'], '1'),
        (['--tool', 'Repeater'], '2'),
        (['--tool', 'Scanner', '--method', 'post', '--path', '/api', '--after', '2026-10-29 10:30:00'], '1'),
        (['--errors-only'], '1'),
        (['--before', '2026-10-29 10:30:00'], '1'),
    ])
    def test_activity_filters(self, activity_db, flags, count):
        result = self._run(activity_db, *flags, '--count')
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == count

    def test_module_filter_is_explicitly_unavailable(self, activity_db):
        result = self._run(activity_db, '--module', 'sqli')
        assert result.returncode == 1
        assert '--module is only available for legacy' in result.stderr
        assert 'Traceback' not in result.stderr

    def test_tool_filter_is_explicitly_unavailable_for_legacy(self, db):
        result = self._run(db, '--tool', 'Scanner')
        assert result.returncode == 1
        assert '--tool requires an ACTIVITY' in result.stderr

    def test_reads_user_example_without_changes(self):
        import hashlib
        path = PROJECT_ROOT / 'example_db_log.sqlite'
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with sqlite3.connect(path) as conn:
            expected = conn.execute("SELECT COUNT(*) FROM ACTIVITY WHERE BURP_TOOL='Intruder'").fetchone()[0]
        result = self._run(str(path), '--tool', 'Intruder', '--count')
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == str(expected)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest

    def test_uri_special_characters_in_db_path(self, activity_db, tmp_path):
        import shutil
        path = tmp_path / 'log?#.sqlite'
        shutil.copy2(activity_db, path)
        result = self._run(str(path), '--count')
        assert result.returncode == 0 and result.stdout.strip() == '4'
