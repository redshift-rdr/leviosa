import subprocess
import sys
from pathlib import Path

import pytest

from leviosa import build_parser

PROJECT_ROOT = Path(__file__).parent.parent


class TestParser:
    def test_target_required(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args([])

    def test_no_proxy_flag(self):
        args = build_parser().parse_args(["http://example.com", "--no-proxy"])
        assert args.no_proxy is True

    def test_no_proxy_defaults_false(self):
        args = build_parser().parse_args(["http://example.com"])
        assert args.no_proxy is False

    def test_concurrency_override(self):
        args = build_parser().parse_args(["http://example.com", "--concurrency", "5"])
        assert args.concurrency == 5

    def test_concurrency_defaults_none(self):
        args = build_parser().parse_args(["http://example.com"])
        assert args.concurrency is None

    def test_max_body_bytes_override(self):
        args = build_parser().parse_args(["http://example.com", "--max-body-bytes", "2048"])
        assert args.max_body_bytes == 2048

    def test_max_body_bytes_defaults_none(self):
        args = build_parser().parse_args(["http://example.com"])
        assert args.max_body_bytes is None

    def test_module_accumulates(self):
        args = build_parser().parse_args(["http://x.com", "--module", "a", "--module", "b"])
        assert args.modules == ["a", "b"]

    def test_module_short_flag(self):
        args = build_parser().parse_args(["http://x.com", "-m", "fuzzer"])
        assert args.modules == ["fuzzer"]

    def test_module_defaults_empty(self):
        args = build_parser().parse_args(["http://x.com"])
        assert args.modules == []

    def test_verbose_flag(self):
        args = build_parser().parse_args(["http://x.com", "--verbose"])
        assert args.verbose is True

    def test_verbose_short_flag(self):
        args = build_parser().parse_args(["http://x.com", "-v"])
        assert args.verbose is True


class TestCLIIntegration:
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "leviosa.py", *args],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )

    def test_help_exits_zero(self):
        assert self._run("--help").returncode == 0

    def test_help_mentions_key_flags(self):
        stdout = self._run("--help").stdout
        assert "--no-proxy" in stdout
        assert "--module" in stdout
        assert "--concurrency" in stdout
        assert "--verbose" in stdout

    def test_runs_with_url(self):
        # One response line printed regardless of whether the connection succeeds
        result = self._run("http://example.com", "--no-proxy")
        assert result.returncode == 0
        assert len(result.stdout.strip().splitlines()) == 1

    def test_runs_with_json_file(self):
        # example_requests_input_file.json has 6 requests; localhost:3000 won't be
        # running so they'll fail gracefully with status 0, but we still get 6 lines
        result = self._run("example_requests_input_file.json", "--no-proxy")
        assert result.returncode == 0
        assert len(result.stdout.strip().splitlines()) == 6

    def test_response_line_format(self):
        result = self._run("http://example.com", "--no-proxy")
        line = result.stdout.strip().splitlines()[0]
        parts = line.split()
        assert len(parts) == 3           # "<status> <METHOD> <url>"
        assert parts[1] == "GET"
        assert parts[2].startswith("http")

    def test_verbose_modules_in_stderr(self):
        result = self._run("http://x.com", "--no-proxy", "--verbose", "-m", "passthrough")
        assert result.returncode == 0
        assert "passthrough" in result.stderr

    def test_verbose_output_goes_to_stderr(self):
        result = self._run("http://x.com", "--no-proxy", "--verbose")
        assert result.returncode == 0
        assert "[leviosa]" in result.stderr
        assert "[leviosa]" not in result.stdout

    def test_verbose_shows_proxy_status(self):
        result = self._run("http://x.com", "--no-proxy", "--verbose")
        assert "proxy" in result.stderr
        assert "disabled" in result.stderr

    def test_verbose_shows_proxy_address_when_enabled(self):
        # Even if the proxy isn't reachable, the verbose line should appear
        result = self._run("http://x.com", "--verbose")
        assert "proxy" in result.stderr
        assert "8080" in result.stderr


class TestErrorHandling:
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "leviosa.py", *args],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )

    def test_missing_file_exits_nonzero(self):
        result = self._run("/nonexistent/requests.json", "--no-proxy")
        assert result.returncode != 0

    def test_missing_file_prints_to_stderr(self):
        result = self._run("/nonexistent/requests.json", "--no-proxy")
        assert "error" in result.stderr.lower()
        assert "nonexistent" in result.stderr

    def test_missing_file_no_traceback(self):
        result = self._run("/nonexistent/requests.json", "--no-proxy")
        assert "Traceback" not in result.stderr

    def test_malformed_json_exits_nonzero(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{ not valid json }")
        result = self._run(str(bad), "--no-proxy")
        assert result.returncode != 0

    def test_malformed_json_prints_to_stderr(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{ not valid json }")
        result = self._run(str(bad), "--no-proxy")
        assert "error" in result.stderr.lower()
        assert "Traceback" not in result.stderr

    def test_unknown_module_exits_nonzero(self):
        result = self._run("http://x.com", "--no-proxy", "--module", "doesnotexist")
        assert result.returncode != 0

    def test_unknown_module_prints_to_stderr(self):
        result = self._run("http://x.com", "--no-proxy", "--module", "doesnotexist")
        assert "error" in result.stderr.lower()
        assert "doesnotexist" in result.stderr
        assert "Traceback" not in result.stderr

    def test_module_missing_required_arg_exits_nonzero(self):
        # pathfuzz requires --wordlist; omitting it should exit 1 not crash
        result = self._run("http://x.com/FUZZ", "--no-proxy", "--module", "pathfuzz")
        assert result.returncode != 0

    def test_module_missing_required_arg_no_traceback(self):
        result = self._run("http://x.com/FUZZ", "--no-proxy", "--module", "pathfuzz")
        assert "Traceback" not in result.stderr


class TestEntryPoint:
    def _entry_point(self):
        return Path(sys.executable).parent / "leviosa"

    def test_entry_point_exists(self):
        assert self._entry_point().exists()

    def test_entry_point_help_exits_zero(self):
        result = subprocess.run(
            [str(self._entry_point()), "--help"],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )
        assert result.returncode == 0

    def test_entry_point_mentions_key_flags(self):
        result = subprocess.run(
            [str(self._entry_point()), "--help"],
            capture_output=True,
            text=True,
            cwd=PROJECT_ROOT,
        )
        assert "--module" in result.stdout
        assert "--no-proxy" in result.stdout
