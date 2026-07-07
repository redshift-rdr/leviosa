"""
End-to-end integration test: parsers → config → module loader → setup → run_modules.
HTTP calls are mocked with aioresponses so no real network is needed.
"""
from unittest.mock import AsyncMock, patch

import pytest

from core.config import Config
from core.loader import load_modules
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from core.parsers import detect_and_parse
from core.runner import run_modules


def _fake_response(url: str, status: int) -> LeviosaResponse:
    return LeviosaResponse(
        status=status,
        headers={},
        body=b"",
        request=LeviosaRequest(method="GET", url=url, headers=[], params=[]),
    )


class TestPathFuzzEndToEnd:
    """
    Full pipeline: parse input → load module → setup → mutate → (mocked) send → analyze.
    Asserts the correct findings reach stdout.
    """

    async def test_keyword_mode_golden_path(self, tmp_path, capsys):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\nbackup\nsecret\n")

        requests = detect_and_parse("http://example.com/FUZZ")

        modules = load_modules(["pathfuzz"])
        modules[0].setup(["--wordlist", str(wordlist)])

        config = Config()
        config.proxy_enabled = False

        fake_responses = [
            _fake_response("http://example.com/admin", 200),
            _fake_response("http://example.com/backup", 404),
            _fake_response("http://example.com/secret", 403),
        ]

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = fake_responses
            await run_modules(modules, requests, config, LeviosaContext())

        out = capsys.readouterr().out
        lines = out.strip().splitlines()
        # Only non-404 responses appear
        assert len(lines) == 2
        assert any("200" in l and "admin" in l for l in lines)
        assert any("403" in l and "secret" in l for l in lines)
        assert not any("backup" in l for l in lines)

    async def test_recursive_mode_golden_path(self, tmp_path, capsys):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\nuser\n")

        # /api/v1 has 2 segments → 2 depth levels × 2 words = 4 mutated requests
        requests = detect_and_parse("http://target.local/api/v1")

        modules = load_modules(["pathfuzz"])
        modules[0].setup(["--wordlist", str(wordlist), "--recursive"])

        config = Config()
        config.proxy_enabled = False

        fake_responses = [
            _fake_response("http://target.local/admin/", 200),
            _fake_response("http://target.local/user/", 404),
            _fake_response("http://target.local/api/admin/", 403),
            _fake_response("http://target.local/api/user/", 404),
        ]

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = fake_responses
            await run_modules(modules, requests, config, LeviosaContext())

        out = capsys.readouterr().out
        lines = out.strip().splitlines()
        # 200 and 403 should appear; 404s suppressed
        assert len(lines) == 2
        assert any("200" in l for l in lines)
        assert any("403" in l for l in lines)

    async def test_send_receives_correct_mutated_urls(self, tmp_path):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\nlogin\n")

        requests = detect_and_parse("http://example.com/FUZZ")

        modules = load_modules(["pathfuzz"])
        modules[0].setup(["--wordlist", str(wordlist)])

        config = Config()
        config.proxy_enabled = False

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = []
            await run_modules(modules, requests, config, LeviosaContext())

        sent = mock_send.call_args[0][0]
        sent_urls = [r.url for r in sent]
        assert "http://example.com/admin" in sent_urls
        assert "http://example.com/login" in sent_urls

    async def test_json_input_file_parsed_correctly(self, tmp_path, capsys):
        """Parse from a JSON request file, not just a bare URL."""
        import json

        req_file = tmp_path / "requests.json"
        req_file.write_text(json.dumps([{
            "method": "GET",
            "url": "http://example.com/FUZZ",
            "headers": ["Host: example.com"],
            "params": [],
            "hashkey": 12345,
        }]))

        wordlist = tmp_path / "words.txt"
        wordlist.write_text("admin\n")

        requests = detect_and_parse(str(req_file))
        assert len(requests) == 1

        modules = load_modules(["pathfuzz"])
        modules[0].setup(["--wordlist", str(wordlist)])

        config = Config()
        config.proxy_enabled = False

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = [_fake_response("http://example.com/admin", 200)]
            await run_modules(modules, requests, config, LeviosaContext())

        out = capsys.readouterr().out
        assert "200" in out
        assert "admin" in out

    async def test_no_findings_produces_no_output(self, tmp_path, capsys):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("missing\nnope\n")

        requests = detect_and_parse("http://example.com/FUZZ")

        modules = load_modules(["pathfuzz"])
        modules[0].setup(["--wordlist", str(wordlist)])

        config = Config()
        config.proxy_enabled = False

        fake_responses = [
            _fake_response("http://example.com/missing", 404),
            _fake_response("http://example.com/nope", 404),
        ]

        with patch("core.runner.send", new_callable=AsyncMock) as mock_send:
            mock_send.return_value = fake_responses
            await run_modules(modules, requests, config, LeviosaContext())

        assert capsys.readouterr().out == ""
