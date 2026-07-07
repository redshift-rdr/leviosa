import json
import pytest
from pathlib import Path

from core.parsers import parse_url, parse_url_file, parse_request_file, detect_and_parse

EXAMPLE_JSON = Path(__file__).parent.parent / "example_requests_input_file.json"


class TestParseUrl:
    def test_returns_single_request(self):
        assert len(parse_url("http://example.com/path")) == 1

    def test_method_is_get(self):
        assert parse_url("http://example.com")[0].method == "GET"

    def test_url_preserved(self):
        url = "http://example.com/test?foo=bar"
        assert parse_url(url)[0].url == url

    def test_empty_params_and_headers(self):
        req = parse_url("http://example.com")[0]
        assert req.params == []
        assert req.headers == []


class TestParseUrlFile:
    def test_parses_multiple_urls(self, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("http://a.com\nhttp://b.com\nhttp://c.com\n")
        assert len(parse_url_file(str(f))) == 3

    def test_blank_lines_ignored(self, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("http://a.com\n\nhttp://b.com\n\n")
        assert len(parse_url_file(str(f))) == 2

    def test_urls_correct(self, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("http://a.com\nhttp://b.com\n")
        result = parse_url_file(str(f))
        assert result[0].url == "http://a.com"
        assert result[1].url == "http://b.com"

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_url_file("/nonexistent/path/urls.txt")


class TestParseRequestFile:
    def test_parses_all_six_requests(self):
        assert len(parse_request_file(str(EXAMPLE_JSON))) == 6

    def test_methods_correct(self):
        methods = {r.method for r in parse_request_file(str(EXAMPLE_JSON))}
        assert methods == {"GET", "POST", "HEAD"}

    def test_urls_populated(self):
        for req in parse_request_file(str(EXAMPLE_JSON)):
            assert req.url.startswith("http://")

    def test_post_has_cookie_and_json_params(self):
        result = parse_request_file(str(EXAMPLE_JSON))
        post_req = next(r for r in result if r.method == "POST")
        param_types = {p.type for p in post_req.params}
        assert "cookie" in param_types
        assert "json" in param_types

    def test_post_json_params_correct(self):
        result = parse_request_file(str(EXAMPLE_JSON))
        post_req = next(r for r in result if r.method == "POST")
        json_params = {p.name: p.value for p in post_req.params if p.type == "json"}
        assert json_params == {"email": "test@test.com", "password": "password"}

    def test_hashkeys_preserved(self):
        for req in parse_request_file(str(EXAMPLE_JSON)):
            assert req.hashkey is not None

    def test_headers_populated(self):
        for req in parse_request_file(str(EXAMPLE_JSON)):
            assert len(req.headers) > 0

    def test_malformed_json_raises(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{ not valid json }")
        with pytest.raises(json.JSONDecodeError):
            parse_request_file(str(f))

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            parse_request_file("/nonexistent/requests.json")


class TestDetectAndParse:
    def test_http_url(self):
        result = detect_and_parse("http://example.com")
        assert len(result) == 1
        assert result[0].url == "http://example.com"

    def test_https_url(self):
        result = detect_and_parse("https://example.com")
        assert len(result) == 1
        assert result[0].url == "https://example.com"

    def test_json_file(self):
        assert len(detect_and_parse(str(EXAMPLE_JSON))) == 6

    def test_txt_file(self, tmp_path):
        f = tmp_path / "urls.txt"
        f.write_text("http://a.com\nhttp://b.com\n")
        assert len(detect_and_parse(str(f))) == 2
