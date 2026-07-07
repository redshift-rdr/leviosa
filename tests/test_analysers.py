import re

import pytest

from core.analysers import (
    HeaderAnalyser,
    RegexAnalyser,
    ResponseSizeAnalyser,
    StatusCodeAnalyser,
    TextMatchAnalyser,
)
from core.models import LeviosaRequest, LeviosaResponse


def make_response(
    status: int = 200,
    body: bytes = b"",
    headers: dict | None = None,
) -> LeviosaResponse:
    req = LeviosaRequest(method="GET", url="http://example.com/", headers=[], params=[])
    return LeviosaResponse(
        status=status,
        headers=headers or {},
        body=body,
        request=req,
    )


# ---------------------------------------------------------------------------
# StatusCodeAnalyser
# ---------------------------------------------------------------------------

class TestStatusCodeAnalyser:
    def test_matches_listed_code(self):
        assert StatusCodeAnalyser([200]).matches(make_response(200)) is not None

    def test_no_match_for_unlisted_code(self):
        assert StatusCodeAnalyser([200]).matches(make_response(404)) is None

    def test_matches_any_in_list(self):
        a = StatusCodeAnalyser([200, 403, 500])
        assert a.matches(make_response(200)) is not None
        assert a.matches(make_response(403)) is not None
        assert a.matches(make_response(500)) is not None

    def test_no_match_outside_list(self):
        assert StatusCodeAnalyser([200, 403]).matches(make_response(301)) is None

    def test_description_contains_status(self):
        result = StatusCodeAnalyser([403]).matches(make_response(403))
        assert "403" in result

    def test_description_format(self):
        assert StatusCodeAnalyser([200]).matches(make_response(200)) == "status=200"

    def test_empty_codes_never_matches(self):
        assert StatusCodeAnalyser([]).matches(make_response(200)) is None


# ---------------------------------------------------------------------------
# TextMatchAnalyser
# ---------------------------------------------------------------------------

class TestTextMatchAnalyser:
    def test_matches_present_text(self):
        r = make_response(body=b"hello admin world")
        assert TextMatchAnalyser("admin").matches(r) is not None

    def test_no_match_absent_text(self):
        r = make_response(body=b"nothing here")
        assert TextMatchAnalyser("admin").matches(r) is None

    def test_case_sensitive_by_default(self):
        r = make_response(body=b"Admin panel")
        assert TextMatchAnalyser("admin").matches(r) is None

    def test_case_insensitive_flag(self):
        r = make_response(body=b"Admin panel")
        assert TextMatchAnalyser("admin", case_sensitive=False).matches(r) is not None

    def test_case_insensitive_no_false_positive(self):
        r = make_response(body=b"nothing")
        assert TextMatchAnalyser("admin", case_sensitive=False).matches(r) is None

    def test_description_contains_text(self):
        r = make_response(body=b"root:x:0:0")
        result = TextMatchAnalyser("root").matches(r)
        assert "root" in result

    def test_description_format(self):
        r = make_response(body=b"secret")
        assert TextMatchAnalyser("secret").matches(r) == "body contains 'secret'"

    def test_binary_body_decoded_leniently(self):
        # Invalid UTF-8 bytes should not raise
        r = make_response(body=b"\xff\xfe" + b"admin")
        assert TextMatchAnalyser("admin").matches(r) is not None

    def test_empty_body_no_match(self):
        assert TextMatchAnalyser("admin").matches(make_response(body=b"")) is None


# ---------------------------------------------------------------------------
# RegexAnalyser
# ---------------------------------------------------------------------------

class TestRegexAnalyser:
    def test_matches_pattern(self):
        r = make_response(body=b"error: syntax near 'DROP'")
        assert RegexAnalyser(r"syntax.*DROP").matches(r) is not None

    def test_no_match_for_non_matching_body(self):
        r = make_response(body=b"everything is fine")
        assert RegexAnalyser(r"syntax.*DROP").matches(r) is None

    def test_case_insensitive_flag(self):
        r = make_response(body=b"SQL Syntax Error")
        assert RegexAnalyser(r"sql syntax", flags=re.IGNORECASE).matches(r) is not None

    def test_multiline_flag(self):
        r = make_response(body=b"line one\nERROR: something")
        assert RegexAnalyser(r"^ERROR", flags=re.MULTILINE).matches(r) is not None

    def test_description_contains_pattern(self):
        r = make_response(body=b"stack trace: Exception")
        result = RegexAnalyser(r"stack trace").matches(r)
        assert "stack trace" in result

    def test_description_format(self):
        r = make_response(body=b"admin")
        assert RegexAnalyser(r"admin").matches(r) == "body matches /admin/"

    def test_empty_body_no_match(self):
        assert RegexAnalyser(r"\w+").matches(make_response(body=b"")) is None

    def test_binary_body_decoded_leniently(self):
        r = make_response(body=b"\xff\xfetarget_string")
        assert RegexAnalyser(r"target_string").matches(r) is not None


# ---------------------------------------------------------------------------
# ResponseSizeAnalyser
# ---------------------------------------------------------------------------

class TestResponseSizeAnalyser:
    def test_within_range_matches(self):
        r = make_response(body=b"x" * 500)
        assert ResponseSizeAnalyser(min_size=100, max_size=1000).matches(r) is not None

    def test_below_min_no_match(self):
        r = make_response(body=b"x" * 50)
        assert ResponseSizeAnalyser(min_size=100).matches(r) is None

    def test_above_max_no_match(self):
        r = make_response(body=b"x" * 2000)
        assert ResponseSizeAnalyser(max_size=1000).matches(r) is None

    def test_exactly_at_min_matches(self):
        r = make_response(body=b"x" * 100)
        assert ResponseSizeAnalyser(min_size=100).matches(r) is not None

    def test_exactly_at_max_matches(self):
        r = make_response(body=b"x" * 100)
        assert ResponseSizeAnalyser(max_size=100).matches(r) is not None

    def test_min_only(self):
        r = make_response(body=b"x" * 200)
        assert ResponseSizeAnalyser(min_size=100).matches(r) is not None

    def test_max_only(self):
        r = make_response(body=b"x" * 50)
        assert ResponseSizeAnalyser(max_size=100).matches(r) is not None

    def test_neither_raises(self):
        with pytest.raises(ValueError):
            ResponseSizeAnalyser()

    def test_empty_body_matches_max_only(self):
        assert ResponseSizeAnalyser(max_size=100).matches(make_response(body=b"")) is not None

    def test_description_contains_size(self):
        r = make_response(body=b"x" * 42)
        result = ResponseSizeAnalyser(min_size=1).matches(r)
        assert "42" in result

    def test_description_format(self):
        r = make_response(body=b"hello")
        assert ResponseSizeAnalyser(min_size=1).matches(r) == "size=5"


# ---------------------------------------------------------------------------
# HeaderAnalyser
# ---------------------------------------------------------------------------

class TestHeaderAnalyser:
    def test_presence_check_header_exists(self):
        r = make_response(headers={"Server": "Apache"})
        assert HeaderAnalyser("Server").matches(r) is not None

    def test_presence_check_header_absent(self):
        r = make_response(headers={})
        assert HeaderAnalyser("Server").matches(r) is None

    def test_header_name_case_insensitive(self):
        r = make_response(headers={"content-type": "text/html"})
        assert HeaderAnalyser("Content-Type").matches(r) is not None

    def test_value_match_exact(self):
        r = make_response(headers={"Server": "Apache/2.4"})
        assert HeaderAnalyser("Server", value="Apache/2.4").matches(r) is not None

    def test_value_match_case_insensitive(self):
        r = make_response(headers={"Server": "APACHE/2.4"})
        assert HeaderAnalyser("Server", value="apache/2.4").matches(r) is not None

    def test_value_mismatch_no_match(self):
        r = make_response(headers={"Server": "nginx"})
        assert HeaderAnalyser("Server", value="Apache").matches(r) is None

    def test_pattern_match(self):
        r = make_response(headers={"Server": "Apache/2.4.51"})
        assert HeaderAnalyser("Server", pattern=r"Apache/\d").matches(r) is not None

    def test_pattern_no_match(self):
        r = make_response(headers={"Server": "nginx/1.18"})
        assert HeaderAnalyser("Server", pattern=r"Apache/\d").matches(r) is None

    def test_pattern_takes_priority_over_value(self):
        # When both pattern and value given, pattern is used
        r = make_response(headers={"Server": "Apache/2.4"})
        result = HeaderAnalyser("Server", value="ignored", pattern=r"Apache").matches(r)
        assert result is not None

    def test_description_contains_header_name(self):
        r = make_response(headers={"X-Powered-By": "PHP/8.1"})
        result = HeaderAnalyser("X-Powered-By").matches(r)
        assert "X-Powered-By" in result

    def test_description_contains_header_value(self):
        r = make_response(headers={"Server": "IIS/10"})
        result = HeaderAnalyser("Server").matches(r)
        assert "IIS/10" in result

    def test_description_format(self):
        r = make_response(headers={"Server": "Apache"})
        assert HeaderAnalyser("Server").matches(r) == "header Server: Apache"
