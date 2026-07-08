import json

import pytest

from core.cookies import (
    apply_overrides,
    cookies_from_request,
    overrides_from_donor,
    overrides_from_header_string,
    parse_cookie_header,
    with_cookie_overrides,
)
from core.models import LeviosaRequest, Param


def make_request(url="http://x.com/", headers=None, params=None, method="GET"):
    return LeviosaRequest(
        method=method,
        url=url,
        headers=headers if headers is not None else [],
        params=params if params is not None else [],
    )


def captured_request(session="OLD", extra_cookie="language=en"):
    """A request shaped like a Burp capture: cookies in both header and params."""
    return make_request(
        headers=[
            "GET /path HTTP/1.1",
            "Host: x.com",
            f"Cookie: {extra_cookie}; session={session}",
        ],
        params=[
            Param(type="cookie", name="language", value="en"),
            Param(type="cookie", name="session", value=session),
            Param(type="json", name="email", value="a@b.com"),
        ],
    )


# ---------------------------------------------------------------------------
# parse_cookie_header
# ---------------------------------------------------------------------------

class TestParseCookieHeader:
    def test_single(self):
        assert parse_cookie_header("session=abc") == [("session", "abc")]

    def test_multiple_ordered(self):
        assert parse_cookie_header("a=1; b=2; c=3") == [("a", "1"), ("b", "2"), ("c", "3")]

    def test_whitespace_trimmed(self):
        assert parse_cookie_header("  a =  1 ;b= 2 ") == [("a", "1"), ("b", "2")]

    def test_value_with_equals(self):
        # base64-ish JWT values contain '=' padding
        assert parse_cookie_header("t=ab==") == [("t", "ab==")]

    def test_blank_tokens_ignored(self):
        assert parse_cookie_header("a=1;; ;b=2") == [("a", "1"), ("b", "2")]

    def test_empty(self):
        assert parse_cookie_header("") == []


# ---------------------------------------------------------------------------
# overrides_from_header_string
# ---------------------------------------------------------------------------

class TestOverridesFromHeaderString:
    def test_builds_map(self):
        assert overrides_from_header_string("session=abc; csrf=xyz") == {
            "session": "abc",
            "csrf": "xyz",
        }


# ---------------------------------------------------------------------------
# cookies_from_request / overrides_from_donor
# ---------------------------------------------------------------------------

class TestCookiesFromRequest:
    def test_extracts_from_params_and_header(self):
        req = captured_request(session="FRESH")
        cookies = cookies_from_request(req)
        assert cookies["session"] == "FRESH"
        assert cookies["language"] == "en"

    def test_params_win_over_header(self):
        req = make_request(
            headers=["Cookie: session=HEADER"],
            params=[Param(type="cookie", name="session", value="PARAM")],
        )
        assert cookies_from_request(req)["session"] == "PARAM"

    def test_header_only_cookie_extracted(self):
        req = make_request(headers=["Cookie: only=header"])
        assert cookies_from_request(req) == {"only": "header"}

    def test_non_cookie_params_ignored(self):
        req = make_request(params=[Param(type="json", name="x", value="y")])
        assert cookies_from_request(req) == {}


class TestOverridesFromDonor:
    def test_reads_fresh_cookies(self, tmp_path):
        donor = tmp_path / "fresh.json"
        donor.write_text(json.dumps([{
            "method": "GET",
            "url": "http://x.com/",
            "headers": ["Cookie: session=NEWSESSION; csrf=NEWCSRF"],
            "params": [
                {"type": "cookie", "name": "session", "value": "NEWSESSION"},
                {"type": "cookie", "name": "csrf", "value": "NEWCSRF"},
            ],
        }]))
        assert overrides_from_donor(str(donor)) == {
            "session": "NEWSESSION",
            "csrf": "NEWCSRF",
        }

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            overrides_from_donor("/nonexistent/fresh.json")


# ---------------------------------------------------------------------------
# apply_overrides — replace by name in BOTH places
# ---------------------------------------------------------------------------

class TestApplyOverrides:
    def test_replaces_param_value(self):
        req = captured_request(session="OLD")
        out = apply_overrides(req, {"session": "NEW"})
        session_params = [p.value for p in out.params if p.name == "session"]
        assert session_params == ["NEW"]

    def test_replaces_header_value(self):
        req = captured_request(session="OLD")
        out = apply_overrides(req, {"session": "NEW"})
        cookie_header = next(h for h in out.headers if h.startswith("Cookie:"))
        assert "session=NEW" in cookie_header
        assert "session=OLD" not in cookie_header

    def test_untouched_cookies_preserved(self):
        req = captured_request(session="OLD")
        out = apply_overrides(req, {"session": "NEW"})
        cookie_header = next(h for h in out.headers if h.startswith("Cookie:"))
        assert "language=en" in cookie_header
        assert any(p.name == "language" and p.value == "en" for p in out.params)

    def test_non_cookie_params_preserved(self):
        req = captured_request(session="OLD")
        out = apply_overrides(req, {"session": "NEW"})
        assert any(p.type == "json" and p.name == "email" for p in out.params)

    def test_unrelated_headers_untouched(self):
        req = captured_request(session="OLD")
        out = apply_overrides(req, {"session": "NEW"})
        assert "Host: x.com" in out.headers
        assert "GET /path HTTP/1.1" in out.headers

    def test_name_not_present_is_noop(self):
        req = captured_request(session="OLD")
        out = apply_overrides(req, {"doesnotexist": "X"})
        assert out.params == req.params
        assert out.headers == req.headers

    def test_original_request_not_mutated(self):
        req = captured_request(session="OLD")
        apply_overrides(req, {"session": "NEW"})
        assert any(p.name == "session" and p.value == "OLD" for p in req.params)
        assert any("session=OLD" in h for h in req.headers)

    def test_header_cookie_replaced_even_without_matching_param(self):
        req = make_request(headers=["Cookie: session=OLD"])
        out = apply_overrides(req, {"session": "NEW"})
        assert out.headers == ["Cookie: session=NEW"]

    def test_cookie_header_ordering_and_format_preserved(self):
        req = make_request(headers=["Cookie: a=1; session=OLD; b=2"])
        out = apply_overrides(req, {"session": "NEW"})
        assert out.headers == ["Cookie: a=1; session=NEW; b=2"]


# ---------------------------------------------------------------------------
# with_cookie_overrides — source-layer wrapper
# ---------------------------------------------------------------------------

class TestWithCookieOverrides:
    def test_noop_when_empty(self):
        def source():
            return iter([make_request()])

        assert with_cookie_overrides(source, {}) is source

    def test_applies_to_every_request(self):
        reqs = [captured_request(session="OLD"), captured_request(session="OLD")]

        def source():
            return iter(reqs)

        wrapped = with_cookie_overrides(source, {"session": "NEW"})
        out = list(wrapped())
        assert all(
            any(p.name == "session" and p.value == "NEW" for p in r.params)
            for r in out
        )

    def test_fresh_iterator_each_call(self):
        def source():
            return iter([captured_request(session="OLD")])

        wrapped = with_cookie_overrides(source, {"session": "NEW"})
        first = list(wrapped())
        second = list(wrapped())
        assert len(first) == len(second) == 1

    def test_is_lazy(self):
        import types

        def source():
            return iter([captured_request()])

        wrapped = with_cookie_overrides(source, {"session": "NEW"})
        assert isinstance(wrapped(), types.GeneratorType)
