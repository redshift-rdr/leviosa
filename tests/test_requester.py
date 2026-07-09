import asyncio
from contextlib import aclosing

import aiohttp
import pytest
from aioresponses import CallbackResult, aioresponses

from core.config import Config
from core.models import LeviosaRequest, Param
from core.requester import (
    _build_kwargs,
    _parse_headers,
    _split_proxy_auth,
    resolve_proxy,
    send,
)


# ---------------------------------------------------------------------------
# resolve_proxy / _split_proxy_auth unit tests
# ---------------------------------------------------------------------------

class TestResolveProxy:
    def test_default_is_direct(self):
        assert resolve_proxy(Config(), use_burp=False) == (None, None)

    def test_use_burp_routes_to_burp_endpoint(self):
        c = Config(burp_host="127.0.0.1", burp_port=8080)
        url, auth = resolve_proxy(c, use_burp=True)
        assert url == "http://127.0.0.1:8080"
        assert auth is None

    def test_custom_proxy_used_for_non_burp(self):
        c = Config(proxy_url="http://127.0.0.1:8081")
        url, auth = resolve_proxy(c, use_burp=False)
        assert url == "http://127.0.0.1:8081"
        assert auth is None

    def test_burp_opt_in_beats_custom_proxy(self):
        c = Config(proxy_url="http://127.0.0.1:8081")
        url, _ = resolve_proxy(c, use_burp=True)
        assert url == "http://127.0.0.1:8080"

    def test_no_proxy_overrides_burp(self):
        c = Config(no_proxy=True)
        assert resolve_proxy(c, use_burp=True) == (None, None)

    def test_no_proxy_overrides_custom(self):
        c = Config(no_proxy=True, proxy_url="http://127.0.0.1:8081")
        assert resolve_proxy(c, use_burp=False) == (None, None)

    def test_custom_proxy_credentials_split_out(self):
        c = Config(proxy_url="http://user:pass@127.0.0.1:8081")
        url, auth = resolve_proxy(c, use_burp=False)
        # Credentials are stripped from the URL (so it is safe to log) and
        # returned as BasicAuth.
        assert url == "http://127.0.0.1:8081"
        assert auth == aiohttp.BasicAuth("user", "pass")


class TestSplitProxyAuth:
    def test_no_credentials(self):
        assert _split_proxy_auth("http://127.0.0.1:8081") == (
            "http://127.0.0.1:8081",
            None,
        )

    def test_with_credentials(self):
        url, auth = _split_proxy_auth("http://user:pass@host:9000")
        assert url == "http://host:9000"
        assert auth == aiohttp.BasicAuth("user", "pass")


async def collect(requests, config, read_body=True):
    """Drain the streaming engine into a list (completion order)."""
    return [r async for r in send(requests, config, read_body=read_body)]


def make_request(url="http://example.com", method="GET", params=None, headers=None):
    return LeviosaRequest(
        method=method,
        url=url,
        headers=headers or [],
        params=params or [],
    )


@pytest.fixture
def cfg():
    return Config()


# ---------------------------------------------------------------------------
# _parse_headers unit tests
# ---------------------------------------------------------------------------

class TestParseHeaders:
    def test_single_header(self):
        assert _parse_headers(["Host: example.com"]) == {"Host": "example.com"}

    def test_request_line_skipped(self):
        result = _parse_headers(["GET /path HTTP/1.1", "Host: example.com"])
        assert result == {"Host": "example.com"}

    def test_head_request_line_skipped(self):
        result = _parse_headers(["HEAD /api/ HTTP/1.1", "Accept: */*"])
        assert result == {"Accept": "*/*"}

    def test_multiple_headers(self):
        result = _parse_headers(["Host: a.com", "Accept: application/json"])
        assert result["Host"] == "a.com"
        assert result["Accept"] == "application/json"

    def test_empty_list(self):
        assert _parse_headers([]) == {}

    def test_colon_in_value_preserved(self):
        result = _parse_headers(["Authorization: Bearer abc:def"])
        assert result["Authorization"] == "Bearer abc:def"

    def test_real_example_headers(self):
        raw = [
            "GET /rest/products/1/reviews HTTP/1.1",
            "Host: localhost:3000",
            "Accept: application/json, text/plain, */*",
            "Cookie: language=en",
        ]
        result = _parse_headers(raw)
        assert "Host" in result
        assert "Accept" in result
        assert "Cookie" in result
        assert len(result) == 3  # request line excluded


# ---------------------------------------------------------------------------
# _build_kwargs unit tests
# ---------------------------------------------------------------------------

class TestBuildKwargs:
    def test_cookie_params(self):
        kwargs, _ = _build_kwargs([Param(type="cookie", name="session", value="xyz")])
        assert kwargs["cookies"] == {"session": "xyz"}

    def test_json_params(self):
        kwargs, _ = _build_kwargs([Param(type="json", name="email", value="a@b.com")])
        assert kwargs["json"] == {"email": "a@b.com"}

    def test_query_params(self):
        kwargs, _ = _build_kwargs([Param(type="query", name="q", value="search")])
        assert kwargs["params"] == {"q": "search"}

    def test_form_params(self):
        kwargs, _ = _build_kwargs([Param(type="form", name="field", value="val")])
        assert kwargs["data"] == {"field": "val"}

    def test_header_params_in_extra(self):
        _, extra = _build_kwargs([Param(type="header", name="X-Token", value="abc")])
        assert extra == {"X-Token": "abc"}

    def test_header_params_not_in_kwargs(self):
        kwargs, _ = _build_kwargs([Param(type="header", name="X-Token", value="abc")])
        assert "X-Token" not in kwargs

    def test_empty_params(self):
        kwargs, extra = _build_kwargs([])
        assert kwargs == {}
        assert extra == {}

    def test_no_spurious_empty_keys(self):
        kwargs, _ = _build_kwargs([Param(type="json", name="k", value="v")])
        assert "cookies" not in kwargs
        assert "params" not in kwargs
        assert "data" not in kwargs

    def test_multiple_param_types(self):
        params = [
            Param(type="cookie", name="c", value="1"),
            Param(type="json", name="j", value="2"),
            Param(type="query", name="q", value="3"),
        ]
        kwargs, _ = _build_kwargs(params)
        assert "cookies" in kwargs
        assert "json" in kwargs
        assert "params" in kwargs


# ---------------------------------------------------------------------------
# send() integration tests (all HTTP calls mocked via aioresponses)
# ---------------------------------------------------------------------------

class TestSend:
    async def test_status_code_captured(self, cfg):
        with aioresponses() as m:
            m.get("http://example.com", status=200, body=b"")
            responses = await collect([make_request()], cfg)
        assert responses[0].status == 200

    async def test_body_captured(self, cfg):
        with aioresponses() as m:
            m.get("http://example.com", status=200, body=b"hello world")
            responses = await collect([make_request()], cfg)
        assert responses[0].body == b"hello world"

    async def test_request_back_reference(self, cfg):
        req = make_request()
        with aioresponses() as m:
            m.get("http://example.com", status=200, body=b"")
            responses = await collect([req], cfg)
        assert responses[0].request is req

    async def test_all_requests_returned(self, cfg):
        with aioresponses() as m:
            m.get("http://a.com", status=200, body=b"")
            m.get("http://b.com", status=404, body=b"")
            m.get("http://c.com", status=500, body=b"")
            responses = await collect(
                [make_request("http://a.com"), make_request("http://b.com"), make_request("http://c.com")],
                cfg,
            )
        assert len(responses) == 3

    async def test_all_responses_delivered_regardless_of_order(self, cfg):
        # Output is completion-ordered, so match statuses to URLs via a dict.
        with aioresponses() as m:
            m.get("http://a.com", status=200, body=b"")
            m.get("http://b.com", status=201, body=b"")
            m.get("http://c.com", status=202, body=b"")
            responses = await collect(
                [make_request("http://a.com"), make_request("http://b.com"), make_request("http://c.com")],
                cfg,
            )
        by_url = {r.request.url: r.status for r in responses}
        assert by_url == {
            "http://a.com": 200,
            "http://b.com": 201,
            "http://c.com": 202,
        }

    async def test_head_method(self, cfg):
        with aioresponses() as m:
            m.head("http://example.com", status=200, body=b"")
            responses = await collect([make_request(method="HEAD")], cfg)
        assert responses[0].status == 200

    async def test_post_method(self, cfg):
        with aioresponses() as m:
            m.post("http://example.com", status=201, body=b"")
            req = make_request(method="POST", params=[Param(type="json", name="k", value="v")])
            responses = await collect([req], cfg)
        assert responses[0].status == 201

    async def test_client_error_returns_zero_status(self, cfg):
        with aioresponses() as m:
            m.get("http://example.com", exception=aiohttp.ClientConnectionError())
            responses = await collect([make_request()], cfg)
        assert responses[0].status == 0
        assert responses[0].body == b""

    async def test_error_does_not_block_other_requests(self, cfg):
        with aioresponses() as m:
            m.get("http://fail.com", exception=aiohttp.ClientConnectionError())
            m.get("http://ok.com", status=200, body=b"")
            responses = await collect(
                [make_request("http://fail.com"), make_request("http://ok.com")],
                cfg,
            )
        assert len(responses) == 2
        by_url = {r.request.url: r.status for r in responses}
        assert by_url["http://fail.com"] == 0
        assert by_url["http://ok.com"] == 200

    async def test_concurrency_limit_completes_all(self, cfg):
        cfg.concurrency = 2
        with aioresponses() as m:
            for i in range(10):
                m.get(f"http://example.com/page{i}", status=200, body=b"")
            requests = [make_request(f"http://example.com/page{i}") for i in range(10)]
            responses = await collect(requests, cfg)
        assert len(responses) == 10
        assert all(r.status == 200 for r in responses)

    async def test_concurrency_never_exceeds_limit(self, cfg):
        cfg.concurrency = 3
        in_flight = 0
        max_in_flight = 0

        async def counting_callback(url, **kwargs):
            nonlocal in_flight, max_in_flight
            in_flight += 1
            max_in_flight = max(max_in_flight, in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1
            return CallbackResult(status=200, body=b"")

        with aioresponses() as m:
            for i in range(9):
                m.get(f"http://example.com/p{i}", callback=counting_callback)
            requests = [make_request(f"http://example.com/p{i}") for i in range(9)]
            await collect(requests, cfg)

        assert max_in_flight <= 3

    async def test_proxy_passed_does_not_raise(self):
        config = Config()
        with aioresponses() as m:
            m.get("http://example.com", status=200, body=b"")
            responses = [
                r async for r in send(
                    [make_request()], config, proxy="http://127.0.0.1:8080"
                )
            ]
        assert responses[0].status == 200

    async def test_header_from_request_sent(self, cfg):
        req = make_request(headers=["GET /path HTTP/1.1", "X-Custom: testval"])
        with aioresponses() as m:
            m.get("http://example.com", status=200, body=b"")
            responses = await collect([req], cfg)
        assert responses[0].status == 200


# ---------------------------------------------------------------------------
# Body cap / read_body
# ---------------------------------------------------------------------------

class TestBodyCap:
    async def test_body_truncated_to_cap(self, cfg):
        cfg.max_body_bytes = 10
        with aioresponses() as m:
            m.get("http://example.com", status=200, body=b"x" * 100)
            responses = await collect([make_request()], cfg)
        assert responses[0].body == b"x" * 10

    async def test_cap_zero_reads_full_body(self, cfg):
        cfg.max_body_bytes = 0
        with aioresponses() as m:
            m.get("http://example.com", status=200, body=b"y" * 5000)
            responses = await collect([make_request()], cfg)
        assert responses[0].body == b"y" * 5000

    async def test_body_shorter_than_cap_untouched(self, cfg):
        cfg.max_body_bytes = 1000
        with aioresponses() as m:
            m.get("http://example.com", status=200, body=b"short")
            responses = await collect([make_request()], cfg)
        assert responses[0].body == b"short"

    async def test_read_body_false_yields_empty_body(self, cfg):
        with aioresponses() as m:
            m.get("http://example.com", status=200, body=b"hello world")
            responses = await collect([make_request()], cfg, read_body=False)
        assert responses[0].status == 200
        assert responses[0].body == b""


# ---------------------------------------------------------------------------
# Deterministic cleanup — abandoning the stream must not leak tasks/sessions
# ---------------------------------------------------------------------------

class TestCleanup:
    def _pending(self):
        return [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]

    async def test_early_break_leaves_no_pending_tasks(self, cfg):
        cfg.concurrency = 5
        with aioresponses() as m:
            for i in range(20):
                m.get(f"http://example.com/p{i}", status=200, body=b"")
            requests = [make_request(f"http://example.com/p{i}") for i in range(20)]
            async with aclosing(send(iter(requests), cfg)) as stream:
                async for _ in stream:
                    break
        await asyncio.sleep(0)  # let cancellations settle
        assert self._pending() == []

    async def test_exception_in_consumer_leaves_no_pending_tasks(self, cfg):
        cfg.concurrency = 5

        class Boom(Exception):
            pass

        with aioresponses() as m:
            for i in range(20):
                m.get(f"http://example.com/p{i}", status=200, body=b"")
            requests = [make_request(f"http://example.com/p{i}") for i in range(20)]
            with pytest.raises(Boom):
                async with aclosing(send(iter(requests), cfg)) as stream:
                    async for _ in stream:
                        raise Boom()
        await asyncio.sleep(0)
        assert self._pending() == []
