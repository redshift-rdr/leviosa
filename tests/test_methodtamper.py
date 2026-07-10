import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from modules.methodtamper import (
    MethodTamper,
    _DEFAULT_METHODS,
    _DEFAULT_OVERRIDE_HEADERS,
    _DEFAULT_OVERRIDE_METHODS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(url="http://example.com/", method="GET", headers=None):
    return LeviosaRequest(method=method, url=url, headers=headers or [], params=[])


def make_response(method="GET", status=200, headers=None, url="http://example.com/",
                  req_headers=None):
    req = make_request(url=url, method=method, headers=req_headers)
    return LeviosaResponse(status=status, headers=headers or {}, body=b"", request=req)


async def run(module, responses, context=None):
    context = context or LeviosaContext()
    for resp in responses:
        await module.analyze_one(resp, context)
    await module.finalize(context)
    return context


def configured(args=None):
    m = MethodTamper()
    m.setup(args or [])
    return m


# ---------------------------------------------------------------------------
# Loader compatibility
# ---------------------------------------------------------------------------

def test_loads_via_loader():
    from core.loader import load_modules
    instances = load_modules(["methodtamper"])
    assert len(instances) == 1
    assert type(instances[0]).__name__ == "MethodTamper"


def test_needs_body_false():
    assert MethodTamper.needs_body is False


def test_does_not_opt_into_burp_by_default():
    assert MethodTamper.use_burp is False


# ---------------------------------------------------------------------------
# mutate — variant generation
# ---------------------------------------------------------------------------

class TestMutate:
    async def test_emits_baseline_plus_methods_plus_overrides(self):
        m = configured()
        variants = list(await m.mutate([make_request(method="GET")], LeviosaContext()))
        # baseline + each method + (headers x override methods)
        expected = (
            1
            + len(_DEFAULT_METHODS)
            + len(_DEFAULT_OVERRIDE_HEADERS) * len(_DEFAULT_OVERRIDE_METHODS)
        )
        assert len(variants) == expected

    async def test_baseline_is_first_and_unchanged(self):
        req = make_request(method="POST")
        m = configured()
        variants = list(await m.mutate([req], LeviosaContext()))
        assert variants[0] is req

    async def test_records_baseline_method(self):
        m = configured()
        list(await m.mutate([make_request(url="http://x/", method="POST")], LeviosaContext()))
        assert m._original_method["http://x/"] == "POST"

    async def test_method_variants_present(self):
        m = configured()
        variants = list(await m.mutate([make_request(method="GET")], LeviosaContext()))
        methods = {v.method for v in variants}
        assert "TRACE" in methods and "DELETE" in methods and "FOOBAR" in methods

    async def test_override_variants_carry_header(self):
        m = configured()
        variants = list(await m.mutate([make_request(method="GET")], LeviosaContext()))
        override_headers = [
            h for v in variants for h in v.headers
            if h.lower().startswith("x-http-method-override:")
        ]
        assert any("DELETE" in h for h in override_headers)

    async def test_override_variants_use_post(self):
        # Override variants are sent as POST regardless of the seed method.
        m = configured()
        variants = list(await m.mutate([make_request(method="GET")], LeviosaContext()))
        override_variants = [
            v for v in variants
            if any(h.lower().startswith("x-http-method-override:") for h in v.headers)
        ]
        assert override_variants
        assert all(v.method == "POST" for v in override_variants)

    async def test_no_override_flag(self):
        m = configured(["--no-override"])
        variants = list(await m.mutate([make_request(method="GET")], LeviosaContext()))
        assert len(variants) == 1 + len(_DEFAULT_METHODS)
        assert not any("override" in h.lower() for v in variants for h in v.headers)

    async def test_does_not_mutate_seed_request(self):
        req = make_request(method="GET", headers=["Accept: */*"])
        m = configured()
        list(await m.mutate([req], LeviosaContext()))
        assert req.headers == ["Accept: */*"] and req.method == "GET"

    async def test_custom_methods_flag(self):
        m = configured(["--methods", "get,put"])
        variants = list(await m.mutate([make_request()], LeviosaContext()))
        # override still on by default
        method_variants = variants[1:1 + 2]
        assert [v.method for v in method_variants] == ["GET", "PUT"]


# ---------------------------------------------------------------------------
# _findings — detection logic
# ---------------------------------------------------------------------------

class TestFindings:
    def test_trace_200_is_xst(self):
        m = configured()
        f = m._findings(make_response(method="TRACE", status=200))
        assert any("Cross-Site Tracing" in x for x in f)

    def test_track_200_is_xst(self):
        m = configured()
        f = m._findings(make_response(method="TRACK", status=200))
        assert any("Cross-Site Tracing" in x for x in f)

    def test_trace_405_is_clean(self):
        m = configured()
        assert m._findings(make_response(method="TRACE", status=405)) == []

    def test_delete_200_flagged(self):
        m = configured()
        f = m._findings(make_response(method="DELETE", status=200))
        assert any("state-changing method enabled" in x for x in f)

    def test_put_405_clean(self):
        m = configured()
        assert m._findings(make_response(method="PUT", status=405)) == []

    def test_connect_200_flagged(self):
        m = configured()
        f = m._findings(make_response(method="CONNECT", status=200))
        assert any("tunnelling" in x for x in f)

    def test_invalid_method_accepted(self):
        m = configured()
        f = m._findings(make_response(method="FOOBAR", status=200))
        assert any("no method whitelist" in x for x in f)

    def test_invalid_method_rejected_clean(self):
        m = configured()
        assert m._findings(make_response(method="FOOBAR", status=501)) == []

    def test_options_allow_dangerous(self):
        m = configured()
        f = m._findings(make_response(
            method="OPTIONS", status=200, headers={"Allow": "GET, POST, PUT, DELETE"}
        ))
        assert any("advertises dangerous methods: DELETE, PUT" in x for x in f)

    def test_options_allow_safe_clean(self):
        m = configured()
        assert m._findings(make_response(
            method="OPTIONS", status=200, headers={"Allow": "GET, HEAD, POST"}
        )) == []

    def test_override_dangerous_accepted(self):
        m = configured()
        resp = make_response(
            method="POST", status=200,
            req_headers=["X-HTTP-Method-Override: DELETE"],
        )
        f = m._findings(resp)
        assert any("override X-HTTP-Method-Override: DELETE accepted (200)" in x for x in f)

    def test_override_rejected_clean(self):
        m = configured()
        resp = make_response(
            method="POST", status=405,
            req_headers=["X-HTTP-Method-Override: DELETE"],
        )
        assert m._findings(resp) == []


# ---------------------------------------------------------------------------
# analyze_one / finalize — output and differences report
# ---------------------------------------------------------------------------

class TestOutput:
    async def test_prints_finding(self, capsys):
        await run(configured(), [make_response(method="TRACE", status=200, url="http://x/")])
        out = capsys.readouterr().out
        assert "[METHODTAMPER]" in out
        assert "Cross-Site Tracing" in out
        assert "http://x/" in out

    async def test_network_error_skipped(self, capsys):
        await run(configured(), [make_response(method="TRACE", status=0)])
        assert capsys.readouterr().out == ""

    async def test_finalize_tally_with_counts(self, capsys):
        responses = [
            make_response(method="TRACE", status=200, url="http://a/"),
            make_response(method="TRACE", status=200, url="http://b/"),
        ]
        await run(configured(), responses)
        out = capsys.readouterr().out
        assert "interesting method behaviours (unique)" in out
        assert "(2 responses)" in out

    async def test_differences_report_flags_deviations(self, capsys):
        # Seed baseline GET=404; DELETE returns 200 → a difference.
        m = configured()
        m._original_method["http://x/"] = "GET"
        responses = [
            make_response(method="GET", status=404, url="http://x/"),
            make_response(method="DELETE", status=200, url="http://x/"),
            make_response(method="HEAD", status=404, url="http://x/"),  # same as baseline
        ]
        await run(m, responses)
        out = capsys.readouterr().out
        assert "response-code differences vs baseline" in out
        assert "baseline GET=404" in out
        assert "DELETE=200" in out
        assert "HEAD=" not in out  # unchanged, filtered out

    async def test_no_differences_no_report(self, capsys):
        m = configured()
        m._original_method["http://x/"] = "GET"
        responses = [
            make_response(method="GET", status=200, url="http://x/"),
            make_response(method="HEAD", status=200, url="http://x/"),
        ]
        await run(m, responses)
        assert "differences" not in capsys.readouterr().out

    async def test_uses_namespaced_context_keys(self):
        ctx = await run(configured(), [make_response(method="TRACE", status=200)])
        assert "methodtamper.findings" in ctx.data
        assert "methodtamper.matrix" in ctx.data
