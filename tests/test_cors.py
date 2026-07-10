import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from modules.cors import Cors, _DEFAULT_EVIL_ORIGIN, _SUBDOMAIN_LABEL


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(url="http://example.com/", method="GET", headers=None):
    return LeviosaRequest(method=method, url=url, headers=headers or [], params=[])


def make_response(headers, request=None, status=200):
    return LeviosaResponse(
        status=status, headers=headers, body=b"",
        request=request or make_request(),
    )


async def run(module, responses, context=None):
    """Drive analyze_one over each response, then finalize."""
    context = context or LeviosaContext()
    for resp in responses:
        await module.analyze_one(resp, context)
    await module.finalize(context)
    return context


def origin_of(req):
    return Cors._request_origin(req)


# ---------------------------------------------------------------------------
# Loader compatibility
# ---------------------------------------------------------------------------

def test_loads_via_loader():
    from core.loader import load_modules
    instances = load_modules(["cors"])
    assert len(instances) == 1
    assert type(instances[0]).__name__ == "Cors"


def test_needs_body_false():
    assert Cors.needs_body is False


def test_does_not_opt_into_burp_by_default():
    assert Cors.use_burp is False


# ---------------------------------------------------------------------------
# mutate — forges Origin headers
# ---------------------------------------------------------------------------

class TestMutate:
    async def test_emits_three_probes_per_request(self):
        m = Cors()
        m.setup([])
        variants = list(await m.mutate([make_request("http://example.com/")], LeviosaContext()))
        origins = [origin_of(v) for v in variants]
        assert origins == [
            _DEFAULT_EVIL_ORIGIN,
            "null",
            f"http://{_SUBDOMAIN_LABEL}.example.com",
        ]

    async def test_subdomain_probe_uses_url_scheme_and_host(self):
        m = Cors()
        m.setup([])
        variants = list(await m.mutate([make_request("https://api.target.io/v1")], LeviosaContext()))
        origins = [origin_of(v) for v in variants]
        assert f"https://{_SUBDOMAIN_LABEL}.api.target.io" in origins

    async def test_replaces_existing_origin_header(self):
        m = Cors()
        m.setup([])
        req = make_request("http://example.com/", headers=["Origin: http://real.com", "Accept: */*"])
        variants = list(await m.mutate([req], LeviosaContext()))
        for v in variants:
            # Exactly one Origin header, and it is one of our probes.
            origins = [h for h in v.headers if h.lower().startswith("origin:")]
            assert len(origins) == 1
            assert "http://real.com" not in origins[0]
            # Unrelated headers are preserved.
            assert "Accept: */*" in v.headers

    async def test_does_not_mutate_seed_request(self):
        m = Cors()
        m.setup([])
        req = make_request("http://example.com/", headers=["Accept: */*"])
        list(await m.mutate([req], LeviosaContext()))
        # The seed's headers list must be untouched (no aliasing via replace).
        assert req.headers == ["Accept: */*"]

    async def test_custom_evil_origin(self):
        m = Cors()
        m.setup(["--evil-origin", "https://attacker.test"])
        variants = list(await m.mutate([make_request()], LeviosaContext()))
        assert "https://attacker.test" in [origin_of(v) for v in variants]


# ---------------------------------------------------------------------------
# analyze_one — detection logic
# ---------------------------------------------------------------------------

class TestAnalyze:
    def _probe_req(self, origin, url="http://example.com/"):
        return make_request(url=url, headers=[f"Origin: {origin}"])

    async def test_reflects_arbitrary_origin(self, capsys):
        m = Cors()
        m.setup([])
        req = self._probe_req(_DEFAULT_EVIL_ORIGIN)
        resp = make_response({"Access-Control-Allow-Origin": _DEFAULT_EVIL_ORIGIN}, request=req)
        ctx = await run(m, [resp])
        out = capsys.readouterr().out
        assert "reflects arbitrary origin" in out
        assert _DEFAULT_EVIL_ORIGIN in out
        assert "cors.findings" in ctx.data

    async def test_reflection_with_credentials_flagged(self, capsys):
        m = Cors()
        m.setup([])
        req = self._probe_req(_DEFAULT_EVIL_ORIGIN)
        resp = make_response({
            "Access-Control-Allow-Origin": _DEFAULT_EVIL_ORIGIN,
            "Access-Control-Allow-Credentials": "true",
        }, request=req)
        await run(m, [resp])
        out = capsys.readouterr().out
        assert "Access-Control-Allow-Credentials: true" in out

    async def test_reflects_subdomain(self, capsys):
        m = Cors()
        m.setup([])
        sub = f"http://{_SUBDOMAIN_LABEL}.example.com"
        req = self._probe_req(sub)
        resp = make_response({"Access-Control-Allow-Origin": sub}, request=req)
        await run(m, [resp])
        assert "reflects arbitrary subdomain of host" in capsys.readouterr().out

    async def test_trusts_null_origin(self, capsys):
        m = Cors()
        m.setup([])
        req = self._probe_req("null")
        resp = make_response({"Access-Control-Allow-Origin": "null"}, request=req)
        await run(m, [resp])
        assert "trusts null origin" in capsys.readouterr().out

    async def test_wildcard_acao(self, capsys):
        m = Cors()
        m.setup([])
        req = self._probe_req(_DEFAULT_EVIL_ORIGIN)
        resp = make_response({"Access-Control-Allow-Origin": "*"}, request=req)
        await run(m, [resp])
        assert "wildcard ACAO (*)" in capsys.readouterr().out

    async def test_header_lookup_case_insensitive(self, capsys):
        m = Cors()
        m.setup([])
        req = self._probe_req(_DEFAULT_EVIL_ORIGIN)
        resp = make_response({"access-control-allow-origin": _DEFAULT_EVIL_ORIGIN}, request=req)
        await run(m, [resp])
        assert "reflects arbitrary origin" in capsys.readouterr().out

    async def test_no_acao_header_silent(self, capsys):
        m = Cors()
        m.setup([])
        req = self._probe_req(_DEFAULT_EVIL_ORIGIN)
        resp = make_response({"Content-Type": "text/html"}, request=req)
        await run(m, [resp])
        assert capsys.readouterr().out == ""

    async def test_non_reflecting_acao_silent(self, capsys):
        # Server echoes its own trusted origin, not our probe — safe.
        m = Cors()
        m.setup([])
        req = self._probe_req(_DEFAULT_EVIL_ORIGIN)
        resp = make_response(
            {"Access-Control-Allow-Origin": "https://trusted.example.com"}, request=req
        )
        await run(m, [resp])
        assert capsys.readouterr().out == ""

    async def test_network_error_skipped(self, capsys):
        m = Cors()
        m.setup([])
        req = self._probe_req(_DEFAULT_EVIL_ORIGIN)
        resp = make_response(
            {"Access-Control-Allow-Origin": _DEFAULT_EVIL_ORIGIN}, request=req, status=0
        )
        await run(m, [resp])
        assert capsys.readouterr().out == ""

    async def test_response_without_origin_probe_ignored(self, capsys):
        # A response whose request carries no Origin isn't one of our probes.
        m = Cors()
        m.setup([])
        resp = make_response(
            {"Access-Control-Allow-Origin": "*"}, request=make_request()
        )
        await run(m, [resp])
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# finalize — aggregation
# ---------------------------------------------------------------------------

class TestFinalize:
    def _probe_req(self, origin, url="http://example.com/"):
        return make_request(url=url, headers=[f"Origin: {origin}"])

    async def test_dedupes_with_counts(self, capsys):
        m = Cors()
        m.setup([])
        req = self._probe_req(_DEFAULT_EVIL_ORIGIN)
        responses = [
            make_response({"Access-Control-Allow-Origin": "*"}, request=req),
            make_response({"Access-Control-Allow-Origin": "*"}, request=req),
        ]
        await run(m, responses)
        out = capsys.readouterr().out
        assert "CORS misconfigurations (unique)" in out
        assert "wildcard ACAO (*)  (2 responses)" in out

    async def test_silent_when_no_findings(self, capsys):
        m = Cors()
        m.setup([])
        req = self._probe_req(_DEFAULT_EVIL_ORIGIN)
        resp = make_response({"Content-Type": "text/html"}, request=req)
        await run(m, [resp])
        assert capsys.readouterr().out == ""
