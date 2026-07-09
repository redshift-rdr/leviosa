import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param
from modules.errorpages import ALL_TECHNIQUES, ErrorPages


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(url="http://example.com/app", method="GET", params=None, headers=None):
    return LeviosaRequest(
        method=method,
        url=url,
        headers=headers if headers is not None else [],
        params=params if params is not None else [],
    )


def make_response(request, status=200, body=b""):
    return LeviosaResponse(status=status, headers={}, body=body, request=request)


def induce(module, req):
    """Return {technique: [variant, ...]} from the module's lazy variant stream."""
    out: dict[str, list] = {}
    for variant in module._variants([req]):
        label = module._techniques[id(variant)]
        out.setdefault(label, []).append(variant)
    return out


# ---------------------------------------------------------------------------
# Loader / class attributes
# ---------------------------------------------------------------------------

def test_loads_via_loader():
    from core.loader import load_modules
    instances = load_modules(["errorpages"])
    assert len(instances) == 1
    assert type(instances[0]).__name__ == "ErrorPages"


def test_needs_body_true():
    assert ErrorPages.needs_body is True


def test_does_not_opt_into_burp():
    assert ErrorPages.use_burp is False


# ---------------------------------------------------------------------------
# setup()
# ---------------------------------------------------------------------------

class TestSetup:
    def test_default_enables_all_techniques(self):
        m = ErrorPages()
        m.setup([])
        assert m._enabled == ALL_TECHNIQUES

    def test_restrict_techniques(self):
        m = ErrorPages()
        m.setup(["--techniques", "not-found,bad-method"])
        assert m._enabled == ["not-found", "bad-method"]

    def test_unknown_technique_raises(self):
        m = ErrorPages()
        with pytest.raises(RuntimeError, match="unknown technique"):
            m.setup(["--techniques", "not-found,bogus"])

    def test_long_url_len_configurable(self):
        m = ErrorPages()
        m.setup(["--long-url-len", "100"])
        assert m._long_url_len == 100

    def test_ignores_unknown_flags(self):
        m = ErrorPages()
        m.setup(["--wordlist", "x.txt", "--techniques", "bad-method"])
        assert m._enabled == ["bad-method"]


# ---------------------------------------------------------------------------
# Induction techniques
# ---------------------------------------------------------------------------

class TestInduction:
    def test_not_found_appends_segment(self):
        m = ErrorPages()
        variants = induce(m, make_request("http://example.com/app"))
        urls = [v.url for v in variants["not-found"]]
        assert urls == ["http://example.com/app/leviosa_404_probe_zzq7"]

    def test_not_found_on_bare_domain(self):
        m = ErrorPages()
        variants = induce(m, make_request("http://example.com"))
        assert variants["not-found"][0].url == "http://example.com/leviosa_404_probe_zzq7"

    def test_bad_method_changes_verb_only(self):
        m = ErrorPages()
        req = make_request("http://example.com/app", method="GET")
        variant = induce(m, req)["bad-method"][0]
        assert variant.method == "LEVIOSA"
        assert variant.url == req.url

    def test_long_url_length(self):
        m = ErrorPages()
        m.setup(["--long-url-len", "500"])
        variant = induce(m, make_request("http://example.com/app"))["long-url"][0]
        # /app + "/" + 500 "L"s
        assert variant.url == "http://example.com/app/" + ("L" * 500)

    def test_special_path_present(self):
        m = ErrorPages()
        variant = induce(m, make_request("http://example.com/app"))["special-path"][0]
        assert variant.url.startswith("http://example.com/app/leviosa")

    def test_param_injection_covers_each_param_and_payload(self):
        m = ErrorPages()
        params = [
            Param(type="query", name="q", value="x"),
            Param(type="json", name="email", value="a@b.com"),
        ]
        variants = induce(m, make_request(params=params))["param-injection"]
        # 2 injectable params x 7 breaker payloads
        assert len(variants) == 2 * 7
        # Each variant mutates exactly one param and leaves the sibling intact.
        for v in variants:
            changed = [p for p in v.params if p.value not in ("x", "a@b.com")]
            assert len(changed) == 1

    def test_param_injection_skips_header_params(self):
        m = ErrorPages()
        params = [Param(type="header", name="X-Api", value="v")]
        variants = induce(m, make_request(params=params))
        # header params are not injectable → no param-injection variants
        assert "param-injection" not in variants

    def test_param_injection_deepcopies_no_alias(self):
        # Mutating one variant's param must not leak into the original or siblings.
        m = ErrorPages()
        req = make_request(params=[Param(type="query", name="q", value="orig")])
        variants = induce(m, req)["param-injection"]
        assert req.params[0].value == "orig"
        values = {v.params[0].value for v in variants}
        assert len(values) == len(variants)  # all distinct payloads, none aliased

    def test_junk_param_adds_query_param(self):
        m = ErrorPages()
        variants = induce(m, make_request(params=[]))["junk-param"]
        assert len(variants) == 3
        for v in variants:
            assert v.params[-1].name == "leviosa_test"
            assert v.params[-1].type == "query"

    def test_restricted_techniques_only_emit_selected(self):
        m = ErrorPages()
        m.setup(["--techniques", "not-found,bad-method"])
        variants = induce(m, make_request("http://example.com/app"))
        assert set(variants) == {"not-found", "bad-method"}


# ---------------------------------------------------------------------------
# Disclosure signature detection
# ---------------------------------------------------------------------------

class TestDisclosures:
    @pytest.mark.parametrize("name,body", [
        ("php-error", b"<b>Warning</b>: mysql_connect() in /x.php on line 42"),
        ("python-traceback", b'Traceback (most recent call last):\n  File "app.py", line 10, in <module>'),
        ("java-trace", b"at com.example.Foo(Foo.java:88)\njava.lang.NullPointerException"),
        ("dotnet-error", b"System.NullReferenceException: Object reference ... ASP.NET"),
        ("sql-error", b"You have an error in your SQL syntax near ''"),
        ("node-error", b"TypeError: Cannot read properties of undefined at Object.foo (server.js:12:5)"),
        ("path-disclosure", b"failed opening /var/www/html/index.php"),
        ("stack-trace", b"Full stack trace follows"),
    ])
    def test_signature_detected(self, name, body):
        m = ErrorPages()
        resp = make_response(make_request(), status=500, body=body)
        assert name in m._disclosures(resp)

    def test_benign_body_no_disclosure(self):
        m = ErrorPages()
        resp = make_response(make_request(), status=404, body=b"<h1>Not Found</h1>")
        assert m._disclosures(resp) == []


# ---------------------------------------------------------------------------
# analyze_one / finalize
# ---------------------------------------------------------------------------

class TestAnalyze:
    async def test_error_status_reported_with_technique(self, capsys):
        m = ErrorPages()
        req = make_request("http://example.com/app/x", method="GET")
        m._techniques[id(req)] = "not-found"
        await m.analyze_one(make_response(req, status=404), LeviosaContext())
        out = capsys.readouterr().out
        assert "[ERRORPAGES] 404 GET http://example.com/app/x" in out
        assert "induced: not-found" in out

    async def test_disclosure_on_200_is_reported(self, capsys):
        m = ErrorPages()
        req = make_request()
        m._techniques[id(req)] = "param-injection"
        body = b"<b>Fatal error</b>: on line 7"
        await m.analyze_one(make_response(req, status=200, body=body), LeviosaContext())
        out = capsys.readouterr().out
        assert "200" in out
        assert "disclosure: php-error" in out

    async def test_clean_non_error_not_reported(self, capsys):
        m = ErrorPages()
        req = make_request()
        m._techniques[id(req)] = "not-found"
        await m.analyze_one(make_response(req, status=200, body=b"ok"), LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_network_error_skipped(self, capsys):
        m = ErrorPages()
        req = make_request()
        m._techniques[id(req)] = "bad-method"
        await m.analyze_one(make_response(req, status=0), LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_technique_map_entry_consumed(self):
        m = ErrorPages()
        req = make_request()
        m._techniques[id(req)] = "not-found"
        await m.analyze_one(make_response(req, status=404), LeviosaContext())
        # Popped after analysis so the map stays bounded.
        assert id(req) not in m._techniques

    async def test_finalize_summarises_status_and_disclosures(self, capsys):
        m = ErrorPages()
        ctx = LeviosaContext()
        for status, body, tech in [
            (404, b"nf", "not-found"),
            (404, b"nf", "not-found"),
            (500, b"You have an error in your SQL syntax", "param-injection"),
        ]:
            req = make_request()
            m._techniques[id(req)] = tech
            await m.analyze_one(make_response(req, status=status, body=body), ctx)
        capsys.readouterr()  # discard per-response lines
        await m.finalize(ctx)
        out = capsys.readouterr().out
        assert "--- summary ---" in out
        assert "status 404: 2" in out
        assert "status 500: 1" in out
        assert "sql-error: 1" in out

    async def test_finalize_silent_when_no_findings(self, capsys):
        m = ErrorPages()
        await m.finalize(LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_stats_use_namespaced_key(self):
        m = ErrorPages()
        ctx = LeviosaContext()
        req = make_request()
        m._techniques[id(req)] = "not-found"
        await m.analyze_one(make_response(req, status=404, body=b"x"), ctx)
        assert "errorpages.stats" in ctx.data
