import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from modules.csp import ContentSecurityPolicy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(url="http://example.com/", method="GET"):
    return LeviosaRequest(method=method, url=url, headers=[], params=[])


def make_response(headers, status=200, url="http://example.com/"):
    return LeviosaResponse(
        status=status, headers=headers, body=b"", request=make_request(url)
    )


async def run(module, responses, context=None):
    """Drive analyze_one over each response, then finalize."""
    context = context or LeviosaContext()
    for resp in responses:
        await module.analyze_one(resp, context)
    await module.finalize(context)
    return context


# ---------------------------------------------------------------------------
# Loader compatibility
# ---------------------------------------------------------------------------

def test_loads_via_loader():
    from core.loader import load_modules
    instances = load_modules(["csp"])
    assert len(instances) == 1
    assert type(instances[0]).__name__ == "ContentSecurityPolicy"


def test_needs_body_false():
    assert ContentSecurityPolicy.needs_body is False


def test_does_not_opt_into_burp_by_default():
    assert ContentSecurityPolicy.use_burp is False


# ---------------------------------------------------------------------------
# mutate — passive, requests pass through unchanged
# ---------------------------------------------------------------------------

class TestMutate:
    async def test_returns_requests_unchanged(self):
        reqs = [make_request("http://a.com"), make_request("http://b.com")]
        result = await ContentSecurityPolicy().mutate(reqs, LeviosaContext())
        assert result is reqs


# ---------------------------------------------------------------------------
# _evaluate — detection logic
# ---------------------------------------------------------------------------

class TestEvaluate:
    def test_missing_header(self):
        m = ContentSecurityPolicy()
        assert m._evaluate(make_response({"Content-Type": "text/html"})) == [
            "missing Content-Security-Policy header"
        ]

    def test_clean_policy_no_issues(self):
        m = ContentSecurityPolicy()
        resp = make_response(
            {"Content-Security-Policy": "default-src 'self'; object-src 'none'"}
        )
        assert m._evaluate(resp) == []

    def test_header_lookup_case_insensitive(self):
        m = ContentSecurityPolicy()
        resp = make_response({"content-security-policy": "default-src 'self'"})
        assert m._evaluate(resp) == []

    def test_unsafe_inline(self):
        m = ContentSecurityPolicy()
        resp = make_response(
            {"Content-Security-Policy": "script-src 'self' 'unsafe-inline'"}
        )
        assert m._evaluate(resp) == ["script-src allows 'unsafe-inline'"]

    def test_unsafe_eval(self):
        m = ContentSecurityPolicy()
        resp = make_response(
            {"Content-Security-Policy": "script-src 'unsafe-eval'"}
        )
        assert m._evaluate(resp) == ["script-src allows 'unsafe-eval'"]

    def test_unsafe_keyword_case_insensitive(self):
        m = ContentSecurityPolicy()
        resp = make_response(
            {"Content-Security-Policy": "script-src 'UNSAFE-INLINE'"}
        )
        assert m._evaluate(resp) == ["script-src allows 'unsafe-inline'"]

    def test_bare_wildcard_source(self):
        m = ContentSecurityPolicy()
        resp = make_response({"Content-Security-Policy": "default-src *"})
        assert m._evaluate(resp) == ["default-src uses wildcard source '*'"]

    def test_host_wildcard_source(self):
        m = ContentSecurityPolicy()
        resp = make_response(
            {"Content-Security-Policy": "img-src *.example.com"}
        )
        assert m._evaluate(resp) == [
            "img-src uses wildcard source '*.example.com'"
        ]

    def test_multiple_issues_reported(self):
        m = ContentSecurityPolicy()
        resp = make_response({
            "Content-Security-Policy":
                "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
        })
        assert m._evaluate(resp) == [
            "default-src uses wildcard source '*'",
            "script-src allows 'unsafe-inline'",
            "script-src allows 'unsafe-eval'",
        ]

    def test_non_source_directives_ignored(self):
        # report-uri carries a URL, not a source list — no wildcard false hit.
        m = ContentSecurityPolicy()
        resp = make_response({
            "Content-Security-Policy":
                "default-src 'self'; report-uri /csp; upgrade-insecure-requests",
        })
        assert m._evaluate(resp) == []

    def test_report_only_mode(self):
        m = ContentSecurityPolicy()
        resp = make_response(
            {"Content-Security-Policy-Report-Only": "default-src 'self'"}
        )
        assert m._evaluate(resp) == [
            "CSP present only in report-only mode (not enforced)"
        ]

    def test_report_only_still_analyses_policy(self):
        m = ContentSecurityPolicy()
        resp = make_response(
            {"Content-Security-Policy-Report-Only": "script-src 'unsafe-inline'"}
        )
        assert m._evaluate(resp) == [
            "CSP present only in report-only mode (not enforced)",
            "script-src allows 'unsafe-inline'",
        ]

    def test_enforcing_takes_precedence_over_report_only(self):
        # When both headers are present, the enforcing policy is authoritative
        # and report-only is not flagged as "not enforced".
        m = ContentSecurityPolicy()
        resp = make_response({
            "Content-Security-Policy": "default-src 'self'",
            "Content-Security-Policy-Report-Only": "default-src *",
        })
        assert m._evaluate(resp) == []


# ---------------------------------------------------------------------------
# analyze_one / finalize — output and aggregation
# ---------------------------------------------------------------------------

class TestOutput:
    async def test_prints_per_response_finding(self, capsys):
        m = ContentSecurityPolicy()
        await run(m, [make_response({"Content-Type": "text/html"}, url="http://x/")])
        out = capsys.readouterr().out
        assert "[CSP]" in out
        assert "missing Content-Security-Policy header" in out
        assert "http://x/" in out

    async def test_no_output_for_clean_policy(self, capsys):
        m = ContentSecurityPolicy()
        await run(m, [make_response({"Content-Security-Policy": "default-src 'self'"})])
        assert capsys.readouterr().out == ""

    async def test_network_error_skipped(self, capsys):
        m = ContentSecurityPolicy()
        await run(m, [make_response({"Content-Type": "text/html"}, status=0)])
        assert capsys.readouterr().out == ""

    async def test_finalize_dedupes_with_counts(self, capsys):
        m = ContentSecurityPolicy()
        responses = [
            make_response({"Content-Type": "text/html"}, url="http://a/"),
            make_response({"Content-Type": "text/html"}, url="http://b/"),
            make_response(
                {"Content-Security-Policy": "script-src 'unsafe-inline'"},
                url="http://c/",
            ),
        ]
        await run(m, responses)
        out = capsys.readouterr().out
        assert "Content-Security-Policy issues (unique)" in out
        assert "missing Content-Security-Policy header  (2 responses)" in out
        assert "script-src allows 'unsafe-inline'  (1 response)" in out

    async def test_finalize_silent_when_no_findings(self, capsys):
        m = ContentSecurityPolicy()
        await run(m, [make_response({"Content-Security-Policy": "default-src 'self'"})])
        assert capsys.readouterr().out == ""

    async def test_findings_use_namespaced_context_key(self):
        m = ContentSecurityPolicy()
        ctx = await run(m, [make_response({"Content-Type": "text/html"})])
        assert "csp.findings" in ctx.data
