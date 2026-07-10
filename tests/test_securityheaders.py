import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from modules.securityheaders import SecurityHeaders

# A response header set that satisfies every check, so a test can drop one
# header at a time and assert only the intended issue appears.
CLEAN = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(url="https://example.com/", method="GET"):
    return LeviosaRequest(method=method, url=url, headers=[], params=[])


def make_response(headers, status=200, url="https://example.com/"):
    return LeviosaResponse(
        status=status, headers=headers, body=b"", request=make_request(url)
    )


def without(*names):
    """A copy of CLEAN with the named headers removed."""
    lowered = {n.lower() for n in names}
    return {k: v for k, v in CLEAN.items() if k.lower() not in lowered}


async def run(module, responses, context=None):
    context = context or LeviosaContext()
    for resp in responses:
        await module.analyze_one(resp, context)
    await module.finalize(context)
    return context


def configured():
    m = SecurityHeaders()
    m.setup([])
    return m


# ---------------------------------------------------------------------------
# Loader compatibility
# ---------------------------------------------------------------------------

def test_loads_via_loader():
    from core.loader import load_modules
    instances = load_modules(["securityheaders"])
    assert len(instances) == 1
    assert type(instances[0]).__name__ == "SecurityHeaders"


def test_needs_body_false():
    assert SecurityHeaders.needs_body is False


def test_does_not_opt_into_burp_by_default():
    assert SecurityHeaders.use_burp is False


class TestMutate:
    async def test_returns_requests_unchanged(self):
        reqs = [make_request("https://a.com"), make_request("https://b.com")]
        result = await configured().mutate(reqs, LeviosaContext())
        assert result is reqs


# ---------------------------------------------------------------------------
# Clean response — nothing flagged
# ---------------------------------------------------------------------------

class TestClean:
    def test_fully_configured_has_no_issues(self):
        assert configured()._evaluate(make_response(CLEAN)) == []

    def test_frame_ancestors_satisfies_clickjacking(self):
        headers = without("X-Frame-Options")
        headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        assert configured()._evaluate(make_response(headers)) == []

    def test_header_lookup_case_insensitive(self):
        headers = {k.lower(): v for k, v in CLEAN.items()}
        assert configured()._evaluate(make_response(headers)) == []


# ---------------------------------------------------------------------------
# HSTS
# ---------------------------------------------------------------------------

class TestHsts:
    def test_missing(self):
        issues = configured()._evaluate(make_response(without("Strict-Transport-Security")))
        assert "missing Strict-Transport-Security (HSTS)" in issues

    def test_no_max_age(self):
        h = without("Strict-Transport-Security")
        h["Strict-Transport-Security"] = "includeSubDomains"
        assert "HSTS has no max-age directive" in configured()._evaluate(make_response(h))

    def test_max_age_zero(self):
        h = without("Strict-Transport-Security")
        h["Strict-Transport-Security"] = "max-age=0; includeSubDomains"
        assert "HSTS max-age=0 (disables HSTS)" in configured()._evaluate(make_response(h))

    def test_max_age_too_low(self):
        h = without("Strict-Transport-Security")
        h["Strict-Transport-Security"] = "max-age=3600; includeSubDomains"
        issues = configured()._evaluate(make_response(h))
        assert any("HSTS max-age too low (3600 < 31536000)" == i for i in issues)

    def test_missing_include_subdomains(self):
        h = without("Strict-Transport-Security")
        h["Strict-Transport-Security"] = "max-age=63072000"
        assert "HSTS missing includeSubDomains" in configured()._evaluate(make_response(h))

    def test_min_age_flag(self):
        m = SecurityHeaders()
        m.setup(["--hsts-min-age", "1000"])
        h = without("Strict-Transport-Security")
        h["Strict-Transport-Security"] = "max-age=3600; includeSubDomains"
        # 3600 >= 1000 now, so no too-low issue.
        assert not any("too low" in i for i in m._evaluate(make_response(h)))

    def test_hsts_skipped_over_http(self):
        # HSTS is ignored by browsers over cleartext, so don't flag its absence.
        issues = configured()._evaluate(
            make_response(without("Strict-Transport-Security"), url="http://example.com/")
        )
        assert not any("HSTS" in i or "Strict-Transport-Security" in i for i in issues)


# ---------------------------------------------------------------------------
# X-Content-Type-Options
# ---------------------------------------------------------------------------

class TestNoSniff:
    def test_missing(self):
        issues = configured()._evaluate(make_response(without("X-Content-Type-Options")))
        assert "missing X-Content-Type-Options (expected 'nosniff')" in issues

    def test_wrong_value(self):
        h = without("X-Content-Type-Options")
        h["X-Content-Type-Options"] = "sniff"
        assert (
            "X-Content-Type-Options is 'sniff' (expected 'nosniff')"
            in configured()._evaluate(make_response(h))
        )


# ---------------------------------------------------------------------------
# Clickjacking
# ---------------------------------------------------------------------------

class TestClickjacking:
    def test_missing_both(self):
        issues = configured()._evaluate(make_response(without("X-Frame-Options")))
        assert (
            "no anti-clickjacking header (X-Frame-Options or CSP frame-ancestors)"
            in issues
        )

    def test_sameorigin_ok(self):
        h = without("X-Frame-Options")
        h["X-Frame-Options"] = "SAMEORIGIN"
        assert not any("clickjacking" in i or "X-Frame-Options" in i
                       for i in configured()._evaluate(make_response(h)))

    def test_bad_xfo_value(self):
        h = without("X-Frame-Options")
        h["X-Frame-Options"] = "ALLOW-FROM https://x"
        assert any("X-Frame-Options has unexpected value" in i
                   for i in configured()._evaluate(make_response(h)))


# ---------------------------------------------------------------------------
# Referrer-Policy
# ---------------------------------------------------------------------------

class TestReferrer:
    def test_missing(self):
        assert "missing Referrer-Policy" in configured()._evaluate(
            make_response(without("Referrer-Policy"))
        )

    def test_weak_value(self):
        h = without("Referrer-Policy")
        h["Referrer-Policy"] = "unsafe-url"
        assert any("may leak referrer" in i for i in configured()._evaluate(make_response(h)))


# ---------------------------------------------------------------------------
# Recommended tier
# ---------------------------------------------------------------------------

class TestRecommended:
    def test_missing_permissions_policy(self):
        assert "missing Permissions-Policy (recommended)" in configured()._evaluate(
            make_response(without("Permissions-Policy"))
        )

    def test_missing_cross_origin_headers(self):
        issues = configured()._evaluate(make_response(
            without("Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
                    "Cross-Origin-Resource-Policy")
        ))
        assert "missing Cross-Origin-Opener-Policy (recommended)" in issues
        assert "missing Cross-Origin-Embedder-Policy (recommended)" in issues
        assert "missing Cross-Origin-Resource-Policy (recommended)" in issues

    def test_deprecated_xss_protection(self):
        h = dict(CLEAN)
        h["X-XSS-Protection"] = "1; mode=block"
        assert any("X-XSS-Protection is '1; mode=block'" in i
                   for i in configured()._evaluate(make_response(h)))

    def test_no_recommended_flag_skips_tier(self):
        m = SecurityHeaders()
        m.setup(["--no-recommended"])
        # A clean core response missing only recommended headers → no issues.
        issues = m._evaluate(make_response(
            without("Permissions-Policy", "Cross-Origin-Opener-Policy",
                    "Cross-Origin-Embedder-Policy", "Cross-Origin-Resource-Policy")
        ))
        assert issues == []


# ---------------------------------------------------------------------------
# analyze_one / finalize
# ---------------------------------------------------------------------------

class TestOutput:
    async def test_prints_findings(self, capsys):
        await run(configured(), [make_response(without("X-Content-Type-Options"), url="https://x/")])
        out = capsys.readouterr().out
        assert "[SECHEADERS]" in out
        assert "missing X-Content-Type-Options" in out
        assert "https://x/" in out

    async def test_no_output_when_clean(self, capsys):
        await run(configured(), [make_response(CLEAN)])
        assert capsys.readouterr().out == ""

    async def test_network_error_skipped(self, capsys):
        await run(configured(), [make_response(without("X-Content-Type-Options"), status=0)])
        assert capsys.readouterr().out == ""

    async def test_finalize_dedupes_with_counts(self, capsys):
        responses = [
            make_response(without("Referrer-Policy"), url="https://a/"),
            make_response(without("Referrer-Policy"), url="https://b/"),
        ]
        await run(configured(), responses)
        out = capsys.readouterr().out
        assert "security header issues (unique)" in out
        assert "missing Referrer-Policy  (2 responses)" in out

    async def test_findings_use_namespaced_context_key(self):
        ctx = await run(configured(), [make_response(without("Referrer-Policy"))])
        assert "securityheaders.findings" in ctx.data
