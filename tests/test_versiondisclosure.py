import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from modules.versiondisclosure import VersionDisclosure


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
    instances = load_modules(["versiondisclosure"])
    assert len(instances) == 1
    assert type(instances[0]).__name__ == "VersionDisclosure"


def test_needs_body_false():
    # Header-only module: the engine should never read response bodies.
    assert VersionDisclosure.needs_body is False


def test_does_not_opt_into_burp_by_default():
    assert VersionDisclosure.use_burp is False


# ---------------------------------------------------------------------------
# mutate — passive, requests pass through unchanged
# ---------------------------------------------------------------------------

class TestMutate:
    async def test_returns_requests_unchanged(self):
        reqs = [make_request("http://a.com"), make_request("http://b.com")]
        result = await VersionDisclosure().mutate(reqs, LeviosaContext())
        assert result is reqs


# ---------------------------------------------------------------------------
# _disclosures — detection logic
# ---------------------------------------------------------------------------

class TestDisclosures:
    def test_curated_server_header(self):
        m = VersionDisclosure()
        hits = m._disclosures(make_response({"Server": "nginx/1.18.0"}))
        assert hits == [("Server", "nginx/1.18.0")]

    def test_curated_x_powered_by(self):
        m = VersionDisclosure()
        hits = m._disclosures(make_response({"X-Powered-By": "PHP/8.1.2"}))
        assert hits == [("X-Powered-By", "PHP/8.1.2")]

    def test_curated_header_reported_even_without_version(self):
        # Curated headers disclose the software by their presence alone.
        m = VersionDisclosure()
        hits = m._disclosures(make_response({"X-Powered-By": "Express"}))
        assert hits == [("X-Powered-By", "Express")]

    def test_header_match_is_case_insensitive(self):
        m = VersionDisclosure()
        hits = m._disclosures(make_response({"server": "Apache/2.4.41 (Ubuntu)"}))
        # Reported using the curated display casing, not the wire casing.
        assert hits == [("Server", "Apache/2.4.41 (Ubuntu)")]

    def test_multiple_headers(self):
        m = VersionDisclosure()
        resp = make_response({
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/8.1.2",
            "Content-Type": "text/html",
        })
        hits = dict(m._disclosures(resp))
        assert hits == {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.2"}

    def test_heuristic_flags_uncurated_version_header(self):
        m = VersionDisclosure()
        hits = m._disclosures(make_response({"X-Custom-Engine": "WidgetKit/3.2.1"}))
        assert hits == [("X-Custom-Engine", "WidgetKit/3.2.1")]

    def test_heuristic_ignores_ordinary_headers(self):
        m = VersionDisclosure()
        resp = make_response({
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-cache",
            "Date": "Mon, 01 Jan 2024 00:00:00 GMT",
        })
        assert m._disclosures(resp) == []

    def test_no_disclosing_headers(self):
        m = VersionDisclosure()
        assert m._disclosures(make_response({"Content-Length": "42"})) == []

    def test_no_heuristic_skips_uncurated(self):
        m = VersionDisclosure()
        m.setup(["--no-heuristic"])
        resp = make_response({
            "Server": "nginx/1.18.0",          # curated → still reported
            "X-Custom-Engine": "WidgetKit/3.2.1",  # uncurated → skipped
        })
        assert m._disclosures(resp) == [("Server", "nginx/1.18.0")]


# ---------------------------------------------------------------------------
# setup — flags
# ---------------------------------------------------------------------------

class TestSetup:
    def test_extra_header_added_to_curated_set(self):
        m = VersionDisclosure()
        m.setup(["--extra-header", "X-My-Version"])
        hits = m._disclosures(make_response({"X-My-Version": "beta"}))
        assert hits == [("X-My-Version", "beta")]

    def test_extra_header_repeatable(self):
        m = VersionDisclosure()
        m.setup(["--extra-header", "X-One", "--extra-header", "X-Two"])
        resp = make_response({"X-One": "a", "X-Two": "b"})
        assert dict(m._disclosures(resp)) == {"X-One": "a", "X-Two": "b"}

    def test_heuristic_on_by_default(self):
        m = VersionDisclosure()
        m.setup([])
        assert m._heuristic is True

    def test_ignores_unknown_flags(self):
        # setup must tolerate flags meant for other modules.
        m = VersionDisclosure()
        m.setup(["--wordlist", "foo.txt", "--extra-header", "X-Z"])
        assert m._disclosures(make_response({"X-Z": "1"})) == [("X-Z", "1")]


# ---------------------------------------------------------------------------
# analyze_one / finalize — output and aggregation
# ---------------------------------------------------------------------------

class TestOutput:
    async def test_prints_per_response_hit(self, capsys):
        m = VersionDisclosure()
        await run(m, [make_response({"Server": "nginx/1.18.0"}, url="http://x/")])
        out = capsys.readouterr().out
        assert "[VERSIONDISCLOSURE]" in out
        assert "Server: nginx/1.18.0" in out
        assert "http://x/" in out

    async def test_no_output_when_nothing_disclosed(self, capsys):
        m = VersionDisclosure()
        await run(m, [make_response({"Content-Length": "5"})])
        assert capsys.readouterr().out == ""

    async def test_network_error_skipped(self, capsys):
        m = VersionDisclosure()
        # status 0 with a (hypothetical) header must not be reported.
        await run(m, [make_response({"Server": "nginx"}, status=0)])
        assert capsys.readouterr().out == ""

    async def test_finalize_dedupes_inventory_with_counts(self, capsys):
        m = VersionDisclosure()
        responses = [
            make_response({"Server": "nginx/1.18.0"}, url="http://a/"),
            make_response({"Server": "nginx/1.18.0"}, url="http://b/"),
            make_response({"X-Powered-By": "PHP/8.1.2"}, url="http://c/"),
        ]
        await run(m, responses)
        out = capsys.readouterr().out
        assert "disclosed software/versions (unique)" in out
        assert "Server: nginx/1.18.0  (2 responses)" in out
        assert "X-Powered-By: PHP/8.1.2  (1 response)" in out

    async def test_finalize_silent_when_no_findings(self, capsys):
        m = VersionDisclosure()
        await run(m, [make_response({"Content-Type": "text/html"})])
        assert capsys.readouterr().out == ""

    async def test_inventory_uses_namespaced_context_key(self):
        m = VersionDisclosure()
        ctx = await run(m, [make_response({"Server": "nginx/1.18.0"})])
        assert "versiondisclosure.inventory" in ctx.data
