import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param
from modules.sqli import SqlInjection, _DEFAULT_PAYLOADS

MYSQL_ERROR = (
    b"<html><body>You have an error in your SQL syntax; check the manual that "
    b"corresponds to your MySQL server version near \"'\"</body></html>"
)
CLEAN_BODY = b"<html><body>Welcome, results below</body></html>"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(url="http://example.com/item", method="GET", params=None):
    return LeviosaRequest(method=method, url=url, headers=[], params=params or [])


def response_for(request, status=200, body=b""):
    return LeviosaResponse(status=status, headers={}, body=body, request=request)


def configured(args=None):
    m = SqlInjection()
    m.setup(args or [])
    return m


async def drive(module, seeds, body_for, status_for=None):
    """
    Run mutate, build a response per variant (body/status chosen by callbacks
    keyed on the variant's meta), then analyze + finalize.
    """
    ctx = LeviosaContext()
    variants = list(await module.mutate(seeds, ctx))
    for v in variants:
        meta = module._meta[id(v)]
        body = body_for(meta, v)
        status = status_for(meta, v) if status_for else 200
        await module.analyze_one(response_for(v, status=status, body=body), ctx)
    await module.finalize(ctx)
    return ctx


# ---------------------------------------------------------------------------
# Loader / basics
# ---------------------------------------------------------------------------

def test_loads_via_loader():
    from core.loader import load_modules
    instances = load_modules(["sqli"])
    assert len(instances) == 1
    assert type(instances[0]).__name__ == "SqlInjection"


def test_needs_body_true():
    assert SqlInjection.needs_body is True


def test_uses_burp():
    assert SqlInjection.use_burp is True


# ---------------------------------------------------------------------------
# setup — flags
# ---------------------------------------------------------------------------

class TestSetup:
    def test_default_payloads(self):
        assert configured()._payloads == _DEFAULT_PAYLOADS

    def test_payload_file(self, tmp_path):
        p = tmp_path / "pl.txt"
        p.write_text("'\n\"\n")
        m = configured(["--payloads", str(p)])
        assert m._payloads == ["'", '"']

    def test_empty_payload_file_raises(self, tmp_path):
        p = tmp_path / "empty.txt"
        p.write_text("\n\n")
        with pytest.raises(RuntimeError, match="is empty"):
            configured(["--payloads", str(p)])

    def test_param_types_flag(self):
        m = configured(["--param-types", "query,header"])
        assert m._param_types == ["query", "header"]

    def test_replace_flag(self):
        assert configured(["--replace"])._append is False
        assert configured([])._append is True


# ---------------------------------------------------------------------------
# mutate — one param, one payload at a time
# ---------------------------------------------------------------------------

class TestMutate:
    async def test_baseline_first_and_unchanged(self):
        req = make_request(params=[Param("query", "id", "5")])
        m = configured()
        variants = list(await m.mutate([req], LeviosaContext()))
        assert variants[0] is req

    async def test_one_variant_per_param_payload(self):
        params = [Param("query", "id", "5"), Param("query", "q", "x")]
        m = configured()
        variants = list(await m.mutate([make_request(params=params)], LeviosaContext()))
        # baseline + (2 params * len(payloads))
        assert len(variants) == 1 + 2 * len(_DEFAULT_PAYLOADS)

    async def test_only_target_param_changes(self):
        params = [Param("query", "id", "5"), Param("query", "q", "keep")]
        m = configured()
        variants = list(await m.mutate([make_request(params=params)], LeviosaContext()))
        # find a variant injecting 'id' with a lone quote
        injected = [
            v for v in variants
            if m._meta[id(v)][1] == "id" and m._meta[id(v)][3] == "'"
        ][0]
        by_name = {p.name: p.value for p in injected.params}
        assert by_name["id"] == "5'"      # appended
        assert by_name["q"] == "keep"     # sibling untouched

    async def test_replace_mode_overwrites(self):
        m = configured(["--replace"])
        variants = list(await m.mutate(
            [make_request(params=[Param("query", "id", "5")])], LeviosaContext()
        ))
        injected = [v for v in variants if m._meta[id(v)][3] == "'"][0]
        assert injected.params[0].value == "'"

    async def test_non_injectable_params_skipped(self):
        # header params are not in the default set → not injected.
        params = [Param("header", "X-Api", "k"), Param("query", "id", "5")]
        m = configured()
        variants = list(await m.mutate([make_request(params=params)], LeviosaContext()))
        injected_names = {m._meta[id(v)][1] for v in variants} - {None}
        assert injected_names == {"id"}

    async def test_does_not_mutate_seed(self):
        params = [Param("query", "id", "5")]
        req = make_request(params=params)
        m = configured()
        list(await m.mutate([req], LeviosaContext()))
        assert req.params[0].value == "5"

    async def test_request_with_no_injectable_params_only_baseline(self):
        m = configured()
        variants = list(await m.mutate([make_request(params=[])], LeviosaContext()))
        assert len(variants) == 1


# ---------------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------------

class TestDetection:
    def test_matches_mysql(self):
        hits = configured()._matched_dbms(MYSQL_ERROR.decode())
        assert any(dbms == "MySQL" for dbms, _ in hits)

    def test_matches_oracle(self):
        hits = configured()._matched_dbms("ORA-01756: quoted string not properly terminated")
        assert any(dbms == "Oracle" for dbms, _ in hits)

    def test_clean_body_no_match(self):
        assert configured()._matched_dbms(CLEAN_BODY.decode()) == []


class TestFinalize:
    async def test_reports_error_based_finding(self, capsys):
        seeds = [make_request(params=[Param("query", "id", "5")])]

        def body_for(meta, v):
            # baseline clean; any injected 'id' variant returns a MySQL error
            return MYSQL_ERROR if meta[1] == "id" else CLEAN_BODY

        await drive(configured(), seeds, body_for)
        out = capsys.readouterr().out
        assert "SQL injection indicators" in out
        assert "MySQL error" in out
        assert "param 'id' (query)" in out
        assert "confirmed error-based" in out

    async def test_baseline_error_suppresses_finding(self, capsys):
        # Page ALWAYS shows the MySQL error (even baseline) → not attributable
        # to injection → no finding.
        seeds = [make_request(params=[Param("query", "id", "5")])]
        await drive(configured(), seeds, lambda meta, v: MYSQL_ERROR)
        assert capsys.readouterr().out == ""

    async def test_dedupes_same_param_same_dbms(self, capsys):
        # Every payload triggers MySQL on 'id' → one finding, not len(payloads).
        seeds = [make_request(params=[Param("query", "id", "5")])]

        def body_for(meta, v):
            return MYSQL_ERROR if meta[1] == "id" else CLEAN_BODY

        await drive(configured(), seeds, body_for)
        out = capsys.readouterr().out
        assert out.count("MySQL error") == 1
        assert "1 confirmed error-based" in out

    async def test_http_500_indicator(self, capsys):
        seeds = [make_request(params=[Param("query", "id", "5")])]

        def status_for(meta, v):
            return 500 if meta[1] == "id" else 200

        await drive(configured(), seeds, lambda meta, v: CLEAN_BODY, status_for)
        out = capsys.readouterr().out
        assert "HTTP 500 introduced (baseline 200)" in out
        assert "error-code-only indicator" in out

    async def test_silent_when_clean(self, capsys):
        seeds = [make_request(params=[Param("query", "id", "5")])]
        await drive(configured(), seeds, lambda meta, v: CLEAN_BODY)
        assert capsys.readouterr().out == ""

    async def test_uses_namespaced_context_key(self):
        seeds = [make_request(params=[Param("query", "id", "5")])]
        ctx = await drive(configured(), seeds, lambda meta, v: CLEAN_BODY)
        assert "sqli.results" in ctx.data
