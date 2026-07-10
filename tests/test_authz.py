import json

import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param
from modules.authz import Authz


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(url="http://example.com/", method="GET", headers=None, params=None):
    return LeviosaRequest(
        method=method, url=url, headers=headers or [], params=params or []
    )


def session_file(tmp_path, name, cookies):
    """Write a minimal request file whose only request carries the cookies."""
    path = tmp_path / name
    path.write_text(json.dumps([{
        "method": "GET",
        "url": "http://login/",
        "headers": [],
        "params": [{"type": "cookie", "name": n, "value": v} for n, v in cookies.items()],
    }]))
    return str(path)


def response_for(request, status):
    return LeviosaResponse(status=status, headers={}, body=b"", request=request)


async def drive(module, seeds, status_map):
    """
    Run mutate, produce a response for each variant using status_map keyed by
    (endpoint_index, column_label), then analyze + finalize.
    """
    ctx = LeviosaContext()
    variants = list(await module.mutate(seeds, ctx))
    for v in variants:
        idx, label = module._request_meta[id(v)]
        await module.analyze_one(response_for(v, status_map[(idx, label)]), ctx)
    await module.finalize(ctx)
    return ctx


# ---------------------------------------------------------------------------
# Loader / basics
# ---------------------------------------------------------------------------

def test_loads_via_loader():
    from core.loader import load_modules
    instances = load_modules(["authz"])
    assert len(instances) == 1
    assert type(instances[0]).__name__ == "Authz"


def test_needs_body_false():
    assert Authz.needs_body is False


def test_routes_through_burp():
    # authz opts into burp so the auth-matrix traffic is easy to inspect/replay.
    assert Authz.use_burp is True


# ---------------------------------------------------------------------------
# setup — session loading and flags
# ---------------------------------------------------------------------------

class TestSetup:
    def test_requires_a_session(self):
        with pytest.raises(RuntimeError, match="requires at least one --session"):
            Authz().setup([])

    def test_label_defaults_to_file_stem(self, tmp_path):
        path = session_file(tmp_path, "admin.json", {"session": "A"})
        m = Authz()
        m.setup(["--session", path])
        assert m._sessions[0][0] == "admin"
        assert m._sessions[0][1] == {"session": "A"}

    def test_explicit_label(self, tmp_path):
        path = session_file(tmp_path, "u.json", {"session": "A"})
        m = Authz()
        m.setup(["--session", f"boss={path}"])
        assert m._sessions[0][0] == "boss"

    def test_multiple_sessions_ordered(self, tmp_path):
        a = session_file(tmp_path, "a.json", {"s": "1"})
        b = session_file(tmp_path, "b.json", {"s": "2"})
        m = Authz()
        m.setup(["--session", f"admin={a}", "--session", f"guest={b}"])
        assert [label for label, _ in m._sessions] == ["admin", "guest"]

    def test_duplicate_labels_disambiguated(self, tmp_path):
        a = session_file(tmp_path, "dup.json", {"s": "1"})
        b = session_file(tmp_path, "dup2.json", {"s": "2"})
        m = Authz()
        m.setup(["--session", f"user={a}", "--session", f"user={b}"])
        assert [label for label, _ in m._sessions] == ["user", "user#2"]

    def test_missing_file_raises_runtimeerror(self):
        with pytest.raises(RuntimeError, match="session file not found"):
            Authz().setup(["--session", "/no/such/file.json"])

    def test_empty_cookies_warns_but_loads(self, tmp_path, capsys):
        path = session_file(tmp_path, "anon.json", {})
        m = Authz()
        m.setup(["--session", path])
        assert m._sessions[0][1] == {}
        assert "no cookies found" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# _impersonate — cookie replacement
# ---------------------------------------------------------------------------

class TestImpersonate:
    def test_replaces_cookie_params(self):
        req = make_request(params=[
            Param("cookie", "session", "OLD"),
            Param("query", "q", "1"),
        ])
        out = Authz._impersonate(req, {"session": "NEW", "extra": "X"})
        cookies = {p.name: p.value for p in out.params if p.type == "cookie"}
        assert cookies == {"session": "NEW", "extra": "X"}
        # non-cookie params preserved
        assert Param("query", "q", "1") in out.params

    def test_drops_raw_cookie_header(self):
        req = make_request(headers=["Cookie: session=OLD", "Accept: */*"])
        out = Authz._impersonate(req, {"session": "NEW"})
        assert "Accept: */*" in out.headers
        assert not any(h.lower().startswith("cookie:") for h in out.headers)

    def test_does_not_mutate_seed(self):
        req = make_request(
            headers=["Cookie: session=OLD"],
            params=[Param("cookie", "session", "OLD")],
        )
        Authz._impersonate(req, {"session": "NEW"})
        assert req.headers == ["Cookie: session=OLD"]
        assert req.params == [Param("cookie", "session", "OLD")]


# ---------------------------------------------------------------------------
# mutate — variant generation and correlation
# ---------------------------------------------------------------------------

class TestMutate:
    def _module(self, tmp_path):
        a = session_file(tmp_path, "admin.json", {"s": "A"})
        g = session_file(tmp_path, "guest.json", {"s": "G"})
        m = Authz()
        m.setup(["--session", f"admin={a}", "--session", f"guest={g}"])
        return m

    async def test_emits_baseline_plus_one_per_session(self, tmp_path):
        m = self._module(tmp_path)
        variants = list(await m.mutate([make_request()], LeviosaContext()))
        assert len(variants) == 3  # original + admin + guest

    async def test_baseline_is_original_object(self, tmp_path):
        m = self._module(tmp_path)
        req = make_request()
        variants = list(await m.mutate([req], LeviosaContext()))
        assert variants[0] is req

    async def test_meta_maps_each_variant(self, tmp_path):
        m = self._module(tmp_path)
        variants = list(await m.mutate([make_request(url="http://x/")], LeviosaContext()))
        labels = [m._request_meta[id(v)][1] for v in variants]
        assert labels == ["(original)", "admin", "guest"]
        assert m._endpoints == ["GET /"]


# ---------------------------------------------------------------------------
# finalize — the table
# ---------------------------------------------------------------------------

class TestTable:
    def _module(self, tmp_path):
        a = session_file(tmp_path, "admin.json", {"s": "A"})
        g = session_file(tmp_path, "guest.json", {"s": "G"})
        m = Authz()
        m.setup(["--session", f"admin={a}", "--session", f"guest={g}"])
        return m

    async def test_renders_matrix(self, tmp_path, capsys):
        m = self._module(tmp_path)
        seeds = [make_request(url="http://x/admin")]
        status = {
            (0, "(original)"): 200,
            (0, "admin"): 200,
            (0, "guest"): 403,
        }
        await drive(m, seeds, status)
        out = capsys.readouterr().out
        assert "authorisation matrix" in out
        assert "(original)" in out and "admin" in out and "guest" in out
        assert "GET /admin" in out
        # guest differs from original → starred; admin matches → not starred
        assert "403*" in out
        assert "1 of 1 endpoints differ across users" in out

    async def test_no_star_when_all_match(self, tmp_path, capsys):
        m = self._module(tmp_path)
        seeds = [make_request(url="http://x/pub")]
        status = {
            (0, "(original)"): 200,
            (0, "admin"): 200,
            (0, "guest"): 200,
        }
        await drive(m, seeds, status)
        out = capsys.readouterr().out
        assert "*" not in out.split("* = status")[0]  # no star before the legend
        assert "0 of 1 endpoints differ across users" in out

    async def test_network_error_rendered_as_err(self, tmp_path, capsys):
        m = self._module(tmp_path)
        seeds = [make_request(url="http://x/")]
        status = {
            (0, "(original)"): 200,
            (0, "admin"): 0,
            (0, "guest"): 200,
        }
        await drive(m, seeds, status)
        assert "ERR" in capsys.readouterr().out

    async def test_multiple_endpoints(self, tmp_path, capsys):
        m = self._module(tmp_path)
        seeds = [make_request(url="http://x/a"), make_request(url="http://x/b")]
        status = {
            (0, "(original)"): 200, (0, "admin"): 200, (0, "guest"): 200,
            (1, "(original)"): 200, (1, "admin"): 200, (1, "guest"): 500,
        }
        await drive(m, seeds, status)
        out = capsys.readouterr().out
        assert "GET /a" in out and "GET /b" in out
        assert "1 of 2 endpoints differ across users" in out

    async def test_silent_when_no_results(self, tmp_path, capsys):
        m = self._module(tmp_path)
        await m.finalize(LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_results_use_namespaced_context_key(self, tmp_path):
        m = self._module(tmp_path)
        ctx = await drive(m, [make_request()], {
            (0, "(original)"): 200, (0, "admin"): 200, (0, "guest"): 200,
        })
        assert "authz.results" in ctx.data
