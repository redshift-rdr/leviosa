import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from modules.adminfinder import AdminFinder


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(url="http://example.com/", method="GET", headers=None, params=None):
    return LeviosaRequest(
        method=method,
        url=url,
        headers=headers if headers is not None else [],
        params=params if params is not None else [],
    )


def make_response(url, status=200, headers=None, body=b""):
    return LeviosaResponse(
        status=status,
        headers=headers if headers is not None else {},
        body=body,
        request=make_request(url),
    )


def make_finder(wordlist=None):
    f = AdminFinder()
    if wordlist is not None:
        f._wordlist = list(wordlist)
    return f


# ---------------------------------------------------------------------------
# Loader compatibility — importing PathFuzzer must not add a 2nd subclass
# ---------------------------------------------------------------------------

def test_loads_via_loader():
    from core.loader import load_modules
    instances = load_modules(["adminfinder"])
    assert len(instances) == 1
    assert type(instances[0]).__name__ == "AdminFinder"


# ---------------------------------------------------------------------------
# setup()
# ---------------------------------------------------------------------------

class TestSetup:
    def test_default_uses_builtin_list(self):
        f = AdminFinder()
        f.setup([])
        assert f._wordlist == AdminFinder.DEFAULT_ADMIN_PATHS
        assert "admin" in f._wordlist

    def test_admin_wordlist_replaces_builtin(self, tmp_path):
        wl = tmp_path / "admin.txt"
        wl.write_text("secret-panel\nhidden/\n")
        f = AdminFinder()
        f.setup(["--admin-wordlist", str(wl)])
        assert f._wordlist == ["secret-panel", "hidden/"]

    def test_leading_slash_stripped(self, tmp_path):
        wl = tmp_path / "admin.txt"
        wl.write_text("/admin\n/manager/\n")
        f = AdminFinder()
        f.setup(["--admin-wordlist", str(wl)])
        assert f._wordlist == ["admin", "manager/"]

    def test_admin_extra_appends(self, tmp_path):
        extra = tmp_path / "extra.txt"
        extra.write_text("bespoke-admin\n")
        f = AdminFinder()
        f.setup(["--admin-extra", str(extra)])
        assert f._wordlist[: len(AdminFinder.DEFAULT_ADMIN_PATHS)] == AdminFinder.DEFAULT_ADMIN_PATHS
        assert f._wordlist[-1] == "bespoke-admin"

    def test_blank_lines_ignored(self, tmp_path):
        wl = tmp_path / "admin.txt"
        wl.write_text("admin\n\n\nmanager\n")
        f = AdminFinder()
        f.setup(["--admin-wordlist", str(wl)])
        assert f._wordlist == ["admin", "manager"]

    def test_ignores_unknown_args(self):
        f = AdminFinder()
        f.setup(["--some-other-module-flag", "value"])
        assert f._wordlist == AdminFinder.DEFAULT_ADMIN_PATHS


# ---------------------------------------------------------------------------
# mutate()
# ---------------------------------------------------------------------------

class TestMutate:
    async def test_variant_count_matches_wordlist(self):
        f = make_finder(["admin", "manager", "cp"])
        result = await f.mutate([make_request("http://x.com/")], LeviosaContext())
        assert len(result) == 3

    async def test_paths_appended_to_origin(self):
        f = make_finder(["admin", "wp-admin/"])
        result = await f.mutate([make_request("http://x.com/deep/page")], LeviosaContext())
        urls = [r.url for r in result]
        assert "http://x.com/admin" in urls
        assert "http://x.com/wp-admin/" in urls

    async def test_query_and_fragment_dropped(self):
        f = make_finder(["admin"])
        result = await f.mutate([make_request("http://x.com/page?a=1#frag")], LeviosaContext())
        assert result[0].url == "http://x.com/admin"

    async def test_port_preserved(self):
        f = make_finder(["admin"])
        result = await f.mutate([make_request("http://x.com:8443/whatever")], LeviosaContext())
        assert result[0].url == "http://x.com:8443/admin"

    async def test_https_scheme_preserved(self):
        f = make_finder(["admin"])
        result = await f.mutate([make_request("https://x.com/")], LeviosaContext())
        assert result[0].url == "https://x.com/admin"

    async def test_headers_and_method_preserved(self):
        f = make_finder(["admin"])
        req = make_request("http://x.com/", method="POST", headers=["Cookie: s=1"])
        result = await f.mutate([req], LeviosaContext())
        assert result[0].method == "POST"
        assert result[0].headers == ["Cookie: s=1"]

    async def test_multiple_requests_multiplied(self):
        f = make_finder(["admin", "cp"])
        reqs = [make_request("http://x.com/"), make_request("http://y.com/")]
        result = await f.mutate(reqs, LeviosaContext())
        assert len(result) == 4

    async def test_original_request_unchanged(self):
        f = make_finder(["admin"])
        original = make_request("http://x.com/original/path")
        await f.mutate([original], LeviosaContext())
        assert original.url == "http://x.com/original/path"

    async def test_empty_wordlist_raises(self):
        f = make_finder([])
        with pytest.raises(RuntimeError, match="admin"):
            await f.mutate([make_request()], LeviosaContext())


# ---------------------------------------------------------------------------
# analyze()
# ---------------------------------------------------------------------------

class TestAnalyze:
    async def test_404_suppressed(self, capsys):
        f = make_finder()
        await f.analyze([make_response("http://x.com/admin", status=404)], LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_network_error_suppressed(self, capsys):
        f = make_finder()
        await f.analyze([make_response("http://x.com/admin", status=0)], LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_200_reported(self, capsys):
        f = make_finder()
        await f.analyze([make_response("http://x.com/admin", status=200)], LeviosaContext())
        out = capsys.readouterr().out
        assert "[ADMINFINDER] 200 GET http://x.com/admin" in out

    async def test_403_reported(self, capsys):
        f = make_finder()
        await f.analyze([make_response("http://x.com/admin", status=403)], LeviosaContext())
        assert "[ADMINFINDER]" in capsys.readouterr().out

    async def test_auth_challenge_flagged(self, capsys):
        f = make_finder()
        resp = make_response(
            "http://x.com/admin",
            status=401,
            headers={"WWW-Authenticate": "Basic realm=admin"},
        )
        await f.analyze([resp], LeviosaContext())
        out = capsys.readouterr().out
        assert "likely admin: auth-challenge" in out

    async def test_401_without_header_not_flagged(self, capsys):
        f = make_finder()
        resp = make_response("http://x.com/admin", status=401, headers={})
        await f.analyze([resp], LeviosaContext())
        out = capsys.readouterr().out
        assert "[ADMINFINDER] 401" in out
        assert "likely admin" not in out

    async def test_login_page_body_flagged(self, capsys):
        f = make_finder()
        body = b"<html><form><input type='password' name='pw'></form></html>"
        resp = make_response("http://x.com/admin", status=200, body=body)
        await f.analyze([resp], LeviosaContext())
        assert "likely admin: login-page" in capsys.readouterr().out

    async def test_admin_title_flagged(self, capsys):
        f = make_finder()
        body = b"<html><head><title>Admin Console</title></head></html>"
        resp = make_response("http://x.com/console", status=200, body=body)
        await f.analyze([resp], LeviosaContext())
        assert "login-page" in capsys.readouterr().out

    async def test_plain_page_not_flagged(self, capsys):
        f = make_finder()
        resp = make_response("http://x.com/admin", status=200, body=b"<html>hello</html>")
        await f.analyze([resp], LeviosaContext())
        out = capsys.readouterr().out
        assert "[ADMINFINDER] 200" in out
        assert "likely admin" not in out

    async def test_mixed_only_interesting_reported(self, capsys):
        f = make_finder()
        responses = [
            make_response("http://x.com/admin", status=200),
            make_response("http://x.com/administrator", status=404),
            make_response("http://x.com/cp", status=302),
        ]
        await f.analyze(responses, LeviosaContext())
        lines = capsys.readouterr().out.strip().splitlines()
        assert len(lines) == 2
