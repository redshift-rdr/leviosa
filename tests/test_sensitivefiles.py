import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from modules.sensitivefiles import SensitiveFiles


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


def make_response(url, status=200, body=b""):
    return LeviosaResponse(status=status, headers={}, body=body, request=make_request(url))


def make_finder(wordlist=None):
    f = SensitiveFiles()
    if wordlist is not None:
        f._wordlist = list(wordlist)
    return f


# ---------------------------------------------------------------------------
# Loader compatibility
# ---------------------------------------------------------------------------

def test_loads_via_loader():
    from core.loader import load_modules
    instances = load_modules(["sensitivefiles"])
    assert len(instances) == 1
    assert type(instances[0]).__name__ == "SensitiveFiles"


def test_recursive_enabled_by_default():
    assert SensitiveFiles()._recursive is True


# ---------------------------------------------------------------------------
# setup()
# ---------------------------------------------------------------------------

class TestSetup:
    def test_default_uses_builtin_list(self):
        f = SensitiveFiles()
        f.setup([])
        assert f._wordlist == SensitiveFiles.DEFAULT_SENSITIVE_PATHS
        assert ".env" in f._wordlist
        assert ".git/config" in f._wordlist

    def test_wordlist_replaces_builtin(self, tmp_path):
        wl = tmp_path / "sens.txt"
        wl.write_text(".secret\nbackups/\n")
        f = SensitiveFiles()
        f.setup(["--sensitive-wordlist", str(wl)])
        assert f._wordlist == [".secret", "backups/"]

    def test_leading_slash_stripped_trailing_kept(self, tmp_path):
        wl = tmp_path / "sens.txt"
        wl.write_text("/.git/\n/.env\n")
        f = SensitiveFiles()
        f.setup(["--sensitive-wordlist", str(wl)])
        assert f._wordlist == [".git/", ".env"]

    def test_extra_appends(self, tmp_path):
        extra = tmp_path / "extra.txt"
        extra.write_text("custom.bak\n")
        f = SensitiveFiles()
        f.setup(["--sensitive-extra", str(extra)])
        assert f._wordlist[: len(SensitiveFiles.DEFAULT_SENSITIVE_PATHS)] == \
            SensitiveFiles.DEFAULT_SENSITIVE_PATHS
        assert f._wordlist[-1] == "custom.bak"

    def test_ignores_unknown_args(self):
        f = SensitiveFiles()
        f.setup(["--wordlist", "for-another-module.txt"])
        assert f._wordlist == SensitiveFiles.DEFAULT_SENSITIVE_PATHS


# ---------------------------------------------------------------------------
# mutate() — recursion at every path level
# ---------------------------------------------------------------------------

class TestMutate:
    async def test_bare_domain_root_only(self):
        f = make_finder([".env", ".git/"])
        result = list(await f.mutate([make_request("http://x.com/")], LeviosaContext()))
        assert [r.url for r in result] == ["http://x.com/.env", "http://x.com/.git/"]

    async def test_all_levels_including_full_path(self):
        f = make_finder([".env"])
        result = list(await f.mutate([make_request("http://x.com/a/b/c")], LeviosaContext()))
        urls = [r.url for r in result]
        assert urls == [
            "http://x.com/.env",
            "http://x.com/a/.env",
            "http://x.com/a/b/.env",
            "http://x.com/a/b/c/.env",
        ]

    async def test_level_count(self):
        # 3 path segments -> 4 levels; 2 words -> 8 variants
        f = make_finder([".env", ".git/config"])
        result = list(await f.mutate([make_request("http://x.com/a/b/c")], LeviosaContext()))
        assert len(result) == 8

    async def test_files_have_no_trailing_slash(self):
        f = make_finder([".env"])
        result = list(await f.mutate([make_request("http://x.com/a")], LeviosaContext()))
        assert all(not r.url.endswith("/") for r in result)

    async def test_directories_keep_trailing_slash(self):
        f = make_finder([".git/"])
        result = list(await f.mutate([make_request("http://x.com/a")], LeviosaContext()))
        assert all(r.url.endswith("/.git/") for r in result)

    async def test_nested_file_path(self):
        f = make_finder([".git/config"])
        result = list(await f.mutate([make_request("http://x.com/app")], LeviosaContext()))
        assert "http://x.com/.git/config" in [r.url for r in result]
        assert "http://x.com/app/.git/config" in [r.url for r in result]

    async def test_query_and_fragment_dropped(self):
        f = make_finder([".env"])
        result = list(await f.mutate([make_request("http://x.com/a?b=1#f")], LeviosaContext()))
        assert result[0].url == "http://x.com/.env"

    async def test_port_and_scheme_preserved(self):
        f = make_finder([".env"])
        result = list(await f.mutate([make_request("https://x.com:8443/a")], LeviosaContext()))
        assert result[0].url == "https://x.com:8443/.env"

    async def test_headers_and_method_preserved(self):
        f = make_finder([".env"])
        req = make_request("http://x.com/a", method="POST", headers=["Cookie: s=1"])
        result = list(await f.mutate([req], LeviosaContext()))
        assert result[0].method == "POST"
        assert result[0].headers == ["Cookie: s=1"]

    async def test_original_request_unchanged(self):
        f = make_finder([".env"])
        original = make_request("http://x.com/a/b")
        list(await f.mutate([original], LeviosaContext()))
        assert original.url == "http://x.com/a/b"

    async def test_multiple_requests(self):
        f = make_finder([".env"])
        reqs = [make_request("http://x.com/a"), make_request("http://y.com/")]
        result = list(await f.mutate(reqs, LeviosaContext()))
        # x.com/a -> 2 levels, y.com/ -> 1 level
        assert len(result) == 3

    async def test_empty_wordlist_raises(self):
        f = make_finder([])
        with pytest.raises(RuntimeError, match="sensitivefiles"):
            await f.mutate([make_request()], LeviosaContext())


# ---------------------------------------------------------------------------
# needs_body — sensitivefiles inspects bodies, so it must read them
# ---------------------------------------------------------------------------

def test_sensitivefiles_needs_body_true():
    assert SensitiveFiles.needs_body is True


# ---------------------------------------------------------------------------
# analyze_one()
# ---------------------------------------------------------------------------

class TestAnalyzeOne:
    async def test_404_suppressed(self, capsys):
        f = make_finder()
        await f.analyze_one(make_response("http://x.com/.env", status=404), LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_network_error_suppressed(self, capsys):
        f = make_finder()
        await f.analyze_one(make_response("http://x.com/.env", status=0), LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_200_reported(self, capsys):
        f = make_finder()
        await f.analyze_one(make_response("http://x.com/.env", status=200), LeviosaContext())
        assert "[SENSITIVEFILES] 200 GET http://x.com/.env" in capsys.readouterr().out

    async def test_403_reported(self, capsys):
        f = make_finder()
        await f.analyze_one(make_response("http://x.com/.git/", status=403), LeviosaContext())
        assert "[SENSITIVEFILES]" in capsys.readouterr().out

    async def test_git_config_flagged(self, capsys):
        f = make_finder()
        body = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
        await f.analyze_one(make_response("http://x.com/.git/config", status=200, body=body),
                            LeviosaContext())
        assert "exposed: git-repo" in capsys.readouterr().out

    async def test_private_key_flagged(self, capsys):
        f = make_finder()
        body = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...\n"
        await f.analyze_one(make_response("http://x.com/id_rsa", status=200, body=body),
                            LeviosaContext())
        assert "exposed: private-key" in capsys.readouterr().out

    async def test_env_secrets_flagged(self, capsys):
        f = make_finder()
        body = b"APP_ENV=production\nDB_PASSWORD=hunter2\nSECRET_KEY=abc\n"
        await f.analyze_one(make_response("http://x.com/.env", status=200, body=body),
                            LeviosaContext())
        assert "exposed: env-secrets" in capsys.readouterr().out

    async def test_htpasswd_flagged(self, capsys):
        f = make_finder()
        body = b"admin:$apr1$xyz$abcdefghijklmnop\n"
        await f.analyze_one(make_response("http://x.com/.htpasswd", status=200, body=body),
                            LeviosaContext())
        assert "exposed: htpasswd" in capsys.readouterr().out

    async def test_sql_dump_flagged(self, capsys):
        f = make_finder()
        body = b"CREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);\n"
        await f.analyze_one(make_response("http://x.com/dump.sql", status=200, body=body),
                            LeviosaContext())
        assert "exposed: sql-dump" in capsys.readouterr().out

    async def test_plain_body_not_flagged(self, capsys):
        f = make_finder()
        await f.analyze_one(make_response("http://x.com/.env", status=200, body=b"nothing here"),
                            LeviosaContext())
        out = capsys.readouterr().out
        assert "[SENSITIVEFILES] 200" in out
        assert "exposed" not in out

    async def test_only_interesting_reported(self, capsys):
        f = make_finder()
        responses = [
            make_response("http://x.com/.env", status=200),
            make_response("http://x.com/.git/config", status=404),
            make_response("http://x.com/.htaccess", status=403),
        ]
        ctx = LeviosaContext()
        for resp in responses:
            await f.analyze_one(resp, ctx)
        lines = capsys.readouterr().out.strip().splitlines()
        assert len(lines) == 2
