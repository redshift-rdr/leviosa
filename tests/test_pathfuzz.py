import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from modules.pathfuzz import PathFuzzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_request(url="http://example.com/FUZZ"):
    return LeviosaRequest(method="GET", url=url, headers=[], params=[])


def make_response(url, status=200):
    return LeviosaResponse(
        status=status,
        headers={},
        body=b"",
        request=make_request(url),
    )


def make_fuzzer(wordlist=None, keyword="FUZZ", recursive=False):
    """Build a PathFuzzer with attributes set directly, bypassing file I/O."""
    f = PathFuzzer()
    f._wordlist = wordlist if wordlist is not None else ["word1", "word2", "word3"]
    f._keyword = keyword
    f._recursive = recursive
    return f


@pytest.fixture
def wordlist_file(tmp_path):
    f = tmp_path / "words.txt"
    f.write_text("admin\nuser\nsecret\n")
    return str(f)


# ---------------------------------------------------------------------------
# setup() tests
# ---------------------------------------------------------------------------

class TestSetup:
    def test_loads_wordlist(self, wordlist_file):
        fuzz = PathFuzzer()
        fuzz.setup(["--wordlist", wordlist_file])
        assert fuzz._wordlist == ["admin", "user", "secret"]

    def test_default_keyword_is_fuzz(self, wordlist_file):
        fuzz = PathFuzzer()
        fuzz.setup(["--wordlist", wordlist_file])
        assert fuzz._keyword == "FUZZ"

    def test_custom_keyword(self, wordlist_file):
        fuzz = PathFuzzer()
        fuzz.setup(["--wordlist", wordlist_file, "--keyword", "INJECT"])
        assert fuzz._keyword == "INJECT"

    def test_recursive_false_by_default(self, wordlist_file):
        fuzz = PathFuzzer()
        fuzz.setup(["--wordlist", wordlist_file])
        assert fuzz._recursive is False

    def test_recursive_flag(self, wordlist_file):
        fuzz = PathFuzzer()
        fuzz.setup(["--wordlist", wordlist_file, "--recursive"])
        assert fuzz._recursive is True

    def test_blank_lines_ignored(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("admin\n\nuser\n\n")
        fuzz = PathFuzzer()
        fuzz.setup(["--wordlist", str(f)])
        assert fuzz._wordlist == ["admin", "user"]

    def test_missing_wordlist_raises(self):
        fuzz = PathFuzzer()
        with pytest.raises(SystemExit):
            fuzz.setup([])

    def test_nonexistent_wordlist_raises(self):
        fuzz = PathFuzzer()
        with pytest.raises(FileNotFoundError):
            fuzz.setup(["--wordlist", "/nonexistent/words.txt"])

    def test_ignores_unknown_args(self, wordlist_file):
        """setup() should not choke on args meant for other modules."""
        fuzz = PathFuzzer()
        fuzz.setup(["--wordlist", wordlist_file, "--some-other-flag", "value"])
        assert fuzz._wordlist == ["admin", "user", "secret"]


# ---------------------------------------------------------------------------
# mutate() — no setup
# ---------------------------------------------------------------------------

class TestMutateWithoutSetup:
    async def test_raises_clear_error(self):
        fuzz = PathFuzzer()
        with pytest.raises(RuntimeError, match="--wordlist"):
            await fuzz.mutate([make_request()], LeviosaContext())


# ---------------------------------------------------------------------------
# Keyword mode
# ---------------------------------------------------------------------------

class TestKeywordMode:
    async def test_count(self):
        fuzz = make_fuzzer(["a", "b", "c"])
        result = await fuzz.mutate([make_request("http://x.com/FUZZ/page")], LeviosaContext())
        assert len(result) == 3

    async def test_two_requests_times_wordlist(self):
        fuzz = make_fuzzer(["a", "b", "c"])
        reqs = [make_request("http://x.com/FUZZ"), make_request("http://y.com/FUZZ")]
        result = await fuzz.mutate(reqs, LeviosaContext())
        assert len(result) == 6

    async def test_keyword_replaced_in_url(self):
        fuzz = make_fuzzer(["admin"])
        result = await fuzz.mutate([make_request("http://x.com/FUZZ/page")], LeviosaContext())
        assert result[0].url == "http://x.com/admin/page"

    async def test_all_words_appear(self):
        fuzz = make_fuzzer(["admin", "user", "secret"])
        result = await fuzz.mutate([make_request("http://x.com/FUZZ")], LeviosaContext())
        urls = [r.url for r in result]
        assert "http://x.com/admin" in urls
        assert "http://x.com/user" in urls
        assert "http://x.com/secret" in urls

    async def test_custom_keyword_replaced(self):
        fuzz = make_fuzzer(["admin"], keyword="INJECT")
        result = await fuzz.mutate([make_request("http://x.com/INJECT/page")], LeviosaContext())
        assert result[0].url == "http://x.com/admin/page"

    async def test_no_keyword_in_url_returns_empty(self):
        fuzz = make_fuzzer(["admin"])
        result = await fuzz.mutate([make_request("http://x.com/path")], LeviosaContext())
        assert result == []

    async def test_no_aliasing(self):
        fuzz = make_fuzzer(["admin", "user"])
        result = await fuzz.mutate([make_request("http://x.com/FUZZ")], LeviosaContext())
        result[0].url = "http://tampered.com"
        assert result[1].url == "http://x.com/user"

    async def test_original_request_unchanged(self):
        fuzz = make_fuzzer(["admin"])
        original = make_request("http://x.com/FUZZ")
        await fuzz.mutate([original], LeviosaContext())
        assert original.url == "http://x.com/FUZZ"


# ---------------------------------------------------------------------------
# Recursive mode
# ---------------------------------------------------------------------------

class TestRecursiveMode:
    async def test_count_one_segment(self):
        # path /page has 1 segment → 1 depth level × 3 words = 3 variants
        fuzz = make_fuzzer(["a", "b", "c"], recursive=True)
        result = await fuzz.mutate([make_request("http://x.com/page")], LeviosaContext())
        assert len(result) == 3

    async def test_count_three_segments(self):
        # path /a/b/c → 3 depth levels × 3 words = 9 variants
        fuzz = make_fuzzer(["a", "b", "c"], recursive=True)
        result = await fuzz.mutate([make_request("http://x.com/seg1/seg2/seg3")], LeviosaContext())
        assert len(result) == 9

    async def test_depth_zero_is_root(self):
        fuzz = make_fuzzer(["admin"], recursive=True)
        result = await fuzz.mutate([make_request("http://x.com/home/page")], LeviosaContext())
        assert result[0].url == "http://x.com/admin/"

    async def test_depth_one_keeps_first_segment(self):
        fuzz = make_fuzzer(["admin"], recursive=True)
        result = await fuzz.mutate([make_request("http://x.com/home/page")], LeviosaContext())
        assert result[1].url == "http://x.com/home/admin/"

    async def test_trailing_slash_always_added(self):
        fuzz = make_fuzzer(["admin"], recursive=True)
        result = await fuzz.mutate([make_request("http://x.com/home/page")], LeviosaContext())
        assert all(r.url.endswith("/") for r in result)

    async def test_host_preserved(self):
        fuzz = make_fuzzer(["admin"], recursive=True)
        result = await fuzz.mutate([make_request("http://target.local:8080/home/page")], LeviosaContext())
        assert all(r.url.startswith("http://target.local:8080/") for r in result)

    async def test_bare_domain_generates_root_level(self):
        # URL with no meaningful path segments → one root level
        fuzz = make_fuzzer(["admin", "user"], recursive=True)
        result = await fuzz.mutate([make_request("http://x.com/")], LeviosaContext())
        assert len(result) == 2
        assert result[0].url == "http://x.com/admin/"

    async def test_no_aliasing(self):
        fuzz = make_fuzzer(["a", "b"], recursive=True)
        result = await fuzz.mutate([make_request("http://x.com/home/page")], LeviosaContext())
        result[0].url = "http://tampered.com/"
        assert result[1].url != "http://tampered.com/"

    async def test_two_requests_multiplied(self):
        fuzz = make_fuzzer(["a", "b"], recursive=True)
        reqs = [make_request("http://x.com/a/b"), make_request("http://y.com/a/b")]
        result = await fuzz.mutate(reqs, LeviosaContext())
        # 2 requests × 2 segments × 2 words = 8
        assert len(result) == 8


# ---------------------------------------------------------------------------
# analyze()
# ---------------------------------------------------------------------------

class TestAnalyze:
    async def test_non_404_printed(self, capsys):
        fuzz = make_fuzzer()
        await fuzz.analyze([make_response("http://x.com/admin/", status=200)], LeviosaContext())
        assert "[PATHFUZZ]" in capsys.readouterr().out

    async def test_404_suppressed(self, capsys):
        fuzz = make_fuzzer()
        await fuzz.analyze([make_response("http://x.com/missing/", status=404)], LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_zero_status_suppressed(self, capsys):
        fuzz = make_fuzzer()
        await fuzz.analyze([make_response("http://x.com/fail/", status=0)], LeviosaContext())
        assert capsys.readouterr().out == ""

    async def test_403_printed(self, capsys):
        fuzz = make_fuzzer()
        await fuzz.analyze([make_response("http://x.com/secret/", status=403)], LeviosaContext())
        assert "[PATHFUZZ]" in capsys.readouterr().out

    async def test_redirect_printed(self, capsys):
        fuzz = make_fuzzer()
        await fuzz.analyze([make_response("http://x.com/moved/", status=301)], LeviosaContext())
        assert "[PATHFUZZ]" in capsys.readouterr().out

    async def test_output_format(self, capsys):
        fuzz = make_fuzzer()
        await fuzz.analyze([make_response("http://x.com/admin/", status=200)], LeviosaContext())
        line = capsys.readouterr().out.strip()
        assert line == "[PATHFUZZ] 200 GET http://x.com/admin/"

    async def test_multiple_interesting_all_printed(self, capsys):
        fuzz = make_fuzzer()
        responses = [
            make_response("http://x.com/admin/", status=200),
            make_response("http://x.com/missing/", status=404),
            make_response("http://x.com/secret/", status=403),
        ]
        await fuzz.analyze(responses, LeviosaContext())
        lines = capsys.readouterr().out.strip().splitlines()
        assert len(lines) == 2

    async def test_all_404_no_output(self, capsys):
        fuzz = make_fuzzer()
        responses = [make_response(f"http://x.com/{w}/", status=404) for w in ["a", "b", "c"]]
        await fuzz.analyze(responses, LeviosaContext())
        assert capsys.readouterr().out == ""
