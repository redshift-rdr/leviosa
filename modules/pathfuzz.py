import argparse
from dataclasses import replace
from urllib.parse import urlparse, urlunparse

from core.analysers import StatusCodeAnalyser
from modules.base import BaseModule


class PathFuzzer(BaseModule):
    """
    Path fuzzer — two modes:

    Keyword mode (default):
        Replace a placeholder keyword in the URL with each wordlist item.
        e.g. http://example.com/FUZZ/resource -> http://example.com/admin/resource

    Recursive mode (--recursive):
        For each depth level of the URL path, build a fuzz URL that keeps the
        path prefix up to that depth and appends a wordlist item.
        e.g. http://example.com/home/next ->
             http://example.com/word/
             http://example.com/home/word/
    """

    # Path fuzzing only inspects status codes, so the engine can skip reading
    # response bodies entirely.
    needs_body = False

    def __init__(self):
        self._wordlist: list[str] | None = None
        self._keyword: str = "FUZZ"
        self._recursive: bool = False
        self._skip = StatusCodeAnalyser([0, 404])
        self._filters = []

    def setup(self, args: list[str]) -> None:
        parser = argparse.ArgumentParser(prog="pathfuzz", add_help=False)
        parser.add_argument("--wordlist", required=True, metavar="PATH",
                            help="Path to wordlist file (one entry per line)")
        parser.add_argument("--keyword", default="FUZZ", metavar="KW",
                            help="Placeholder in the URL to replace (default: FUZZ)")
        parser.add_argument("--recursive", action="store_true",
                            help="Fuzz every path depth level, not just the keyword position")
        parsed, _ = parser.parse_known_args(args)

        with open(parsed.wordlist) as f:
            self._wordlist = [line.strip() for line in f if line.strip()]
        self._keyword = parsed.keyword
        self._recursive = parsed.recursive
        self.parse_request_filters(args)

    async def mutate(self, requests, context):
        if self._wordlist is None:
            raise RuntimeError(
                "pathfuzz requires --wordlist <path>. "
                "Pass it after the leviosa flags, e.g.: "
                "leviosa target.json --module pathfuzz --wordlist words.txt"
            )
        return self._variants(requests)

    def _variants(self, requests):
        """Lazily yield one variant at a time so the whole set never resides in memory."""
        for req in requests:
            if self._recursive:
                yield from self._recursive_variants(req)
            else:
                yield from self._keyword_variants(req)

    def _keyword_variants(self, req):
        if self._keyword not in req.url:
            return
        for word in self._wordlist:
            # url-only mutation: replace() shallow-copies, safe to share the
            # unmutated headers/params (the engine only reads them).
            yield replace(req, url=req.url.replace(self._keyword, word))

    def _recursive_variants(self, req):
        parsed = urlparse(req.url)
        segments = [s for s in parsed.path.rstrip("/").split("/") if s]
        # Always fuzz at least the root level, even for bare-domain URLs
        depth_count = max(len(segments), 1)
        for depth in range(depth_count):
            prefix_parts = segments[:depth]
            prefix = "/" + "/".join(prefix_parts) if prefix_parts else ""
            for word in self._wordlist:
                fuzz_path = f"{prefix}/{word}/"
                new_parsed = parsed._replace(path=fuzz_path)
                yield replace(req, url=urlunparse(new_parsed))

    async def analyze_one(self, response, context):
        if not self._skip.matches(response):
            print(f"[PATHFUZZ] {response.status} {response.request.method} {response.request.url}")
