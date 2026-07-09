import argparse
import copy
import re
from dataclasses import replace
from urllib.parse import urlparse, urlunparse

from core.models import Param
from modules.base import BaseModule

# Namespaced context key for the cross-response summary built in analyze_one
# and emitted in finalize().
_CONTEXT_KEY = "errorpages.stats"

# Deterministic segment appended to induce a 404 (unlikely to exist).
_NOT_FOUND_SEG = "leviosa_404_probe_zzq7"

# All induction techniques, in the order they are applied per request.
ALL_TECHNIQUES = [
    "not-found",        # append a nonexistent path segment            -> 404
    "bad-method",       # send an invalid HTTP verb                     -> 405/501/400
    "long-url",         # oversized path segment                        -> 414/500/400
    "special-path",     # path segment of parser-breaking characters    -> 400/500
    "param-injection",  # break existing params with hostile values     -> 500 + disclosure
    "junk-param",       # add hostile query params (works with no params)
]

# Values that tend to break parsers / trigger stack traces when reflected into
# a parameter the application actually processes.
_BREAKERS = [
    "'",
    '"',
    "'\"`)>",
    "{{7*7}}",
    "${7*7}",
    "../../../../../../etc/passwd",
    "A" * 2048,
]

# Parameter types worth injecting into. Header injection is deliberately avoided
# — a malformed header tends to break the client request, not the server.
_INJECTABLE = {"query", "json", "form", "cookie"}

# Information-disclosure signatures looked for in error-page bodies. Heuristic,
# case-insensitive. Each (name, regex) pair names a class of leak.
_SIGNATURES = [
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in [
        ("php-error",
         r"<b>\s*(?:warning|fatal error|parse error|notice)\s*</b>|\.php on line \d+"
         r"|xdebug|call to (?:undefined|a member)"),
        ("python-traceback",
         r"traceback \(most recent call last\)|file \"[^\"]+\", line \d+, in "
         r"|werkzeug|django\.\w+"),
        ("java-trace",
         r"at [\w.$]+\([\w$<>]+\.java:\d+\)|java\.lang\.\w+exception|javax\.servlet"
         r"|org\.springframework|nested exception is"),
        ("dotnet-error",
         r"system\.[\w.]+exception|asp\.net|\.cs:line \d+|runtime error"
         r"|microsoft\.\w+\.\w+"),
        ("ruby-error",
         r"(?:runtimeerror|nomethoderror|nameerror|argumenterror)\b|\.rb:\d+:in "
         r"|actioncontroller"),
        ("node-error",
         r"at \w[\w.]* \([^)]*\.js:\d+:\d+\)|node_modules|referenceerror:"
         r"|typeerror: |cannot read propert"),
        ("sql-error",
         r"you have an error in your sql syntax|sql syntax.*?mysql|warning:\s*\w*_?sql"
         r"|unclosed quotation mark|ora-\d{5}|postgresql|sqlstate\[|sqlite_"
         r"|odbc\s+driver|native client|quoted string not properly terminated"),
        ("stack-trace", r"stack ?trace|backtrace|call stack"),
        ("path-disclosure",
         r"/var/www/|/home/[\w.-]+/|/usr/local/|/opt/[\w.-]+"
         r"|[A-Za-z]:\\(?:inetpub|windows|users|xampp|wamp|program files)"),
        ("debug-info",
         r"whoops\b|symfony profiler|display_errors|debug(?:ging)? (?:mode|information)"
         r"|application trace"),
    ]
]


class ErrorPages(BaseModule):
    """
    Error-page hunter.

    For each input request this module emits several mutated variants, each
    designed to induce a different class of error response — a missing path
    (404), an invalid method (405/501), an oversized or malformed URL
    (414/400), and hostile parameter values that break server-side parsers
    (500). Every response is then classified:

      - any 4xx/5xx status is reported as an error page, tagged with the
        technique that induced it;
      - the body is scanned for information-disclosure signatures (language
        stack traces, SQL errors, filesystem paths, debug pages), which are
        reported even on a 200 response — a leaked stack trace behind a 200 is
        exactly the kind of masked error worth surfacing.

    finalize() prints a summary: a count per status code and per disclosure
    signature seen across the whole run.
    """

    # Bodies are scanned for disclosure signatures, so they must be read.
    needs_body = True

    def __init__(self):
        self._enabled = list(ALL_TECHNIQUES)
        self._long_url_len = 4096
        self._filters = []
        # Maps id(variant request) -> technique label. Populated as variants are
        # yielded and popped as each response is analysed, so it stays bounded to
        # roughly the in-flight window rather than growing with the whole scan.
        self._techniques: dict[int, str] = {}

    def option_parser(self):
        parser = argparse.ArgumentParser(prog="errorpages", add_help=False)
        parser.add_argument(
            "--techniques", metavar="LIST", default=None,
            help="Comma-separated subset of techniques to run. Available: "
                 + ", ".join(ALL_TECHNIQUES),
        )
        parser.add_argument(
            "--long-url-len", type=int, default=4096, metavar="N",
            help="Length of the oversized path segment for the long-url technique "
                 "(default: 4096)",
        )
        return parser

    def setup(self, args: list[str]) -> None:
        parsed, _ = self.option_parser().parse_known_args(args)

        if parsed.techniques:
            chosen = [t.strip() for t in parsed.techniques.split(",") if t.strip()]
            invalid = [t for t in chosen if t not in ALL_TECHNIQUES]
            if invalid:
                raise RuntimeError(
                    f"errorpages: unknown technique(s): {', '.join(invalid)}. "
                    f"Available: {', '.join(ALL_TECHNIQUES)}"
                )
            self._enabled = chosen
        self._long_url_len = parsed.long_url_len
        self.parse_request_filters(args)

    async def mutate(self, requests, context):
        return self._variants(requests)

    def _variants(self, requests):
        """Lazily yield one induced variant at a time, tagging each with its technique."""
        enabled = set(self._enabled)
        for req in requests:
            for label, variant in self._induce(req, enabled):
                self._techniques[id(variant)] = label
                yield variant

    def _induce(self, req, enabled):
        parsed = urlparse(req.url)
        base_path = parsed.path.rstrip("/")
        if "not-found" in enabled:
            yield "not-found", self._url_variant(req, parsed, f"{base_path}/{_NOT_FOUND_SEG}")
        if "special-path" in enabled:
            yield "special-path", self._url_variant(req, parsed, f"{base_path}/leviosa'\";<>()")
        if "long-url" in enabled:
            yield "long-url", self._url_variant(req, parsed, f"{base_path}/{'L' * self._long_url_len}")
        if "bad-method" in enabled:
            # url-only in spirit: only the verb changes, headers/params are read-only.
            yield "bad-method", replace(req, method="LEVIOSA")
        if "param-injection" in enabled:
            yield from self._param_variants(req)
        if "junk-param" in enabled:
            yield from self._junk_param_variants(req)

    @staticmethod
    def _url_variant(req, parsed, new_path):
        url = urlunparse(parsed._replace(path=new_path, params="", query="", fragment=""))
        # url-only mutation: replace() shallow-copies, safe to alias headers/params.
        return replace(req, url=url)

    def _param_variants(self, req):
        # Mutating Param values in place requires a deepcopy (replace would alias
        # the params list and corrupt sibling variants).
        injectable = [i for i, p in enumerate(req.params) if p.type in _INJECTABLE]
        for i in injectable:
            for payload in _BREAKERS:
                variant = copy.deepcopy(req)
                variant.params[i].value = payload
                yield "param-injection", variant

    def _junk_param_variants(self, req):
        # Adds a hostile query param, so it induces parse errors even when the
        # request carries no params of its own.
        for payload in _BREAKERS[:3]:
            variant = copy.deepcopy(req)
            variant.params.append(Param(type="query", name="leviosa_test", value=payload))
            yield "junk-param", variant

    @staticmethod
    def _disclosures(response) -> list[str]:
        text = response.body.decode("utf-8", errors="replace")
        return [name for name, rx in _SIGNATURES if rx.search(text)]

    async def analyze_one(self, response, context):
        # status == 0 is a network error — nothing was induced.
        if response.status == 0:
            self._techniques.pop(id(response.request), None)
            return
        technique = self._techniques.pop(id(response.request), "unknown")
        is_error = response.status >= 400
        disclosures = self._disclosures(response) if response.body else []
        if not is_error and not disclosures:
            return

        stats = context.data.setdefault(_CONTEXT_KEY, {"status": {}, "disclosures": {}})
        stats["status"][response.status] = stats["status"].get(response.status, 0) + 1
        for name in disclosures:
            stats["disclosures"][name] = stats["disclosures"].get(name, 0) + 1

        parts = [f"induced: {technique}"]
        if disclosures:
            parts.append(f"disclosure: {', '.join(disclosures)}")
        print(
            f"[ERRORPAGES] {response.status} {response.request.method} "
            f"{response.request.url}  [{' | '.join(parts)}]"
        )

    async def finalize(self, context):
        stats = context.data.get(_CONTEXT_KEY)
        if not stats:
            return
        print("[ERRORPAGES] --- summary ---")
        for status, count in sorted(stats["status"].items()):
            print(f"[ERRORPAGES]   status {status}: {count}")
        if stats["disclosures"]:
            print("[ERRORPAGES]   information disclosure signatures:")
            for name, count in sorted(stats["disclosures"].items()):
                print(f"[ERRORPAGES]     {name}: {count}")
