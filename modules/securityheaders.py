import argparse
import re
from urllib.parse import urlsplit

from modules.base import BaseModule

# Namespaced context key for the cross-response tally built in analyze_one and
# emitted in finalize().
_CONTEXT_KEY = "securityheaders.findings"

# Default minimum acceptable HSTS max-age (1 year, in seconds) — the value the
# hstspreload.org list and OWASP recommend.
_DEFAULT_HSTS_MIN_AGE = 31536000

# Pulls the integer out of an HSTS "max-age=<n>" directive (value optionally
# quoted). Case-insensitive; whitespace around "=" tolerated.
_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d+)\"?", re.IGNORECASE)

# Referrer-Policy values that still leak the full URL cross-origin (or to
# insecure destinations) and so weaken privacy/security.
_WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade", ""}

# Extra security headers whose absence is worth flagging. Reported only when the
# recommended tier is enabled (default on; disable with --no-recommended). These
# are display-name / lookup-name (lower-cased) pairs.
_RECOMMENDED_HEADERS = [
    ("Permissions-Policy", "permissions-policy"),
    ("Cross-Origin-Opener-Policy", "cross-origin-opener-policy"),
    ("Cross-Origin-Embedder-Policy", "cross-origin-embedder-policy"),
    ("Cross-Origin-Resource-Policy", "cross-origin-resource-policy"),
]


class SecurityHeaders(BaseModule):
    """
    Passive security-header auditor.

    Sends each request unchanged and inspects the response headers for missing
    or misconfigured security controls. Checks, always run:

      * HSTS — Strict-Transport-Security must be present (on HTTPS responses)
        with a max-age at least --hsts-min-age; max-age=0, a missing max-age,
        a too-low max-age, or a missing includeSubDomains are all flagged.
      * MIME sniffing — X-Content-Type-Options must be exactly 'nosniff'.
      * Clickjacking — at least one of X-Frame-Options (DENY/SAMEORIGIN) or a
        CSP 'frame-ancestors' directive must be present.
      * Referrer-Policy — must be present and not a referrer-leaking value.

    Recommended tier (default on, --no-recommended to skip): flags absence of
    Permissions-Policy and the Cross-Origin-{Opener,Embedder,Resource}-Policy
    isolation headers, and a non-'0' (deprecated) X-XSS-Protection.

    Deliberately does NOT audit CSP directives (see the csp module), software
    disclosure headers such as Server/X-Powered-By (versiondisclosure), or CORS
    ACAO/ACAC (cors) — it only reads CSP to confirm a frame-ancestors clickjacking
    defence.

    Only headers are inspected, so needs_body is False (no bodies downloaded).
    """

    # Header-only module: no need to read response bodies.
    needs_body = False

    def __init__(self):
        self._hsts_min_age = _DEFAULT_HSTS_MIN_AGE
        self._recommended = True
        self._filters = []

    def option_parser(self):
        parser = argparse.ArgumentParser(prog="securityheaders", add_help=False)
        parser.add_argument(
            "--hsts-min-age", type=int, default=_DEFAULT_HSTS_MIN_AGE, metavar="SECONDS",
            help="Minimum acceptable HSTS max-age in seconds "
                 f"(default: {_DEFAULT_HSTS_MIN_AGE} = 1 year)",
        )
        parser.add_argument(
            "--no-recommended", action="store_true",
            help="Only check the core headers (HSTS, X-Content-Type-Options, "
                 "anti-clickjacking, Referrer-Policy); skip the recommended-tier "
                 "headers (Permissions-Policy, Cross-Origin-*-Policy, X-XSS-Protection)",
        )
        return parser

    def setup(self, args: list[str]) -> None:
        parsed, _ = self.option_parser().parse_known_args(args)
        self._hsts_min_age = parsed.hsts_min_age
        self._recommended = not parsed.no_recommended
        self.parse_request_filters(args)

    async def mutate(self, requests, context):
        # Passive check: send the requests exactly as provided.
        return requests

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _get(response, name: str) -> str | None:
        """Case-insensitive header lookup; returns the raw value or None."""
        for key, value in response.headers.items():
            if key.lower() == name:
                return value
        return None

    def _has_frame_ancestors(self, response) -> bool:
        """True if the CSP header declares a frame-ancestors directive."""
        csp = self._get(response, "content-security-policy")
        if not csp:
            return False
        for part in csp.split(";"):
            tokens = part.split()
            if tokens and tokens[0].lower() == "frame-ancestors":
                return True
        return False

    # ------------------------------------------------------------------- checks

    def _check_hsts(self, response, issues: list[str]) -> None:
        # HSTS is ignored by browsers when delivered over cleartext HTTP, so it
        # is only meaningful (and only required) on HTTPS responses.
        if urlsplit(response.request.url).scheme.lower() != "https":
            return
        hsts = self._get(response, "strict-transport-security")
        if hsts is None:
            issues.append("missing Strict-Transport-Security (HSTS)")
            return
        match = _MAX_AGE.search(hsts)
        if not match:
            issues.append("HSTS has no max-age directive")
            return
        max_age = int(match.group(1))
        if max_age == 0:
            issues.append("HSTS max-age=0 (disables HSTS)")
        elif max_age < self._hsts_min_age:
            issues.append(f"HSTS max-age too low ({max_age} < {self._hsts_min_age})")
        if "includesubdomains" not in hsts.lower():
            issues.append("HSTS missing includeSubDomains")

    def _check_nosniff(self, response, issues: list[str]) -> None:
        value = self._get(response, "x-content-type-options")
        if value is None:
            issues.append("missing X-Content-Type-Options (expected 'nosniff')")
        elif value.strip().lower() != "nosniff":
            issues.append(
                f"X-Content-Type-Options is '{value.strip()}' (expected 'nosniff')"
            )

    def _check_clickjacking(self, response, issues: list[str]) -> None:
        xfo = self._get(response, "x-frame-options")
        if xfo is None and not self._has_frame_ancestors(response):
            issues.append(
                "no anti-clickjacking header (X-Frame-Options or CSP frame-ancestors)"
            )
            return
        if xfo is not None and xfo.strip().lower() not in ("deny", "sameorigin"):
            issues.append(f"X-Frame-Options has unexpected value '{xfo.strip()}'")

    def _check_referrer(self, response, issues: list[str]) -> None:
        value = self._get(response, "referrer-policy")
        if value is None:
            issues.append("missing Referrer-Policy")
        elif value.strip().lower() in _WEAK_REFERRER:
            issues.append(f"Referrer-Policy '{value.strip()}' may leak referrer")

    def _check_recommended(self, response, issues: list[str]) -> None:
        for display, name in _RECOMMENDED_HEADERS:
            if self._get(response, name) is None:
                issues.append(f"missing {display} (recommended)")
        xss = self._get(response, "x-xss-protection")
        if xss is not None and xss.strip() != "0":
            issues.append(
                f"X-XSS-Protection is '{xss.strip()}' "
                "(deprecated; recommended value '0')"
            )

    def _evaluate(self, response) -> list[str]:
        issues: list[str] = []
        self._check_hsts(response, issues)
        self._check_nosniff(response, issues)
        self._check_clickjacking(response, issues)
        self._check_referrer(response, issues)
        if self._recommended:
            self._check_recommended(response, issues)
        return issues

    # ------------------------------------------------------------ analyse/emit

    async def analyze_one(self, response, context):
        # status == 0 is a network error — no headers to audit.
        if response.status == 0:
            return
        issues = self._evaluate(response)
        if not issues:
            return

        # Accumulate a deduplicated tally for the finalize() summary.
        tally = context.data.setdefault(_CONTEXT_KEY, {})
        for issue in issues:
            tally[issue] = tally.get(issue, 0) + 1

        print(
            f"[SECHEADERS] {response.status} {response.request.method} "
            f"{response.request.url}  {' | '.join(issues)}"
        )

    async def finalize(self, context):
        tally = context.data.get(_CONTEXT_KEY)
        if not tally:
            return
        print("[SECHEADERS] --- security header issues (unique) ---")
        for issue, count in sorted(tally.items()):
            plural = "response" if count == 1 else "responses"
            print(f"[SECHEADERS]   {issue}  ({count} {plural})")
