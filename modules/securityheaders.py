import argparse
import re
from urllib.parse import urlsplit

from core.tooltags import BurpTool
from modules.base import BaseModule

# Namespaced context key for the cross-response tally built in analyze_one and
# emitted in finalize().
_CONTEXT_KEY = "securityheaders.findings"

# Default minimum acceptable HSTS max-age (1 year, in seconds) — the value the
# hstspreload.org list and OWASP recommend.
_DEFAULT_HSTS_MIN_AGE = 31536000

# Pulls the integer out of an HSTS "max-age=<n>" directive (value optionally
# quoted). Case-insensitive; whitespace around "=" tolerated.
_MAX_AGE = re.compile(r'max-age\s*=\s*(?:"([0-9]+)"|([0-9]+))', re.IGNORECASE)

# Referrer-Policy values that still leak the full URL cross-origin (or to
# insecure destinations) and so weaken privacy/security.
_WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}
_REFERRER_VALUES = _WEAK_REFERRER | {
    "no-referrer", "same-origin", "origin", "strict-origin",
    "origin-when-cross-origin", "strict-origin-when-cross-origin",
}
_PERMISSION = re.compile(
    r'([a-z][a-z0-9-]*)\s*=\s*(\*|\([^()]*\))'
    r'(?:\s*;\s*[a-z][a-z0-9_-]*(?:\s*=\s*(?:[a-zA-Z0-9_.*:/-]+|"[^"\\\r\n]*"|\?[01]))?)*'
)
_ALLOWLIST = re.compile(r'(?:self|"[^"\\\r\n]+")')
_ALLOWLIST_CONTENT = re.compile(_ALLOWLIST.pattern + r'(?:[ \t]+' + _ALLOWLIST.pattern + r')*')

# Extra security headers whose absence is worth flagging. Reported only when the
# recommended tier is enabled (default on; disable with --no-recommended). These
# are display-name / lookup-name (lower-cased) pairs.
_RECOMMENDED_HEADERS = [
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
      * Referrer-Policy — recognized effective policy and weak-value checks.
      * Permissions-Policy — missing/malformed/duplicate directives and broad allowlists.

    Recommended tier (default on, --no-recommended to skip): flags absence of
    the Cross-Origin-{Opener,Embedder,Resource}-Policy
    isolation headers, and a non-'0' (deprecated) X-XSS-Protection.

    Deliberately does NOT audit CSP directives (see the csp module), software
    disclosure headers such as Server/X-Powered-By (versiondisclosure), or CORS
    ACAO/ACAC (cors) — it only reads CSP to confirm a frame-ancestors clickjacking
    defence.

    Only headers are inspected, so needs_body is False (no bodies downloaded).
    """

    tool = BurpTool.SCANNER

    # Header-only module: no need to read response bodies.
    needs_body = False
    follow_redirects = False

    def __init__(self):
        self._hsts_min_age = _DEFAULT_HSTS_MIN_AGE
        self._recommended = True
        self._filters = []

    def option_parser(self):
        parser = argparse.ArgumentParser(prog="securityheaders", add_help=False, allow_abbrev=False)
        parser.add_argument(
            "--hsts-min-age", type=int, default=_DEFAULT_HSTS_MIN_AGE, metavar="SECONDS",
            help="Minimum acceptable HSTS max-age in seconds "
                 f"(default: {_DEFAULT_HSTS_MIN_AGE} = 1 year)",
        )
        parser.add_argument(
            "--no-recommended", action="store_true",
            help="Only check the core headers (HSTS, X-Content-Type-Options, "
                 "anti-clickjacking, Referrer-Policy, Permissions-Policy); skip the "
                 "extra headers (Cross-Origin-*-Policy, X-XSS-Protection)",
        )
        return parser

    def setup(self, args: list[str]) -> None:
        parsed, _ = self.option_parser().parse_known_args(args)
        if parsed.hsts_min_age < 1:
            raise ValueError("--hsts-min-age must be a positive integer")
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
        return response.headers.get(name)

    def _has_frame_ancestors(self, response) -> bool:
        """True if the CSP header declares a frame-ancestors directive."""
        for csp in response.headers.getall("content-security-policy", []):
            for policy in csp.split(','):
                for part in policy.split(';'):
                    tokens = part.split()
                    if tokens and tokens[0].lower() == 'frame-ancestors':
                        # Only recognize conservative restricting policies here.
                        # Empty and wildcard policies provide no useful fallback.
                        sources = tokens[1:]
                        if sources in [["'none'"], ["'self'"]]:
                            return True
                        if sources and all(source == "'self'" or (source.startswith(('https://', 'http://'))
                                           and '*' not in source) for source in sources):
                            try:
                                if all(source == "'self'" or (urlsplit(source).hostname and urlsplit(source).username is None) for source in sources):
                                    return True
                            except ValueError:
                                pass
                        break  # CSP uses the first occurrence of a directive.
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
        directives = [part.strip() for part in hsts.split(';') if part.strip()]
        ages = [part for part in directives if part.split('=', 1)[0].strip().lower() == 'max-age']
        if not ages:
            issues.append("HSTS has no max-age directive")
            return
        if len(ages) != 1:
            issues.append("HSTS has duplicate max-age directives")
            return
        match = _MAX_AGE.fullmatch(ages[0])
        if not match:
            issues.append("HSTS has an invalid max-age directive")
            return
        # Compare bounded integers: avoid huge untrusted integer conversions.
        digits = (match.group(1) or match.group(2)).lstrip('0') or '0'
        minimum = str(self._hsts_min_age)
        if digits == '0':
            issues.append("HSTS max-age=0 (disables HSTS)")
        elif (len(digits), digits) < (len(minimum), minimum):
            issues.append(f"HSTS max-age too low ({digits} < {self._hsts_min_age})")
        names = [part.split('=', 1)[0].strip().lower() for part in directives]
        if 'includesubdomains' not in names:
            issues.append("HSTS missing includeSubDomains")
        elif any(part.split('=', 1)[0].strip().lower() == 'includesubdomains' and '=' in part for part in directives):
            issues.append("HSTS includeSubDomains must not have a value")

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
        values = response.headers.getall('referrer-policy', [])
        if not values:
            issues.append("missing Referrer-Policy")
            return
        tokens = [token.strip() for token in ','.join(values).split(',')]
        recognized = [token for token in tokens if token in _REFERRER_VALUES]
        if not recognized:
            issues.append("Referrer-Policy has no recognized policy value")
        elif recognized[-1] in _WEAK_REFERRER:
            issues.append(f"Referrer-Policy '{recognized[-1]}' may leak referrer")

    def _check_permissions(self, response, issues):
        values = response.headers.getall('permissions-policy', [])
        if not values:
            issues.append('missing Permissions-Policy')
            return
        # Split dictionary members outside quoted origins; commas can occur in
        # quoted strings. Support the header allowlist forms, not iframe syntax.
        value = ','.join(values)
        members = re.split(r',(?=(?:[^"]*"[^"]*")*[^"]*$)', value)
        seen = set()
        for member in members:
            match = _PERMISSION.fullmatch(member.strip())
            if not match:
                issues.append('Permissions-Policy has an empty or malformed directive')
                continue
            feature, allow = match.groups()
            if feature in seen:
                issues.append(f'Permissions-Policy repeats feature {feature}')
            seen.add(feature)
            if allow == '*':
                issues.append(f'Permissions-Policy {feature} allows all origins (review intended access)')
                continue
            content = allow[1:-1].strip()
            tokens = _ALLOWLIST.findall(content)
            if content and _ALLOWLIST_CONTENT.fullmatch(content) is None:
                issues.append(f'Permissions-Policy {feature} has an invalid allowlist')
            elif any(token.startswith('"') and '*' in token for token in tokens):
                issues.append(f'Permissions-Policy {feature} has a wildcard origin (review intended access)')
            else:
                for token in tokens:
                    if token == 'self':
                        continue
                    try:
                        parsed = urlsplit(token[1:-1])
                        valid = (parsed.scheme in {'http', 'https'} and parsed.hostname and
                                 parsed.username is None and parsed.password is None and
                                 not parsed.query and not parsed.fragment and parsed.path in {'', '/'})
                        parsed.port
                    except ValueError:
                        valid = False
                    if not valid:
                        issues.append(f'Permissions-Policy {feature} has an invalid origin')
                        break

    def _check_duplicates(self, response, issues):
        for name in ('Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options'):
            if len(response.headers.getall(name, [])) > 1:
                issues.append(f'duplicate {name} headers; review browser handling')

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
        self._check_permissions(response, issues)
        self._check_duplicates(response, issues)
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
        tally = context.state.setdefault(_CONTEXT_KEY, {})
        for issue in issues:
            tally[issue] = tally.get(issue, 0) + 1

        self.report(response, context,
            f"[SECHEADERS] {response.status} {response.request.method} "
            f"{response.request.url}  {' | '.join(issues)}", evidence={"issues": issues}
        )

    async def finalize(self, context):
        tally = context.state.get(_CONTEXT_KEY)
        if not tally:
            return
        context.write("[SECHEADERS] --- security header issues (unique) ---")
        for issue, count in sorted(tally.items()):
            plural = "response" if count == 1 else "responses"
            context.write(f"[SECHEADERS]   {issue}  ({count} {plural})")
