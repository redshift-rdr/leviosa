import argparse

from modules.base import BaseModule

# Namespaced context key for the cross-response tally built in analyze_one and
# emitted in finalize().
_CONTEXT_KEY = "csp.findings"

# The enforcing and report-only CSP header names (matched case-insensitively).
_CSP_HEADER = "content-security-policy"
_CSP_REPORT_ONLY_HEADER = "content-security-policy-report-only"

# Source-list keywords that weaken a policy. Compared after stripping the
# surrounding single quotes and lower-casing, so both 'unsafe-inline' and
# UNSAFE-INLINE match. 'unsafe-inline' / 'unsafe-eval' re-open the very holes
# CSP exists to close; 'unsafe-hashes' relaxes inline event-handler hashing.
_UNSAFE_KEYWORDS = {
    "unsafe-inline",
    "unsafe-eval",
    "unsafe-hashes",
}

# Directives that do not take a source list, so the unsafe/wildcard source
# checks don't apply (and would only produce noise) — skip them.
_NON_SOURCE_DIRECTIVES = {
    "sandbox",
    "report-uri",
    "report-to",
    "upgrade-insecure-requests",
    "block-all-mixed-content",
    "require-trusted-types-for",
    "trusted-types",
}


class ContentSecurityPolicy(BaseModule):
    """
    Passive Content-Security-Policy auditor.

    Sends each request unchanged and inspects the response headers for the
    Content-Security-Policy (and Content-Security-Policy-Report-Only) header,
    reporting:

      1. Absence — no CSP header at all, so the browser applies no policy.
      2. Report-only mode — the policy is delivered via
         Content-Security-Policy-Report-Only, which browsers report on but do
         NOT enforce, so it provides no protection. (The report-only policy is
         still analysed for the issues below, as it usually mirrors the intended
         enforcing policy.)
      3. Unsafe directives — any source list containing 'unsafe-inline',
         'unsafe-eval' or 'unsafe-hashes'.
      4. Wildcard sources — a bare '*' (allow-anything) or a host wildcard such
         as '*.example.com' in any fetch directive.

    Per-response findings are printed as they arrive; finalize() then prints a
    deduplicated tally of every distinct issue observed across the run.

    Only headers are inspected, so needs_body is False (no bodies downloaded).
    """

    # Header-only module: no need to read response bodies.
    needs_body = False

    def __init__(self):
        self._filters = []

    def setup(self, args: list[str]) -> None:
        # No module-specific flags; just enable the standard request filters.
        self.parse_request_filters(args)

    async def mutate(self, requests, context):
        # Passive check: send the requests exactly as provided.
        return requests

    @staticmethod
    def _header(response, name: str) -> str | None:
        """Case-insensitive header lookup; returns the raw value or None."""
        for key, value in response.headers.items():
            if key.lower() == name:
                return value
        return None

    @staticmethod
    def _parse_policy(value: str) -> list[tuple[str, list[str]]]:
        """
        Parse a CSP header value into (directive_name, sources) pairs, preserving
        directive order. Directive names are lower-cased; source tokens are left
        as-is (their casing/quoting is meaningful for display).
        """
        directives: list[tuple[str, list[str]]] = []
        for part in value.split(";"):
            tokens = part.split()
            if not tokens:
                continue
            directives.append((tokens[0].lower(), tokens[1:]))
        return directives

    @classmethod
    def _policy_issues(cls, value: str) -> list[str]:
        """
        Return issue strings for unsafe keywords and wildcard sources found in a
        CSP header value.
        """
        issues: list[str] = []
        for name, sources in cls._parse_policy(value):
            if name in _NON_SOURCE_DIRECTIVES:
                continue
            for source in sources:
                token = source.strip("'").lower()
                if token in _UNSAFE_KEYWORDS:
                    issues.append(f"{name} allows '{token}'")
                elif source == "*":
                    issues.append(f"{name} uses wildcard source '*'")
                elif source.startswith("*."):
                    issues.append(f"{name} uses wildcard source '{source}'")
        return issues

    def _evaluate(self, response) -> list[str]:
        """Return every CSP issue string for a single response."""
        enforcing = self._header(response, _CSP_HEADER)
        report_only = self._header(response, _CSP_REPORT_ONLY_HEADER)

        if enforcing is None and report_only is None:
            return ["missing Content-Security-Policy header"]

        issues: list[str] = []
        if enforcing is not None:
            policy = enforcing
        else:
            # Only a report-only policy is present: it is not enforced. Still
            # analyse it, since it typically mirrors the intended policy.
            issues.append(
                "CSP present only in report-only mode (not enforced)"
            )
            policy = report_only

        issues.extend(self._policy_issues(policy))
        return issues

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
            f"[CSP] {response.status} {response.request.method} "
            f"{response.request.url}  {' | '.join(issues)}"
        )

    async def finalize(self, context):
        tally = context.data.get(_CONTEXT_KEY)
        if not tally:
            return
        print("[CSP] --- Content-Security-Policy issues (unique) ---")
        for issue, count in sorted(tally.items()):
            plural = "response" if count == 1 else "responses"
            print(f"[CSP]   {issue}  ({count} {plural})")
