import argparse
from dataclasses import replace
from urllib.parse import urlsplit

from modules.base import BaseModule

# Namespaced context key for the cross-response tally built in analyze_one and
# emitted in finalize().
_CONTEXT_KEY = "cors.findings"

# Attacker-controlled origin used to detect blind reflection of an arbitrary
# cross-origin. Overridable with --evil-origin.
_DEFAULT_EVIL_ORIGIN = "https://leviosa-cors-probe.example"

# Label prepended to the target host for the "trusts any subdomain" probe, e.g.
# https://leviosa-cors.target.com — catches policies that reflect any
# *.target.com origin (a subdomain takeover then yields a working CORS bypass).
_SUBDOMAIN_LABEL = "leviosa-cors"


class Cors(BaseModule):
    """
    Active CORS (Cross-Origin Resource Sharing) misconfiguration probe.

    For each input request it re-sends the request several times, each with a
    different forged Origin header, and inspects the reflected
    Access-Control-Allow-Origin (ACAO) response header for trust it should not
    grant. The probe origins are:

      * arbitrary  — an attacker-controlled external origin
                     (https://leviosa-cors-probe.example by default); reflection
                     means *any* site can read the response.
      * subdomain  — an arbitrary subdomain of the target host
                     (https://leviosa-cors.<host>); reflection means any
                     subdomain is trusted, exploitable via subdomain takeover.
      * null       — the literal "null" origin, produced by sandboxed iframes and
                     some redirects; trusting it is a common bypass.

    For every reflecting or wildcard response it also checks
    Access-Control-Allow-Credentials: reflection/subdomain/null trust combined
    with credentials: true lets an attacker read authenticated responses and is
    the high-severity case.

    Only headers are inspected, so needs_body is False (no bodies downloaded).
    """

    # Header-only module: no need to read response bodies.
    needs_body = False

    def __init__(self):
        self._evil_origin = _DEFAULT_EVIL_ORIGIN
        self._filters = []

    def option_parser(self):
        parser = argparse.ArgumentParser(prog="cors", add_help=False)
        parser.add_argument(
            "--evil-origin", metavar="ORIGIN", default=_DEFAULT_EVIL_ORIGIN,
            help="Arbitrary external Origin to test for reflection "
                 f"(default: {_DEFAULT_EVIL_ORIGIN})",
        )
        return parser

    def setup(self, args: list[str]) -> None:
        parsed, _ = self.option_parser().parse_known_args(args)
        self._evil_origin = parsed.evil_origin
        self.parse_request_filters(args)

    # ------------------------------------------------------------------ mutate

    async def mutate(self, requests, context):
        return self._variants(requests)

    def _variants(self, requests):
        """Lazily yield one Origin-forged variant per probe, per request."""
        for req in requests:
            for origin in self._probe_origins(req):
                yield self._with_origin(req, origin)

    def _probe_origins(self, req) -> list[str]:
        origins = [self._evil_origin, "null"]
        parts = urlsplit(req.url)
        if parts.hostname:
            scheme = parts.scheme or "https"
            origins.append(f"{scheme}://{_SUBDOMAIN_LABEL}.{parts.hostname}")
        return origins

    @staticmethod
    def _with_origin(req, origin: str):
        # Build a fresh headers list (dropping any existing Origin) so replace()
        # never aliases and mutates the seed request's list across variants.
        headers = [
            h for h in req.headers
            if h.split(":", 1)[0].strip().lower() != "origin"
        ]
        headers.append(f"Origin: {origin}")
        return replace(req, headers=headers)

    # ----------------------------------------------------------------- analyse

    @staticmethod
    def _request_origin(req) -> str | None:
        for h in req.headers:
            name, sep, value = h.partition(":")
            if sep and name.strip().lower() == "origin":
                return value.strip()
        return None

    @staticmethod
    def _resp_header(response, name: str) -> str | None:
        for key, value in response.headers.items():
            if key.lower() == name:
                return value
        return None

    @staticmethod
    def _classify(origin: str, req) -> str:
        if origin == "null":
            return "null origin"
        host = urlsplit(req.url).hostname
        o_host = urlsplit(origin).hostname
        if host and o_host and o_host != host and o_host.endswith("." + host):
            return "arbitrary subdomain of host"
        return "arbitrary origin"

    async def analyze_one(self, response, context):
        # status == 0 is a network error — nothing to audit.
        if response.status == 0:
            return
        origin = self._request_origin(response.request)
        if origin is None:
            return  # not one of our forged requests

        acao = self._resp_header(response, "access-control-allow-origin")
        if acao is None:
            return  # no ACAO header — no cross-origin trust granted
        acao = acao.strip()

        creds = (
            (self._resp_header(response, "access-control-allow-credentials") or "")
            .strip().lower() == "true"
        )

        if acao == "*":
            finding = "wildcard ACAO (*)"
        elif origin == "null" and acao.lower() == "null":
            finding = "trusts null origin"
        elif acao == origin:
            finding = f"reflects {self._classify(origin, response.request)} ({origin})"
        else:
            return  # ACAO present but does not reflect our probe / not wildcard

        if creds:
            finding += " with Access-Control-Allow-Credentials: true"

        # Accumulate a deduplicated tally for the finalize() summary.
        tally = context.data.setdefault(_CONTEXT_KEY, {})
        tally[finding] = tally.get(finding, 0) + 1

        print(
            f"[CORS] {response.status} {response.request.method} "
            f"{response.request.url}  {finding}"
        )

    async def finalize(self, context):
        tally = context.data.get(_CONTEXT_KEY)
        if not tally:
            return
        print("[CORS] --- CORS misconfigurations (unique) ---")
        for finding, count in sorted(tally.items()):
            plural = "response" if count == 1 else "responses"
            print(f"[CORS]   {finding}  ({count} {plural})")
