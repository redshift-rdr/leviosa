import argparse
import re

from modules.base import BaseModule

# Namespaced context key for the cross-response inventory built in analyze_one
# and emitted in finalize().
_CONTEXT_KEY = "versiondisclosure.inventory"

# Matches a "product/version" token anywhere in a header value, e.g.
# "nginx/1.18.0", "PHP/8.1.2", "Apache/2.4.41". The slash must be followed by a
# digit, so ordinary values like "text/html" or "no-cache" never match. This is
# the heuristic used to flag *uncurated* headers that leak a version.
_VERSION_TOKEN = re.compile(r"[A-Za-z][\w.+-]*/\d[\w.]*")


class VersionDisclosure(BaseModule):
    """
    Passive software/version fingerprinting from response headers.

    Sends each request unchanged and inspects the response headers for
    information disclosure. Two tiers of detection:

      1. Curated headers (DISCLOSING_HEADERS) — reported whenever present,
         regardless of value, because their mere presence names the software
         (e.g. Server, X-Powered-By, X-AspNet-Version, X-Generator).
      2. Heuristic — any *other* header whose value carries a "product/version"
         token such as "Foo/1.2.3" is reported too, catching disclosures from
         headers not on the curated list. Disable with --no-heuristic.

    Per-response hits are printed as they arrive; finalize() then prints a
    deduplicated inventory of every distinct "Header: value" observed, which
    doubles as a quick technology stack summary for the target.

    Only headers are inspected, so needs_body is False (no bodies downloaded).
    """

    # Curated set of headers known to disclose software and/or version info.
    # Matched case-insensitively; the original casing here is used for display.
    DISCLOSING_HEADERS = [
        # Web servers / reverse proxies / load balancers
        "Server",
        "Via",
        "X-Server",
        "X-Backend-Server",
        "X-Served-By",
        "X-BEServer",
        "X-Varnish",
        "X-Cache-Handler",
        # Languages / frameworks / app servers
        "X-Powered-By",
        "X-AspNet-Version",
        "X-AspNetMvc-Version",
        "X-Runtime",             # Rails
        "X-Application-Context",  # Spring Boot
        "X-Cocoon-Version",
        "X-Version",
        "X-Framework",
        # CMS / products
        "X-Generator",           # Drupal, etc.
        "X-Powered-CMS",
        "X-Drupal-Cache",
        "X-Redirect-By",         # WordPress
        "X-Pingback",            # WordPress presence
        "Liferay-Portal",
        "MicrosoftSharePointTeamServices",
        "X-SharePointHealthScore",
        "X-OWA-Version",         # Exchange / Outlook Web Access
        "X-Jenkins",
        "X-Confluence-Request-Time",
        # Performance / CDN modules that name the software
        "X-Mod-Pagespeed",
        "X-Page-Speed",
        "X-Turbo-Charged-By",
        "X-LiteSpeed-Cache",
        "X-CF-Powered-By",
    ]

    # Header-only module: no need to read response bodies.
    needs_body = False

    def __init__(self):
        # Lower-cased lookup set for O(1) case-insensitive membership tests.
        self._known = {h.lower() for h in self.DISCLOSING_HEADERS}
        # Preserve preferred display casing for curated headers.
        self._display = {h.lower(): h for h in self.DISCLOSING_HEADERS}
        self._heuristic = True
        self._filters = []

    def setup(self, args: list[str]) -> None:
        parser = argparse.ArgumentParser(prog="versiondisclosure", add_help=False)
        parser.add_argument(
            "--extra-header", metavar="NAME", action="append", default=[],
            help="Additional header name to always report if present (repeatable)",
        )
        parser.add_argument(
            "--no-heuristic", action="store_true",
            help="Only report curated headers; skip the product/version scan of "
                 "other headers",
        )
        parsed, _ = parser.parse_known_args(args)

        for name in parsed.extra_header:
            self._known.add(name.lower())
            self._display.setdefault(name.lower(), name)
        self._heuristic = not parsed.no_heuristic
        self.parse_request_filters(args)

    def _disclosures(self, response) -> list[tuple[str, str]]:
        """
        Return (display_name, value) pairs for every disclosing header in the
        response: curated headers (always), plus — unless disabled — any other
        header whose value carries a product/version token.
        """
        hits: list[tuple[str, str]] = []
        for name, value in response.headers.items():
            lname = name.lower()
            if lname in self._known:
                hits.append((self._display.get(lname, name), value))
            elif self._heuristic and _VERSION_TOKEN.search(value):
                hits.append((name, value))
        return hits

    async def mutate(self, requests, context):
        # Passive check: send the requests exactly as provided.
        return requests

    async def analyze_one(self, response, context):
        # status == 0 is a network error — nothing to fingerprint.
        if response.status == 0:
            return
        hits = self._disclosures(response)
        if not hits:
            return

        # Accumulate a deduplicated inventory for the finalize() summary.
        inventory = context.data.setdefault(_CONTEXT_KEY, {})
        for name, value in hits:
            inventory[(name, value)] = inventory.get((name, value), 0) + 1

        disclosed = " | ".join(f"{name}: {value}" for name, value in hits)
        print(
            f"[VERSIONDISCLOSURE] {response.status} {response.request.method} "
            f"{response.request.url}  {disclosed}"
        )

    async def finalize(self, context):
        inventory = context.data.get(_CONTEXT_KEY)
        if not inventory:
            return
        print("[VERSIONDISCLOSURE] --- disclosed software/versions (unique) ---")
        # Sort by header name then value for stable, readable output.
        for (name, value), count in sorted(inventory.items()):
            plural = "response" if count == 1 else "responses"
            print(f"[VERSIONDISCLOSURE]   {name}: {value}  ({count} {plural})")
