import argparse
from dataclasses import replace

from core.tooltags import BurpTool
from modules.base import BaseModule
from core.headers import parse_headers, without_headers

# Namespaced context keys: the interesting-findings tally and the per-URL
# method/status matrix used for the finalize() "differences" report.
_FINDINGS_KEY = "methodtamper.findings"
_MATRIX_KEY = "methodtamper.matrix"

# HTTP methods tried against each request (in addition to the untouched
# original, which serves as the baseline). "FOOBAR" is a deliberately invalid
# method: a success means the server applies no method whitelist. Overridable
# with --methods.
_DEFAULT_METHODS = [
    "OPTIONS", "TRACE", "TRACK", "PUT", "DELETE", "PATCH", "CONNECT", "HEAD",
    "FOOBAR",
]

# Method-override request headers understood by many frameworks/proxies. A
# server that honours these lets a client smuggle a dangerous method past
# filters that only inspect the real request line. Overridable via CLI.
_DEFAULT_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
]

# Methods injected through the override headers — restricted to the dangerous
# ones, since that is where honouring an override actually matters.
_DEFAULT_OVERRIDE_METHODS = ["PUT", "DELETE", "PATCH", "TRACE"]

# TRACE/TRACK echo the request and enable Cross-Site Tracing (XST) when allowed.
_XST_METHODS = {"TRACE", "TRACK"}
# State-changing methods that should almost never be openly accepted.
_WRITE_METHODS = {"PUT", "DELETE", "PATCH"}
# Everything worth flagging when accepted, whether direct or via override.
_DANGEROUS = _XST_METHODS | _WRITE_METHODS | {"CONNECT"}
# Standard methods, used to spot acceptance of an arbitrary/unknown verb.
_KNOWN_METHODS = {
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT",
}


def _is_success(status: int) -> bool:
    return 200 <= status < 300


class MethodTamper(BaseModule):
    """
    HTTP method tampering probe.

    For each input request it re-sends the request under a range of HTTP methods
    (OPTIONS, TRACE/TRACK, PUT, DELETE, PATCH, CONNECT, HEAD, an invalid verb),
    and also re-sends it as a POST carrying method-override headers
    (X-HTTP-Method-Override and friends) set to dangerous methods — POST because
    most frameworks only honour these headers on a POST. The unmodified request
    is sent too as a baseline.

    Responses are judged against what a hardened server should return:

      * TRACE/TRACK answered with 2xx  -> Cross-Site Tracing (XST).
      * CONNECT answered with 2xx      -> tunnelling/proxy behaviour.
      * PUT/DELETE/PATCH answered 2xx  -> a state-changing method left enabled.
      * an invalid verb answered 2xx   -> no method whitelist.
      * a method-override header that yields 2xx for a dangerous method
                                       -> the override is honoured and can bypass
                                          method-based access controls.
      * OPTIONS Allow that advertises dangerous methods.

    finalize() additionally prints, per URL, every tested method/override whose
    status code differs from the baseline response — the concrete "unexpected
    response" view.

    Only status codes and the Allow header are needed, so needs_body is False.
    """

    tool = BurpTool.SCANNER

    # Status/header-only module: the engine skips reading response bodies.
    needs_body = False

    def __init__(self):
        self._methods = list(_DEFAULT_METHODS)
        self._override_headers = list(_DEFAULT_OVERRIDE_HEADERS)
        self._override_methods = list(_DEFAULT_OVERRIDE_METHODS)
        self._use_override = True
        self._filters = []

    def option_parser(self):
        parser = argparse.ArgumentParser(prog="methodtamper", add_help=False, allow_abbrev=False)
        parser.add_argument(
            "--methods", metavar="CSV", default=None,
            help="Comma-separated methods to try instead of the default set "
                 f"({','.join(_DEFAULT_METHODS)})",
        )
        parser.add_argument(
            "--override-methods", metavar="CSV", default=None,
            help="Comma-separated methods to inject via override headers "
                 f"(default {','.join(_DEFAULT_OVERRIDE_METHODS)})",
        )
        parser.add_argument(
            "--override-headers", metavar="CSV", default=None,
            help="Comma-separated override header names to test "
                 f"(default {','.join(_DEFAULT_OVERRIDE_HEADERS)})",
        )
        parser.add_argument(
            "--no-override", action="store_true",
            help="Skip the method-override header variants; only vary the "
                 "request method itself",
        )
        return parser

    def setup(self, args: list[str]) -> None:
        parsed, _ = self.option_parser().parse_known_args(args)
        if parsed.methods:
            self._methods = [m.strip().upper() for m in parsed.methods.split(",") if m.strip()]
        if parsed.override_methods:
            self._override_methods = [
                m.strip().upper() for m in parsed.override_methods.split(",") if m.strip()
            ]
        if parsed.override_headers:
            self._override_headers = [
                h.strip() for h in parsed.override_headers.split(",") if h.strip()
            ]
        self._use_override = not parsed.no_override
        self.parse_request_filters(args)

    # ------------------------------------------------------------------ mutate

    async def mutate(self, requests, context):
        return self._variants(requests)

    def _variants(self, requests):
        for req in requests:
            # Baseline: the untouched request, and the reference for finalize().
            original = replace(req, metadata={**req.metadata,
                "methodtamper.original_method": req.method.upper(),
                "methodtamper.baseline": True})
            yield original
            req = replace(original, metadata={**original.metadata, "methodtamper.baseline": False})

            for method in self._methods:
                # Method-only change: replace() safely shares the read-only
                # headers/params across variants.
                yield replace(req, method=method)

            if self._use_override:
                for header in self._override_headers:
                    for om in self._override_methods:
                        yield self._with_override(req, header, om)

    @staticmethod
    def _with_override(req, header: str, method: str):
        # Fresh headers list (dropping any same-named override header) so
        # replace() never aliases the seed request's list across variants.
        # The transport method is forced to POST: most frameworks only honour
        # a method-override header on a POST request.
        headers = without_headers(req.headers, [header])
        headers.append(f"{header}: {method}")
        return replace(req, method="POST", headers=headers)

    # ----------------------------------------------------------------- analyse

    def _request_override(self, req) -> tuple[str, str] | None:
        """Return (header_name, method) for the first override header present."""
        wanted = {h.lower() for h in self._override_headers}
        for name, value in parse_headers(req.headers).items():
            if name.lower() in wanted:
                return name, value.strip().upper()
        return None

    @staticmethod
    def _allow_header(response) -> str | None:
        return response.headers.get("allow")

    def _findings(self, response) -> list[str]:
        method = response.request.method.upper()
        status = response.status
        url = response.request.url
        override = self._request_override(response.request)

        findings: list[str] = []

        if override is not None:
            header, om = override
            if _is_success(status) and om in _DANGEROUS:
                findings.append(
                    f"override {header}: {om} accepted ({status}) — "
                    f"method filtering bypassable"
                )
            return findings  # override variants are judged solely on the override

        if method in _XST_METHODS and _is_success(status):
            findings.append(f"{method} enabled ({status}) — Cross-Site Tracing (XST)")
        elif method == "CONNECT" and _is_success(status):
            findings.append(f"CONNECT accepted ({status}) — tunnelling/proxy behaviour")
        elif method in _WRITE_METHODS and _is_success(status):
            findings.append(f"{method} accepted ({status}) — state-changing method enabled")
        elif method not in _KNOWN_METHODS and _is_success(status):
            findings.append(f"invalid method {method} accepted ({status}) — no method whitelist")
        elif method == "OPTIONS":
            allow = self._allow_header(response)
            if allow:
                advertised = {m.strip().upper() for m in allow.split(",") if m.strip()}
                dangerous = sorted(advertised & _DANGEROUS)
                if dangerous:
                    findings.append(
                        f"OPTIONS Allow advertises dangerous methods: {', '.join(dangerous)}"
                    )
        return findings

    def _matrix_label(self, response) -> str:
        override = self._request_override(response.request)
        if override is not None:
            header, om = override
            return f"{om} via {header}"
        return response.request.method.upper()

    async def analyze_one(self, response, context):
        # status == 0 is a network error — nothing to compare.
        if response.status == 0:
            return

        # Record every observation for the finalize() differences report.
        matrix = context.state.setdefault(_MATRIX_KEY, {})
        req = response.request
        entry = matrix.setdefault(req.seed_id, {"url": req.url,
            "method": req.metadata.get("methodtamper.original_method", req.method.upper()),
            "baseline": None, "variants": {}})
        if req.metadata.get("methodtamper.baseline"):
            entry["baseline"] = response.status
        else:
            entry["variants"][self._matrix_label(response)] = response.status

        findings = self._findings(response)
        if not findings:
            return

        tally = context.state.setdefault(_FINDINGS_KEY, {})
        for finding in findings:
            tally[finding] = tally.get(finding, 0) + 1

        self.report(response, context,
            f"[METHODTAMPER] {response.status} {self._matrix_label(response)} "
            f"{response.request.url}  {' | '.join(findings)}",
            evidence={"findings": findings, "variant": self._matrix_label(response)}
        )

    async def finalize(self, context):
        tally = context.state.get(_FINDINGS_KEY)
        if tally:
            context.write("[METHODTAMPER] --- interesting method behaviours (unique) ---")
            for finding, count in sorted(tally.items()):
                plural = "response" if count == 1 else "responses"
                context.write(f"[METHODTAMPER]   {finding}  ({count} {plural})")

        self._report_differences(context)

    def _report_differences(self, context):
        matrix = context.state.get(_MATRIX_KEY)
        if not matrix:
            return
        printed_header = False
        for entry in sorted(matrix.values(), key=lambda e: (e["url"], e["method"])):
            url = entry["url"]
            labels = entry["variants"]
            baseline_label = entry["method"]
            base_status = entry["baseline"]
            if base_status is None:
                continue
            diffs = sorted(
                (label, status) for label, status in labels.items()
                if status != base_status
            )
            if not diffs:
                continue
            if not printed_header:
                context.write("[METHODTAMPER] --- response-code differences vs baseline ---")
                printed_header = True
            base = f"{baseline_label}={base_status}" if base_status is not None else "baseline=?"
            changes = ", ".join(f"{label}={status}" for label, status in diffs)
            context.write(f"[METHODTAMPER]   {url}  (baseline {base})  {changes}")
