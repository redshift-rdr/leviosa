import argparse
import re
from dataclasses import replace

from modules.base import BaseModule

# Namespaced context key for the results grid built in analyze_one and reported
# in finalize(): {endpoint_index: {"baseline": set, "baseline_status": int,
# "hits": [...]}}.
_CONTEXT_KEY = "sqli.results"

# Parameter locations injected by default. Header injection is possible but
# noisy, so it is opt-in via --param-types.
_DEFAULT_PARAM_TYPES = ["query", "json", "form", "cookie"]

# Error-provoking payloads appended (by default) to each parameter's existing
# value, one parameter and one payload per request. A lone quote/backslash is
# the classic syntax-breaker; the boolean/order-by ones catch parsers that
# survive a bare quote.
_DEFAULT_PAYLOADS = [
    "'",
    '"',
    "')",
    "';",
    "\\",
    "' OR '1'='1",
    "1' ORDER BY 10000-- -",
    "' AND '1'='2",
]

# DBMS error signatures. A match in an injected response (that is NOT already
# present in the baseline response) is a strong error-based SQLi indicator.
_SIGNATURES = [
    ("MySQL", [
        r"SQL syntax.*MySQL",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"Warning.*\bmysqli?_",
        r"MySqlException",
        r"valid MySQL result",
        r"com\.mysql\.jdbc",
    ]),
    ("PostgreSQL", [
        r"PostgreSQL.*ERROR",
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"PSQLException",
        r"unterminated quoted string at or near",
        r"invalid input syntax for",
    ]),
    ("Microsoft SQL Server", [
        r"Microsoft SQL Server",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"Unclosed quotation mark after the character string",
        r"System\.Data\.SqlClient\.SqlException",
        r"Incorrect syntax near",
    ]),
    ("Oracle", [
        r"ORA-\d{5}",
        r"Oracle error",
        r"quoted string not properly terminated",
        r"OracleException",
        r"Oracle.*Driver",
    ]),
    ("SQLite", [
        r"SQLite/JDBCDriver",
        r"System\.Data\.SQLite\.SQLiteException",
        r"SQLite3::",
        r"sqlite3\.OperationalError",
        r"unrecognized token:",
        r"SQL logic error",
    ]),
]


class SqlInjection(BaseModule):
    """
    Error-based SQL injection probe.

    Injects SQLi payloads into request parameters one parameter at a time, one
    payload per request, then scans each response body for DBMS error signatures
    (MySQL, PostgreSQL, MSSQL, Oracle, SQLite). The unmodified request is sent
    first as a baseline: any error signature already present without injection is
    ignored, so pages that always show SQL errors don't produce false positives.
    A signature that appears only after injection is reported as a finding; an
    HTTP 500 introduced by a payload (baseline was not 500) is reported as a
    weaker indicator.

    Payloads are appended to the parameter's existing value by default (so
    id=5 becomes id=5') — the most reliable way to break an in-context query;
    use --replace to overwrite instead. Injects query/json/form/cookie params by
    default (--param-types to change).

    Routes through burp (use_burp = True) so the injection traffic can be
    inspected and replayed by hand.
    """

    # Needs the response body to scan for SQL error strings.
    needs_body = True
    # Route through burp so the (relatively low-volume) probe traffic is easy to
    # inspect and replay manually.
    use_burp = True

    def __init__(self):
        self._payloads = list(_DEFAULT_PAYLOADS)
        self._param_types = list(_DEFAULT_PARAM_TYPES)
        self._append = True
        self._signatures = [
            (dbms, [re.compile(p, re.IGNORECASE) for p in pats])
            for dbms, pats in _SIGNATURES
        ]
        # id(request) -> (endpoint_index, param_name|None, param_type|None, payload|None)
        self._meta: dict[int, tuple] = {}
        self._endpoints: list[str] = []
        self._filters = []

    def option_parser(self):
        parser = argparse.ArgumentParser(prog="sqli", add_help=False)
        parser.add_argument(
            "--payloads", metavar="FILE", default=None,
            help="File of injection payloads, one per line (default: a built-in "
                 "error-based set)",
        )
        parser.add_argument(
            "--param-types", metavar="CSV", default=None,
            help="Comma-separated parameter locations to inject "
                 f"(default: {','.join(_DEFAULT_PARAM_TYPES)}; also 'header')",
        )
        parser.add_argument(
            "--replace", action="store_true",
            help="Replace the parameter value with the payload instead of "
                 "appending to the existing value",
        )
        return parser

    def setup(self, args: list[str]) -> None:
        parsed, _ = self.option_parser().parse_known_args(args)
        if parsed.payloads:
            with open(parsed.payloads) as f:
                self._payloads = [line.rstrip("\n") for line in f if line.strip()]
            if not self._payloads:
                raise RuntimeError(f"sqli: payload file {parsed.payloads!r} is empty")
        if parsed.param_types:
            self._param_types = [
                t.strip().lower() for t in parsed.param_types.split(",") if t.strip()
            ]
        self._append = not parsed.replace
        self.parse_request_filters(args)

    # ------------------------------------------------------------------ mutate

    async def mutate(self, requests, context):
        self._meta = {}
        self._endpoints = []
        return self._variants(requests)

    def _variants(self, requests):
        for req in requests:
            idx = len(self._endpoints)
            self._endpoints.append(f"{req.method} {req.url}")

            # Baseline: the unmodified request, sent first as the FP reference.
            self._meta[id(req)] = (idx, None, None, None)
            yield req

            injectable = [
                (i, p) for i, p in enumerate(req.params)
                if p.type in self._param_types
            ]
            for i, param in injectable:
                for payload in self._payloads:
                    variant = self._inject(req, i, payload)
                    self._meta[id(variant)] = (idx, param.name, param.type, payload)
                    yield variant

    def _inject(self, req, target_index: int, payload: str):
        # Build a fresh params list, replacing only the target Param's value with
        # a new Param object; other Params are shared read-only (never mutated),
        # so no deepcopy is needed and siblings can't be corrupted.
        new_params = [
            replace(p, value=(p.value + payload) if self._append else payload)
            if i == target_index else p
            for i, p in enumerate(req.params)
        ]
        return replace(req, params=new_params)

    # ----------------------------------------------------------------- analyse

    def _matched_dbms(self, text: str) -> list[tuple[str, str]]:
        """Return (dbms, snippet) for each DBMS whose error signature matches."""
        hits = []
        for dbms, patterns in self._signatures:
            for rx in patterns:
                m = rx.search(text)
                if m:
                    hits.append((dbms, self._snippet(m.group(0))))
                    break  # one hit per DBMS is enough
        return hits

    @staticmethod
    def _snippet(text: str) -> str:
        collapsed = " ".join(text.split())
        return collapsed[:80]

    async def analyze_one(self, response, context):
        meta = self._meta.get(id(response.request))
        if meta is None:
            return  # not one of our variants
        idx, name, ptype, payload = meta

        text = response.body.decode("utf-8", "ignore") if response.body else ""
        matched = self._matched_dbms(text)

        results = context.data.setdefault(_CONTEXT_KEY, {})
        entry = results.setdefault(idx, {"baseline": set(), "baseline_status": None, "hits": []})

        if name is None:  # baseline
            entry["baseline"] = {dbms for dbms, _ in matched}
            entry["baseline_status"] = response.status
        else:
            entry["hits"].append({
                "param": name, "ptype": ptype, "payload": payload,
                "status": response.status, "matched": matched,
            })

    async def finalize(self, context):
        results = context.data.get(_CONTEXT_KEY)
        if not results:
            return

        lines: list[str] = []
        # Dedup keys so many payloads triggering the same DBMS on the same param
        # collapse to a single finding.
        seen_error: set[tuple] = set()
        seen_500: set[tuple] = set()

        for idx in sorted(results):
            entry = results[idx]
            baseline = entry["baseline"]
            base_status = entry["baseline_status"]
            endpoint = self._endpoints[idx]
            for hit in entry["hits"]:
                new = [(dbms, snip) for dbms, snip in hit["matched"] if dbms not in baseline]
                if new:
                    for dbms, snip in new:
                        key = (idx, hit["param"], hit["ptype"], dbms)
                        if key in seen_error:
                            continue
                        seen_error.add(key)
                        lines.append(
                            f"[SQLI] {dbms} error — {endpoint}  "
                            f"param '{hit['param']}' ({hit['ptype']})  "
                            f"payload {hit['payload']!r}  :: {snip}"
                        )
                elif hit["status"] == 500 and base_status not in (None, 500):
                    key = (idx, hit["param"], hit["ptype"])
                    if key in seen_500:
                        continue
                    seen_500.add(key)
                    lines.append(
                        f"[SQLI] HTTP 500 introduced (baseline {base_status}) — "
                        f"{endpoint}  param '{hit['param']}' ({hit['ptype']})  "
                        f"payload {hit['payload']!r}  (possible SQLi, verify manually)"
                    )

        if not lines:
            return
        print("[SQLI] --- SQL injection indicators ---")
        for line in lines:
            print(line)
        print(f"[SQLI] {len(seen_error)} confirmed error-based, "
              f"{len(seen_500)} error-code-only indicator(s)")
