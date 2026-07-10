import argparse
import json
from dataclasses import replace
from pathlib import Path

from core.cookies import overrides_from_donor
from core.models import Param
from modules.base import BaseModule

# Namespaced context key for the results grid built in analyze_one and rendered
# in finalize(): {endpoint_index: {column_label: status}}.
_CONTEXT_KEY = "authz.results"

# Column label for the untouched (as-captured) request.
_ORIGINAL = "(original)"

# Cap the endpoint column width so long URLs don't blow out the table.
_ENDPOINT_MAX = 64


class Authz(BaseModule):
    """
    Authorisation / access-control matrix.

    Each --session file is a captured request file whose cookies represent one
    user's session. For every input request the module sends:

      * the request unchanged (the "(original)" column), then
      * the request once per session, with its cookie set fully replaced by that
        session's cookies (impersonating each user).

    finalize() prints a table of the resulting status codes, one row per
    endpoint and one column per user, so you can eyeball where access differs
    between users — e.g. an endpoint that returns 200 for a low-privilege
    session it should reject (broken access control), or a resource that is
    identical for every user (missing per-user authorisation).

    Cookies are swapped wholesale — every existing cookie (params and the raw
    Cookie header) is dropped and replaced with the session's — so one user's
    request never leaks into another's. Only status codes are compared, so
    needs_body is False.
    """

    # Status-only module: the engine skips reading response bodies.
    needs_body = False
    use_burp = True

    def __init__(self):
        # list of (label, {cookie_name: value})
        self._sessions: list[tuple[str, dict[str, str]]] = []
        # id(request) -> (endpoint_index, column_label), built during mutate().
        self._request_meta: dict[int, tuple[int, str]] = {}
        # endpoint_index -> display label ("METHOD url").
        self._endpoints: list[str] = []
        self._filters = []

    def option_parser(self):
        parser = argparse.ArgumentParser(prog="authz", add_help=False)
        parser.add_argument(
            "--session", metavar="[LABEL=]FILE", action="append", default=[],
            help="Request file whose cookies represent one user's session "
                 "(repeatable). Optionally prefix a display name, e.g. "
                 "--session admin=admin.json --session guest=guest.json",
        )
        return parser

    def setup(self, args: list[str]) -> None:
        parsed, _ = self.option_parser().parse_known_args(args)
        if not parsed.session:
            raise RuntimeError(
                "authz requires at least one --session [LABEL=]FILE. Example: "
                "leviosa reqs.json --module authz "
                "--session admin=admin.json --session guest=guest.json"
            )

        seen: set[str] = set()
        for arg in parsed.session:
            label, path = self._split_session_arg(arg)
            label = self._unique_label(label, seen)
            try:
                cookies = overrides_from_donor(path)
            except FileNotFoundError:
                raise RuntimeError(f"authz: session file not found: {path!r}")
            except (json.JSONDecodeError, KeyError) as e:
                raise RuntimeError(f"authz: could not parse session file {path!r}: {e}")
            if not cookies:
                print(f"[AUTHZ] warning: no cookies found in {path!r} "
                      f"(session '{label}' will be sent unauthenticated)")
            self._sessions.append((label, cookies))

        self.parse_request_filters(args)

    @staticmethod
    def _split_session_arg(arg: str) -> tuple[str, str]:
        if "=" in arg:
            label, path = arg.split("=", 1)
            return label.strip(), path.strip()
        return Path(arg).stem, arg

    @staticmethod
    def _unique_label(label: str, seen: set[str]) -> str:
        base, n = label, 2
        while label in seen:
            label = f"{base}#{n}"
            n += 1
        seen.add(label)
        return label

    # ------------------------------------------------------------------ mutate

    async def mutate(self, requests, context):
        # Reset correlation state for this run before the engine consumes it.
        self._request_meta = {}
        self._endpoints = []
        return self._variants(requests)

    def _variants(self, requests):
        for req in requests:
            idx = len(self._endpoints)
            self._endpoints.append(self._endpoint_label(req))

            # Baseline: the request exactly as captured.
            self._request_meta[id(req)] = (idx, _ORIGINAL)
            yield req

            # One impersonated variant per session.
            for label, cookies in self._sessions:
                variant = self._impersonate(req, cookies)
                self._request_meta[id(variant)] = (idx, label)
                yield variant

    @staticmethod
    def _endpoint_label(req) -> str:
        return f"{req.method} {req.url}"

    @staticmethod
    def _impersonate(req, cookies: dict[str, str]):
        # Drop every existing cookie (structured params + raw Cookie header) and
        # inject the session's cookies as params. A fresh params/headers list is
        # built so the source's cached request objects are never mutated.
        params = [p for p in req.params if p.type != "cookie"]
        params += [Param("cookie", name, value) for name, value in cookies.items()]
        headers = [
            h for h in req.headers
            if h.partition(":")[0].strip().lower() != "cookie"
        ]
        return replace(req, params=params, headers=headers)

    # ----------------------------------------------------------------- analyse

    async def analyze_one(self, response, context):
        meta = self._request_meta.get(id(response.request))
        if meta is None:
            return  # not one of our variants
        idx, label = meta
        results = context.data.setdefault(_CONTEXT_KEY, {})
        results.setdefault(idx, {})[label] = response.status

    async def finalize(self, context):
        results = context.data.get(_CONTEXT_KEY)
        if not results:
            return

        columns = [_ORIGINAL] + [label for label, _ in self._sessions]
        header = ["ENDPOINT"] + columns
        rows = []
        differing = 0
        for idx in sorted(results):
            row_data = results[idx]
            base = row_data.get(_ORIGINAL)
            cells = []
            row_differs = False
            for col in columns:
                status = row_data.get(col)
                text = self._cell(status)
                if col != _ORIGINAL and status is not None and base is not None \
                        and status != base:
                    text += "*"
                    row_differs = True
                cells.append(text)
            differing += row_differs
            rows.append([self._truncate(self._endpoints[idx])] + cells)

        print("[AUTHZ] --- authorisation matrix (status code per user) ---")
        for line in self._render_table(header, rows):
            print(f"[AUTHZ] {line}")
        print("[AUTHZ] * = status differs from (original); "
              "'-' = no response, 'ERR' = network error")
        print(f"[AUTHZ] {differing} of {len(rows)} endpoints differ across users")

    @staticmethod
    def _cell(status) -> str:
        if status is None:
            return "-"
        if status == 0:
            return "ERR"
        return str(status)

    @staticmethod
    def _truncate(label: str) -> str:
        if len(label) <= _ENDPOINT_MAX:
            return label
        return label[: _ENDPOINT_MAX - 1] + "…"

    @staticmethod
    def _render_table(header: list[str], rows: list[list[str]]) -> list[str]:
        widths = [len(h) for h in header]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(cell))

        def fmt(cells):
            return "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

        lines = [fmt(header), "  ".join("-" * w for w in widths)]
        lines += [fmt(row) for row in rows]
        return lines
