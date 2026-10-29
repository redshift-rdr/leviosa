import argparse
import json
from hashlib import sha256
import re
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from core.tooltags import BurpTool
from core.cookies import overrides_from_donor
from core.models import Param
from modules.base import BaseModule
from core.reporting import Finding
from core.headers import without_headers, parse_headers
from core.parsers import parse_request_file

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

    Replay each captured request unchanged and under each supplied identity.
    Cookies and configured credential/tenant headers are replaced wholesale.
    Optional anonymous requests strip those credentials. Body comparison reports
    observations; explicit access rules identify unexpected successful access.
    Redirects remain visible rather than following them to a generic login page.
    """

    tool = BurpTool.INTRUDER
    path_options = {'--session': 'session', '--access-rules': 'file'}
    follow_redirects = False
    store_response_cookies = False

    # Body reads are enabled by setup for comparison or access rules.
    needs_body = False
    use_burp = True

    def __init__(self):
        # list of (label, {cookie_name: value})
        self._sessions: list[tuple[str, dict[str, str]]] = []
        # endpoint_index -> display label ("METHOD url").
        self._endpoints: list[str] = []
        self._filters = []
        self._identity_headers = {}
        self._header_names = {"authorization", "x-api-key", "x-tenant-id"}
        self._anonymous = False
        self._rules = []
        self._compare_body = False

    def option_parser(self):
        parser = argparse.ArgumentParser(prog="authz", add_help=False, allow_abbrev=False)
        parser.add_argument(
            "--session", metavar="[LABEL=]FILE", action="append", default=[],
            help="Request file whose cookies and identity headers represent one user "
                 "(repeatable). Optionally prefix a display name, e.g. "
                 "--session admin=admin.json --session guest=guest.json",
        )
        parser.add_argument('--identity-header', action='append', default=[], metavar='NAME',
                            help='Additional credential/tenant header to replace from donor captures')
        parser.add_argument('--anonymous', action='store_true', help='Add a request without configured credentials')
        parser.add_argument('--compare-body', action='store_true', help='Compare normalized response fingerprints')
        parser.add_argument('--access-rules', metavar='FILE', help='JSON rules: method, url, allowed identity labels, optional contains marker')
        return parser

    def setup(self, args: list[str]) -> None:
        parsed, _ = self.option_parser().parse_known_args(args)
        self._sessions = []
        self._identity_headers = {}
        self._rules = []
        self._header_names = {"authorization", "x-api-key", "x-tenant-id"}
        self._anonymous = parsed.anonymous
        self._compare_body = parsed.compare_body
        self._header_names.update(name.lower() for name in parsed.identity_header)
        if any(not name or any(c.isspace() or c == ':' for c in name) for name in self._header_names):
            raise ValueError('invalid identity header name')
        if parsed.access_rules:
            self._rules = json.loads(Path(parsed.access_rules).read_text())
            if not isinstance(self._rules, list):
                raise ValueError('access rules must be a JSON list')
            seen_rules = set()
            for rule in self._rules:
                if (not isinstance(rule, dict) or not isinstance(rule.get('method'), str)
                        or not isinstance(rule.get('url'), str)
                        or not isinstance(rule.get('allowed'), list) or not rule['allowed']
                        or not all(isinstance(label, str) for label in rule['allowed'])
                        or ('contains' in rule and (not isinstance(rule['contains'], str) or not rule['contains']))):
                    raise ValueError('each access rule requires method, url, nonempty allowed labels and an optional nonempty contains string')
                key = (rule['method'].upper(), rule['url'])
                if key in seen_rules:
                    raise ValueError('duplicate access rule')
                seen_rules.add(key)
        self.needs_body = self._compare_body or bool(self._rules)
        if not parsed.session:
            raise RuntimeError(
                "authz requires at least one --session [LABEL=]FILE. Example: "
                "leviosa reqs.json --module authz "
                "--session admin=admin.json --session guest=guest.json"
            )

        seen: set[str] = set()
        for arg in parsed.session:
            label, path = self._split_session_arg(arg)
            if not label or label in {_ORIGINAL, '(anonymous)'}:
                raise ValueError('session labels must be nonempty and cannot use reserved matrix labels')
            label = self._unique_label(label, seen)
            try:
                cookies = overrides_from_donor(path)
                donor_headers = {}
                for donor in parse_request_file(path):
                    headers = parse_headers(donor.headers)
                    for param in donor.params:
                        if param.type == 'header':
                            headers[param.name] = str(param.value)
                    for name in self._header_names:
                        if name in headers:
                            donor_headers[name] = headers[name]
                self._identity_headers[label] = donor_headers
            except FileNotFoundError:
                raise RuntimeError(f"authz: session file not found: {path!r}")
            except (json.JSONDecodeError, KeyError) as e:
                raise RuntimeError(f"authz: could not parse session file {path!r}: {e}")
            if not cookies and not donor_headers:
                print(f"[AUTHZ] warning: no cookies found in {path!r} "
                      f"(session '{label}' will be sent unauthenticated)")
            self._sessions.append((label, cookies))

        labels = {label for label, _ in self._sessions}
        if any(set(rule['allowed']) - labels for rule in self._rules):
            raise ValueError('access rule allowed labels must name supplied sessions')
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
        self._endpoints = []
        return self._variants(requests)

    def _variants(self, requests):
        for req in requests:
            idx = len(self._endpoints)
            self._endpoints.append(self._endpoint_label(req))

            # Baseline: the request exactly as captured.
            original = replace(req, metadata={**req.metadata, "authz": (idx, _ORIGINAL)})
            yield original

            # One impersonated variant per session.
            for label, cookies in self._sessions:
                variant = self._with_identity(req, cookies, self._identity_headers.get(label, {}))
                variant.metadata["authz"] = (idx, label)
                yield variant
            if self._anonymous:
                variant = self._with_identity(req, {}, {})
                variant.metadata['authz'] = (idx, '(anonymous)')
                yield variant

    def _with_identity(self, req, cookies, headers):
        variant = self._impersonate(req, cookies)
        return replace(variant,
                       headers=without_headers(variant.headers, self._header_names) +
                               [f'{name}: {value}' for name, value in headers.items()],
                       params=[p for p in variant.params if not
                               (p.type == 'header' and p.name.lower() in self._header_names)])

    @staticmethod
    def _endpoint_label(req) -> str:
        # Strip scheme+host so the column shows just the path (+ query), which is
        # far easier to scan than a full URL repeated on every row.
        parts = urlsplit(req.url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        return f"{req.method} {path}"

    @staticmethod
    def _impersonate(req, cookies: dict[str, str]):
        # Drop every existing cookie (structured params + raw Cookie header) and
        # inject the session's cookies as params. A fresh params/headers list is
        # built so the source's cached request objects are never mutated.
        params = [p for p in req.params if p.type != "cookie" and not
                  (p.type == 'header' and p.name.lower() == 'cookie')]
        params += [Param("cookie", name, value) for name, value in cookies.items()]
        headers = without_headers(req.headers, ["cookie"])
        return replace(req, params=params, headers=headers)

    # ----------------------------------------------------------------- analyse

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get("authz")
        if meta is None:
            return  # not one of our variants
        idx, label = meta
        results = context.state.setdefault(_CONTEXT_KEY, {})
        results.setdefault(idx, {})[label] = response.status
        body = response.body.decode('utf-8', 'replace')
        try:
            normalized = json.dumps(json.loads(body), sort_keys=True, separators=(',', ':'))
        except (ValueError, TypeError):
            normalized = re.sub(r'\s+', ' ', body).strip()
        details = context.state.setdefault('authz.details', {})
        details.setdefault(idx, {})[label] = {
            'status': response.status, 'fingerprint': sha256(normalized.encode()).hexdigest(),
            'bytes': len(response.body),
        }
        if label != _ORIGINAL:
            for rule in self._rules:
                if (response.request.method.upper() == rule['method'].upper()
                        and response.request.url == rule['url'] and label not in rule['allowed']
                        and 200 <= response.status < 300
                        and ('contains' not in rule or rule['contains'] in body)):
                    self.report(response, context, f'[AUTHZ] Unexpected access by {label}: {self._endpoint_label(response.request)}',
                                evidence={'session': label, 'expected_allowed': rule['allowed'],
                                          'marker_matched': 'contains' in rule}, confidence='indicator')
        # Matrix cells are observations, delivered to programmatic reporters too.
        context.reporter.report(Finding(
            module=type(self).__name__, request=response.request,
            observation=f"{label}: {response.status}",
            evidence={"session": label, "status": response.status,
                      **(details[idx][label] if self.needs_body else {})},
            terminal_visible=False,
        ))

    async def finalize(self, context):
        results = context.state.get(_CONTEXT_KEY)
        if not results:
            return

        columns = [_ORIGINAL] + [label for label, _ in self._sessions]
        if self._anonymous:
            columns.append('(anonymous)')
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

        if self._compare_body:
            for idx, values in context.state.get('authz.details', {}).items():
                base = values.get(_ORIGINAL)
                if base and base['bytes'] and 200 <= base['status'] < 300:
                    for label, value in values.items():
                        if label != _ORIGINAL and 200 <= value['status'] < 300 and value['fingerprint'] == base['fingerprint']:
                            context.write(f'[AUTHZ] {self._endpoints[idx]}: {label} matches original normalized body (observation; verify expected access)')
        context.write("[AUTHZ] --- authorisation matrix (status code per user) ---")
        for line in self._render_table(header, rows):
            context.write(f"[AUTHZ] {line}")
        context.write("[AUTHZ] * = status differs from (original); "
              "'-' = no response, 'ERR' = network error")
        context.write(f"[AUTHZ] {differing} of {len(rows)} endpoints differ across users")

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
