"""
Cookie overrides — refresh stale session cookies in captured requests.

Captured requests carry cookies in two places: the structured `params`
(``{"type": "cookie", ...}``) and the raw ``Cookie:`` line in `headers`. When a
session times out, both need the fresh value or the stale one leaks back in from
whichever place was left untouched. These helpers replace cookies **by name** in
both locations at the source layer, so every request the tool sends — for every
module — carries the fresh values.

Overrides are sourced from a pasted ``Cookie:`` header string (--cookies) or from
a freshly captured donor request file (--cookie-from). Replacement is by name and
only touches cookies already present; other cookies and everything else in the
request are left intact.
"""
from collections.abc import Callable, Iterable
from dataclasses import replace

from core.models import LeviosaRequest
from core.parsers import parse_request_file


def parse_cookie_header(value: str) -> list[tuple[str, str]]:
    """Split a ``Cookie:`` header value into ordered (name, value) pairs."""
    pairs = []
    for token in value.split(";"):
        token = token.strip()
        if not token:
            continue
        name, _, val = token.partition("=")
        pairs.append((name.strip(), val.strip()))
    return pairs


def overrides_from_header_string(raw: str) -> dict[str, str]:
    """Build a name→value override map from a pasted ``Cookie:`` header string."""
    return {name: val for name, val in parse_cookie_header(raw)}


def cookies_from_request(req: LeviosaRequest) -> dict[str, str]:
    """Extract every cookie from one request (raw Cookie header + cookie params)."""
    cookies: dict[str, str] = {}
    for header in req.headers:
        name, sep, value = header.partition(": ")
        if sep and name.lower() == "cookie":
            cookies.update(parse_cookie_header(value))
    # Structured params take precedence over the raw header.
    for param in req.params:
        if param.type == "cookie":
            cookies[param.name] = param.value
    return cookies


def overrides_from_donor(path: str) -> dict[str, str]:
    """
    Build a name→value override map from a freshly captured donor request file.

    Cookies from every request in the file are merged (later requests win); in
    practice all requests in one capture share the same fresh session, so order
    does not matter.
    """
    overrides: dict[str, str] = {}
    for req in parse_request_file(path):
        overrides.update(cookies_from_request(req))
    return overrides


def _rewrite_cookie_header(header: str, overrides: dict[str, str]) -> str:
    """Return the header with matching cookie values replaced; non-Cookie headers pass through."""
    name, sep, value = header.partition(": ")
    if not sep or name.lower() != "cookie":
        return header
    rebuilt = "; ".join(
        f"{k}={overrides.get(k, v)}" for k, v in parse_cookie_header(value)
    )
    return f"{name}: {rebuilt}"


def apply_overrides(req: LeviosaRequest, overrides: dict[str, str]) -> LeviosaRequest:
    """
    Return a copy of req with cookies replaced by name in both the cookie params
    and the raw ``Cookie:`` header. Fresh lists are built so the source's cached
    request objects are never mutated.
    """
    new_params = [
        replace(p, value=overrides[p.name])
        if p.type == "cookie" and p.name in overrides
        else p
        for p in req.params
    ]
    new_headers = [_rewrite_cookie_header(h, overrides) for h in req.headers]
    return replace(req, params=new_params, headers=new_headers)


def with_cookie_overrides(
    source: Callable[[], Iterable[LeviosaRequest]],
    overrides: dict[str, str],
) -> Callable[[], Iterable[LeviosaRequest]]:
    """
    Wrap a request-source factory so each request it yields has its cookies
    refreshed. Preserves laziness and the fresh-iterator-per-call contract; a
    no-op (returns the original factory) when there are no overrides.
    """
    if not overrides:
        return source

    def factory() -> Iterable[LeviosaRequest]:
        for req in source():
            yield apply_overrides(req, overrides)

    return factory
