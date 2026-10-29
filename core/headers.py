"""HTTP header helpers that preserve ordering and repeated field names."""
from multidict import CIMultiDict


def split_header(raw: str) -> tuple[str, str] | None:
    name, sep, value = raw.partition(":")
    if not sep or not name or any(c.isspace() for c in name):
        return None
    return name, value.lstrip(" \t")


def parse_headers(raw_headers: list[str]) -> CIMultiDict[str]:
    headers = CIMultiDict()
    for raw in raw_headers:
        if pair := split_header(raw):
            headers.add(*pair)
    return headers


def without_headers(raw_headers: list[str], names) -> list[str]:
    names = {name.lower() for name in names}
    return [raw for raw in raw_headers
            if not (pair := split_header(raw)) or pair[0].lower() not in names]


def transport_headers(headers) -> CIMultiDict[str]:
    """Use one casing per field so aiohttp preserves mixed-case duplicates.

    aiohttp's session header preparation tracks already-added names with a
    case-sensitive set, even though it writes into a case-insensitive multidict.
    """
    names = {}
    return CIMultiDict((names.setdefault(name.lower(), name), value)
                      for name, value in headers.items())
