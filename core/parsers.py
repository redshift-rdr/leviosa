import json
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from core.models import LeviosaRequest, Param


def parse_url(url: str) -> list[LeviosaRequest]:
    return [LeviosaRequest(method="GET", url=url, headers=[], params=[])]


def parse_url_file(path: str) -> Iterator[LeviosaRequest]:
    """
    Stream one request per non-blank line. This is a generator so a huge URL
    list is never fully materialised; the `with` block keeps the file handle
    tied to the generator's lifetime, so partial consumption still closes it.
    """
    with open(path) as f:
        for line in f:
            url = line.strip()
            if url:
                yield LeviosaRequest(method="GET", url=url, headers=[], params=[])


def parse_request_file(path: str) -> list[LeviosaRequest]:
    with open(path) as f:
        data = json.load(f)
    requests = []
    for item in data:
        params = [
            Param(type=p["type"], name=p["name"], value=p["value"])
            for p in item.get("params", [])
        ]
        requests.append(LeviosaRequest(
            method=item["method"],
            url=item["url"],
            headers=item.get("headers", []),
            params=params,
            hashkey=item.get("hashkey"),
        ))
    return requests


def request_source(target: str) -> Callable[[], Iterable[LeviosaRequest]]:
    """
    Resolve a target into a factory that produces a *fresh* iterable of requests
    each time it is called (each module gets its own independent iterator).

    Validation is eager so friendly errors surface synchronously at call time
    rather than deep inside the async pipeline: missing files raise
    FileNotFoundError and malformed JSON raises json.JSONDecodeError here.
    """
    if target.startswith("http://") or target.startswith("https://"):
        return lambda: parse_url(target)

    if not Path(target).exists():
        raise FileNotFoundError(f"file not found: {target!r}")

    if Path(target).suffix == ".json":
        # Parse once, eagerly (raises JSONDecodeError synchronously); replay the
        # cached list on each call.
        cached = parse_request_file(target)
        return lambda: iter(cached)

    # URL-list file: re-open and stream per module so memory stays O(1).
    return lambda: parse_url_file(target)
