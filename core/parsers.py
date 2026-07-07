import json
from pathlib import Path

from core.models import LeviosaRequest, Param


def parse_url(url: str) -> list[LeviosaRequest]:
    return [LeviosaRequest(method="GET", url=url, headers=[], params=[])]


def parse_url_file(path: str) -> list[LeviosaRequest]:
    requests = []
    with open(path) as f:
        for line in f:
            url = line.strip()
            if url:
                requests.extend(parse_url(url))
    return requests


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


def detect_and_parse(target: str) -> list[LeviosaRequest]:
    if target.startswith("http://") or target.startswith("https://"):
        return parse_url(target)
    if Path(target).suffix == ".json":
        return parse_request_file(target)
    return parse_url_file(target)
