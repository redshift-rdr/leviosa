"""Regression coverage for the module and HTTP extension boundaries."""
import argparse
import base64
import json
import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
from aiohttp import web
from multidict import CIMultiDict

from core.config import Config
from core.loader import discover_modules, load_modules
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param, RequestBody
from core.options import setup_modules
from core.parsers import parse_request_file
from core.requester import send
from core.runner import run_modules
from leviosa import build_parser
from modules.base import BaseModule
from modules.methodtamper import MethodTamper
from modules.sqli import SqlInjection


class RecordingReporter:
    def __init__(self):
        self.findings = []
        self.messages = []

    def report(self, finding):
        self.findings.append(finding)

    def write(self, message):
        self.messages.append(message)


def request(url="http://example.test/item", **kwargs):
    return LeviosaRequest("GET", url, [], [], **kwargs)


def test_installed_module_listing_outside_checkout(tmp_path):
    result = subprocess.run(
        [str(Path(sys.executable).parent / "leviosa"), "--list-modules"],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "sqli" in result.stdout
    assert "failed to load" not in result.stdout


def test_discovery_ignores_cwd_and_imported_classes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert "pathfuzz" in discover_modules()
    (tmp_path / "custom.py").write_text('''from __future__ import annotations
from dataclasses import dataclass
from modules.pathfuzz import PathFuzzer
@dataclass
class Options:
    value: str = "default"
class Custom(PathFuzzer):
    pass
''')
    assert type(load_modules(["custom"], str(tmp_path))[0]).__name__ == "Custom"


@pytest.mark.parametrize("name", ["../outside", "base", "_private"])
def test_loader_rejects_non_public_names(name):
    with pytest.raises(ValueError):
        load_modules([name])


@pytest.mark.parametrize("flags", [["--typo"], ["--sampl", "1"], ["--wordlist", "unused.txt"]])
def test_cli_rejects_unused_flags_before_logging(tmp_path, flags):
    result = subprocess.run(
        [str(Path(sys.executable).parent / "leviosa"), "http://127.0.0.1:1", *flags],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "unrecognized arguments" in result.stderr
    assert not (tmp_path / "leviosa.db").exists()


class SimpleModule(BaseModule):
    async def mutate(self, requests, context):
        return requests


def test_filters_work_without_module_setup_hook():
    from core.filters import MethodFilter
    module = SimpleModule()
    setup_modules([module], [], [MethodFilter(["POST"])], build_parser())
    assert list(module.cli_filters[0].apply([request(), replace(request(), method="POST")]))[0].method == "POST"


def test_conflicting_module_options_are_rejected(capsys):
    class WithOption(SimpleModule):
        def option_parser(self):
            parser = argparse.ArgumentParser(add_help=False)
            parser.add_argument("--shared")
            return parser
    with pytest.raises(SystemExit):
        setup_modules([WithOption(), WithOption()], [], [], build_parser())
    assert "declared by both" in capsys.readouterr().err


async def fake_send(requests, config, **kwargs):
    for req in requests:
        yield LeviosaResponse(200, {}, b"", req)


async def test_invocation_state_is_private_and_reporter_is_replaceable(capsys):
    class Counting(SimpleModule):
        async def analyze_one(self, response, context):
            context.state["count"] = context.state.get("count", 0) + 1
            context.data["runs"] = context.data.get("runs", 0) + 1
            self.report(response, context, "observed", evidence={"count": context.state["count"]})
    reporter = RecordingReporter()
    context = LeviosaContext(reporter=reporter)
    module = Counting()
    with patch("core.runner.send", fake_send):
        for _ in range(2):
            await run_modules([module, module], lambda: [request()], Config(), context)
    assert [f.evidence["count"] for f in reporter.findings] == [1, 1, 1, 1]
    assert context.data == {"runs": 4}
    assert context.state == {}
    assert reporter.findings[0].request.url == "http://example.test/item"
    assert capsys.readouterr().out == ""


def test_variants_have_distinct_ids_and_independent_metadata():
    seed = request(metadata={"source": "capture"})
    first = replace(seed, method="POST")
    second = replace(seed, method="PUT")
    first.metadata["probe"] = "one"
    assert len({seed.request_id, first.request_id, second.request_id}) == 3
    assert seed.seed_id == first.seed_id == second.seed_id
    assert "probe" not in seed.metadata and "probe" not in second.metadata


async def test_method_comparisons_do_not_merge_same_url_requests():
    module = MethodTamper()
    module.setup(["--methods", "HEAD", "--no-override"])
    reporter = RecordingReporter()
    context = LeviosaContext(reporter=reporter)
    seeds = [request(), request()]
    variants = list(await module.mutate(seeds, context))
    for req in reversed(variants):
        baseline = req.metadata["methodtamper.baseline"]
        status = 404 if req.seed_id == seeds[0].seed_id and baseline else 200
        await module.analyze_one(LeviosaResponse(status, {}, b"", req), context)
    await module.finalize(context)
    assert len(context.state["methodtamper.matrix"]) == 2
    assert sum("baseline GET=404" in text for text in reporter.messages) == 1


async def test_sqli_handles_late_baseline_and_releases_seed_state():
    module = SqlInjection()
    module.setup([])
    reporter = RecordingReporter()
    context = LeviosaContext(reporter=reporter)
    seed = request()
    seed.params = [Param("query", "id", "1")]
    variants = list(await module.mutate([seed], context))
    error = b"You have an error in your SQL syntax near MySQL"
    for req in reversed(variants):
        await module.analyze_one(LeviosaResponse(200, {}, error, req), context)
    assert not reporter.findings  # baseline has the same error: suppress it
    assert context.state["sqli.results"] == {}
    # A second seed with a clean baseline produces one deduplicated finding.
    variants = list(await module.mutate([seed], context))
    for req in reversed(variants):
        body = b"clean" if req.metadata["sqli"][1] is None else error
        await module.analyze_one(LeviosaResponse(200, {}, body, req), context)
    assert len(reporter.findings) == 1
    assert reporter.findings[0].evidence["parameter"] == "id"
    assert context.state["sqli.results"] == {}


@pytest.fixture
async def echo_server():
    async def echo(req):
        body = await req.read()
        return web.json_response({
            "query": list(req.query.items()),
            "headers": [[k.decode(), v.decode()] for k, v in req.raw_headers],
            "body": base64.b64encode(body).decode(),
        }, headers=CIMultiDict([("X-Reply", "one"), ("x-reply", "two")]))
    app = web.Application()
    app.router.add_route("*", "/", echo)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    try:
        await web.SockSite(runner, sock).start()
        yield f"http://127.0.0.1:{port}/"
    finally:
        await runner.cleanup()
        sock.close()


async def dispatch(req):
    return [response async for response in send([req], Config())][0]


async def test_duplicate_http_fields_survive_real_transport(echo_server):
    req = LeviosaRequest("POST", echo_server + "?q=existing", ["X-Probe:one", "x-probe:\ttwo"], [
        Param("query", "q", "first"), Param("query", "q", "second"),
        Param("form", "field", "one"), Param("form", "field", "two"),
    ])
    response = await dispatch(req)
    result = json.loads(response.body)
    assert result["query"] == [["q", "existing"], ["q", "first"], ["q", "second"]]
    assert [v for k, v in result["headers"] if k.lower() == "x-probe"] == ["one", "two"]
    assert base64.b64decode(result["body"]) == b"field=one&field=two"
    assert response.headers.getall("X-REPLY") == ["one", "two"]


@pytest.mark.parametrize("body,expected", [
    (RequestBody("raw", b"\x00\xffbinary"), b"\x00\xffbinary"),
    (RequestBody("raw", "text"), b"text"),
    (RequestBody("json", {"nested": [True, None, {"count": 3}]}), None),
    (RequestBody("json", None), b"null"),
])
async def test_explicit_bodies_survive_real_transport(echo_server, body, expected):
    req = LeviosaRequest("POST", echo_server, [], [], body=body)
    result = json.loads((await dispatch(req)).body)
    raw = base64.b64decode(result["body"])
    if expected is not None:
        assert raw == expected
    else:
        assert json.loads(raw) == body.value


async def test_header_parameters_replace_case_insensitively(echo_server):
    req = LeviosaRequest("GET", echo_server, ["X-Token:old"], [
        Param("header", "x-token", "one"), Param("header", "X-Token", "two"),
    ])
    result = json.loads((await dispatch(req)).body)
    assert [v for k, v in result["headers"] if k.lower() == "x-token"] == ["one", "two"]


def test_request_file_supports_nested_and_binary_bodies(tmp_path):
    path = tmp_path / "requests.json"
    path.write_text(json.dumps([
        {"method": "POST", "url": "http://example.test", "body": {"kind": "json", "value": [1, {"x": False}]}},
        {"method": "POST", "url": "http://example.test", "body": {"kind": "raw", "value": "AP8=", "encoding": "base64"}},
    ]))
    requests = parse_request_file(str(path))
    assert requests[0].body.value == [1, {"x": False}]
    assert requests[1].body.value == b"\x00\xff"


async def test_conflicting_body_representations_are_rejected(echo_server):
    req = LeviosaRequest("POST", echo_server, [], [Param("form", "x", "y")], body=RequestBody("json", {}))
    with pytest.raises(ValueError, match="cannot be combined"):
        await dispatch(req)




@pytest.mark.parametrize("listing_first", [True, False])
def test_cli_lists_custom_directory_in_either_option_order(tmp_path, listing_first):
    (tmp_path / "custom.py").write_text('''from modules.base import BaseModule
class Custom(BaseModule):
    async def mutate(self, requests, context):
        return requests
''')
    listing = ["--list-modules"]
    directory = ["--modules-dir", str(tmp_path)]
    result = subprocess.run(
        [str(Path(sys.executable).parent / "leviosa"),
         *(listing + directory if listing_first else directory + listing)],
        cwd=tmp_path, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "custom" in result.stdout and "failed to load" not in result.stdout
    assert "pathfuzz" not in result.stdout


async def test_shared_filters_compose_with_custom_module_filters():
    from core.filters import MethodFilter, TakeFilter
    received = []

    class Filtered(SimpleModule):
        def request_filters(self):
            return [TakeFilter(1)]

        async def mutate(self, requests, context):
            received.extend(requests)
            return []
    module = Filtered()
    setup_modules([module], [], [MethodFilter(["POST"])], build_parser())
    seeds = [request(), replace(request(), method="POST"), replace(request(), method="POST")]
    with patch("core.runner.send", fake_send):
        await run_modules([module], lambda: seeds, Config(), LeviosaContext())
    assert len(received) == 1 and received[0].method == "POST"
