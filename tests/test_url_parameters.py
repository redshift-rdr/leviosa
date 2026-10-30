"""Regression coverage for imported URL params and embedded URL query strings."""
from urllib.parse import parse_qsl, urlsplit

import pytest

from core.models import LeviosaContext, LeviosaRequest, Param
from core.parsers import parse_request_file
from core.probes import input_variants
from core.requester import _build_kwargs, send
from core.config import Config
from modules.authentication import Authentication
from modules.businesslogic import inputs, mutate_input
from modules.errorpages import ErrorPages
from modules.sqli import SqlInjection


def request(url="http://example.com/login", params=None):
    return LeviosaRequest("GET", url, [], params or [])


def test_imported_url_parameters_are_canonical_query_inputs(tmp_path):
    source = tmp_path / "requests.json"
    source.write_text('[{"method":"GET","url":"http://example.com/login","params":['
                      '{"type":"url","name":"username","value":"alice"},'
                      '{"type":"url","name":"password","value":"secret"}]}]')
    req = parse_request_file(source)[0]
    assert [p.type for p in req.params] == ["query", "query"]
    assert Authentication().fields(req) is not None
    targets = list(inputs(req))
    assert [t["location"] for t in targets] == ["query", "query"]
    changed = mutate_input(req, targets[0], "replace", "bob")
    assert changed.params[0].value == "bob"
    assert req.params[0].value == "alice"
    assert len(list(input_variants(req, "probe"))) == 2
    kwargs, _ = _build_kwargs(req.params)
    assert list(kwargs["params"].items()) == [("username", "alice"), ("password", "secret")]


@pytest.mark.parametrize("replace_value", [False, True])
async def test_sqli_embedded_query_occurrences(replace_value):
    req = request("http://example.com/item?id=1&id=&q=a%26b#section",
                  [Param("url", "extra", "keep")])
    module = SqlInjection()
    module.setup(["--replace"] if replace_value else [])
    module._payloads = ["'"]
    variants = list(await module.mutate([req], LeviosaContext()))
    assert len(variants) == 5  # baseline, three URL occurrences, one structured param
    assert variants[0].metadata["sqli.total"] == 5
    original = parse_qsl(urlsplit(req.url).query, keep_blank_values=True)
    for index, variant in enumerate(variants[1:4]):
        expected = list(original)
        name, value = expected[index]
        expected[index] = (name, "'" if replace_value else value + "'")
        assert parse_qsl(urlsplit(variant.url).query, keep_blank_values=True) == expected
        assert urlsplit(variant.url).fragment == "section"
        assert variant.params[0].value == "keep"
    assert req.url.endswith("q=a%26b#section")
    assert req.params[0].value == "keep"


async def test_sqli_url_filter_alias_and_query_exclusion():
    req = request("http://example.com/item?id=1", [Param("url", "q", "x")])
    module = SqlInjection()
    module.setup(["--param-types", "url"])
    module._payloads = ["'"]
    assert len(list(await module.mutate([req], LeviosaContext()))) == 3
    module.setup(["--param-types", "header"])
    assert len(list(await module.mutate([req], LeviosaContext()))) == 1


def test_errorpages_mutates_each_embedded_query_occurrence():
    req = request("http://example.com/app?id=1&id=&q=a%26b")
    module = ErrorPages()
    module.setup(["--techniques", "param-injection"])
    variants = list(module._variants([req]))
    assert variants
    original = parse_qsl(urlsplit(req.url).query, keep_blank_values=True)
    changed_indexes = set()
    for variant in variants:
        pairs = parse_qsl(urlsplit(variant.url).query, keep_blank_values=True)
        assert [name for name, _ in pairs] == ["id", "id", "q"]
        changed = [i for i, pair in enumerate(pairs) if pair != original[i]]
        assert len(changed) == 1
        changed_indexes.add(changed[0])
    assert changed_indexes == {0, 1, 2}


async def test_url_params_sent_in_get_query():
    from aiohttp import web

    async def echo(req):
        assert req.method == "GET"
        assert list(req.query.items()) == [
            ("existing", "yes"), ("q", "a&b"), ("q", ""), ("space", "a b")]
        assert await req.read() == b""
        return web.Response(text="ok")

    app = web.Application()
    app.router.add_get("/", echo)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        port = site._server.sockets[0].getsockname()[1]
        req = request(f"http://127.0.0.1:{port}/?existing=yes", [
            Param("url", "q", "a&b"), Param("url", "q", ""), Param("url", "space", "a b")])
        responses = [response async for response in send([req], Config(no_proxy=True))]
        assert responses[0].status == 200
    finally:
        await runner.cleanup()
