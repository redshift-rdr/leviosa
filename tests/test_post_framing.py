"""Captured framing must never truncate serialized or mutated request bodies."""
import copy
import json
import socket
from dataclasses import replace
from urllib.parse import parse_qsl

import pytest
from aiohttp import web

from core.config import Config
from core.logdb import TrafficLogger
from core.models import LeviosaRequest, Param, RequestBody
from core.requester import _request_options, send


@pytest.fixture
async def receiver():
    received = []
    async def handler(req):
        body = await req.read()
        received.append((req.headers.copy(), body))
        return web.Response(text='ok')
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    try:
        await web.SockSite(runner, sock).start()
        yield f'http://127.0.0.1:{sock.getsockname()[1]}/', received
    finally:
        await runner.cleanup()
        sock.close()


def payload_request(url, kind):
    req = LeviosaRequest('POST', url, ['Content-Length: 1'], [])
    value = {'pageNumber': '1', 'documentDateFrom': '2026-01-01', 'views': ['完整', 'complete']}
    if kind == 'json-params':
        req.params = [Param('json', name, val) for name, val in value.items()]
    elif kind == 'explicit-json':
        req.body = RequestBody('json', value)
    elif kind == 'form':
        req.params = [Param('form', 'q', 'first'), Param('form', 'q', 'second'), Param('form', 'country', '中国')]
    elif kind == 'raw-text':
        req.headers.append('Content-Type: application/json; charset=utf-8')
        req.body = RequestBody('raw', json.dumps(value, ensure_ascii=False))
    elif kind == 'raw-bytes':
        req.body = RequestBody('raw', b'\x00\xff\x01complete\r\n')
    elif kind == 'multipart':
        req.headers.append('Content-Type: multipart/form-data; boundary=fixture')
        req.body = RequestBody('raw', b'--fixture\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\ncomplete file contents\r\n--fixture--\r\n')
    return req, value


@pytest.mark.parametrize('kind', ['json-params', 'explicit-json', 'form', 'raw-text', 'raw-bytes', 'multipart'])
@pytest.mark.parametrize('framing', ['short', 'long', 'duplicate', 'structured', 'chunked'])
async def test_complete_body_reaches_server_and_traffic_log(receiver, tmp_path, kind, framing):
    url, received = receiver
    req, expected_json = payload_request(url, kind)
    if framing == 'long':
        req.headers[0] = 'Content-Length: 999999'
    elif framing == 'duplicate':
        req.headers += ['content-length: 2', 'CONTENT-LENGTH: 3']
    elif framing == 'structured':
        req.params += [Param('header', 'content-length', '2'), Param('header', 'Transfer-Encoding', 'chunked')]
    elif framing == 'chunked':
        req.headers += ['Transfer-Encoding: chunked']
    before = copy.deepcopy(req)
    logger = TrafficLogger(str(tmp_path / 'traffic.sqlite'))
    try:
        # Response-body caps must not cap outgoing request bodies.
        response, = [r async for r in send([req], Config(timeout=3, max_body_bytes=1), logger=logger)]
        raw, = logger.conn.execute('SELECT REQUEST_RAW FROM ACTIVITY').fetchone()
    finally:
        logger.close()
    assert response.status == 200
    headers, body = received[0]
    assert len(headers.getall('Content-Length')) == 1
    assert int(headers['Content-Length']) == len(body)
    assert 'Transfer-Encoding' not in headers
    if kind in {'json-params', 'explicit-json', 'raw-text'}:
        assert json.loads(body) == expected_json
        assert body.endswith(b'}')
    elif kind == 'form':
        assert parse_qsl(body.decode()) == [('q', 'first'), ('q', 'second'), ('country', '中国')]
    else:
        assert body == req.body.value
    # TrafficLogger maps arbitrary non-UTF8 bytes to Latin-1. Compare logged
    # bodies as text through that same public representation, not reserialized JSON.
    logged_body = raw.split('\r\n\r\n', 1)[1]
    try:
        expected_text = body.decode('utf-8')
    except UnicodeDecodeError:
        expected_text = body.decode('latin-1')
    assert logged_body == expected_text
    assert req == before


async def test_mutated_body_gets_its_own_length(receiver):
    url, received = receiver
    seed = LeviosaRequest('POST', url, ['Content-Length: 2'], [], body=RequestBody('json', {}))
    variant = replace(seed, body=RequestBody('json', {'views': ['longer generated probe', '完成']}))
    responses = [r async for r in send([seed, variant], Config(concurrency=1, timeout=3))]
    assert [r.status for r in responses] == [200, 200]
    assert [json.loads(body) for _, body in received] == [{}, {'views': ['longer generated probe', '完成']}]
    assert all(int(headers['Content-Length']) == len(body) for headers, body in received)
    assert seed.headers == variant.headers == ['Content-Length: 2']


@pytest.mark.parametrize('method', ['GET', 'POST', 'HEAD'])
async def test_bodyless_requests_do_not_retain_nonzero_captured_length(receiver, method):
    url, received = receiver
    req = LeviosaRequest(method, url, ['Content-Length: 500', 'Transfer-Encoding: chunked'], [])
    response, = [r async for r in send([req], Config(timeout=3))]
    assert response.status == 200
    headers, body = received[0]
    assert body == b''
    assert headers.get('Content-Length') in {None, '0'}
    assert 'Transfer-Encoding' not in headers


def test_transport_normalization_removes_all_framing_sources_and_preserves_other_headers():
    req = LeviosaRequest('POST', 'https://app.test/',
        ['Content-Length: 1', 'content-length: 2', 'Transfer-Encoding: chunked', 'X-Test: unchanged'],
        [Param('header', 'Content-Length', '3'), Param('header', 'TRANSFER-ENCODING', 'chunked'), Param('json', 'views', ['complete'])])
    before = copy.deepcopy(req)
    headers, kwargs = _request_options(req)
    assert 'Content-Length' not in headers and 'Transfer-Encoding' not in headers
    assert headers['X-Test'] == 'unchanged'
    assert kwargs['json'] == {'views': ['complete']}
    assert req == before
