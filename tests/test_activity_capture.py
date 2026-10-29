"""Check database rows against real HTTP traffic, rather than reconstructed seeds."""
import json
import socket
import sqlite3
from datetime import datetime

import pytest
from aiohttp import web

from core.config import Config
from core.logdb import TrafficLogger
from core.models import LeviosaRequest, Param, RequestBody
from core.requester import send


@pytest.fixture
async def server():
    received = []

    async def handler(req):
        body = await req.read()
        received.append((req.method, req.raw_path, list(req.raw_headers), body))
        if req.path == '/redirect-failure':
            return web.Response(status=302, headers={'Location': req.query['next']}, text='redirect body')
        if req.path == '/redirect':
            return web.Response(status=302, headers={'Location': '/final?q=next'}, text='redirect body')
        return web.Response(text='response café')

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    address = f'http://127.0.0.1:{sock.getsockname()[1]}'
    try:
        await web.SockSite(runner, sock).start()
        yield address, received
    finally:
        await runner.cleanup()
        sock.close()


def read_rows(path):
    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute('SELECT * FROM ACTIVITY ORDER BY rowid')]


async def logged(requests, path, config=None, read_body=True, **kwargs):
    logger = TrafficLogger(str(path))
    try:
        return [resp async for resp in send(requests, config or Config(), read_body=read_body,
                                            logger=logger, **kwargs)]
    finally:
        logger.close()


async def test_capture_prepared_request_and_response_without_module_body(server, tmp_path):
    url, received = server
    path = tmp_path / 'log.sqlite'
    req = LeviosaRequest('POST', url + '/api?q=original', ['X-Probe:one', 'x-probe:two'], [
        Param('query', 'q', 'one'), Param('query', 'q', 'two'),
        Param('cookie', 'session', 'fresh'),
        Param('json', 'nested', {'items': [1, True, None]}),
    ])
    started = datetime.now().replace(microsecond=0)
    response, = await logged([req], path, read_body=False)
    record, = read_rows(path)
    method, target, headers, body = received[0]
    expected_head = f'{method} {target} HTTP/1.1\r\n' + ''.join(
        f'{name.decode()}: {value.decode()}\r\n' for name, value in headers
    ) + '\r\n'
    assert record['REQUEST_RAW'] == expected_head + body.decode()
    assert 'session=fresh' in record['REQUEST_RAW']
    assert json.loads(body) == {'nested': {'items': [1, True, None]}}
    assert record['TARGET_URL'] == url + '/api?q=original&q=one&q=two'
    assert record['LOCAL_SOURCE_IP'] == '127.0.0.1'
    assert record['RESPONSE_RAW'] == 'response café'
    assert record['HTTP_STATUS_CODE'] == '200'
    assert record['BURP_TOOL'] == 'Repeater'
    assert started <= datetime.strptime(record['SEND_DATETIME'], '%Y-%m-%d %H:%M:%S') <= datetime.now()
    assert response.body == b''  # body capture does not change module contract


@pytest.mark.parametrize('body', [
    RequestBody('raw', b'\x00\xffbinary'),
    RequestBody('json', {'items': [True, None, {'count': 2}]}),
    RequestBody('json', None),
])
async def test_explicit_body_capture(server, tmp_path, body):
    url, received = server
    path = tmp_path / 'log.sqlite'
    await logged([LeviosaRequest('POST', url, [], [], body=body)], path)
    raw = read_rows(path)[0]['REQUEST_RAW'].split('\r\n\r\n', 1)[1]
    if body.kind == 'json':
        assert json.loads(raw) == body.value
    else:
        assert raw.encode('latin-1') == received[0][3] == body.value


async def test_form_fields_preserved_in_raw_request(server, tmp_path):
    url, received = server
    path = tmp_path / 'log.sqlite'
    req = LeviosaRequest('POST', url, [], [Param('form', 'name', 'one'), Param('form', 'name', 'two')])
    await logged([req], path)
    raw = read_rows(path)[0]['REQUEST_RAW']
    assert raw.endswith('\r\n\r\nname=one&name=two')
    assert 'application/x-www-form-urlencoded' in raw


async def test_body_cap_also_applies_to_logging(server, tmp_path):
    url, _ = server
    path = tmp_path / 'log.sqlite'
    response, = await logged([LeviosaRequest('GET', url, [], [])], path, Config(max_body_bytes=4), read_body=False)
    assert read_rows(path)[0]['RESPONSE_RAW'] == 'resp'
    assert response.body == b''


async def test_each_redirect_hop_has_its_own_row(server, tmp_path):
    url, _ = server
    path = tmp_path / 'log.sqlite'
    response, = await logged([LeviosaRequest('GET', url + '/redirect', [], [])], path, Config(follow_redirects=True))
    rows = read_rows(path)
    assert [(row['TARGET_URL'], row['HTTP_STATUS_CODE'], row['RESPONSE_RAW']) for row in rows] == [
        (url + '/redirect', '302', 'redirect body'),
        (url + '/final?q=next', '200', 'response café'),
    ]
    assert rows[0]['REQUEST_RAW'].startswith('GET /redirect HTTP/1.1\r\n')
    assert rows[1]['REQUEST_RAW'].startswith('GET /final?q=next HTTP/1.1\r\n')
    assert response.status == 200


async def test_connection_failure_keeps_attempt_without_inventing_raw_message(tmp_path):
    path = tmp_path / 'log.sqlite'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))  # reserve a port, but do not listen
        url = f'http://127.0.0.1:{sock.getsockname()[1]}/'
        response, = await logged([LeviosaRequest('GET', url, [], [])], path, tool='Scanner')
    row, = read_rows(path)
    assert row['TARGET_URL'] == url
    assert row['BURP_TOOL'] == 'Scanner'
    assert row['HTTP_STATUS_CODE'] == '0'
    assert row['REQUEST_RAW'] == row['RESPONSE_RAW'] == row['LOCAL_SOURCE_IP'] == ''
    assert response.status == 0


async def test_concurrent_requests_do_not_mix_capture_state(server, tmp_path):
    url, _ = server
    path = tmp_path / 'log.sqlite'
    reqs = [LeviosaRequest('POST', f'{url}/?i={i}', [], [], body=RequestBody('raw', f'body={i}')) for i in range(24)]
    await logged(reqs, path, Config(concurrency=6))
    rows = read_rows(path)
    assert len(rows) == 24
    for row in rows:
        number = row['TARGET_URL'].split('i=')[1]
        assert row['REQUEST_RAW'].startswith(f'POST /?i={number} HTTP/1.1\r\n')
        assert row['REQUEST_RAW'].endswith(f'\r\n\r\nbody={number}')


async def test_http_proxy_uses_actual_absolute_request_target(server, tmp_path):
    proxy, _ = server
    path = tmp_path / 'log.sqlite'
    url = 'http://target.invalid/api?q=one'
    await logged([LeviosaRequest('GET', url, [], [])], path, proxy=proxy)
    row, = read_rows(path)
    assert row['TARGET_URL'] == url
    assert row['REQUEST_RAW'].startswith(f'GET {url} HTTP/1.1\r\n')


async def test_no_log_preserves_status_only_no_body_contract(server):
    url, _ = server
    response, = [resp async for resp in send([LeviosaRequest('GET', url, [], [])], Config(), read_body=False)]
    assert response.body == b''
    assert response.traffic == []


async def test_chunked_request_raw_includes_transfer_framing(server):
    import aiohttp
    from core.capture import Capture, CapturedRequest, current_capture, trace_config
    from core.requester import _read_capped
    url, received = server
    capture = Capture(1024, _read_capped)

    async def chunks():
        yield b'payload'

    token = current_capture.set(capture)
    try:
        async with aiohttp.ClientSession(request_class=CapturedRequest, trace_configs=[trace_config()]) as session:
            async with session.post(url, data=chunks()) as response:
                await response.read()
    finally:
        current_capture.reset(token)
    assert received[0][3] == b'payload'
    assert capture.records[0].request_raw.endswith(b'\r\n\r\n7\r\npayload\r\n0\r\n\r\n')


async def test_capture_matches_wire_with_stale_content_length(tmp_path):
    import asyncio
    received = []

    async def handler(reader, writer):
        try:
            headers = await reader.readuntil(b'\r\n\r\n')
            body = await reader.readexactly(6)
            received.append(headers + body)
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok')
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handler, '127.0.0.1', 0)
    try:
        url = f'http://127.0.0.1:{server.sockets[0].getsockname()[1]}/'
        path = tmp_path / 'log.sqlite'
        req = LeviosaRequest('POST', url, ['Content-Length: 3'], [], body=RequestBody('raw', 'abcdef'))
        await logged([req], path)
        assert received[0].endswith(b'\r\n\r\nabcdef')
        assert read_rows(path)[0]['REQUEST_RAW'].encode() == received[0]
    finally:
        server.close()
        await server.wait_closed()


async def test_redirect_to_failed_connection_retains_actual_next_url(server, tmp_path):
    from urllib.parse import urlencode
    url, _ = server
    path = tmp_path / 'log.sqlite'
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        failed_url = f'http://127.0.0.1:{sock.getsockname()[1]}/unreachable'
        start_url = url + '/redirect-failure?' + urlencode({'next': failed_url})
        await logged([LeviosaRequest('POST', start_url, [], [])], path, Config(follow_redirects=True))
    first, failed = read_rows(path)
    assert first['HTTP_STATUS_CODE'] == '302'
    assert failed['TARGET_URL'] == failed_url
    assert failed['HTTP_METHOD'] == 'GET'  # actual method chosen after POST/302
    assert failed['HTTP_STATUS_CODE'] == '0'
    assert failed['REQUEST_RAW'] == failed['LOCAL_SOURCE_IP'] == ''


@pytest.mark.parametrize('module_args,expected_tool', [
    ([], 'Repeater'), (['--module', 'securityheaders'], 'Scanner'), (['--tool', 'Intruder'], 'Intruder'),
])
async def test_cli_writes_only_activity_while_findings_stay_on_console(server, tmp_path, module_args, expected_tool):
    import asyncio
    import sys
    from pathlib import Path
    url, _ = server
    path = tmp_path / 'cli.sqlite'
    script = Path(__file__).resolve().parent.parent / 'leviosa.py'
    process = await asyncio.create_subprocess_exec(
        sys.executable, str(script), url + '/', '--no-proxy', '--log-db', str(path), *module_args,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode()
    row, = read_rows(path)
    assert row['RESPONSE_RAW'] == 'response café'
    assert row['BURP_TOOL'] == expected_tool
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [('ACTIVITY',)]
    if '--module' in module_args:
        assert '[SECHEADERS]' in stdout.decode()
        assert 'missing' in stdout.decode()
    else:
        assert stdout.decode().startswith('200 GET ')


@pytest.mark.parametrize('flags,config_text,expected', [
    ([], '', ['Repeater', 'Scanner', 'Intruder']),
    (['--tool', 'Scanner'], '', ['Scanner', 'Scanner', 'Scanner']),
    (['--module-tool', 'pathfuzz=Repeater'], '', ['Repeater', 'Scanner', 'Repeater']),
    (['--tool', 'Intruder', '--module-tool', 'pathfuzz=Repeater'], '', ['Intruder', 'Intruder', 'Repeater']),
    ([], '[tools]\ndefault="Intruder"\n[tools.modules]\nsecurityheaders="Repeater"\npathfuzz="Scanner"\n',
     ['Intruder', 'Repeater', 'Scanner']),
    (['--tool', 'Scanner'], '[tools.modules]\npathfuzz="Repeater"\n', ['Scanner', 'Scanner', 'Scanner']),
    (['--module-tool', 'pathfuzz=Repeater'], '[tools]\ndefault="Intruder"\n[tools.modules]\nsecurityheaders="Repeater"\n',
     ['Intruder', 'Repeater', 'Repeater']),
])
async def test_cli_tag_defaults_and_override_precedence(server, tmp_path, flags, config_text, expected):
    import asyncio
    import sys
    from pathlib import Path
    url, received = server
    path = tmp_path / 'tagged.sqlite'
    wordlist = tmp_path / 'words.txt'
    wordlist.write_text('check\n')
    (tmp_path / 'leviosa.toml').write_text(config_text)
    script = Path(__file__).resolve().parent.parent / 'leviosa.py'
    process = await asyncio.create_subprocess_exec(
        sys.executable, str(script), url + '/', '--no-proxy', '--log-db', str(path),
        '-m', 'passthrough', '-m', 'securityheaders', '-m', 'pathfuzz',
        '--wordlist', str(wordlist), '--recursive', *flags,
        cwd=tmp_path, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode()
    assert [row['BURP_TOOL'] for row in read_rows(path)] == expected
    assert len(received) == 3
    for _, _, headers, _ in received:
        assert not any(name.lower() in (b'burp-tool', b'x-burp-tool', b'tool', b'x-tool') for name, _ in headers)
    with sqlite3.connect(path) as conn:
        assert len(conn.execute('PRAGMA table_info(ACTIVITY)').fetchall()) == 8
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [('ACTIVITY',)]


@pytest.mark.parametrize('random_timing', [True, False])
async def test_explicit_send_tag_covers_redirect_hops_and_timing_branches(server, tmp_path, random_timing):
    url, _ = server
    path = tmp_path / 'tags.sqlite'
    await logged([LeviosaRequest('GET', url + '/redirect', [], [])], path,
                 Config(tool='Scanner', follow_redirects=True, random_timing=random_timing), tool='Intruder')
    assert [row['BURP_TOOL'] for row in read_rows(path)] == ['Intruder', 'Intruder']


@pytest.mark.parametrize('flags,config_text,expected_message', [
    (['--human-mode', '--human-timing-min', '0', '--human-timing-max', '0'], '', 'human mode:'),
    (['--human-timing-min', '0', '--human-timing-max', '0'], '', 'human mode:'),
    ([], '[timing]\nhuman=true\nhuman_min=0\nhuman_max=0\n', 'human mode:'),
    (['--no-human-mode'], '[timing]\nhuman=true\n', None),
    (['--human-mode', '--random-timing', '--random-timing-min', '0', '--random-timing-max', '0'], '', 'random timing:'),
    (['--human-mode', '--no-random-timing', '--human-timing-min', '0', '--human-timing-max', '0'],
     '[timing]\nrandom=true\n', 'human mode:'),
    (['--no-human-mode', '--human-timing-min', '0', '--human-timing-max', '0'], '', None),
])
async def test_cli_timing_configuration_and_precedence(server, tmp_path, flags, config_text, expected_message):
    import asyncio
    import sys
    from pathlib import Path
    url, _ = server
    path = tmp_path / 'human.sqlite'
    inputs = tmp_path / 'urls.txt'
    inputs.write_text(url + '/first\n' + url + '/second\n')
    (tmp_path / 'leviosa.toml').write_text(config_text)
    script = Path(__file__).resolve().parent.parent / 'leviosa.py'
    process = await asyncio.create_subprocess_exec(
        sys.executable, str(script), str(inputs), '--no-proxy', '--log-db', str(path), '--verbose', *flags,
        cwd=tmp_path, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    assert process.returncode == 0, stderr.decode()
    if expected_message:
        assert expected_message in stderr.decode()
    else:
        assert 'human mode:' not in stderr.decode() and 'random timing:' not in stderr.decode()
    assert [row['BURP_TOOL'] for row in read_rows(path)] == ['Repeater', 'Repeater']
    assert len(stdout.decode().strip().splitlines()) == 2
