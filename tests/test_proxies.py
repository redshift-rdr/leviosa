"""Ordered proxy routing, opt-in Burp and per-hop behavior against real listeners."""
import asyncio
import re
import socket
import sqlite3
from dataclasses import replace

import aiohttp
import pytest
from aiohttp import web

from core.config import Config, load_config
from core.logdb import TrafficLogger
from core.models import LeviosaRequest, Param, LeviosaContext
from core.proxies import ProxyRule, load_proxy_file, resolve_proxy, split_proxy_auth
from core.requester import send
from core.runner import run_modules
from modules.passthrough import PassthroughModule


@pytest.fixture
async def listeners():
    arrivals = {'one': [], 'two': [], 'origin': []}
    runners, sockets, addresses = [], [], {}
    def handler(name):
        async def receive(req):
            arrivals[name].append((req.raw_path, req.headers.get('Proxy-Authorization'), req.headers.get('Authorization')))
            await req.read()
            if req.path == '/redirect':
                return web.Response(status=302, headers={'Location': addresses['origin'] + '/final'})
            if req.path == '/redirect-two':
                return web.Response(status=302, headers={'Location': 'http://service.invalid/second'})
            return web.Response(text=name)
        return receive
    try:
        for name in arrivals:
            app = web.Application()
            app.router.add_route('*', '/{path:.*}', handler(name))
            runner = web.AppRunner(app)
            await runner.setup()
            sock = socket.socket()
            sock.bind(('127.0.0.1', 0))
            await web.SockSite(runner, sock).start()
            runners.append(runner)
            sockets.append(sock)
            addresses[name] = f'http://127.0.0.1:{sock.getsockname()[1]}'
        yield addresses, arrivals
    finally:
        for runner in runners:
            await runner.cleanup()
        for sock in sockets:
            sock.close()


def request(url, params=None):
    return LeviosaRequest('GET', url, [], params or [])


async def dispatch(reqs, cfg, **kwargs):
    return [response async for response in send(reqs, cfg, **kwargs)]


def test_default_direct_even_when_module_hints_burp():
    assert resolve_proxy(Config(), True) == (None, None)
    assert resolve_proxy(Config(burp=True), False) == ('http://127.0.0.1:8080', None)


def test_first_enabled_match_direct_exception_and_fallback():
    rules = (ProxyRule('/private', 'http://disabled:9000', enabled=False),
             ProxyRule('/private', None), ProxyRule('example', 'http://specific:9000'),
             ProxyRule('.*', 'http://catchall:9000'))
    cfg = Config(proxy_rules=rules, proxy_url='http://fallback:9000')
    assert resolve_proxy(cfg, url='http://example/private') == (None, None)
    assert resolve_proxy(cfg, url='http://example/path')[0] == 'http://specific:9000'
    assert resolve_proxy(cfg, url='http://other/path')[0] == 'http://catchall:9000'
    assert resolve_proxy(replace(cfg, proxy_rules=()), url='http://other')[0] == 'http://fallback:9000'
    assert resolve_proxy(replace(cfg, burp=True), url='http://example/private')[0] == 'http://127.0.0.1:8080'
    assert resolve_proxy(replace(cfg, burp=True, no_proxy=True), url='http://example') == (None, None)


async def test_routing_rules_and_burp_mode_on_wire(listeners):
    addresses, arrivals = listeners
    cfg = Config(proxy_rules=(ProxyRule('/private', addresses['one']), ProxyRule('.*', addresses['two'])))
    result = await dispatch([request('http://service.invalid/private'), request('http://service.invalid/public')], cfg)
    assert {r.body for r in result} == {b'one', b'two'}
    # Explicit Burp mode overrides every endpoint rule, for raw dispatch too.
    host, port = addresses['one'].removeprefix('http://').split(':')
    cfg = replace(cfg, burp=True, burp_host=host, burp_port=int(port))
    response, = await dispatch([request('http://service.invalid/public')], cfg)
    assert response.body == b'one'
    assert len(arrivals['two']) == 1


async def test_default_passthrough_module_does_not_connect_to_burp(listeners):
    addresses, arrivals = listeners
    await run_modules([PassthroughModule()], lambda: iter([request(addresses['origin'] + '/private')]),
                      Config(burp_port=1), LeviosaContext())
    assert len(arrivals['origin']) == 1
    assert not arrivals['one'] and not arrivals['two']


async def test_prepared_query_parameters_participate_in_regex_matching(listeners):
    addresses, _ = listeners
    cfg = Config(proxy_rules=(ProxyRule(r'\?route=one$', addresses['one']),), proxy_url=addresses['two'])
    response, = await dispatch([request('http://service.invalid/', [Param('query', 'route', 'one')])], cfg)
    assert response.body == b'one'


async def test_redirect_reselects_proxy_and_never_forwards_proxy_credentials_to_origin(listeners, tmp_path):
    addresses, arrivals = listeners
    proxy = addresses['one'].replace('http://', 'http://user:secret@')
    cfg = Config(follow_redirects=True, proxy_url=proxy, proxy_rules=(ProxyRule(re.escape(addresses['origin']), None),))
    logger = TrafficLogger(str(tmp_path / 'traffic.db'))
    try:
        response, = await dispatch([request('http://service.invalid/redirect')], cfg, logger=logger)
        rows = logger.conn.execute('SELECT TARGET_URL, HTTP_STATUS_CODE FROM ACTIVITY ORDER BY rowid').fetchall()
    finally:
        logger.close()
    assert response.body == b'origin'
    assert arrivals['one'][0][1] == aiohttp.BasicAuth('user', 'secret').encode()
    assert arrivals['origin'][0][1] is None
    assert rows == [('http://service.invalid/redirect', '302'), (addresses['origin'] + '/final', '200')]


async def test_redirect_between_two_authenticated_upstreams(listeners):
    addresses, arrivals = listeners
    one = addresses['one'].replace('http://', 'http://first:password@')
    two = addresses['two'].replace('http://', 'http://second:other@')
    cfg = Config(follow_redirects=True, proxy_rules=(ProxyRule('/redirect-two$', one), ProxyRule('/second$', two)))
    response, = await dispatch([request('http://service.invalid/redirect-two')], cfg)
    assert response.body == b'two'
    assert arrivals['one'][0][1] == aiohttp.BasicAuth('first', 'password').encode()
    assert arrivals['two'][0][1] == aiohttp.BasicAuth('second', 'other').encode()


async def test_no_proxy_beats_all_configured_routes(listeners):
    addresses, arrivals = listeners
    cfg = Config(no_proxy=True, burp=True, proxy_rules=(ProxyRule('.*', addresses['one']),), proxy_url=addresses['two'])
    response, = await dispatch([request(addresses['origin'])], cfg)
    assert response.body == b'origin'
    assert not arrivals['one'] and not arrivals['two']


async def test_unreachable_selected_proxy_does_not_fall_back_direct(listeners):
    addresses, arrivals = listeners
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        bad = f'http://127.0.0.1:{sock.getsockname()[1]}'
    response, = await dispatch([request(addresses['origin'])], Config(proxy_rules=(ProxyRule('.*', bad),), timeout=1))
    assert response.status == 0
    assert not arrivals['origin']


def test_file_schema_relative_configuration_and_cli_override(tmp_path):
    from leviosa import build_parser, _apply_cli
    path = tmp_path / 'proxies.toml'
    path.write_text('default_proxy="http://fallback:9000"\n[[rules]]\nendpoint_regex="/direct"\ndirect=true\n'
                    '[[rules]]\nendpoint_regex=".*"\nproxy="http://upstream:9000"\n')
    main = tmp_path / 'leviosa.toml'
    main.write_text('[burp]\nenabled=true\n[proxy]\nconfig_file="proxies.toml"\n')
    cfg = load_config(str(main))
    cfg.validate_proxies()
    assert cfg.proxy_config_path == str(path)
    assert len(cfg.proxy_rules) == 2
    parser = build_parser()
    args, _ = parser.parse_known_args(['http://app.test', '--no-burp', '--proxy', 'http://cli:9000'])
    _apply_cli(cfg, args, parser)
    assert not cfg.burp
    assert cfg.proxy_url == 'http://cli:9000'
    assert resolve_proxy(cfg, url='http://app.test/direct') == (None, None)


@pytest.mark.parametrize('contents', [
    'unknown=true', 'rules=1', 'default_proxy="socks5://host:1080"',
    '[[rules]]\nendpoint_regex="["\ndirect=true',
    '[[rules]]\nendpoint_regex=".*"',
    '[[rules]]\nendpoint_regex=".*"\ndirect=true\nproxy="http://host:9000"',
    '[[rules]]\nendpoint_regex=".*"\nproxy="http://user:secret@host:9000/path"',
    '[[rules]]\nendpoint_regex=".*"\ndirect="yes"',
])
def test_invalid_rules_fail_preflight(tmp_path, contents):
    path = tmp_path / 'proxies.toml'
    path.write_text(contents)
    with pytest.raises(ValueError):
        Config(proxy_config_path=str(path)).validate_proxies()


def test_proxy_auth_ipv6_and_escaped_credentials():
    url, auth = split_proxy_auth('http://user:p%40ss@[::1]:8080')
    assert url == 'http://[::1]:8080'
    assert auth == aiohttp.BasicAuth('user', 'p@ss')


async def test_authentication_checks_use_their_own_endpoint_route(listeners):
    addresses, arrivals = listeners
    cfg = Config(auth_check=True, auth_check_url='http://service.invalid/health', auth_success_text='one',
                 proxy_rules=(ProxyRule('/health$', addresses['one']), ProxyRule('.*', addresses['two'])))
    req = request('http://service.invalid/private')
    req.headers = ['Authorization: Bearer captured-token']
    response, = await dispatch([req], cfg)
    assert response.body == b'two'
    assert len(arrivals['one']) == len(arrivals['two']) == 1
    assert arrivals['one'][0][0] == 'http://service.invalid/health'


def test_scan_relative_proxy_file_and_input_output_collision(tmp_path):
    from core.scans import read_scan, scan_config, prepare_scan
    from core.options import ValidationParser
    proxies = tmp_path / 'proxies.toml'
    proxies.write_text('[[rules]]\nendpoint_regex=".*"\ndirect=true\n')
    scan = tmp_path / 'scan.toml'
    scan.write_text('target="http://service.invalid/"\nproxy_config_path="proxies.toml"\n'
                    'database="proxies.toml"\n[[steps]]\nmodule="passthrough"\n')
    definition = read_scan(str(scan))
    cfg = scan_config(definition, Config())
    assert cfg.proxy_config_path == str(proxies)
    with pytest.raises(ValueError, match='output would overwrite'):
        prepare_scan(definition, cfg, ValidationParser(add_help=False))
    plan = prepare_scan(definition, replace(cfg, log_enabled=False), ValidationParser(add_help=False))
    assert len(plan.config.proxy_rules) == 1


async def test_https_connect_uses_selected_authenticated_proxy(tmp_path):
    import shutil
    import ssl
    import subprocess
    if shutil.which('openssl') is None:
        pytest.skip('openssl needed for the local HTTPS fixture')
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-keyout', str(key), '-out', str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    tunnels, origin_requests, clients = [], [], set()
    async def origin(reader, writer):
        try:
            origin_requests.append(await reader.readuntil(b'\r\n\r\n'))
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecure')
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    secure = await asyncio.start_server(origin, '127.0.0.1', 0, ssl=tls)
    port = secure.sockets[0].getsockname()[1]
    async def pipe(reader, writer):
        try:
            while chunk := await reader.read(65536):
                writer.write(chunk)
                await writer.drain()
        finally:
            writer.close()
    async def proxy(reader, writer):
        task = asyncio.current_task()
        clients.add(task)
        try:
            tunnels.append(await reader.readuntil(b'\r\n\r\n'))
            remote_reader, remote_writer = await asyncio.open_connection('127.0.0.1', port)
            writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
            await writer.drain()
            await asyncio.gather(pipe(reader, remote_writer), pipe(remote_reader, writer))
        finally:
            writer.close()
            await writer.wait_closed()
            clients.discard(task)
    upstream = await asyncio.start_server(proxy, '127.0.0.1', 0)
    proxy_port = upstream.sockets[0].getsockname()[1]
    try:
        cfg = Config(proxy_rules=(ProxyRule('^https://secure.invalid/', f'http://user:secret@127.0.0.1:{proxy_port}'),))
        response, = await dispatch([request('https://secure.invalid/private')], cfg)
        assert response.status == 200 and response.body == b'secure'
        assert tunnels[0].startswith(b'CONNECT secure.invalid:443 HTTP/1.1\r\n')
        assert b'Proxy-Authorization: Basic ' in tunnels[0]
        assert b'Proxy-Authorization:' not in origin_requests[0]
    finally:
        upstream.close()
        secure.close()
        await upstream.wait_closed()
        await secure.wait_closed()
        if clients:
            await asyncio.wait_for(asyncio.gather(*clients), 3)


async def run_cli(directory, *args):
    import sys
    from pathlib import Path
    script = Path(__file__).resolve().parent.parent / 'leviosa.py'
    process = await asyncio.create_subprocess_exec(sys.executable, str(script), *args, cwd=directory,
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        out, err = await asyncio.wait_for(process.communicate(), 8)
        return process.returncode, out.decode(), err.decode()
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


async def test_cli_burp_is_explicit_for_passthrough(listeners, tmp_path):
    addresses, arrivals = listeners
    port = int(addresses['one'].rsplit(':', 1)[1])
    (tmp_path / 'leviosa.toml').write_text(f'[burp]\nport={port}\n')
    code, _, err = await run_cli(tmp_path, addresses['origin'] + '/', '--module', 'passthrough', '--no-log')
    assert code == 0, err
    assert len(arrivals['origin']) == 1 and not arrivals['one']
    code, _, err = await run_cli(tmp_path, addresses['origin'] + '/', '--module', 'passthrough', '--no-log', '--burp')
    assert code == 0, err
    assert len(arrivals['origin']) == len(arrivals['one']) == 1


async def test_cli_rules_file_and_verbose_auth_redaction(listeners, tmp_path):
    addresses, arrivals = listeners
    credential_proxy = addresses['two'].replace('http://', 'http://proxy-user:unique-private-secret@')
    (tmp_path / 'routes.toml').write_text('[[rules]]\nendpoint_regex=".*"\nproxy="' + credential_proxy + '"\n')
    (tmp_path / 'leviosa.toml').write_text('[burp]\nenabled=true\n')
    code, out, err = await run_cli(tmp_path, 'http://service.invalid/', '--proxy-config', 'routes.toml',
                                   '--no-burp', '--no-log', '--verbose')
    assert code == 0 and '200 GET' in out, err
    assert len(arrivals['two']) == 1 and not arrivals['one']
    assert 'unique-private-secret' not in out + err
    assert 'proxy-user' not in out + err
