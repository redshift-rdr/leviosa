import copy
import json
import socket

import pytest
from aiohttp import web

from core.config import Config
from core.logdb import TrafficLogger
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param, RequestBody
from core.runner import run_modules
from modules.authentication import Authentication


class Reporter:
    def __init__(self):
        self.findings, self.messages = [], []
    def report(self, finding):
        self.findings.append(finding)
    def write(self, message):
        self.messages.append(message)


def context():
    return LeviosaContext(reporter=Reporter())


def seed(url='https://app.test/api/login'):
    return LeviosaRequest('POST', url, ['Authorization: Bearer session-secret', 'Cookie: sid=before'], [],
                          body=RequestBody('json', {'username': 'alice', 'password': 'Known-password-123', 'csrf': 'keep'}))


def module(risky=False, args=()):
    instance = Authentication()
    instance.setup((['--risky', '--login-success-text', 'authenticated=true'] if risky else []) + list(args))
    return instance


async def probes(instance=None, req=None, ctx=None):
    return list(await (instance or module()).mutate([req or seed()], ctx or context()))


async def test_default_never_submits_captured_login_credentials():
    req = seed('https://app.test/api/login?username=alice&password=Known-password-123')
    original = copy.deepcopy(req)
    variants = await probes(req=req)
    assert len(variants) == 1
    page = variants[0]
    assert page.method == 'GET' and page.url == 'https://app.test/api/login'
    assert page.headers == [] and page.params == [] and page.body is None
    assert 'alice' not in repr(page) and 'Known-password-123' not in repr(page)
    assert req == original


@pytest.mark.parametrize('path', ['/profile', '/admin', '/authz', '/password/reset', '/register', '/logout', '/login/history'])
async def test_non_login_endpoints_skipped(path):
    assert await probes(req=seed('https://app.test' + path)) == []


async def test_custom_endpoint_and_field_detection():
    instance = module(True, ['--login-path', '^/custom$', '--login-user-field', 'credentials/id', '--login-password-field', 'credentials/secret'])
    req = seed('https://app.test/custom')
    req.body.value = {'credentials': {'id': 'alice', 'secret': 'Known-password-123'}}
    variants = await probes(instance, req)
    assert len(variants) > 10
    assert any(v.body and v.body.value['credentials'].get('secret') == '' for v in variants)


@pytest.mark.parametrize('kind', ['json', 'form', 'raw-json', 'raw-form'])
async def test_risky_fields_mutated_and_original_preserved(kind):
    req = seed()
    if kind == 'form':
        req.body = None
        req.params = [Param('form', 'username', 'alice'), Param('form', 'password', 'Known-password-123'), Param('form', 'csrf', 'keep')]
    elif kind == 'raw-json':
        req.headers.append('Content-Type: application/json')
        req.body = RequestBody('raw', json.dumps(req.body.value))
    elif kind == 'raw-form':
        req.headers.append('Content-Type: application/x-www-form-urlencoded')
        req.body = RequestBody('raw', b'username=alice&password=Known-password-123&csrf=keep')
    original = copy.deepcopy(req)
    variants = await probes(module(True), req)
    labels = {v.metadata['authentication']['probe'] for v in variants}
    assert {'baseline', 'invalid-account', 'empty-password', 'missing-password', 'known-user-wrong-password',
            'sql-authentication-bypass', 'password-guess', 'default-credentials', 'repeated-failure'} <= labels
    if kind in {'json', 'raw-json'}:
        assert 'nosql-authentication-bypass' in labels
    assert req == original
    assert len({v.request_id for v in variants}) == len(variants)
    assert all(v.metadata.get('leviosa.redact_traffic') for v in variants if v.metadata['authentication']['probe'] != 'page')


async def test_bounded_requests_and_deduplication():
    instance = module(True, ['--login-max-attempts', '3'])
    req = seed()
    variants = list(await instance.mutate([req, req], context()))
    assert [v.metadata['authentication']['probe'] for v in variants] == ['page', 'baseline', 'invalid-account', 'known-user-wrong-password']


async def test_page_form_transport_cookie_and_disclosure_findings_redact_secrets():
    instance = module()
    ctx = context()
    page = (await probes(req=seed('http://app.test/login?password=secret')))[0]
    body = b'<form action="http://other.test/login"><input name="password" type="text"></form>Traceback (most recent call last):'
    response = LeviosaResponse(200, {'Set-Cookie': 'sid=session-secret; Path=/'}, body, page)
    await instance.analyze_one(response, ctx)
    observations = '\n'.join(f.observation for f in ctx.reporter.findings)
    assert all(text in observations for text in ['unencrypted HTTP', 'query parameters', 'does not use POST', 'not HTTPS', 'different origin', 'not masked', 'CSRF', 'missing Secure', 'internal errors'])
    assert all('secret' not in repr(finding) for finding in ctx.reporter.findings)


async def test_success_comparison_and_explicit_enumeration():
    instance = module(True)
    ctx = context()
    variants = {req.metadata['authentication']['probe']: req for req in await probes(instance)}
    for name, status, body in [('baseline', 200, b'authenticated=true'),
                               ('invalid-account', 401, b'unknown user'),
                               ('known-user-wrong-password', 401, b'wrong password'),
                               ('empty-password', 200, b'authenticated=true')]:
        await instance.analyze_one(LeviosaResponse(status, {}, body, variants[name]), ctx)
    await instance.finalize(ctx)
    output = '\n'.join(f.observation for f in ctx.reporter.findings)
    assert 'Possible authentication weakness: empty-password' in output
    assert 'possible account enumeration' in output
    assert ctx.state == {}
    assert 'Known-password-123' not in repr(ctx.reporter.findings)
    assert 'alice' not in repr(ctx.reporter.findings)


@pytest.mark.parametrize('baseline_status,baseline_body,negative_status,negative_body', [
    (401, b'denied', 401, b'denied'),
    (200, b'authenticated=true', 200, b'authenticated=true'),
    (200, b'authenticated=true', 500, b'error'),
    (200, b'authenticated=true', 429, b'too many attempts'),
])
async def test_bad_controls_do_not_claim_bypass(baseline_status, baseline_body, negative_status, negative_body):
    instance, ctx = module(True), context()
    variants = {req.metadata['authentication']['probe']: req for req in await probes(instance)}
    for name, status, body in [('baseline', baseline_status, baseline_body), ('invalid-account', negative_status, negative_body), ('empty-password', 200, b'authenticated=true')]:
        await instance.analyze_one(LeviosaResponse(status, {}, body, variants[name]), ctx)
    await instance.finalize(ctx)
    assert not any('Possible authentication weakness' in f.observation for f in ctx.reporter.findings)


def test_risky_requires_success_signal_and_password_file_is_gated(tmp_path):
    instance = Authentication()
    for args in [['--risky'], ['--login-passwords', str(tmp_path / 'passwords')], ['--login-max-attempts', '1'], ['--login-path', '[']]:
        with pytest.raises(ValueError):
            instance.setup(args)
    path = tmp_path / 'passwords'
    path.write_text('candidate1\ncandidate2\ncandidate3\n')
    instance.setup(['--risky', '--login-success-text', 'ok', '--login-passwords', str(path), '--login-max-attempts', '2'])
    assert instance.passwords == ['candidate1', 'candidate2']


def test_redirect_success_signal():
    instance = Authentication()
    instance.setup(['--risky', '--login-success-location', r'^/account(?:/|$)'])
    assert instance.success(LeviosaResponse(302, {'Location': '/account/home'}, b'', seed()))
    assert not instance.success(LeviosaResponse(302, {'Location': '/login'}, b'', seed()))
    assert not instance.success(LeviosaResponse(200, {'Location': '/account/home'}, b'', seed()))


@pytest.mark.parametrize('preview', [0, 5])
@pytest.mark.parametrize('stop', ['429', '423', 'locked', 'retry-after', 'page-429', 'baseline-failed'])
async def test_real_login_server_sequential_stop_and_redacted_traffic(tmp_path, stop, preview):
    attempts, methods = [], []
    async def handler(req):
        methods.append(req.method)
        if req.method == 'GET':
            return web.Response(status=429 if stop == 'page-429' else 200, text='login')
        body = await req.json()
        attempts.append(body)
        if len(attempts) == 1:
            return web.Response(text='denied' if stop == 'baseline-failed' else 'authenticated=true')
        if len(attempts) == 2:
            return web.Response(status=401, text='unknown user')
        if stop == 'locked':
            return web.Response(status=200, text='account is locked')
        if stop == 'retry-after':
            return web.Response(status=200, headers={'Retry-After': '60'}, text='slow down')
        return web.Response(status=int(stop), text='denied')
    app = web.Application()
    app.router.add_route('*', '/login', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    url = f'http://127.0.0.1:{sock.getsockname()[1]}/login'
    logger = TrafficLogger(str(tmp_path / 'traffic.db'))
    try:
        await web.SockSite(runner, sock).start()
        ctx = context()
        instance = module(True)
        req = seed(url)
        await run_modules([instance], lambda: iter([req]), Config(concurrency=20, no_proxy=True), ctx, logger, repeater_preview=preview)
        expected = 0 if stop == 'page-429' else 1 if stop == 'baseline-failed' else 3
        assert len(attempts) == expected
        assert methods == ['GET'] + ['POST'] * expected
        rows = logger.conn.execute('SELECT REQUEST_RAW, RESPONSE_RAW FROM ACTIVITY').fetchall()
        assert all(row == ('[redacted test exchange]', '[redacted test exchange]') for row in rows[1:])
        assert 'Known-password-123' not in repr(rows)
        assert 'alice' not in repr(ctx.reporter.findings)
    finally:
        logger.close()
        await runner.cleanup()
        sock.close()


def test_loader_and_sequential_request_contract():
    from core.loader import load_modules
    instance, = load_modules(['authentication'])
    assert isinstance(instance, Authentication)
    assert instance.max_concurrency == 1
    assert instance.store_response_cookies is False
    assert instance.follow_redirects is False


@pytest.mark.parametrize('risky,vulnerable', [(False, True), (True, False), (True, True)])
async def test_real_login_success_comparison_and_safe_default(tmp_path, risky, vulnerable):
    posts = []
    async def handler(req):
        if req.method == 'GET':
            return web.Response(text='<form method="post"><input name="username"><input type="password" name="password"><input type="hidden" name="csrf"></form>')
        body = await req.json()
        posts.append(body)
        if body.get('username') != 'alice':
            return web.Response(status=401, text='unknown user')
        secret = body.get('password')
        if secret == 'Known-password-123' or vulnerable and secret == '':
            return web.Response(text='authenticated=true', headers={'Cache-Control': 'no-store'})
        return web.Response(status=401, text='wrong password')
    app = web.Application()
    app.router.add_route('*', '/login', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    url = f'http://127.0.0.1:{sock.getsockname()[1]}/login'
    try:
        await web.SockSite(runner, sock).start()
        instance, ctx = module(risky), context()
        await run_modules([instance], lambda: iter([seed(url)]), Config(concurrency=20, no_proxy=True), ctx)
        weaknesses = [f.observation for f in ctx.reporter.findings if 'Possible authentication weakness' in f.observation]
        assert bool(weaknesses) is (risky and vulnerable)
        assert bool(posts) is risky
        assert len(posts) <= 30
    finally:
        await runner.cleanup()
        sock.close()


async def test_password_acceptance_of_incorrect_password_is_flagged():
    instance, ctx = module(True), context()
    variants = {req.metadata['authentication']['probe']: req for req in await probes(instance)}
    for name, body in [('baseline', b'authenticated=true'), ('invalid-account', b'unknown user'), ('known-user-wrong-password', b'authenticated=true')]:
        await instance.analyze_one(LeviosaResponse(200, {}, body, variants[name]), ctx)
    await instance.finalize(ctx)
    assert any('Possible authentication weakness: known-user-wrong-password' in f.observation for f in ctx.reporter.findings)


async def test_authenticated_session_rotation_and_password_reflection_are_redacted():
    instance, ctx = module(True), context()
    baseline = next(req for req in await probes(instance) if req.metadata['authentication']['probe'] == 'baseline')
    await instance.analyze_one(LeviosaResponse(200, {'Set-Cookie': 'sid=before; Secure; HttpOnly; SameSite=Lax'},
                                             b'authenticated=true Known-password-123', baseline), ctx)
    output = '\n'.join(f.observation for f in ctx.reporter.findings)
    assert 'Session cookie unchanged' in output
    assert 'Submitted password appears' in output
    assert 'Known-password-123' not in repr(ctx.reporter.findings)


async def test_transport_failure_stops_active_generation():
    instance, ctx = module(True), context()
    stream = iter(await instance.mutate([seed()], ctx))
    page = next(stream)
    await instance.analyze_one(LeviosaResponse(0, {}, b'', page), ctx)
    assert list(stream) == []


async def test_repeated_module_runs_do_not_share_private_state():
    instance = module()
    req = seed()
    one, two = await probes(instance, req), await probes(instance, req)
    assert len(one) == len(two) == 1


async def test_lockout_stops_later_captures_of_other_login_methods():
    instance, ctx = module(True), context()
    first = seed()
    second = seed()
    second.method = 'GET'
    stream = iter(await instance.mutate([first, second], ctx))
    page = next(stream)
    await instance.analyze_one(LeviosaResponse(200, {}, b'login form', page), ctx)
    baseline = next(stream)
    await instance.analyze_one(LeviosaResponse(200, {}, b'authenticated=true', baseline), ctx)
    negative = next(stream)
    await instance.analyze_one(LeviosaResponse(429, {}, b'too many attempts', negative), ctx)
    assert list(stream) == []


def test_scan_flag_preflight(tmp_path):
    from core.scans import read_scan, prepare_scan, scan_config
    from core.options import ValidationParser
    path = tmp_path / 'scan.toml'
    path.write_text('target="https://app.test/login"\nlog_enabled=false\n'
                    '[[steps]]\nmodule="authentication"\n'
                    'args=["--risky", "--login-success-text", "authenticated=true"]\n')
    definition = read_scan(str(path))
    plan = prepare_scan(definition, scan_config(definition, Config()), ValidationParser(add_help=False))
    assert plan.steps[0].module.risky
