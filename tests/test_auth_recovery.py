"""Authentication recovery must pause before dispatch and verify new credentials."""
import socket
from dataclasses import replace

import pytest
from aiohttp import web

from core.auth import AuthGuard, AuthenticationStopped
from core.config import Config, load_config
from core.models import LeviosaRequest, LeviosaResponse, LeviosaContext, Param
from core.requester import send
from core.runner import run_modules
from core.logdb import TrafficLogger
from modules.passthrough import PassthroughModule


def request(url='https://example.test/private', mechanism='bearer', value='old'):
    if mechanism == 'cookies':
        return LeviosaRequest('GET', url, ['Cookie: session=' + value], [Param('cookie', 'session', value)])
    return LeviosaRequest('GET', url, ['Authorization: Bearer ' + value], [])


def config(url='https://example.test', **kwargs):
    return Config(auth_check=True, auth_check_url=url + '/health', auth_success_text='authenticated',
                  auth_check_interval=1, no_proxy=True, **kwargs)


@pytest.fixture
async def site():
    state = {'credential': 'old', 'arrivals': [], 'expire': True, 'health_status': None, 'health_marker': True}
    async def handler(req):
        credential = req.headers.get('Authorization', '').removeprefix('Bearer ') or req.cookies.get('session')
        state['arrivals'].append((req.path, credential))
        if req.path == '/health':
            if state['health_status'] is not None:
                return web.Response(status=state['health_status'], headers={'Location': '/login'})
            if credential != state['credential']:
                return web.Response(text='login', status=200)
            return web.Response(text='authenticated' if state['health_marker'] else 'login')
        if req.path == '/denied':
            return web.Response(status=403)
        status = 200 if credential == state['credential'] else 401
        if state['expire']:
            state['credential'] = 'fresh'
            state['expire'] = False
        return web.Response(status=status, text='scan')
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    url = f'http://127.0.0.1:{sock.getsockname()[1]}'
    try:
        await web.SockSite(runner, sock).start()
        yield url, state
    finally:
        await runner.cleanup()
        sock.close()


@pytest.mark.parametrize('mechanism', ['cookies', 'bearer'])
async def test_pause_retry_verify_and_resume(site, mechanism, tmp_path):
    url, state = site
    req = request(url + '/private', mechanism)
    cfg = config(url)
    pasted = iter(['session=bad', 'Cookie: session=fresh'] if mechanism == 'cookies' else ['Bearer bad', 'Authorization: Bearer fresh'])
    messages = []
    def prompt(label):
        # No next scan request may have been sent while credentials are invalid.
        assert sum(path == '/private' for path, _ in state['arrivals']) == 1
        assert mechanism == 'cookies' and 'Cookie:' in label or mechanism == 'bearer' and 'Bearer' in label
        return next(pasted)
    guard = AuthGuard(cfg, prompt=prompt, write=messages.append)
    logger = TrafficLogger(str(tmp_path / 'traffic.db'))
    try:
        responses = [r async for r in send([req, req, req], cfg, auth_guard=guard, logger=logger)]
        rows = logger.conn.execute("SELECT TARGET_URL, REQUEST_RAW, RESPONSE_RAW FROM ACTIVITY").fetchall()
        assert all(raw == '[redacted test exchange]' and body == '[redacted test exchange]'
                   for target, raw, body in rows if target.endswith('/health'))
    finally:
        logger.close()
    assert [r.status for r in responses] == [200, 200, 200]
    assert [value for path, value in state['arrivals'] if path == '/private'] == ['old', 'fresh', 'fresh']
    assert any('did not authenticate' in message for message in messages)
    assert req == request(url + '/private', mechanism)


async def test_expected_probe_denial_does_not_prompt(site):
    url, state = site
    cfg = config(url)
    guard = AuthGuard(cfg, prompt=lambda _: pytest.fail('Unexpected refresh prompt'))
    req = request(url + '/denied')
    responses = [r async for r in send([req], cfg, auth_guard=guard)]
    assert responses[0].status == 403
    assert [path for path, _ in state['arrivals']] == ['/health', '/denied', '/health']


async def test_ignore_continues_without_further_checks(site):
    url, state = site
    state['credential'] = 'different'
    cfg = config(url)
    guard = AuthGuard(cfg, prompt=lambda _: ':ignore', write=lambda _: None)
    responses = [r async for r in send([request(url + '/private')] * 2, cfg, auth_guard=guard)]
    assert len(responses) == 2
    assert [path for path, _ in state['arrivals']].count('/health') == 1


@pytest.mark.parametrize('action', [':abort', 'eof'])
async def test_abort_or_eof_stops_before_scan_request(site, action):
    url, state = site
    state['credential'] = 'different'
    cfg = config(url)
    def prompt(_):
        if action == 'eof':
            raise EOFError
        return action
    guard = AuthGuard(cfg, prompt=prompt, write=lambda _: None)
    with pytest.raises(AuthenticationStopped):
        _ = [r async for r in send([request(url + '/private')], cfg, auth_guard=guard)]
    assert [path for path, _ in state['arrivals']] == ['/health']


async def test_refresh_persists_between_modules(site):
    url, state = site
    cfg = config(url)
    guard = AuthGuard(cfg, prompt=lambda _: 'fresh', write=lambda _: None)
    req = request(url + '/private')
    await run_modules([PassthroughModule(), PassthroughModule()], lambda: iter([req]), cfg, LeviosaContext(), auth_guard=guard)
    assert [value for path, value in state['arrivals'] if path == '/private'] == ['old', 'fresh']


def test_refresh_preserves_identity_mutations_and_origin():
    cfg = config()
    guard = AuthGuard(cfg)
    req = request()
    guard.bind(req)
    guard.bearer = 'fresh'
    guard.bearer_history.add('fresh')
    updated = guard.apply(req)
    assert updated.headers == ['Authorization: Bearer fresh']
    assert updated.request_id == req.request_id
    assert guard.apply(request(value='attack')).headers == ['Authorization: Bearer attack']
    assert guard.apply(request('https://other.test/private')).headers == ['Authorization: Bearer old']
    assert guard.apply(replace(req, headers=[])).headers == []


def test_cookie_refresh_covers_raw_and_structured_header_locations():
    guard = AuthGuard(config(auth_mechanism='cookies'))
    req = request(mechanism='cookies')
    req.params.append(Param('header', 'Cookie', 'session=old; unrelated=keep'))
    guard.bind(req)
    guard.cookies = {'session': 'fresh', 'unrelated': 'keep', 'newcookie': 'new'}
    guard.cookie_history.update(guard.cookies.items())
    updated = guard.apply(req)
    assert updated.headers == ['Cookie: session=fresh']
    assert updated.params[0].value == 'fresh'
    assert updated.params[1].value == 'session=fresh; unrelated=keep'
    assert any(p.name == 'newcookie' and p.value == 'new' for p in updated.params)
    assert guard.apply(request(mechanism='cookies', value='donor')).headers == ['Cookie: session=donor']


def test_cli_and_config_options(tmp_path):
    from leviosa import build_parser, _apply_cli
    path = tmp_path / 'leviosa.toml'
    path.write_text('[auth]\nenabled=true\nurl="https://example.test/health"\nsuccess_text="authenticated"\nmechanism="cookies"\ninterval=5\n')
    cfg = load_config(str(path))
    cfg.validate_auth()
    assert cfg.auth_check and cfg.auth_check_interval == 5
    parser = build_parser()
    args, _ = parser.parse_known_args(['https://example.test', '--no-auth-check', '--auth-check-interval', '2'])
    _apply_cli(cfg, args, parser)
    assert cfg.auth_check is False and cfg.auth_check_interval == 2


@pytest.mark.parametrize('kwargs', [dict(auth_check_url=None), dict(auth_check_interval=0),
    dict(auth_success_text=''), dict(auth_check_url='https://user:pass@example.test/health'),
    dict(auth_check_url='https://example.test/health#frag'), dict(auth_mechanism='basic')])
def test_invalid_configuration(kwargs):
    cfg = config()
    for name, value in kwargs.items():
        setattr(cfg, name, value)
    with pytest.raises(ValueError):
        cfg.validate_auth()


@pytest.mark.parametrize('action', ['fresh', ':abort'])
async def test_scan_steps_share_refresh_and_abort_stops_later_steps(site, monkeypatch, action):
    from core.scans import PreparedScan, PreparedStep, run_scan
    url, state = site
    cfg = config(url)
    req = request(url + '/private')
    if action == ':abort':
        state['credential'] = 'different'
    monkeypatch.setattr('getpass.getpass', lambda _: action)
    steps = [PreparedStep(i, f'step-{i}', PassthroughModule(), cfg, 0) for i in (1, 2)]
    plan = PreparedScan('auth-test', url, lambda: iter([req]), cfg, steps, None)
    if action == ':abort':
        with pytest.raises(AuthenticationStopped):
            await run_scan(plan)
        assert [path for path, _ in state['arrivals']] == ['/health']
    else:
        outcome = await run_scan(plan)
        assert outcome.completed == 2
        assert [value for path, value in state['arrivals'] if path == '/private'] == ['old', 'fresh']


async def test_interval_and_disabled_behavior(site):
    url, state = site
    state['expire'] = False
    cfg = config(url)
    cfg.auth_check_interval = 2
    req = request(url + '/private')
    _ = [r async for r in send([req] * 3, cfg)]
    assert [path for path, _ in state['arrivals']] == ['/health', '/private', '/private', '/health', '/private']
    state['arrivals'].clear()
    _ = [r async for r in send([req] * 2, replace(cfg, auth_check=False))]
    assert [path for path, _ in state['arrivals']] == ['/private', '/private']


@pytest.mark.parametrize('status', [302, 500, 0])
async def test_unverified_replacements_keep_prompting(status):
    cfg = config()
    pasted = iter(['bad', ':ignore'])
    messages = []
    guard = AuthGuard(cfg, prompt=lambda _: next(pasted), write=messages.append)
    guard.bind(request())
    async def check(req):
        return LeviosaResponse(status, {'Location': '/login'}, b'authenticated', req)
    await guard.ensure(check)
    assert guard.ignored
    assert guard.bearer == 'old'
    assert any('did not authenticate' in message for message in messages)


def test_scan_file_auth_settings_and_cli_precedence(tmp_path):
    from core.scans import read_scan, scan_config
    from leviosa import build_parser, _apply_cli
    path = tmp_path / 'scan.toml'
    path.write_text('auth_check=true\nauth_check_url="https://example.test/health"\n'
                    'auth_success_text="authenticated"\nauth_check_interval=4\n'
                    '[[steps]]\nmodule="passthrough"\n')
    cfg = scan_config(read_scan(str(path)), Config())
    cfg.validate_auth()
    assert cfg.auth_check and cfg.auth_check_interval == 4
    parser = build_parser()
    args, _ = parser.parse_known_args(['--scan', str(path), '--auth-check-interval', '1'])
    _apply_cli(cfg, args, parser, ['passthrough'])
    assert cfg.auth_check_interval == 1


async def test_original_credentials_found_after_unauthenticated_seed(site):
    url, state = site
    state['expire'] = False
    cfg = config(url)
    req = request(url + '/private')
    anonymous = replace(req, headers=[])
    guard = AuthGuard(cfg, prompt=lambda _: pytest.fail('Healthy session must not prompt'))
    await run_modules([PassthroughModule()], lambda: iter([anonymous, req]), cfg, LeviosaContext(), auth_guard=guard)
    assert guard.bound
    assert [value for path, value in state['arrivals'] if path == '/private'] == [None, 'old']


def test_health_uses_effective_cookie_precedence():
    guard = AuthGuard(config(auth_mechanism='cookies'))
    req = request(mechanism='cookies', value='structured')
    req.headers = ['Cookie: session=raw']
    req.params.append(Param('header', 'Cookie', 'session=header-param; csrf=token'))
    guard.bind(req)
    assert guard.cookies == {'session': 'structured', 'csrf': 'token'}
