import html
import json
from dataclasses import replace
from urllib.parse import parse_qsl, urlsplit

import pytest
from aioresponses import CallbackResult, aioresponses
from multidict import CIMultiDict

from core.config import Config
from core.headers import parse_headers
from core.loader import load_modules
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param, RequestBody
from core.probes import input_variants
from core.runner import run_modules
from modules.authz import Authz
from modules.idor import Idor
from modules.openredirect import OpenRedirect
from modules.sessioncookies import SessionCookies
from modules.xss import ReflectedXss


class Reporter:
    def __init__(self):
        self.findings = []
        self.lines = []

    def report(self, finding):
        self.findings.append(finding)

    def write(self, line):
        self.lines.append(line)


def context():
    return LeviosaContext(reporter=Reporter())


def request(**kwargs):
    return LeviosaRequest(**({'method': 'GET', 'url': 'https://app.test/', 'headers': [], 'params': []} | kwargs))


def response(req, body=b'', headers=None, status=200):
    return LeviosaResponse(status, headers or {}, body, req)


@pytest.mark.parametrize('name,kind', [('sessioncookies', SessionCookies), ('openredirect', OpenRedirect),
                                      ('xss', ReflectedXss), ('idor', Idor)])
def test_new_modules_discoverable(name, kind):
    assert isinstance(load_modules([name])[0], kind)


def test_mutation_preserves_duplicates_blank_values_and_seed():
    seed = request(url='https://app.test/?next=a&next=b&empty=', params=[Param('form', 'q', 'old')])
    variants = list(input_variants(seed, 'new'))
    assert len(variants) == 4
    assert parse_qsl(urlsplit(variants[1][2].url).query, keep_blank_values=True) == [('next', 'a'), ('next', 'new'), ('empty', '')]
    assert seed.params[0].value == 'old'
    assert seed.url.endswith('next=a&next=b&empty=')


def test_nested_json_body_mutation_is_independent():
    seed = request(body=RequestBody('json', {'items': [{'id': 1}], 'q': 'old'}))
    variants = list(input_variants(seed, 'probe'))
    assert [name for _, name, _ in variants] == ['items/0/id', 'q']
    assert variants[0][2].body.value == {'items': [{'id': 'probe'}], 'q': 'old'}
    assert variants[1][2].body.value == {'items': [{'id': 1}], 'q': 'probe'}
    assert seed.body.value['items'][0]['id'] == 1


@pytest.mark.parametrize('value,expected', [
    ('sid=secret; Secure; HttpOnly; SameSite=Lax; Path=/account', []),
    ('sid=secret; Path=/', ['missing Secure', 'missing HttpOnly', 'missing explicit SameSite']),
    ('sid=secret; SameSite=None', ['SameSite=None without Secure']),
    ('sid=secret; SameSite=invalid', ['invalid SameSite']),
    ('__Host-sid=secret; Secure; Domain=app.test; Path=/x', ['__Host- requires Path=/ and no Domain']),
    ('__Secure-sid=secret; HttpOnly', ['invalid secure cookie prefix']),
])
async def test_cookie_attributes_and_secret_redaction(value, expected):
    module = SessionCookies()
    module.setup(['--session-cookie', 'sid'])
    ctx = context()
    await module.analyze_one(response(request(), headers={'Set-Cookie': value}), ctx)
    issues = [issue for f in ctx.reporter.findings for issue in f.evidence['issues']]
    assert all(issue in issues for issue in expected)
    if not expected:
        assert not issues
    assert 'secret' not in repr(ctx.reporter.findings)


async def test_cookies_repeat_headers_and_do_not_assume_session_names():
    module, ctx = SessionCookies(), context()
    headers = CIMultiDict([('Set-Cookie', 'theme=dark; Secure'), ('Set-Cookie', 'lang=en; Secure')])
    await module.analyze_one(response(request(), headers=headers), ctx)
    assert not ctx.reporter.findings
    module.setup(['--session-cookie', 'theme', '--session-cookie', 'lang'])
    await module.analyze_one(response(request(), headers=headers), ctx)
    assert {f.evidence['cookie'] for f in ctx.reporter.findings} == {'theme', 'lang'}


async def test_sensitive_cookie_over_http():
    module, ctx = SessionCookies(), context()
    module.setup(['--session-cookie', 'sid'])
    await module.analyze_one(response(request(url='http://app.test/'), headers={'Set-Cookie': 'sid=x; Secure; HttpOnly; SameSite=Lax'}), ctx)
    assert 'session cookie set over HTTP' in ctx.reporter.findings[0].evidence['issues']


@pytest.mark.parametrize('destination,found', [('payload', True), ('relative-payload', True),
    ('https://safe.test/?next=payload', False), ('/login?next=payload', False),
    ('https://payload.safe.test/', False), ('http://[bad', False)])
async def test_redirect_destination_must_be_actual_external_host(destination, found):
    module, ctx = OpenRedirect(), context()
    variant = list(await module.mutate([request(params=[Param('query', 'next', '/')])], ctx))[0]
    host, _, _, payload = variant.metadata['openredirect']
    if destination == 'payload':
        destination = payload
    elif destination == 'relative-payload':
        destination = '//' + host + '/'
    else:
        destination = destination.replace('payload', host)
    await module.analyze_one(response(variant, status=302, headers={'Location': destination}), ctx)
    assert bool(ctx.reporter.findings) is found


@pytest.mark.parametrize('status', [0, 200, 201, 304, 400, 500])
async def test_redirect_non_redirect_status_is_not_finding(status):
    module, ctx = OpenRedirect(), context()
    variant = list(await module.mutate([request(params=[Param('query', 'next', '/')])], ctx))[0]
    await module.analyze_one(response(variant, status=status, headers={'Location': variant.metadata['openredirect'][3]}), ctx)
    assert not ctx.reporter.findings


@pytest.mark.parametrize('template,media,confidence,expected_context', [
    ('<html>{payload}</html>', 'text/html', 'indicator', 'injected HTML element'),
    ('<html>{escaped}</html>', 'text/html', 'observation', 'HTML text'),
    ('<script>const value="{payload}";</script>', 'text/html', 'indicator', 'script text'),
    ('<button onclick="run(\'{marker}\')">x</button>', 'text/html', 'indicator', 'event handler'),
    ('<a href="/{marker}">x</a>', 'text/html', 'indicator', 'URL attribute'),
    ('<div title="{marker}">x</div>', 'text/html', 'observation', 'HTML attribute'),
    ('{payload}', 'application/json', None, None),
    ('{payload}', 'text/plain', None, None),
    ('<html>nothing reflected</html>', 'text/html', None, None),
])
async def test_xss_contexts_and_encoded_reflection(template, media, confidence, expected_context):
    module, ctx = ReflectedXss(), context()
    variant = list(await module.mutate([request(params=[Param('query', 'q', 'old')])], ctx))[0]
    marker, _, _, payload = variant.metadata['xss']
    body = template.format(payload=payload, escaped=html.escape(payload), marker=marker).encode()
    await module.analyze_one(response(variant, body, {'Content-Type': media}), ctx)
    if confidence is None:
        assert not ctx.reporter.findings
    else:
        finding, = ctx.reporter.findings
        assert finding.confidence == confidence
        assert expected_context in finding.evidence['contexts']
        assert finding.evidence['execution_confirmed'] is False


def donor(tmp_path, name, token):
    path = tmp_path / (name + '.json')
    path.write_text(json.dumps([{'method': 'GET', 'url': 'https://app.test/',
        'headers': ['Authorization: Bearer ' + token, 'X-Tenant-ID: ' + name],
        'params': [{'type': 'cookie', 'name': 'sid', 'value': name}]}]))
    return f'{name}={path}'


async def test_identity_replacement_removes_stale_headers_params_and_cookies(tmp_path):
    module, ctx = Authz(), context()
    module.setup(['--session', donor(tmp_path, 'bob', 'B'), '--anonymous'])
    seed = request(headers=['Authorization: Bearer A', 'Cookie: sid=alice', 'X-Tenant-ID: alice', 'Accept: application/json'],
                   params=[Param('header', 'AUTHORIZATION', 'Bearer A'), Param('cookie', 'sid', 'alice')])
    original, bob, anonymous = list(await module.mutate([seed], ctx))
    headers = parse_headers(bob.headers)
    assert headers['Authorization'] == 'Bearer B'
    assert headers['X-Tenant-ID'] == 'bob'
    assert not any(p.type == 'header' for p in bob.params)
    assert bob.params == [Param('cookie', 'sid', 'bob')]
    assert anonymous.headers == ['Accept: application/json']
    assert anonymous.params == []
    assert seed.headers[0] == 'Authorization: Bearer A'


async def test_compare_body_handles_out_of_order_json_and_empty_responses(tmp_path):
    module, ctx = Authz(), context()
    module.setup(['--session', donor(tmp_path, 'bob', 'B'), '--compare-body'])
    original, bob = list(await module.mutate([request()], ctx))
    await module.analyze_one(response(bob, b'{"b":2,"a":1}'), ctx)
    await module.analyze_one(response(original, b'{ "a": 1, "b": 2 }'), ctx)
    await module.finalize(ctx)
    assert any('matches original normalized body' in line for line in ctx.reporter.lines)
    ctx = context()
    for variant in (original, bob):
        await module.analyze_one(response(variant), ctx)
    await module.finalize(ctx)
    assert not any('matches original' in line for line in ctx.reporter.lines)


@pytest.mark.parametrize('status,body,found', [(200, b'object-alice-42', True), (403, b'object-alice-42', False),
                                           (200, b'login page', False), (0, b'', False)])
async def test_idor_requires_expected_owned_object_evidence(tmp_path, status, body, found):
    rule_path = tmp_path / 'rules.json'
    rule_path.write_text(json.dumps([{'method': 'GET', 'url': 'https://app.test/objects/42',
                                     'allowed': ['alice'], 'contains': 'object-alice-42'}]))
    module, ctx = Idor(), context()
    module.setup(['--session', donor(tmp_path, 'alice', 'A'), '--session', donor(tmp_path, 'bob', 'B'),
                  '--access-rules', str(rule_path)])
    variants = list(await module.mutate([request(url='https://app.test/objects/42'), request(url='https://app.test/public')], ctx))
    assert len(variants) == 3
    bob = variants[-1]
    await module.analyze_one(response(bob, body, status=status), ctx)
    findings = [f for f in ctx.reporter.findings if f.terminal_visible]
    assert bool(findings) is found
    if found:
        assert findings[0].confidence == 'indicator'
        assert findings[0].evidence['marker_matched'] is True


@pytest.mark.parametrize('rules', [{}, [{}], [{'method': 'GET', 'url': 'https://app.test/', 'allowed': ['unknown']}],
    [{'method': 'GET', 'url': 'https://app.test/', 'allowed': ['alice'], 'contains': ''}]])
def test_access_rules_validate_before_sending(tmp_path, rules):
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps(rules))
    with pytest.raises(ValueError):
        Authz().setup(['--session', donor(tmp_path, 'alice', 'A'), '--access-rules', str(path)])


def test_idor_requires_explicit_markers(tmp_path):
    with pytest.raises(ValueError, match='idor requires'):
        Idor().setup(['--session', donor(tmp_path, 'alice', 'A')])


async def test_redirect_probes_never_follow_even_when_global_config_enables_it():
    module, ctx = OpenRedirect(), context()
    config = Config(follow_redirects=True, no_proxy=True)
    seed = request(url='https://app.test/', params=[Param('form', 'next', '/')], method='POST')

    def redirect(url, **kwargs):
        return CallbackResult(status=302, headers={'Location': kwargs['data']['next']})

    with aioresponses() as mocked:
        mocked.post('https://app.test/', callback=redirect, repeat=True)
        await run_modules([module], lambda: [seed], config, ctx)
        assert len(ctx.reporter.findings) == 2
        assert len(mocked.requests) == 1
        assert all(call.kwargs['allow_redirects'] is False
                   for calls in mocked.requests.values() for call in calls)
    assert config.follow_redirects is True


async def test_custom_identity_headers_and_cookie_header_params_are_removed(tmp_path):
    module, ctx = Authz(), context()
    module.setup(['--session', donor(tmp_path, 'bob', 'B'), '--identity-header', 'X-Custom-Auth', '--anonymous'])
    seed = request(headers=['X-Custom-Auth: original'], params=[Param('header', 'Cookie', 'sid=original'),
                                                             Param('header', 'X-Custom-Auth', 'original')])
    _, bob, anonymous = list(await module.mutate([seed], ctx))
    assert not any(p.type == 'header' for p in bob.params + anonymous.params)
    assert 'x-custom-auth' not in parse_headers(bob.headers)
    assert anonymous.params == []


@pytest.mark.parametrize('label', ['(original)', '(anonymous)', ''])
def test_reserved_identity_labels_rejected(tmp_path, label):
    path = donor(tmp_path, 'alice', 'A').split('=', 1)[1]
    with pytest.raises(ValueError, match='labels'):
        Authz().setup(['--session', f'{label}={path}'])


async def test_response_cookie_cannot_contaminate_anonymous_identity(tmp_path):
    from aiohttp import web
    app = web.Application()
    seen = []

    async def handler(req):
        seen.append(dict(req.cookies))
        reply = web.Response(text='ok')
        reply.set_cookie('injected', 'previous-user')
        return reply

    app.router.add_get('/', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        module, ctx = Authz(), context()
        module.setup(['--session', donor(tmp_path, 'bob', 'B'), '--anonymous'])
        seed = request(url=f'http://localhost:{port}/', params=[Param('cookie', 'sid', 'alice')])
        await run_modules([module], lambda: [seed], Config(no_proxy=True, concurrency=1), ctx)
        assert seen == [{'sid': 'alice'}, {'sid': 'bob'}, {}]
    finally:
        await runner.cleanup()
