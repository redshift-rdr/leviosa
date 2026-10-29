from copy import deepcopy
from dataclasses import replace

import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param, RequestBody
from modules.jwt import JWT, build, discover, substitute, unpack, decode


def token(key=b'secret'):
    return build({'alg': 'HS256', 'typ': 'JWT'}, {'sub': 'user', 'exp': 2000000000, 'aud': 'app', 'iss': 'issuer'}, key)


def seed(value=None):
    return LeviosaRequest('GET', 'https://example.test/private', ['Authorization: Bearer ' + (value or token())], [])


async def variants(req=None, module=None):
    return list(await (module or JWT()).mutate([req or seed()], LeviosaContext()))


async def test_skips_non_jwts_and_bad_json():
    for value in ('opaque', 'abc.def.ghi', 'e30.e30.', 'a.b.c.d.e'):
        assert await variants(seed(value)) == []


@pytest.mark.parametrize('location', ['header', 'cookie', 'header-param', 'query', 'query-param', 'json', 'form', 'body', 'raw'])
def test_discovery_and_replacement(location):
    value = token()
    req = replace(seed(), headers=[])
    if location == 'header':
        req.headers = ['Authorization: Bearer ' + value]
    elif location == 'cookie':
        req.headers = ['Cookie: session=' + value + '; csrf=untouched']
    elif location in {'header-param', 'query-param'}:
        req.params = [Param(location.split('-')[0], 'token', value)]
    elif location == 'query':
        req.url += '?token=' + value + '&x=1'
    elif location in {'json', 'form'}:
        req.params = [Param(location, 'token', value)]
    elif location == 'body':
        req.body = RequestBody('json', {'nested': [value]})
    elif location == 'raw':
        req.body = RequestBody('raw', ('{"token":"' + value + '"}').encode())
    original = deepcopy(req)
    assert list(discover(req)) == [value]
    mutated = substitute(req, value, token(b'other'))
    assert list(discover(mutated)) == [token(b'other')]
    assert req == original


async def test_probes_and_signed_claim_mutations():
    req = seed()
    original = deepcopy(req)
    probes = await variants(req)
    by_name = {p.metadata['jwt']['probe']: p for p in probes}
    assert {'baseline', 'invalid-token', 'invalid-signature', 'empty-signature', 'alg-none', 'embedded-jwk',
            'expired-claim', 'future-nbf', 'wrong-audience', 'wrong-issuer'} <= by_name.keys()
    assert req == original
    assert len({p.request_id for p in probes}) == len(probes)
    module = JWT()
    for name in ('expired-claim', 'future-nbf', 'wrong-audience', 'wrong-issuer'):
        value = next(iter(discover(by_name[name])))
        header, _ = unpack(value)
        assert module.signing_key(value, header) == b'secret'
    value = next(iter(discover(by_name['invalid-signature'])))
    assert module.signing_key(value, unpack(value)[0]) is None


async def test_unknown_key_does_not_claim_claim_enforcement_tests():
    probes = await variants(seed(token(b'long-random-unlisted-key')))
    assert 'expired-claim' not in {p.metadata['jwt']['probe'] for p in probes}


async def test_multiple_occurrences_replaced_together_and_distinct_tokens_separate():
    req = seed()
    req.params = [Param('cookie', 'session', token()), Param('query', 'other', token(b'other'))]
    probes = await variants(req)
    assert sum(p.metadata['jwt']['probe'] == 'baseline' for p in probes) == 2
    invalid = next(p for p in probes if p.metadata['jwt']['probe'] == 'invalid-token')
    assert token() not in invalid.headers[0]
    assert invalid.params[0].value == 'leviosa-invalid-token'
    assert invalid.params[1].value == token(b'other')


@pytest.mark.parametrize('baseline_status,control_status,control_body,probe_body,expected', [
    (200, 401, b'denied', b'protected', True),
    (200, 200, b'protected', b'protected', False),
    (200, 0, b'', b'protected', False),
    (200, 500, b'error', b'protected', False),
    (401, 401, b'denied', b'protected', False),
    (200, 401, b'denied', b'different', False),
])
async def test_controlled_comparison_out_of_order(baseline_status, control_status, control_body, probe_body, expected, capsys):
    module = JWT()
    context = LeviosaContext()
    probes = {p.metadata['jwt']['probe']: p for p in await variants()}
    for name, status, body in [('alg-none', 200, probe_body), ('invalid-token', control_status, control_body),
                                ('baseline', baseline_status, b'protected')]:
        await module.analyze_one(LeviosaResponse(status, {}, body, probes[name]), context)
    capsys.readouterr()
    await module.finalize(context)
    output = capsys.readouterr().out
    assert bool(output) == expected
    assert token() not in output
    assert context.state == {}


async def test_missing_control_suppresses_bypass(capsys):
    module = JWT()
    context = LeviosaContext()
    probes = {p.metadata['jwt']['probe']: p for p in await variants()}
    for name in ('baseline', 'alg-none'):
        await module.analyze_one(LeviosaResponse(200, {}, b'protected', probes[name]), context)
    capsys.readouterr()
    await module.finalize(context)
    assert capsys.readouterr().out == ''


async def test_public_key_confusion(tmp_path):
    key_file = tmp_path / 'public.pem'
    key_file.write_bytes(b'public key bytes\n')
    module = JWT()
    module.setup(['--jwt-public-key', str(key_file)])
    unsigned = build({'alg': 'RS256'}, {'sub': 'user'}) + 'YWJj'
    probes = await variants(seed(unsigned), module)
    req = next(p for p in probes if p.metadata['jwt']['probe'] == 'algorithm-confusion')
    forged = next(iter(discover(req)))
    module.secrets = [key_file.read_bytes()]
    assert module.signing_key(forged, unpack(forged)[0]) == key_file.read_bytes()


def test_loader_and_invalid_options():
    from core.loader import load_modules
    assert isinstance(load_modules(['jwt'])[0], JWT)
    with pytest.raises(ValueError):
        JWT().setup(['--jwt-success-text', ' '])


async def test_success_marker_allows_dynamic_response_bodies(capsys):
    module = JWT()
    module.setup(['--jwt-success-text', 'account-data'])
    context = LeviosaContext()
    probes = {p.metadata['jwt']['probe']: p for p in await variants()}
    for name, status, body in [('baseline', 200, b'account-data nonce=1'),
                                ('invalid-token', 401, b'denied'),
                                ('alg-none', 200, b'account-data nonce=2')]:
        await module.analyze_one(LeviosaResponse(status, {}, body, probes[name]), context)
    capsys.readouterr()
    await module.finalize(context)
    assert 'Possible validation weakness: alg-none' in capsys.readouterr().out


def test_custom_secret_wordlist(tmp_path):
    path = tmp_path / 'secrets.txt'
    path.write_text('custom-secret\n')
    module = JWT()
    module.setup(['--jwt-secrets', str(path)])
    value = token(b'custom-secret')
    assert module.signing_key(value, unpack(value)[0]) == b'custom-secret'
    assert module.signing_key(token(), unpack(token())[0]) is None
