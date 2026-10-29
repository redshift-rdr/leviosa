from copy import deepcopy

import pytest

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, RequestBody
from modules.errordisclosure import ErrorDisclosure, disclosures


def seed():
    return LeviosaRequest('POST', 'http://example.test/api?id=1&id=2', [], [],
                          body=RequestBody('json', {'user': {'id': 1}}))


async def probes(request=None):
    return list(await ErrorDisclosure().mutate([request or seed()], LeviosaContext()))


async def test_mutations_and_immutability():
    req = seed()
    original = deepcopy(req)
    variants = await probes(req)
    assert req == original
    assert variants[0].metadata['errordisclosure']['technique'] == 'baseline'
    assert len({v.request_id for v in variants}) == len(variants)
    assert all(v.seed_id == req.seed_id for v in variants)
    assert any(v.body.value == {'user': {'id': []}} for v in variants if v.body.kind == 'json')
    assert any(v.metadata['errordisclosure']['technique'] == 'malformed-json' for v in variants)
    query = [v for v in variants if v.metadata['errordisclosure']['location'] == 'query']
    assert any('id=1&' in v.url for v in query)
    assert any('&id=2' in v.url for v in query)


@pytest.mark.parametrize('body,signature', [
    (b'Traceback (most recent call last):', 'python-traceback'),
    (b'System.NullReferenceException: failed', 'dotnet-error'),
    (b'SQLSTATE[42000]', 'sql-error'),
    (b'at com.example.Foo(Foo.java:42)', 'java-trace'),
    (b'failed in /var/www/app', 'path-disclosure'),
])
def test_signatures(body, signature):
    assert signature in disclosures(body)


def test_technology_names_and_generic_errors_are_not_disclosure():
    assert disclosures(b'Welcome to our Django, ASP.NET and PostgreSQL guide. Internal Server Error') == {}


@pytest.mark.parametrize('baseline,probe,status,expected', [
    (b'ok', b'Traceback (most recent call last):', 200, True),
    (b'Traceback (most recent call last):', b'Traceback (most recent call last):', 500, False),
    (b'ok', b'Internal Server Error', 500, False),
    (b'ok', b'Traceback (most recent call last):', 0, False),
])
async def test_baseline_comparison_out_of_order(baseline, probe, status, expected, capsys):
    module = ErrorDisclosure()
    variants = await probes()
    context = LeviosaContext()
    await module.analyze_one(LeviosaResponse(status, {}, probe, variants[1]), context)
    await module.analyze_one(LeviosaResponse(200, {}, baseline, variants[0]), context)
    await module.finalize(context)
    output = capsys.readouterr().out
    assert bool(output) == expected
    if expected:
        assert 'python-traceback' in output
    assert context.state == {}


async def test_failed_baseline_does_not_claim_induced_disclosure(capsys):
    module = ErrorDisclosure()
    variants = await probes()
    context = LeviosaContext()
    await module.analyze_one(LeviosaResponse(500, {}, b'SQLSTATE[42000]', variants[1]), context)
    await module.analyze_one(LeviosaResponse(0, {}, b'', variants[0]), context)
    await module.finalize(context)
    assert capsys.readouterr().out == ''


def test_setup_validation_and_loading():
    from core.loader import load_modules
    assert isinstance(load_modules(['errordisclosure'])[0], ErrorDisclosure)
    with pytest.raises(ValueError):
        ErrorDisclosure().setup(['--error-disclosure-path-length', '0'])
