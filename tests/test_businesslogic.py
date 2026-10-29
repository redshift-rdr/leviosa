import copy
import json
from urllib.parse import parse_qsl, urlsplit

import pytest
from aiohttp import web

from core.config import Config
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param, RequestBody
from core.runner import run_modules
from modules.businesslogic import BusinessLogic, inputs, mutate_input


class Reporter:
    def __init__(self):
        self.findings = []
    def report(self, finding):
        self.findings.append(finding)
    def write(self, message):
        pass


def context():
    return LeviosaContext(reporter=Reporter())


def seed():
    return LeviosaRequest('POST', 'https://app.test/orders', ['Content-Type: application/json', 'Content-Length: 100'], [],
                          body=RequestBody('json', {'items': [{'quantity': 2}], 'total': 20, 'csrf': 'keep'}))


async def variants(req=None, module=None):
    return list(await (module or BusinessLogic()).mutate([req or seed()], context()))


async def test_skips_unrelated_requests():
    req = LeviosaRequest('GET', 'https://app.test/?q=search', [], [])
    assert await variants(req) == []


async def test_baseline_boundaries_omission_and_immutability():
    req = seed()
    original = copy.deepcopy(req)
    probes = await variants(req)
    assert probes[0].body.value == original.body.value
    assert len(probes) == 11  # baseline and five probes for each numeric field
    assert len({p.request_id for p in probes}) == len(probes)
    assert all(p.seed_id == req.seed_id for p in probes)
    assert all(p.body.value['csrf'] == 'keep' for p in probes)
    assert any(p.body.value['items'][0].get('quantity') == -1 for p in probes)
    assert any('quantity' not in p.body.value['items'][0] for p in probes)
    assert req == original
    assert all('Content-Length: 100' not in p.headers for p in probes[1:])


@pytest.mark.parametrize('location', ['url', 'query', 'form', 'json', 'nested-param'])
async def test_supported_locations_and_duplicates(location):
    req = LeviosaRequest('POST', 'https://app.test/order', [], [])
    if location == 'url':
        req.url += '?quantity=2&quantity=3&csrf=keep'
    elif location == 'nested-param':
        req.params = [Param('json', 'order', {'quantity': 2})]
    else:
        req.params = [Param(location, 'quantity', 2 if location == 'json' else '2')]
    original = copy.deepcopy(req)
    probes = await variants(req)
    assert len(probes) > 1
    assert req == original
    duplicates = [p for p in probes[1:] if p.metadata['businesslogic']['operation'] == 'duplicate']
    if location == 'url':
        assert len(duplicates) == 2
        pairs = parse_qsl(urlsplit(duplicates[0].url).query)
        assert pairs == [('quantity', '2'), ('quantity', '-1'), ('quantity', '3'), ('csrf', 'keep')]
    elif location in {'query', 'form'}:
        assert duplicates[0].params[0].value == '2'
        assert duplicates[0].params[1].value == '-1'
    else:
        assert not duplicates


async def test_flags_workflow_and_invalid_coupon_probes():
    req = seed()
    req.body.value = {'isAdmin': False, 'status': 'pending', 'coupon': 'WELCOME'}
    probes = await variants(req)
    assert any(p.body.value.get('isAdmin') is True for p in probes)
    assert any(p.body.value.get('status') == 'approved' for p in probes)
    assert any(p.body.value.get('coupon') == 'LEVIOSA_INVALID_COUPON' for p in probes)


async def test_probe_cap_and_lazy_inputs():
    module = BusinessLogic()
    module.setup(['--logic-max-probes', '2'])
    def requests():
        yield seed()
        raise AssertionError('Must not eagerly drain seeds')
    probes = iter(await module.mutate(requests(), context()))
    assert len([next(probes) for _ in range(3)]) == 3


def rule():
    return {'method': 'POST', 'url': 'https://app.test/orders', 'location': 'json',
            'parameter': 'items/0/quantity', 'values': [-1, 0], 'omit': True, 'success_text': 'order_id'}


def configured(tmp_path, rules=None):
    path = tmp_path / 'rules.json'
    path.write_text(json.dumps(rules if rules is not None else [rule()]))
    module = BusinessLogic()
    module.setup(['--logic-rules', str(path)])
    return module


async def test_rules_only_target_matching_endpoint_and_input(tmp_path):
    module = configured(tmp_path)
    probes = await variants(module=module)
    assert len(probes) == 4
    assert all(p.body.value['total'] == 20 for p in probes)
    assert await variants(LeviosaRequest('GET', 'https://app.test/other', [], []), module) == []


@pytest.mark.parametrize('baseline_status,baseline_body,probe_status,probe_body,expected', [
    (200, b'order_id=1', 200, b'order_id=2', True),
    (401, b'order_id', 200, b'order_id', False),
    (200, b'login', 200, b'order_id', False),
    (200, b'order_id', 200, b'validation failed', False),
    (200, b'order_id', 400, b'order_id', False),
    (200, b'order_id', 0, b'order_id', False),
    (200, b'order_id', 302, b'order_id', False),
])
async def test_rule_reporting_out_of_order(tmp_path, baseline_status, baseline_body, probe_status, probe_body, expected):
    module = configured(tmp_path)
    probes = await variants(module=module)
    ctx = context()
    await module.analyze_one(LeviosaResponse(probe_status, {}, probe_body, probes[1]), ctx)
    await module.analyze_one(LeviosaResponse(baseline_status, {}, baseline_body, probes[0]), ctx)
    await module.finalize(ctx)
    assert bool(ctx.reporter.findings) == expected
    assert ctx.state == {}
    if expected:
        finding = ctx.reporter.findings[0]
        assert finding.confidence == 'indicator'
        assert finding.evidence['value'] == -1
        assert finding.evidence['parameter'] == 'items/0/quantity'


async def test_missing_baseline_and_default_observation():
    module = BusinessLogic()
    probes = await variants()
    ctx = context()
    await module.analyze_one(LeviosaResponse(200, {}, b'ok', probes[1]), ctx)
    await module.finalize(ctx)
    assert ctx.reporter.findings == []
    await module.analyze_one(LeviosaResponse(200, {}, b'ok', probes[1]), ctx)
    await module.analyze_one(LeviosaResponse(200, {}, b'ok', probes[0]), ctx)
    await module.finalize(ctx)
    assert ctx.reporter.findings[0].confidence == 'observation'


@pytest.mark.parametrize('change', [{'success_text': ''}, {'location': 'cookie'}, {'duplicate': True},
                                    {'values': []}, {'values': [float('nan')]}, {'values': [{}]}, {'omit': 1}])
def test_rule_validation(tmp_path, change):
    with pytest.raises(ValueError):
        configured(tmp_path, [rule() | change])


def test_json_paths_escaped_and_nested_array_omission():
    req = seed()
    req.body.value = {'a/b': {'~key': [1, 2]}}
    targets = list(inputs(req))
    assert targets[0]['parameter'] == 'a~1b/~0key/0'
    mutated = mutate_input(req, targets[0], 'omit', None)
    assert mutated.body.value == {'a/b': {'~key': [2]}}
    assert req.body.value == {'a/b': {'~key': [1, 2]}}


@pytest.mark.parametrize('value,encoded', [(True, 'true'), (None, 'null')])
def test_non_json_values_are_transport_safe(value, encoded):
    req = LeviosaRequest('POST', 'https://app.test/', [], [Param('form', 'quantity', '2')])
    target = next(inputs(req))
    assert mutate_input(req, target, 'replace', value).params[0].value == encoded


def test_loader_options_and_paths():
    from core.loader import load_modules
    module, = load_modules(['businesslogic'])
    assert isinstance(module, BusinessLogic)
    assert module.path_options == {'--logic-rules': 'file'}
    with pytest.raises(ValueError):
        module.setup(['--logic-max-probes', '0'])
    with pytest.raises(ValueError):
        module.setup(['--logic-success-text', ''])


@pytest.mark.parametrize('vulnerable', [False, True])
async def test_real_server_rejection_rule(tmp_path, vulnerable):
    import socket
    arrivals = []
    async def handler(req):
        body = await req.json()
        arrivals.append(body)
        quantity = body.get('items', [{}])[0].get('quantity')
        accepted = vulnerable or isinstance(quantity, int) and quantity > 0
        # Deliberately return 200 for application-level rejection too.
        return web.json_response({'order_id': 'test-order'} if accepted else {'error': 'invalid quantity'})
    app = web.Application()
    app.router.add_post('/orders', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    url = f'http://127.0.0.1:{sock.getsockname()[1]}/orders'
    try:
        await web.SockSite(runner, sock).start()
        module = configured(tmp_path, [rule() | {'url': url}])
        req = seed()
        req.url = url
        req.headers = ['Content-Type: application/json']
        ctx = context()
        await run_modules([module], lambda: iter([req]), Config(no_proxy=True), ctx)
        assert len(arrivals) == 4
        assert len(ctx.reporter.findings) == (3 if vulnerable else 0)
    finally:
        await runner.cleanup()
        sock.close()


async def test_bracket_form_field_names():
    req = LeviosaRequest('POST', 'https://app.test/order', [], [Param('form', 'items[0][quantity]', '2')])
    assert len(await variants(req)) == 7


async def test_global_success_marker_rejects_generic_200():
    module = BusinessLogic()
    module.setup(['--logic-success-text', 'order-created'])
    probes = await variants(module=module)
    ctx = context()
    await module.analyze_one(LeviosaResponse(200, {}, b'order-created', probes[0]), ctx)
    await module.analyze_one(LeviosaResponse(200, {}, b'validation failed', probes[1]), ctx)
    await module.finalize(ctx)
    assert ctx.reporter.findings == []
