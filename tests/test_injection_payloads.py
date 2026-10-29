import base64
import html
import asyncio
import json
import re

import pytest
from aiohttp import ClientSession, web

from core.config import Config
from core.headers import parse_headers
from core.loader import load_modules
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param, RequestBody
from core.options import ValidationParser, setup_modules
from core.requester import _request_options
from core.runner import run_modules
from core.scanoutput import ScanReporter
from core.scans import prepare_scan, read_scan
from leviosa import build_parser
from modules.ssti import Ssti
from modules.ssrf import Ssrf
from modules.xxe import Xxe


PASSWD = 'root:x:0:0:root:/root:/bin/bash\n'


class Reporter:
    def __init__(self):
        self.findings, self.events = [], []

    def report(self, finding):
        self.findings.append(finding)

    def write(self, message):
        pass

    def emit(self, event):
        self.events.append(event)


def req(**kwargs):
    return LeviosaRequest(**({'method': 'GET', 'url': 'http://app.test/', 'headers': [],
                             'params': [Param('query', 'input', 'original')]} | kwargs))


def ctx():
    return LeviosaContext(reporter=Reporter())


async def drive(module, namespace, make_body, *, request=None, reverse=False, baseline='', baseline_status=200):
    context = ctx()
    variants = list(await module.mutate([request or req()], context))
    replies = []
    for variant in variants:
        meta = variant.metadata[namespace]
        body = baseline if meta['baseline'] else make_body(meta)
        replies.append(LeviosaResponse(baseline_status if meta['baseline'] else 200, {}, body.encode(), variant))
    for response in reversed(replies) if reverse else replies:
        await module.analyze_one(response, context)
    assert context.state[namespace + '.results'] == {}
    return context, variants


def payload_file(tmp_path, filename, content):
    path = tmp_path / filename
    path.write_text(content)
    return str(path)


@pytest.mark.parametrize('namespace,kind', [('ssti', Ssti), ('ssrf', Ssrf), ('xxe', Xxe)])
def test_modules_discover_and_compose(namespace, kind):
    assert isinstance(load_modules([namespace])[0], kind)
    setup_modules([Ssti(), Ssrf(), Xxe()], [], [], ValidationParser(add_help=False))


@pytest.mark.parametrize('reverse', [False, True])
async def test_ssti_requires_paired_evaluation(reverse):
    module = Ssti()
    context, variants = await drive(module, 'ssti', lambda m: m['expected'] or '', reverse=reverse)
    assert len(context.reporter.findings) == 6
    assert len(variants) == 13
    assert all(len(f.evidence['expected_results']) == 2 for f in context.reporter.findings)
    assert all(f.confidence == 'indicator' for f in context.reporter.findings)


@pytest.mark.parametrize('render', [lambda m: m['payload'], lambda m: html.escape(m['payload']),
    lambda m: m['expected'] if m['arm'] == 0 else 'not evaluated', lambda m: 'template syntax error'])
async def test_ssti_reflection_single_results_and_errors_do_not_flag(render):
    context, _ = await drive(Ssti(), 'ssti', render, reverse=True)
    assert not context.reporter.findings


async def test_ssti_unreachable_baseline_suppresses():
    context, _ = await drive(Ssti(), 'ssti', lambda m: m['expected'], baseline_status=0)
    assert not context.reporter.findings


async def test_ssti_literal_arithmetic_wordlist_and_custom_output(tmp_path):
    module = Ssti()
    module.setup(['--ssti-payloads', payload_file(tmp_path, 'ssti.txt', '{{7*7}}\n')])
    context, variants = await drive(module, 'ssti', lambda m: m['expected'])
    assert len(context.reporter.findings) == 1
    assert '7*7' not in variants[1].metadata['ssti']['payload']
    module.setup(['--ssti-payloads', payload_file(tmp_path, 'custom.txt', '{{custom()}}\n'), '--ssti-marker', 'controlled-result'])
    context, _ = await drive(module, 'ssti', lambda m: 'controlled-result')
    assert len(context.reporter.findings) == 1
    context, _ = await drive(module, 'ssti', lambda m: 'controlled-result', baseline='controlled-result')
    assert not context.reporter.findings


async def test_ssti_preserves_json_inputs_and_keeps_pairs_per_duplicate_field():
    request = req(url='http://app.test/?q=one&q=two', params=[], body=RequestBody('json', {'items': [{'q': 'old'}]}))
    context, variants = await drive(Ssti(), 'ssti', lambda m: m['expected'], request=request, reverse=True)
    assert len(variants) == 1 + 3 * 12
    assert len(context.reporter.findings) == 18
    assert request.metadata == {}
    assert request.body.value == {'items': [{'q': 'old'}]}


@pytest.mark.parametrize('reverse', [False, True])
async def test_ssrf_file_content_and_controlled_markers(tmp_path, reverse):
    module = Ssrf()
    module.setup(['--ssrf-marker', 'controlled-response'])
    context, variants = await drive(module, 'ssrf', lambda m: PASSWD + 'controlled-response', reverse=reverse)
    assert len(variants) == 6  # baseline + five non-callback built-ins
    assert len(context.reporter.findings) == 5
    assert {'unix-passwd', 'custom-marker-1'} == set(context.reporter.findings[0].evidence['signatures'])


@pytest.mark.parametrize('body', ['URL was http://127.0.0.1/', 'Connection refused', 'Internal server error', '200 OK', ''])
async def test_ssrf_errors_and_url_echo_do_not_flag(body):
    context, _ = await drive(Ssrf(), 'ssrf', lambda m: body)
    assert not context.reporter.findings


async def test_ssrf_baseline_and_payload_marker_echo_suppressed(tmp_path):
    module = Ssrf()
    context, _ = await drive(module, 'ssrf', lambda m: PASSWD, baseline=PASSWD, reverse=True)
    assert not context.reporter.findings
    module.setup(['--ssrf-payloads', payload_file(tmp_path, 'urls.txt', 'http://local.test/echo-marker\n'), '--ssrf-marker', 'echo-marker'])
    context, _ = await drive(module, 'ssrf', lambda m: m['payload'])
    assert not context.reporter.findings


@pytest.mark.parametrize('reverse', [False, True])
async def test_xxe_default_file_signatures_and_internal_entity_classification(reverse):
    module = Xxe()
    context, variants = await drive(module, 'xxe', lambda m: m['marker'] if '<!ENTITY left' in m['payload'] else PASSWD, reverse=reverse)
    assert len(variants) == 5
    assert len(context.reporter.findings) == 4
    internal = [f for f in context.reporter.findings if f.evidence['signatures'] == ['internal-entity-expansion']]
    assert len(internal) == 1 and internal[0].confidence == 'observation'
    assert all(f.confidence == 'indicator' for f in context.reporter.findings if f not in internal)


@pytest.mark.parametrize('body', ['XML parse error', 'Entity probe not defined', 'DOCTYPE forbidden', ''])
async def test_xxe_errors_not_findings(body):
    context, _ = await drive(Xxe(), 'xxe', lambda m: body)
    assert not context.reporter.findings


async def test_xxe_base64_external_content_and_baseline(tmp_path):
    module = Xxe()
    module.setup(['--xxe-payloads', payload_file(tmp_path, 'xxe.txt', '<!DOCTYPE r [<!ENTITY p SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><r>&p;</r>\n')])
    encoded = base64.b64encode(PASSWD.encode()).decode()
    context, _ = await drive(module, 'xxe', lambda m: encoded)
    assert context.reporter.findings[0].evidence['signatures'] == ['base64:unix-passwd']
    context, _ = await drive(module, 'xxe', lambda m: encoded, baseline=PASSWD)
    assert not context.reporter.findings


@pytest.mark.parametrize('body', ['<?xml version="1.0"?><root><file>old</file><empty/></root>',
                                '<soap:Envelope xmlns:soap="urn:test"><soap:Body><file>old</file></soap:Body></soap:Envelope>'])
async def test_xxe_preserves_xml_envelope_declaration_and_unmodified_seed(body):
    request = req(method='POST', params=[Param('header', 'Content-Length', '3')],
                  headers=['Content-Type: application/soap+xml', 'Content-Length: 3', 'Digest: stale'],
                  body=RequestBody('raw', body))
    context, variants = await drive(Xxe(), 'xxe', lambda m: PASSWD, request=request)
    assert len(variants) == 1 + 4 * (2 if '<empty/>' in body else 1)
    for variant in variants[1:]:
        assert variant.body.kind == 'raw'
        headers, kwargs = _request_options(variant)
        assert 'Content-Length' not in headers and 'Digest' not in headers
        assert headers['Content-Type'] == 'application/soap+xml'
        assert isinstance(kwargs['data'], bytes)
        text = kwargs['data'].decode()
        if body.startswith('<?xml'):
            assert text.startswith('<?xml version="1.0"?>')
        if 'soap:Envelope' in body:
            assert '<soap:Envelope xmlns:soap="urn:test">' in text
            assert '<!DOCTYPE soap:Envelope' in text or 'xi:include' in text
    assert request.body.value == body and request.headers[1] == 'Content-Length: 3'


async def test_xxe_custom_document_replaces_raw_body_and_escapes_no_payloads(tmp_path):
    document = '<!DOCTYPE root [<!ENTITY p "{left}{right}">]><root>&p;</root>'
    module = Xxe()
    module.setup(['--xxe-payloads', payload_file(tmp_path, 'xxe.txt', document + '\n')])
    request = req(params=[], body=RequestBody('raw', '<original/>'))
    context, variants = await drive(module, 'xxe', lambda m: m['payload'], request=request)
    assert len(variants) == 2
    assert variants[1].body.value.decode().startswith('<!DOCTYPE root')
    assert parse_headers(variants[1].headers)['Content-Type'].startswith('application/xml')
    assert not context.reporter.findings


@pytest.mark.parametrize('namespace,kind,flag', [('ssti', Ssti, '--ssti-payloads'), ('ssrf', Ssrf, '--ssrf-payloads'), ('xxe', Xxe, '--xxe-payloads')])
def test_empty_and_missing_payload_files_rejected(tmp_path, namespace, kind, flag):
    with pytest.raises(ValueError, match='empty'):
        kind().setup([flag, payload_file(tmp_path, 'empty.txt', ' \n\n')])
    with pytest.raises(FileNotFoundError):
        kind().setup([flag, str(tmp_path / 'missing.txt')])


@pytest.mark.parametrize('kind,prefix', [(Ssti, 'ssti'), (Ssrf, 'ssrf'), (Xxe, 'xxe')])
def test_empty_expected_markers_rejected(kind, prefix):
    with pytest.raises(ValueError, match='empty'):
        kind().setup([f'--{prefix}-marker', ' '])


@pytest.mark.parametrize('kind,prefix', [(Ssrf, 'ssrf'), (Xxe, 'xxe')])
@pytest.mark.parametrize('url', ['file:///etc/passwd', 'http://user:pass@listener.test/', 'https://listener.test/#fragment', 'not-a-url'])
def test_callback_validation(kind, prefix, url):
    with pytest.raises(ValueError):
        kind().setup([f'--{prefix}-callback', url])


@pytest.mark.parametrize('kind,prefix', [(Ssrf, 'ssrf'), (Xxe, 'xxe')])
async def test_exact_callback_tokens_old_events_duplicates_and_missing_baseline(tmp_path, kind, prefix):
    path = tmp_path / 'interactions.jsonl'
    path.write_text('{"token":"old-run"}\n')
    module = kind()
    module.setup([f'--{prefix}-callback', 'http://listener.test/callback?a=1', f'--{prefix}-interactions', str(path)])
    context, variants = await drive(module, prefix, lambda m: 'no evidence', baseline_status=0)
    callbacks = [v for v in variants if not v.metadata[prefix]['baseline'] and 'listener.test' in v.metadata[prefix]['payload']]
    assert callbacks
    token = next(iter(module._interactions.pending))
    with path.open('a') as output:
        output.write(json.dumps({'token': token}) + '\n' + json.dumps({'token': token}) + '\n')
    await module.finalize(context)
    assert len(context.reporter.findings) == 1
    assert context.reporter.findings[0].evidence['token'] == token
    assert context.reporter.findings[0].evidence['parameter'] == 'input'
    assert not module._interactions.pending


@pytest.mark.parametrize('kind,prefix', [(Ssrf, 'ssrf'), (Xxe, 'xxe')])
def test_callback_placeholder_and_log_validation(tmp_path, kind, prefix):
    with pytest.raises(ValueError, match='require'):
        kind().setup([f'--{prefix}-payloads', payload_file(tmp_path, 'payloads.txt', '{callback}\n')])
    path = payload_file(tmp_path, 'bad.jsonl', '{"not-token":1}\n')
    with pytest.raises(ValueError, match='token'):
        kind().setup([f'--{prefix}-callback', 'https://listener.test/', f'--{prefix}-interactions', path])


@pytest.mark.parametrize('namespace,payload', [('ssti', '{{{expression}}}'), ('ssrf', 'http://127.0.0.1/'), ('xxe', '<root/>')])
def test_scan_relative_payload_paths(tmp_path, monkeypatch, namespace, payload):
    payload_file(tmp_path, 'payloads.txt', payload + '\n')
    path = tmp_path / 'scan.toml'
    path.write_text(f'target="http://app.test/?input=old"\nlog_enabled=false\n[[steps]]\nmodule="{namespace}"\nargs=["--{namespace}-payloads", "payloads.txt"]\n')
    monkeypatch.chdir(tmp_path.parent)
    plan = prepare_scan(read_scan(str(path)), Config(no_proxy=True),
                        ValidationParser(add_help=False, parents=[build_parser()], allow_abbrev=False))
    assert plan.steps[0].module._payloads == [payload]
    assert plan.steps[0].repeater_preview == 5


async def test_ssrf_real_controlled_fetch_and_interaction_log(tmp_path):
    interactions = tmp_path / 'listener.jsonl'
    interactions.write_text('')

    async def target(request):
        value = request.query['input']
        if value == 'original':
            return web.Response(text='baseline')
        async with ClientSession() as client:
            async with client.get(value) as reply:
                return web.Response(text=await reply.text())

    async def listener(request):
        with interactions.open('a') as output:
            output.write(json.dumps({'token': request.query['leviosa']}) + '\n')
        return web.Response(text='controlled-fetch-body-987')

    app = web.Application()
    app.router.add_get('/target', target)
    app.router.add_get('/listener', listener)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    module = Ssrf()
    module.setup(['--ssrf-payloads', payload_file(tmp_path, 'callbacks.txt', '{callback}\n'),
                  '--ssrf-callback', f'http://127.0.0.1:{port}/listener', '--ssrf-interactions', str(interactions),
                  '--ssrf-marker', 'controlled-fetch-body-987'])
    context = ctx()
    try:
        await run_modules([module], lambda: [req(url=f'http://127.0.0.1:{port}/target')],
                          Config(no_proxy=True), context, repeater_preview=1)
        assert len(context.reporter.findings) == 2
        assert {f.evidence.get('source') for f in context.reporter.findings} == {None, 'interaction-log'}
    finally:
        await runner.cleanup()


@pytest.mark.parametrize('kind,namespace,template', [(Ssrf, 'ssrf', '{callback}'),
    (Xxe, 'xxe', '<!DOCTYPE r [<!ENTITY p SYSTEM "{callback}">]><r>&p;</r>')])
async def test_callback_inputs_get_unique_tokens_and_actual_preview_tags(tmp_path, monkeypatch, kind, namespace, template):
    interactions = tmp_path / 'interactions.jsonl'
    interactions.write_text('')
    module = kind()
    module.setup([f'--{namespace}-payloads', payload_file(tmp_path, 'payloads.txt', template + '\n'),
                  f'--{namespace}-callback', 'https://listener.test/', f'--{namespace}-interactions', str(interactions)])
    tokens = []
    async def send_one(session, request, config, read_body, proxy, auth, capture):
        meta = request.metadata[namespace]
        if not meta['baseline']:
            token = re.search(r'leviosa=([a-f0-9]{32})', meta['payload'])[1]
            tokens.append(token)
            with interactions.open('a') as output:
                output.write(json.dumps({'token': token}) + '\n')
        await asyncio.sleep(0)
        return LeviosaResponse(200, {}, b'no in-band evidence', request)
    monkeypatch.setattr('core.requester._send_one', send_one)
    events = Reporter()
    context = LeviosaContext(reporter=ScanReporter(events, events, {'tool': 'Intruder'}))
    request = req(url='http://app.test/?a=1&a=2', params=[Param('form', 'b', '3')])
    await run_modules([module], lambda: [request], Config(no_proxy=True), context, repeater_preview=2)
    assert len(tokens) == len(set(tokens)) == 3
    findings = [event for event in events.events if event['event'] == 'finding']
    assert [event['tool'] for event in findings] == ['Repeater', 'Intruder', 'Intruder']
    assert [event['evidence']['parameter'] for event in findings] == ['a', 'a', 'b']


async def test_xxe_does_not_inject_into_xml_comments():
    body = '<?xml version="1.0"?><!-- <fake>ignore</fake> --><root><file>old</file></root>'
    context, variants = await drive(Xxe(), 'xxe', lambda m: '', request=req(params=[], body=RequestBody('raw', body)))
    assert len(variants) == 5
    for variant in variants[1:]:
        text = variant.body.value.decode()
        assert '<!-- <fake>ignore</fake> -->' in text
        assert '<!DOCTYPE root' in text or 'xi:include' in text
