import asyncio
from contextlib import aclosing
import json
import socket

import pytest
from aiohttp import web

from core.config import Config
from core.logdb import TrafficLogger
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, Param
from core.options import ValidationParser
from core.requester import send
from core.runner import run_modules
from core.scanoutput import ScanReporter
from core.scans import prepare_scan, read_scan, run_scan, scan_config
from core.tooltags import BurpTool
from leviosa import build_parser
from modules.base import BaseModule


class Events:
    def __init__(self):
        self.events = []
        self.findings = []

    def emit(self, event):
        self.events.append(event)

    def report(self, finding):
        self.findings.append(finding)

    def write(self, message):
        pass


class Logger:
    def __init__(self):
        self.records = []

    def log(self, response, *, tool):
        self.records.append((response.request.url, str(tool)))


def seeds(count=8):
    return [LeviosaRequest('GET', f'http://app.test/{i}', [], []) for i in range(count)]


def plan(tmp_path, settings='', steps='[[steps]]\nmodule="securityheaders"\n'):
    (tmp_path / 'requests.json').write_text(json.dumps([
        {'method': 'GET', 'url': req.url} for req in seeds()]))
    path = tmp_path / 'scan.toml'
    path.write_text('target="requests.json"\nno_proxy=true\nlog_enabled=false\n' + settings + steps)
    definition = read_scan(str(path))
    return prepare_scan(definition, scan_config(definition, Config()),
                        ValidationParser(add_help=False, parents=[build_parser()], allow_abbrev=False))


@pytest.fixture
def transport(monkeypatch):
    records = {'starts': [], 'sessions': [], 'active': 0, 'maximum': {}, 'ends': []}

    async def request(session, req, config, read_body, proxy, auth, capture):
        category = req.metadata.get('leviosa.tool', 'normal')
        records['starts'].append((req.url, category))
        records['sessions'].append(session)
        records['active'] += 1
        records['maximum'][category] = max(records['maximum'].get(category, 0), records['active'])
        await asyncio.sleep(0)
        records['active'] -= 1
        records['ends'].append(req.url)
        return LeviosaResponse(200, {}, b'body', req)

    monkeypatch.setattr('core.requester._send_one', request)
    return records


async def test_configured_default_previews_first_five_then_resumes_with_no_duplicates(tmp_path, transport):
    prepared = plan(tmp_path)
    events, logger = Events(), Logger()
    outcome = await run_scan(prepared, output=ScanReporter(events, events), logger=logger)
    assert outcome.completed == 1
    assert [tag for _, tag in logger.records] == ['Repeater'] * 5 + ['Scanner'] * 3
    assert len({url for url, _ in logger.records}) == 8
    assert transport['maximum']['Repeater'] == 1
    assert transport['maximum']['Scanner'] == 3
    assert len({id(session) for session in transport['sessions']}) == 1
    findings = [event for event in events.events if event['event'] == 'finding']
    assert all(event['tool'] == ('Repeater' if int(event['url'].rsplit('/', 1)[1]) < 5 else 'Scanner') for event in findings)
    assert next(event for event in events.events if event['event'] == 'step_started')['repeater_preview'] == 5


async def test_root_step_override_and_disable_reset_for_each_step(tmp_path, transport):
    prepared = plan(tmp_path, 'repeater_preview=2\n', '''[[steps]]
module="securityheaders"
[[steps]]
module="securityheaders"
tool="Intruder"
repeater_preview=1
[[steps]]
module="securityheaders"
repeater_preview=0
''')
    logger, events = Logger(), Events()
    await run_scan(prepared, output=ScanReporter(events, events), logger=logger)
    tags = [tag for _, tag in logger.records]
    assert tags[:8] == ['Repeater'] * 2 + ['Scanner'] * 6
    assert tags[8:16] == ['Repeater'] + ['Intruder'] * 7
    assert tags[16:] == ['Scanner'] * 8


@pytest.mark.parametrize('count', [0, 2, 5, 100])
async def test_short_empty_and_already_repeater_batches(count, transport):
    for requests in ([], seeds(2)):
        logger = Logger()
        replies = [resp async for resp in send(requests, Config(), tool='Intruder', logger=logger, repeater_preview=count)]
        assert len(replies) == len(requests)
        assert [tag for _, tag in logger.records] == ['Repeater'] * min(count, len(requests)) + ['Intruder'] * max(0, len(requests) - count)
    logger = Logger()
    replies = [resp async for resp in send(seeds(3), Config(), tool='Repeater', logger=logger, repeater_preview=count)]
    assert len(replies) == 3
    assert [tag for _, tag in logger.records] == ['Repeater'] * 3


class Probe(BaseModule):
    tool = BurpTool.SCANNER

    def __init__(self):
        self.analyzed = []
        self.finalized = 0
        self.mutated = 0

    async def mutate(self, requests, context):
        self.mutated += 1
        return iter(requests)

    async def analyze_one(self, response, context):
        context.state['count'] = context.state.get('count', 0) + 1
        self.analyzed.append(response.request)

    async def finalize(self, context):
        self.finalized += 1
        assert context.state['count'] == 8


async def test_single_module_lifecycle_source_identity_and_direct_runner_default(transport):
    original = seeds()
    module = Probe()
    await run_modules([module], lambda: iter(original), Config(concurrency=3), LeviosaContext(), repeater_preview=3)
    assert module.mutated == module.finalized == 1
    assert {req.request_id for req in module.analyzed} == {req.request_id for req in original}
    assert all(req.metadata == {} for req in original)
    transport['starts'].clear()
    await run_modules([Probe()], lambda: seeds(), Config(), LeviosaContext())
    assert {category for _, category in transport['starts']} == {'normal'}


@pytest.mark.parametrize('value', ['-1', 'true', '1.5', '"5"'])
@pytest.mark.parametrize('location', ['root', 'step'])
def test_invalid_counts_rejected_before_scan_execution(tmp_path, value, location):
    settings = f'repeater_preview={value}\n' if location == 'root' else ''
    steps = '[[steps]]\nmodule="securityheaders"\n' + (f'repeater_preview={value}\n' if location == 'step' else '')
    with pytest.raises(ValueError, match='repeater_preview'):
        plan(tmp_path, settings, steps)


async def test_invalid_sender_count_does_not_consume_source():
    def source():
        raise AssertionError('input consumed')
        yield
    with pytest.raises(ValueError, match='repeater_preview'):
        async for _ in send(source(), Config(), repeater_preview=True):
            pass


async def test_human_pacing_stops_after_preview_and_normal_concurrency_returns(monkeypatch, transport):
    class Pacer:
        def __init__(self):
            self.waits = self.ends = 0

        async def wait(self, *args):
            self.waits += 1

        def completed(self):
            self.ends += 1

    pacer = Pacer()
    replies = [r async for r in send(seeds(), Config(human_mode=True, concurrency=3),
                                    tool='Intruder', repeater_preview=3, pacer=pacer)]
    assert pacer.waits == pacer.ends == 3
    assert transport['maximum'] == {'Repeater': 1, 'Intruder': 3}
    assert len(replies) == 8


async def test_random_timing_has_one_delay_per_gap_across_transition(monkeypatch, transport):
    delays = []

    async def sleep(delay):
        delays.append(delay)

    monkeypatch.setattr('core.requester.random.uniform', lambda lo, hi: 2)
    # Patch the module's asyncio binding so fake transport can still yield.
    import types
    import core.requester as requester
    monkeypatch.setattr(requester, 'asyncio', types.SimpleNamespace(
        sleep=sleep, TimeoutError=asyncio.TimeoutError))
    replies = [r async for r in send(seeds(4), Config(random_timing=True), tool='Intruder', repeater_preview=2)]
    assert len(replies) == 4
    assert delays == [2, 2, 2]


async def test_closing_during_preview_does_not_start_normal_phase(transport):
    async with aclosing(send(seeds(), Config(), tool='Intruder', repeater_preview=2)) as stream:
        await anext(stream)
    assert len(transport['starts']) == 1
    assert transport['sessions'][0].closed


async def test_real_http_cookies_redirects_and_database_tags_survive_transition(tmp_path):
    observed = []

    async def handler(req):
        observed.append((req.path, req.cookies.get('session')))
        if req.path == '/0':
            reply = web.Response(status=302, headers={'Location': '/final'})
            reply.set_cookie('session', 'preview-session')
            return reply
        return web.Response(text='ok')

    app = web.Application()
    app.router.add_get('/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    await web.SockSite(runner, sock).start()
    path = tmp_path / 'traffic.sqlite'
    logger = TrafficLogger(str(path))
    try:
        requests = [LeviosaRequest('GET', f'http://localhost:{port}/{i}', [], []) for i in range(3)]
        replies = [r async for r in send(requests, Config(follow_redirects=True, concurrency=1),
                                         tool='Intruder', repeater_preview=1, logger=logger)]
        assert len(replies) == 3
        assert observed == [('/0', None), ('/final', 'preview-session'), ('/1', 'preview-session'), ('/2', 'preview-session')]
        rows = logger.conn.execute('SELECT BURP_TOOL FROM ACTIVITY ORDER BY rowid').fetchall()
        assert rows == [('Repeater',), ('Repeater',), ('Intruder',), ('Intruder',)]
    finally:
        logger.close()
        await runner.cleanup()
        sock.close()


async def test_payload_baseline_analysis_spans_preview_and_normal_phase(tmp_path, monkeypatch):
    prepared = plan(tmp_path, steps='[[steps]]\nmodule="commandinjection"\n')
    # Supply one injectable request; built-ins yield a baseline plus 12 payloads.
    prepared.source = lambda: [LeviosaRequest('GET', 'http://app.test/', [], [
        Param('query', 'host', 'localhost')])]

    async def request(session, req, config, read_body, proxy, auth, capture):
        _, location, _, _, marker, _ = req.metadata['commandinjection']
        return LeviosaResponse(200, {}, marker.encode() if location else b'baseline', req)

    monkeypatch.setattr('core.requester._send_one', request)
    events = Events()
    outcome = await run_scan(prepared, output=ScanReporter(events, events))
    assert outcome.completed == 1
    findings = [event for event in events.events if event['event'] == 'finding']
    assert len(findings) == 12
    assert [event['tool'] for event in findings] == ['Repeater'] * 4 + ['Intruder'] * 8
