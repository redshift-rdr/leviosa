"""Deterministic scheduling checks: no real human-length sleeps in tests."""
import asyncio
from contextlib import aclosing
from dataclasses import replace

import pytest

from core.config import Config, load_config
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from core.requester import send
from core.runner import run_modules
from core.timing import HumanPacer
from core.tooltags import BurpTool
from modules.base import BaseModule

_REAL_SLEEP = asyncio.sleep


class Clock:
    def __init__(self):
        self.now = 100.0
        self.sleeps = []
        self.draws = []

    def monotonic(self):
        return self.now

    def uniform(self, minimum, maximum):
        self.draws.append((minimum, maximum))
        return (minimum + maximum) / 2

    async def sleep(self, delay):
        self.sleeps.append(delay)
        self.now += delay


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr('core.timing.monotonic', clock.monotonic)
    monkeypatch.setattr('core.timing.uniform', clock.uniform)
    monkeypatch.setattr('core.timing.sleep', clock.sleep)
    return clock


@pytest.fixture
def transport(monkeypatch, clock):
    stats = {'active': 0, 'maximum': 0, 'starts': []}

    async def request(session, req, config, read_body, proxy, auth, capture):
        stats['active'] += 1
        stats['maximum'] = max(stats['maximum'], stats['active'])
        stats['starts'].append((req.metadata.get('step', req.url), clock.now))
        await _REAL_SLEEP(0)
        clock.now += req.metadata.get('duration', 1)
        stats['active'] -= 1
        return LeviosaResponse(0 if req.url.endswith('/failed') else 200, {}, b'', req)

    monkeypatch.setattr('core.requester._send_one', request)
    return stats


def seeds(n=3):
    return [LeviosaRequest('GET', f'http://example.test/{i}', [], []) for i in range(n)]


def human_config(**kwargs):
    return Config(human_mode=True, human_timing_min=2, human_timing_max=6, **kwargs)


@pytest.mark.parametrize('tool,expected', [('Repeater', 1), ('Intruder', 3), ('Scanner', 3)])
async def test_only_repeater_is_sequential_and_paced(tool, expected, clock, transport):
    responses = [r async for r in send(seeds(), human_config(concurrency=3), tool=tool)]
    assert len(responses) == 3
    assert transport['maximum'] == expected
    if tool == 'Repeater':
        assert clock.sleeps == [4, 4]
        assert [time for _, time in transport['starts']] == [100, 105, 110]
    else:
        assert clock.sleeps == clock.draws == []


async def test_human_mode_off_keeps_repeater_concurrent(clock, transport):
    await drain(send(seeds(), Config(concurrency=3)))
    assert transport['maximum'] == 3
    assert not clock.sleeps


async def drain(stream):
    return [response async for response in stream]


async def test_fresh_random_interval_per_action(monkeypatch, clock, transport):
    values = iter([2, 6, 3])
    monkeypatch.setattr('core.timing.uniform', lambda lo, hi: next(values))
    await drain(send(seeds(4), human_config()))
    assert clock.sleeps == [2, 6, 3]
    assert [time for _, time in transport['starts']] == [100, 103, 110, 114]


@pytest.mark.parametrize('analysis_time,expected_wait', [(3, [1, 1]), (6, [])])
async def test_analysis_time_counts_towards_interval(clock, transport, analysis_time, expected_wait):
    async for _ in send(seeds(), human_config()):
        clock.now += analysis_time
    assert clock.sleeps == expected_wait


class Step(BaseModule):
    def __init__(self, name, tool, duration=1):
        self.module_name = name
        self.tool = tool
        self.duration = duration

    async def mutate(self, requests, context):
        return (replace(req, metadata={'step': self.module_name, 'duration': self.duration}) for req in requests)


@pytest.mark.parametrize('scan_duration,next_start,waits', [(2, 105, [2]), (20, 121, [])])
async def test_cadence_crosses_modules_and_counts_intervening_scan_time(clock, transport, scan_duration, next_start, waits):
    modules = [Step('first', BurpTool.REPEATER), Step('scan', BurpTool.SCANNER, scan_duration),
               Step('second', BurpTool.REPEATER)]
    await run_modules(modules, lambda: seeds(1), human_config(), LeviosaContext())
    assert transport['starts'] == [('first', 100), ('scan', 101), ('second', next_start)]
    assert clock.sleeps == waits


async def test_each_runner_invocation_has_fresh_cadence(clock, transport):
    config = human_config()
    module = Step('one', BurpTool.REPEATER)
    for _ in range(2):
        await run_modules([module], lambda: seeds(1), config, LeviosaContext())
    assert clock.sleeps == []
    assert transport['starts'] == [('one', 100), ('one', 101)]


async def test_named_tool_override_controls_human_pacing(clock, transport):
    module = Step('scan', BurpTool.SCANNER)
    config = human_config(module_tools={'scan': BurpTool.REPEATER})
    await run_modules([module], seeds, config, LeviosaContext())
    assert transport['maximum'] == 1
    assert clock.sleeps == [4, 4]


async def test_shared_pacer_can_span_direct_send_calls_and_empty_batches(clock, transport):
    pacer = HumanPacer()
    for requests in (seeds(1), [], seeds(1)):
        await drain(send(requests, human_config(), pacer=pacer))
    assert clock.sleeps == [4]
    assert len(clock.draws) == 1


async def test_failed_repeater_request_still_advances_cadence(clock, transport):
    requests = [LeviosaRequest('GET', 'http://example.test/failed', [], []), *seeds(1)]
    responses = await drain(send(requests, human_config()))
    assert [response.status for response in responses] == [0, 200]
    assert clock.sleeps == [4]


@pytest.mark.parametrize('tool', list(BurpTool))
async def test_legacy_random_timing_overrides_human_mode_for_all_tools(monkeypatch, clock, transport, tool):
    monkeypatch.setattr('core.requester.random.uniform', lambda lo, hi: 0.25)
    monkeypatch.setattr('core.requester.asyncio.sleep', clock.sleep)
    config = human_config(random_timing=True, random_timing_min=0.25, random_timing_max=0.25)
    await drain(send(seeds(), config, tool=tool))
    assert transport['maximum'] == 1
    assert clock.sleeps == [0.25, 0.25]
    assert clock.draws == []


async def test_cancellation_during_human_wait_sends_no_next_request(monkeypatch, clock, transport):
    waiting = asyncio.Event()

    async def wait_forever(delay):
        waiting.set()
        await asyncio.Event().wait()

    monkeypatch.setattr('core.timing.sleep', wait_forever)
    async with aclosing(send(seeds(), human_config())) as stream:
        await anext(stream)
        task = asyncio.create_task(anext(stream))
        await asyncio.wait_for(waiting.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert len(transport['starts']) == 1
    assert transport['active'] == 0


@pytest.mark.parametrize('overrides', [
    {'human_timing_min': -1}, {'human_timing_max': float('nan')},
    {'human_timing_min': float('inf')}, {'human_timing_min': 9, 'human_timing_max': 2},
    {'human_timing_min': True}, {'human_timing_max': '8'}, {'human_mode': 'false'},
    {'random_timing_min': -1}, {'random_timing_max': float('inf')},
])
async def test_invalid_timing_fails_before_consuming_source(overrides):
    touched = []

    def source():
        touched.append(True)
        yield from seeds()

    config = Config(**overrides)
    with pytest.raises(ValueError):
        await drain(send(source(), config))
    assert touched == []


def test_toml_human_settings(tmp_path):
    path = tmp_path / 'leviosa.toml'
    path.write_text('[timing]\nhuman=true\nhuman_min=1.5\nhuman_max=4.0\n')
    config = load_config(str(path))
    config.validate_timing()
    assert config.human_mode is True
    assert (config.human_timing_min, config.human_timing_max) == (1.5, 4.0)


@pytest.fixture
async def timed_server():
    import socket
    from time import monotonic
    from aiohttp import web
    stats = {'arrivals': [], 'finished': [], 'active': 0, 'maximum': 0,
             'first': asyncio.Event(), 'three': asyncio.Event(), 'release': asyncio.Event()}

    async def handler(req):
        stats['active'] += 1
        stats['maximum'] = max(stats['maximum'], stats['active'])
        stats['arrivals'].append((req.path, monotonic()))
        stats['first'].set()
        if len(stats['arrivals']) >= 3:
            stats['three'].set()
        try:
            await stats['release'].wait()
            await asyncio.sleep(0.01)
            return web.Response(text='timing test')
        finally:
            stats['active'] -= 1
            stats['finished'].append((req.path, monotonic()))

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    url = f'http://127.0.0.1:{sock.getsockname()[1]}'
    try:
        await web.SockSite(runner, sock).start()
        yield url, stats
    finally:
        stats['release'].set()
        await runner.cleanup()
        sock.close()


@pytest.mark.parametrize('tool,expected', [('Repeater', 1), ('Intruder', 3), ('Scanner', 3)])
async def test_actual_http_concurrency_and_repeater_spacing(timed_server, tool, expected):
    url, stats = timed_server
    requests = [LeviosaRequest('GET', f'{url}/{i}', [], []) for i in range(3)]
    config = Config(human_mode=True, human_timing_min=0.02, human_timing_max=0.03, concurrency=3)
    task = asyncio.create_task(drain(send(requests, config, tool=tool)))
    try:
        await asyncio.wait_for(stats['first' if expected == 1 else 'three'].wait(), 3)
        stats['release'].set()
        responses = await asyncio.wait_for(task, 3)
    finally:
        stats['release'].set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert len(responses) == 3
    assert stats['maximum'] == expected
    if tool == 'Repeater':
        times = [time for _, time in stats['arrivals']]
        assert all(right - left >= 0.02 for left, right in zip(times, times[1:]))


async def test_actual_mixed_module_cadence_and_unchanged_sqlite_schema(timed_server, tmp_path):
    import sqlite3
    from core.logdb import TrafficLogger
    url, stats = timed_server
    stats['release'].set()

    class RealStep(Step):
        async def mutate(self, requests, context):
            count = 3 if self.tool == BurpTool.SCANNER else 1
            return (replace(req, url=f'{req.url}/{self.module_name}/{i}') for req in requests for i in range(count))

    modules = [RealStep('first', BurpTool.REPEATER), RealStep('scan', BurpTool.SCANNER), RealStep('last', BurpTool.REPEATER)]
    path = tmp_path / 'human.sqlite'
    logger = TrafficLogger(str(path))
    try:
        await run_modules(modules, lambda: [LeviosaRequest('GET', url, [], [])],
                          Config(human_mode=True, human_timing_min=0.08, human_timing_max=0.08, concurrency=3),
                          LeviosaContext(), logger)
    finally:
        logger.close()
    arrivals, finished = dict(stats['arrivals']), dict(stats['finished'])
    assert arrivals['/last/0'] - finished['/first/0'] >= 0.08
    assert stats['maximum'] == 3
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [('ACTIVITY',)]
        assert len(conn.execute('PRAGMA table_info(ACTIVITY)').fetchall()) == 8
        assert [row[0] for row in conn.execute('SELECT BURP_TOOL FROM ACTIVITY ORDER BY rowid')] == [
            'Repeater', 'Scanner', 'Scanner', 'Scanner', 'Repeater']
