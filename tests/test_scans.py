"""Scan preparation is offline and complete before ordered execution begins."""
import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from core.config import Config
from core.models import LeviosaResponse
from core.options import ValidationParser
from core.scanoutput import JsonlResults, ResultsWriteError, ScanReporter
from core.scans import prepare_scan, read_scan, run_scan, scan_config
from core.tooltags import BurpTool
from leviosa import build_parser


def plan_for(path, **kwargs):
    definition = read_scan(str(path))
    config = scan_config(definition, kwargs.pop('config', Config(no_proxy=True)))
    parser = ValidationParser(add_help=False, parents=[build_parser()], allow_abbrev=False)
    return prepare_scan(definition, config, parser, **kwargs)


def scan_file(tmp_path, steps='[[steps]]\nmodule="passthrough"\n', settings=''):
    path = tmp_path / 'scan.toml'
    path.write_text('name="test"\ntarget="http://example.test/original"\ndatabase="traffic.sqlite"\n' + settings + steps)
    return path


class MemoryResults:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)


class Terminal:
    def __init__(self):
        self.findings, self.messages = [], []

    def report(self, finding):
        self.findings.append(finding)

    def write(self, message):
        self.messages.append(message)


async def fake_send(requests, config, **kwargs):
    for req in requests:
        yield LeviosaResponse(200, {}, b'', req)


@pytest.mark.parametrize('text', [
    'target="http://example.test"',
    'steps=[]',
    'typo=true\n[[steps]]\nmodule="passthrough"',
    '[[steps]]\nmodule="passthrough"\nargz=[]',
    '[[steps]]\nmodule="passthrough"\nargs="--method GET"',
    'on_error="stop"\n[[steps]]\nmodule="passthrough"',
])
def test_reject_bad_scan_structure(tmp_path, text):
    path = tmp_path / 'scan.toml'
    path.write_text(text)
    with pytest.raises(ValueError):
        read_scan(str(path))


def test_independent_repeat_module_options_and_paths(tmp_path, monkeypatch):
    (tmp_path / 'first.txt').write_text('first\n')
    (tmp_path / 'second.txt').write_text('second\n')
    path = scan_file(tmp_path, '''[[steps]]
module="pathfuzz"
args=["--wordlist", "first.txt", "--recursive"]
[[steps]]
module="pathfuzz"
args=["--wordlist=second.txt", "--recursive"]
''')
    monkeypatch.chdir(tmp_path.parent)
    plan = plan_for(path)
    assert plan.steps[0].module is not plan.steps[1].module
    assert [r.url for r in asyncio.run(plan.steps[0].module.mutate(plan.source(), None))] == ['http://example.test/first/']
    assert [r.url for r in asyncio.run(plan.steps[1].module.mutate(plan.source(), None))] == ['http://example.test/second/']
    assert plan.config.log_db_path == str(tmp_path / 'traffic.sqlite')
    assert not Path(plan.config.log_db_path).exists()


def test_labelled_session_paths_resolve_relative_to_scan(tmp_path):
    (tmp_path / 'user.json').write_text('[{"method":"GET", "url":"http://example.test", "params":[{"type":"cookie","name":"session","value":"new"}]}]')
    path = scan_file(tmp_path, '[[steps]]\nmodule="authz"\nargs=["--session", "user=user.json"]\n')
    module = plan_for(path).steps[0].module
    variants = list(asyncio.run(module.mutate(plan_for(path).source(), None)))
    assert any(param.name == 'session' and param.value == 'new' for param in variants[1].params)


@pytest.mark.parametrize('step', [
    'module="pathfuzz"',
    'module="pathfuzz"\nargs=["--wordlist", "missing.txt"]',
    'module="passthrough"\nargs=["--typo"]',
    'module="passthrough"\ntool="Proxy"',
    'module="passthrough"\nfilters={methods="GET"}',
    'module="passthrough"\nfilters={sample=-1}',
    'module="passthrough"\nfilters={path="["}',
    'module="passthrough"\nfilters={sample=1}\nargs=["--method","GET"]',
])
def test_invalid_later_step_prevents_preparation_without_outputs(tmp_path, step):
    path = scan_file(tmp_path, '[[steps]]\nmodule="passthrough"\n[[steps]]\n' + step + '\n')
    with pytest.raises(ValueError, match='step 2'):
        plan_for(path)
    assert not (tmp_path / 'traffic.sqlite').exists()


@pytest.mark.parametrize('cli_tool,named,expected', [
    (None, None, ['Repeater', 'Scanner']),
    (BurpTool.INTRUDER, None, ['Intruder', 'Intruder']),
    (BurpTool.SCANNER, {'passthrough': BurpTool.REPEATER}, ['Repeater', 'Repeater']),
])
def test_step_tools_and_cli_precedence(tmp_path, cli_tool, named, expected):
    path = scan_file(tmp_path, '[[steps]]\nmodule="passthrough"\ntool="Repeater"\n[[steps]]\nmodule="passthrough"\ntool="Scanner"\n')
    plan = plan_for(path, cli_tool=cli_tool, cli_module_tools=named)
    assert [step.config.tool for step in plan.steps] == expected


@pytest.mark.parametrize('results', ['scan.toml', 'traffic.sqlite', 'wordlist.txt'])
def test_outputs_cannot_alias_inputs_or_each_other(tmp_path, results):
    (tmp_path / 'wordlist.txt').write_text('admin\n')
    path = scan_file(tmp_path, '[[steps]]\nmodule="pathfuzz"\nargs=["--wordlist", "wordlist.txt"]\n', f'results="{results}"\n')
    before = path.read_bytes()
    with pytest.raises(ValueError, match='input|different files'):
        plan_for(path)
    assert path.read_bytes() == before
    assert (tmp_path / 'wordlist.txt').read_text() == 'admin\n'


def test_legacy_database_rejected_read_only(tmp_path):
    path = scan_file(tmp_path)
    db = tmp_path / 'traffic.sqlite'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE traffic (id INTEGER)')
    before = db.read_bytes()
    with pytest.raises(ValueError, match='ACTIVITY-only'):
        plan_for(path)
    assert db.read_bytes() == before


async def test_private_seed_copies_and_per_step_filters(tmp_path):
    inputs = tmp_path / 'input.json'
    inputs.write_text(json.dumps([
        {'method': 'GET', 'url': 'http://example.test/get'},
        {'method': 'POST', 'url': 'http://example.test/post'},
    ]))
    path = scan_file(tmp_path, '[[steps]]\nmodule="passthrough"\nfilters={methods=["GET"]}\n[[steps]]\nmodule="passthrough"\n')
    plan = plan_for(path, target=str(inputs))
    captured = []

    async def mutate_first(requests, context):
        for req in requests:
            req.method = 'DELETE'
            req.headers.append('X-Mutation: first')
            yield_req.append(req)
        return yield_req

    yield_req = []
    plan.steps[0].module.mutate = mutate_first

    async def record(requests, config, **kwargs):
        captured.append([(req.method, list(req.headers)) for req in requests])
        if False:
            yield

    with patch('core.runner.send', record):
        outcome = await run_scan(plan, output=ScanReporter(terminal=Terminal()))
    assert outcome.completed == 2
    assert captured == [[('DELETE', ['X-Mutation: first'])], [('GET', []), ('POST', [])]]


@pytest.fixture
def failing_scan(tmp_path):
    directory = tmp_path / 'plugins'
    directory.mkdir()
    (directory / 'probe.py').write_text('''import argparse
from modules.base import BaseModule
class Probe(BaseModule):
    def option_parser(self):
        p = argparse.ArgumentParser(add_help=False)
        p.add_argument("--fail", default="none")
        return p
    def setup(self, args):
        self.stage = self.option_parser().parse_args(args).fail
    async def mutate(self, requests, context):
        if self.stage == "mutate": raise RuntimeError("mutation failed")
        if self.stage == "exit": raise SystemExit(7)
        return requests
    async def analyze_one(self, response, context):
        if self.stage == "analyze": raise RuntimeError("analysis failed")
        self.report(response, context, "observed", evidence={"binary": b"\\x00\\xff"})
    async def finalize(self, context):
        if self.stage == "finalize": raise RuntimeError("finalize failed")
''')
    return tmp_path


@pytest.mark.parametrize('stage', ['mutate', 'analyze', 'finalize', 'exit'])
async def test_module_failures_continue_and_are_recorded(failing_scan, stage):
    path = scan_file(failing_scan, f'[[steps]]\nmodule="probe"\nargs=["--fail", "{stage}"]\n[[steps]]\nmodule="probe"\n', 'modules_dir="plugins"\n')
    plan = plan_for(path)
    results, terminal = MemoryResults(), Terminal()
    with patch('core.runner.send', fake_send):
        outcome = await run_scan(plan, output=ScanReporter(results, terminal))
    assert (outcome.completed, outcome.failed, outcome.status) == (1, 1, 'completed_with_failures')
    finished = [event for event in results.events if event['event'] == 'step_finished']
    assert [event['status'] for event in finished] == ['failed', 'completed']
    assert 'error' in finished[0]
    assert results.events[-1]['status'] == 'completed_with_failures'
    assert any('continuing' in message for message in terminal.messages)


async def test_interrupt_closes_current_stream_and_does_not_run_later_steps(tmp_path):
    path = scan_file(tmp_path, '[[steps]]\nmodule="passthrough"\n[[steps]]\nmodule="passthrough"\n')
    plan = plan_for(path)
    entered, closed = asyncio.Event(), asyncio.Event()
    results = MemoryResults()

    async def waiting(requests, config, **kwargs):
        entered.set()
        try:
            await asyncio.Event().wait()
            if False:
                yield
        finally:
            closed.set()

    with patch('core.runner.send', waiting):
        task = asyncio.create_task(run_scan(plan, output=ScanReporter(results, Terminal())))
        await asyncio.wait_for(entered.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert closed.is_set()
    assert len([event for event in results.events if event['event'] == 'step_started']) == 1
    assert results.events[-1]['status'] == 'interrupted'


async def test_storage_failure_aborts_instead_of_silently_losing_traffic(tmp_path):
    plan = plan_for(scan_file(tmp_path, '[[steps]]\nmodule="passthrough"\n[[steps]]\nmodule="passthrough"\n'))
    results = MemoryResults()

    async def broken(requests, config, **kwargs):
        raise sqlite3.OperationalError('disk full')
        yield

    with patch('core.runner.send', broken), pytest.raises(sqlite3.OperationalError):
        await run_scan(plan, output=ScanReporter(results, Terminal()))
    assert len([event for event in results.events if event['event'] == 'step_started']) == 1
    assert results.events[-1]['status'] == 'failed'


async def test_jsonl_results_append_flush_and_encode_evidence(failing_scan):
    plan = plan_for(scan_file(failing_scan, '[[steps]]\nmodule="probe"\n', 'modules_dir="plugins"\n'))
    path = failing_scan / 'results.jsonl'
    output = JsonlResults(path)
    try:
        for _ in range(2):
            with patch('core.runner.send', fake_send):
                await run_scan(plan, output=ScanReporter(output, Terminal()))
            assert json.loads(path.read_text().splitlines()[-1])['status'] == 'completed'
    finally:
        output.close()
    events = [json.loads(line) for line in path.read_text().splitlines()]
    starts = [event for event in events if event['event'] == 'scan_started']
    assert len(starts) == 2 and starts[0]['run_id'] != starts[1]['run_id']
    finding = next(event for event in events if event['event'] == 'finding')
    assert finding['evidence']['binary'] == {'encoding': 'base64', 'value': 'AP8='}
    assert finding['module'] == 'probe' and finding['step'] == 1


async def test_human_cadence_is_shared_across_prepared_steps(tmp_path, monkeypatch):
    path = scan_file(tmp_path, '[[steps]]\nmodule="passthrough"\n[[steps]]\nmodule="securityheaders"\n[[steps]]\nmodule="passthrough"\n',
                     'human_mode=true\nhuman_timing_min=10\nhuman_timing_max=10\n')
    plan = plan_for(path)
    clock, starts, sleeps = [100.0], [], []
    monkeypatch.setattr('core.timing.monotonic', lambda: clock[0])
    monkeypatch.setattr('core.timing.uniform', lambda lo, hi: 10)

    async def wait(delay):
        sleeps.append(delay)
        clock[0] += delay

    async def request(session, req, config, read_body, proxy, auth, capture):
        starts.append(clock[0])
        clock[0] += 1
        return LeviosaResponse(200, {}, b'', req)

    monkeypatch.setattr('core.timing.sleep', wait)
    monkeypatch.setattr('core.requester._send_one', request)
    outcome = await run_scan(plan, output=ScanReporter(terminal=Terminal()))
    assert outcome.completed == 3
    assert starts == [100, 111, 122] and sleeps == [10, 10]


async def test_broken_results_storage_stops_later_steps(failing_scan):
    plan = plan_for(scan_file(failing_scan, '[[steps]]\nmodule="probe"\n[[steps]]\nmodule="probe"\n', 'modules_dir="plugins"\n'))

    class BrokenResults(MemoryResults):
        def emit(self, event):
            if event['event'] == 'finding':
                raise ResultsWriteError('disk full')
            super().emit(event)

    results = BrokenResults()
    with patch('core.runner.send', fake_send), pytest.raises(ResultsWriteError):
        await run_scan(plan, output=ScanReporter(results, Terminal()))
    assert len([event for event in results.events if event['event'] == 'step_started']) == 1


async def test_unserializable_module_evidence_is_a_step_failure_not_a_storage_failure(failing_scan):
    plan = plan_for(scan_file(failing_scan, '[[steps]]\nmodule="probe"\n[[steps]]\nmodule="probe"\n', 'modules_dir="plugins"\n'))

    async def bad_evidence(response, context):
        plan.steps[0].module.report(response, context, 'bad', evidence={'unsupported': object()})

    plan.steps[0].module.analyze_one = bad_evidence
    file = JsonlResults(failing_scan / 'results.jsonl')
    try:
        with patch('core.runner.send', fake_send):
            outcome = await run_scan(plan, output=ScanReporter(file, Terminal()))
    finally:
        file.close()
    assert (outcome.failed, outcome.completed) == (1, 1)


def test_example_scan_validates_without_creating_outputs():
    path = Path(__file__).resolve().parent.parent / 'examples' / 'review-scan.toml'
    plan = plan_for(path)
    assert len(plan.steps) == 4
    assert [step.config.tool for step in plan.steps] == ['Repeater', 'Scanner', 'Intruder', 'Repeater']
    assert not Path(plan.config.log_db_path).exists()
    assert not Path(plan.results).exists()


def test_hardlinked_results_cannot_modify_input(tmp_path):
    import os
    path = scan_file(tmp_path)
    alias = tmp_path / 'alias.jsonl'
    os.link(path, alias)
    before = path.read_bytes()
    with pytest.raises(ValueError, match='input'):
        plan_for(path, results=str(alias))
    assert path.read_bytes() == before


def test_source_validation_checks_every_url_without_sending(tmp_path):
    inputs = tmp_path / 'urls.txt'
    inputs.write_text('http://example.test/valid\nnot-a-url\n')
    path = scan_file(tmp_path)
    with pytest.raises(ValueError, match='input request 2'):
        plan_for(path, target=str(inputs))


def test_readonly_results_rejected_during_preflight(tmp_path):
    import os
    path = scan_file(tmp_path)
    output = tmp_path / 'results.jsonl'
    output.write_text('')
    output.chmod(0o444)
    try:
        if os.access(output, os.W_OK):
            pytest.skip('current user can write read-only files')
        with pytest.raises(ValueError, match='not writable'):
            plan_for(path, results=str(output))
    finally:
        output.chmod(0o644)


def test_impossible_seed_headers_fail_preflight_before_any_outputs(tmp_path):
    inputs = tmp_path / 'requests.json'
    inputs.write_text(json.dumps([
        {'method': 'GET', 'url': 'http://example.test/valid'},
        {'method': 'GET', 'url': 'http://example.test/invalid', 'headers': ['X-Test: line\nbad']},
    ]))
    with pytest.raises(ValueError, match='input request 2'):
        plan_for(scan_file(tmp_path), target=str(inputs))
    assert not (tmp_path / 'traffic.sqlite').exists()


@pytest.mark.parametrize('settings', [
    'module_delay=-1', 'module_delay=true', 'module_delay="5"',
    'module_delay=inf', 'module_delay=nan',
    'module_delay_min=1', 'module_delay_max=2',
    'module_delay_min=3\nmodule_delay_max=2',
    'module_delay_min=-1\nmodule_delay_max=2',
    'module_delay_min=0\nmodule_delay_max=inf',
    'module_delay_min=false\nmodule_delay_max=2',
    'module_delay=0\nmodule_delay_min=1\nmodule_delay_max=2',
])
def test_reject_invalid_module_delay(tmp_path, settings):
    with pytest.raises(ValueError, match='module.delay|module delays'):
        plan_for(scan_file(tmp_path, settings=settings + '\n'))


@pytest.mark.parametrize(('settings', 'expected', 'bounds'), [
    ('', [], None),
    ('module_delay=0\n', [], None),
    ('module_delay=2.5\n', [2.5, 2.5], None),
    ('module_delay_min=1\nmodule_delay_max=4\n', [3, 3], (1, 4)),
    ('module_delay_min=2\nmodule_delay_max=2\n', [2, 2], None),
])
async def test_delays_only_between_steps_including_recoverable_failure(
        tmp_path, monkeypatch, settings, expected, bounds):
    path = scan_file(tmp_path, steps='[[steps]]\nmodule="passthrough"\n' * 3,
                     settings=settings)
    plan = plan_for(path)
    events, samples = [], []
    async def run(*args, **kwargs):
        events.append('run')
        if events.count('run') == 2:
            raise RuntimeError('recoverable')
    async def wait(seconds):
        events.append(seconds)
    def uniform(lo, hi):
        samples.append((lo, hi))
        return 3
    monkeypatch.setattr('core.scans.run_modules', run)
    monkeypatch.setattr('core.scans.asyncio.sleep', wait)
    monkeypatch.setattr('core.scans.random.uniform', uniform)
    results = MemoryResults()
    outcome = await run_scan(plan, output=ScanReporter(results, Terminal()))
    assert outcome.completed == 2 and outcome.failed == 1
    assert events == (['run', expected[0], 'run', expected[1], 'run']
                      if expected else ['run'] * 3)
    assert samples == ([bounds, bounds] if bounds else [])
    delays = [event for event in results.events if event['event'] == 'module_delay']
    assert [event['seconds'] for event in delays] == expected
    assert [event['next_step'] for event in delays] == ([2, 3] if expected else [])


async def test_cancellation_during_module_delay_stops_next_step(tmp_path, monkeypatch):
    plan = plan_for(scan_file(tmp_path,
        steps='[[steps]]\nmodule="passthrough"\n' * 2,
        settings='module_delay=5\n'))
    calls = []
    async def run(*args, **kwargs):
        calls.append('run')
    async def wait(seconds):
        raise asyncio.CancelledError
    monkeypatch.setattr('core.scans.run_modules', run)
    monkeypatch.setattr('core.scans.asyncio.sleep', wait)
    results = MemoryResults()
    with pytest.raises(asyncio.CancelledError):
        await run_scan(plan, output=ScanReporter(results, Terminal()))
    assert calls == ['run']
    assert results.events[-1]['event'] == 'scan_finished'
    assert results.events[-1]['status'] == 'interrupted'
