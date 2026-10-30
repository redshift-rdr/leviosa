"""Progress must stay live during awaits without changing request consumption."""
import asyncio
import socket
import sys
from pathlib import Path

import pytest
from aiohttp import web

from core.config import Config, load_config
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse
from core.progress import Progress, ProgressWriteError
from core.requester import send
from core.runner import run_modules
from core.timing import HumanPacer
from modules.passthrough import PassthroughModule


def request():
    return LeviosaRequest('GET', 'https://app.test/?token=PRIVATE_TOKEN', ['Authorization: Bearer SECRET'], [])


async def test_heartbeat_during_slow_request_and_no_output_after_finish(monkeypatch):
    lines, heartbeat = [], asyncio.Event()
    def output(line):
        lines.append(line)
        if 'waiting for responses' in line and 'in-flight=1' in line:
            heartbeat.set()
    async def slow(session, req, *args):
        await asyncio.wait_for(heartbeat.wait(), 1)
        return LeviosaResponse(200, {}, b'', req)
    monkeypatch.setattr('core.requester._send_one', slow)
    with Progress('test', interval=0.01, write=output) as progress:
        responses = [r async for r in send([request()], Config(), progress=progress)]
    assert len(responses) == 1
    assert progress.sent == progress.completed == 1 and progress.active == progress.errors == 0
    assert 'finished' in lines[-1] and 'completed=1' in lines[-1]
    assert all('SECRET' not in line and 'PRIVATE_TOKEN' not in line for line in lines)
    count = len(lines)
    await asyncio.sleep(0.03)
    assert len(lines) == count


async def test_lazy_input_is_not_counted_in_advance_and_errors_counted(monkeypatch):
    async def perform(session, req, *args):
        return LeviosaResponse(0 if req.metadata['index'] == 1 else 403, {}, b'', req)
    monkeypatch.setattr('core.requester._send_one', perform)
    with Progress('lazy', write=lambda _: None) as progress:
        def source():
            for index in range(3):
                assert progress.completed == index
                req = request()
                req.metadata['index'] = index
                yield req
        result = [r async for r in send(source(), Config(concurrency=1), progress=progress)]
    assert len(result) == progress.completed == progress.sent == 3
    assert progress.errors == 1 and progress.active == 0


async def test_heartbeat_during_human_mode_pacing(monkeypatch):
    lines, paced = [], asyncio.Event()
    calls = 0
    async def wait(self, *args):
        nonlocal calls
        calls += 1
        if calls == 2:
            await asyncio.wait_for(paced.wait(), 1)
    async def immediate(session, req, *args):
        return LeviosaResponse(200, {}, b'', req)
    def output(line):
        lines.append(line)
        if 'pacing between requests' in line and 'completed=1' in line:
            paced.set()
    monkeypatch.setattr(HumanPacer, 'wait', wait)
    monkeypatch.setattr('core.requester._send_one', immediate)
    with Progress('paced', interval=0.01, write=output) as progress:
        _ = [r async for r in send([request(), request()], Config(human_mode=True), progress=progress)]
    assert paced.is_set() and progress.completed == 2


async def test_cancellation_cleans_up_progress_and_inflight_counts(monkeypatch):
    began, lines = asyncio.Event(), []
    async def hanging(session, req, *args):
        began.set()
        await asyncio.Event().wait()
    monkeypatch.setattr('core.requester._send_one', hanging)
    progress = Progress('cancelled', interval=0.01, write=lines.append)
    async def run():
        with progress:
            _ = [r async for r in send([request()], Config(), progress=progress)]
    task = asyncio.create_task(run())
    await began.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert progress.active == 0 and progress.cancelled == 1
    assert 'stopped' in lines[-1]
    count = len(lines)
    await asyncio.sleep(0.03)
    assert len(lines) == count


async def test_empty_module_and_disable_progress(capsys):
    await run_modules([PassthroughModule()], lambda: iter(()), Config(), LeviosaContext())
    out = capsys.readouterr()
    assert out.out == ''
    assert 'finished (no requests sent)' in out.err
    await run_modules([PassthroughModule()], lambda: iter(()), Config(progress=False), LeviosaContext())
    assert capsys.readouterr().err == ''


async def test_output_failure_is_propagated_and_timer_stops():
    calls = 0
    def output(line):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise OSError('output closed')
    with pytest.raises(ProgressWriteError, match='output closed'):
        with Progress('failed', interval=0.01, write=output):
            await asyncio.sleep(0.03)
    count = calls
    await asyncio.sleep(0.03)
    assert calls == count


@pytest.mark.parametrize('value', [0, -1, float('nan'), float('inf'), True, '5', 10 ** 1000])
def test_invalid_interval(value):
    with pytest.raises(ValueError, match='progress_interval'):
        Config(progress_interval=value).validate_progress()


def test_config_and_cli_precedence(tmp_path):
    from leviosa import build_parser, _apply_cli
    path = tmp_path / 'leviosa.toml'
    path.write_text('[progress]\nenabled=false\ninterval=12\n')
    config = load_config(str(path))
    config.validate_progress()
    assert config.progress is False and config.progress_interval == 12
    parser = build_parser()
    args, _ = parser.parse_known_args(['https://app.test', '--progress', '--progress-interval', '3'])
    _apply_cli(config, args, parser)
    assert config.progress is True and config.progress_interval == 3


@pytest.mark.parametrize('mode', ['raw', 'module', 'scan'])
async def test_cli_heartbeat_is_visible_before_response_arrives(tmp_path, mode):
    release = asyncio.Event()
    async def handler(req):
        await asyncio.wait_for(release.wait(), 5)
        return web.Response(text='ok')
    app = web.Application()
    app.router.add_get('/', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    process = None
    try:
        await web.SockSite(runner, sock).start()
        url = f'http://127.0.0.1:{sock.getsockname()[1]}/'
        args = [url, '--no-log', '--no-proxy', '--progress-interval', '0.01']
        expected = 'requests'
        if mode == 'module':
            args += ['--module', 'passthrough']
            expected = 'passthrough'
        elif mode == 'scan':
            path = tmp_path / 'scan.toml'
            path.write_text(f'target="{url}"\nlog_enabled=false\nprogress=true\nprogress_interval=0.01\n[[steps]]\nmodule="passthrough"\n')
            args = ['--scan', str(path)]
            expected = 'step 1 passthrough'
        script = Path(__file__).resolve().parent.parent / 'leviosa.py'
        process = await asyncio.create_subprocess_exec(sys.executable, str(script), *args, cwd=tmp_path,
                                                     stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        seen = []
        while True:
            line = await asyncio.wait_for(process.stderr.readline(), 5)
            assert line, b''.join(seen).decode()
            seen.append(line)
            if b'waiting for responses' in line and b'in-flight=1' in line:
                break
        assert expected in b''.join(seen).decode()
        assert process.returncode is None
        release.set()
        _, err = await asyncio.wait_for(process.communicate(), 5)
        assert process.returncode == 0, err.decode()
        assert 'completed=1' in err.decode() and 'finished' in err.decode()
    finally:
        release.set()
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        await runner.cleanup()
        sock.close()


async def test_cli_disable_and_offline_validation_emit_no_progress(tmp_path):
    script = Path(__file__).resolve().parent.parent / 'leviosa.py'
    scan = tmp_path / 'scan.toml'
    scan.write_text('target="http://127.0.0.1:1/"\nlog_enabled=false\n[[steps]]\nmodule="passthrough"\n')
    for args in (['--scan', str(scan), '--validate-scan'],
                 ['http://127.0.0.1:1/', '--no-log', '--no-proxy', '--no-progress']):
        process = await asyncio.create_subprocess_exec(sys.executable, str(script), *args, cwd=tmp_path,
                                                     stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        _, err = await asyncio.wait_for(process.communicate(), 5)
        assert process.returncode == 0
        assert '[PROGRESS]' not in err.decode()


async def test_parallel_preview_counts_each_request_once(monkeypatch):
    from core.tooltags import BurpTool
    active = []
    progress = Progress('parallel', write=lambda _: None)
    async def response(session, req, *args):
        active.append(progress.active)
        await asyncio.sleep(0.01)
        return LeviosaResponse(200, {}, b'', req)
    monkeypatch.setattr('core.requester._send_one', response)
    with progress:
        responses = [r async for r in send([request() for _ in range(5)], Config(concurrency=3),
                                          tool=BurpTool.SCANNER, repeater_preview=2, progress=progress)]
    assert len(responses) == progress.sent == progress.completed == 5
    assert progress.active == progress.errors == 0
    assert max(active) == 3


async def test_authentication_health_requests_are_counted(monkeypatch):
    async def response(session, req, *args):
        return LeviosaResponse(200, {}, b'authenticated' if '/health' in req.url else b'ok', req)
    monkeypatch.setattr('core.requester._send_one', response)
    config = Config(auth_check=True, auth_check_url='https://app.test/health', auth_success_text='authenticated')
    with Progress('auth', write=lambda _: None) as progress:
        result = [r async for r in send([request()], config, progress=progress)]
    assert len(result) == 1
    assert progress.sent == progress.completed == 2
    assert progress.active == progress.errors == 0


async def test_progress_output_failure_stops_later_scan_steps(monkeypatch):
    from core.scans import PreparedScan, PreparedStep, run_scan
    from core.scanoutput import ScanReporter
    messages = []
    class Quiet:
        def write(self, message):
            messages.append(message)
        def report(self, finding):
            pass
    def broken_output(message):
        raise OSError('progress destination closed')
    def progress(*args, **kwargs):
        return Progress(*args, **kwargs, write=broken_output)
    async def unexpected(*args, **kwargs):
        pytest.fail('No traffic should start after progress output fails')
        yield
    monkeypatch.setattr('core.runner.Progress', progress)
    monkeypatch.setattr('core.runner.send', unexpected)
    config = Config(log_enabled=False)
    plan = PreparedScan('progress-test', 'https://app.test/', lambda: iter([request()]), config,
                        [PreparedStep(i, f'step-{i}', PassthroughModule(), config) for i in (1, 2)], None)
    with pytest.raises(ProgressWriteError):
        await run_scan(plan, output=ScanReporter(terminal=Quiet()))
    assert not any('step-2: starting' in message for message in messages)
