"""Exercise the complete scan CLI against a local server, including failure recovery."""
import asyncio
import hashlib
import json
import signal
import socket
import sqlite3
import sys
from pathlib import Path

import pytest
from aiohttp import web

SCRIPT = Path(__file__).resolve().parent.parent / 'leviosa.py'


@pytest.fixture
async def site():
    arrivals = []

    async def handler(req):
        arrivals.append((req.method, req.path, req.headers.get('Cookie')))
        await req.read()
        return web.Response(text='<html>scan test</html>', content_type='text/html')

    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    runner = web.AppRunner(app)
    await runner.setup()
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    url = f'http://127.0.0.1:{sock.getsockname()[1]}'
    try:
        await web.SockSite(runner, sock).start()
        yield url, arrivals
    finally:
        await runner.cleanup()
        sock.close()


async def cli(cwd, *args):
    process = await asyncio.create_subprocess_exec(sys.executable, str(SCRIPT), *map(str, args), cwd=cwd,
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), 8)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
    return process.returncode, stdout.decode(), stderr.decode()


def definition(directory, url, steps='[[steps]]\nmodule="passthrough"\n', extra=''):
    directory.mkdir(exist_ok=True)
    path = directory / 'scan.toml'
    path.write_text(f'name="cli-test"\ntarget="{url}/seed"\nno_proxy=true\ndatabase="traffic.sqlite"\nresults="results.jsonl"\n' + extra + steps)
    return path


def traffic(path):
    with sqlite3.connect(path) as conn:
        return conn.execute('SELECT HTTP_METHOD, TARGET_URL, BURP_TOOL, RESPONSE_RAW FROM ACTIVITY ORDER BY rowid').fetchall()


async def test_validate_only_is_offline_and_creates_no_outputs(site, tmp_path):
    url, arrivals = site
    directory = tmp_path / 'scan'
    path = definition(directory, url)
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    code, out, err = await cli(tmp_path, '--scan', path, '--validate-scan')
    assert code == 0, err
    assert 'Valid: cli-test' in out and 'passthrough (Repeater)' in out
    assert not arrivals
    assert not (directory / 'traffic.sqlite').exists()
    assert not (directory / 'results.jsonl').exists()
    assert hashlib.sha256(path.read_bytes()).hexdigest() == before


async def test_invalid_late_step_never_sends_first_step(site, tmp_path):
    url, arrivals = site
    path = definition(tmp_path, url, '[[steps]]\nmodule="passthrough"\n[[steps]]\nmodule="pathfuzz"\n')
    code, out, err = await cli(tmp_path, '--scan', path)
    assert code == 2 and 'step 2' in err and '--wordlist' in err
    assert 'Traceback' not in err
    assert not arrivals
    assert not (tmp_path / 'traffic.sqlite').exists() and not (tmp_path / 'results.jsonl').exists()


async def test_ordered_scan_repeated_modules_failure_and_jsonl(site, tmp_path):
    url, arrivals = site
    directory = tmp_path / 'scan'
    directory.mkdir()
    (directory / 'one.txt').write_text('one\n')
    (directory / 'two.txt').write_text('two\n')
    plugins = directory / 'plugins'
    plugins.mkdir()
    (plugins / 'broken.py').write_text('''from modules.base import BaseModule
class Broken(BaseModule):
    async def mutate(self, requests, context):
        raise RuntimeError("intentional failure")
''')
    steps = '''[[steps]]
name="baseline"
module="passthrough"
[[steps]]
module="securityheaders"
[[steps]]
module="pathfuzz"
args=["--wordlist", "one.txt", "--recursive"]
[[steps]]
module="broken"
modules_dir="plugins"
[[steps]]
module="pathfuzz"
args=["--wordlist=two.txt", "--recursive"]
tool="Repeater"
[[steps]]
module="securityheaders"
args=["--no-recommended"]
'''
    path = definition(directory, url, steps, 'human_mode=true\nhuman_timing_min=0.01\nhuman_timing_max=0.01\n')
    code, out, err = await cli(tmp_path, '--scan', path)
    assert code == 1, err
    assert 'intentional failure' in out and 'continuing' in out
    assert '5 completed, 1 failed' in out and 'Traceback' not in err
    rows = traffic(directory / 'traffic.sqlite')
    assert [(row[1], row[2]) for row in rows] == [
        (url + '/seed', 'Repeater'), (url + '/seed', 'Repeater'), (url + '/one/', 'Repeater'),
        (url + '/two/', 'Repeater'), (url + '/seed', 'Repeater')]
    assert len(arrivals) == 5
    assert all(row[3] == '<html>scan test</html>' for row in rows)
    with sqlite3.connect(directory / 'traffic.sqlite') as conn:
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [('ACTIVITY',)]
        assert len(conn.execute('PRAGMA table_info(ACTIVITY)').fetchall()) == 8
    events = [json.loads(line) for line in (directory / 'results.jsonl').read_text().splitlines()]
    assert [event['step'] for event in events if event['event'] == 'step_started'] == list(range(1, 7))
    assert events[-1]['status'] == 'completed_with_failures'
    findings = [event for event in events if event['event'] == 'finding']
    first = next(event for event in findings if event['step'] == 2)
    last = next(event for event in findings if event['step'] == 6)
    assert any('recommended' in issue for issue in first['evidence']['issues'])
    assert not any('recommended' in issue for issue in last['evidence']['issues'])


async def test_cli_overrides_target_paths_tools_and_cookie_refresh(site, tmp_path):
    url, arrivals = site
    directory = tmp_path / 'scan'
    path = definition(directory, 'http://invalid.example', '[[steps]]\nmodule="securityheaders"\ntool="Intruder"\n')
    inputs = tmp_path / 'requests.json'
    inputs.write_text(json.dumps([{'method': 'GET', 'url': url + '/override', 'headers': ['Cookie: session=old']}]))
    code, out, err = await cli(tmp_path, 'requests.json', '--scan', path, '--tool', 'Repeater',
                               '--cookies', 'session=new', '--log-db', 'override.sqlite', '--results', 'override.jsonl')
    assert code == 0, err
    assert arrivals == [('GET', '/override', 'session=new')]
    assert traffic(tmp_path / 'override.sqlite')[0][2] == 'Repeater'
    assert (tmp_path / 'override.jsonl').exists()
    assert not (directory / 'traffic.sqlite').exists() and not (directory / 'results.jsonl').exists()


async def test_console_only_results_and_no_log(site, tmp_path):
    url, arrivals = site
    path = tmp_path / 'scan.toml'
    path.write_text(f'target="{url}"\nno_proxy=true\n[[steps]]\nmodule="securityheaders"\n')
    code, out, err = await cli(tmp_path, '--scan', path, '--no-log')
    assert code == 0, err
    assert '[SECHEADERS]' in out and 'completed' in out
    assert len(arrivals) == 1
    assert not list(tmp_path.glob('*.sqlite')) and not list(tmp_path.glob('*.jsonl'))


@pytest.mark.parametrize('flags', [['--module', 'passthrough'], ['--typo'], ['--wordlist', 'words.txt']])
async def test_scan_rejects_ambiguous_cli_module_arguments(site, tmp_path, flags):
    url, arrivals = site
    path = definition(tmp_path, url)
    code, out, err = await cli(tmp_path, '--scan', path, *flags)
    assert code == 2 and 'Traceback' not in err
    assert not arrivals


async def test_sigint_marks_run_interrupted_and_skips_next_step(tmp_path):
    if sys.platform == 'win32':
        pytest.skip('POSIX SIGINT subprocess test')
    plugins = tmp_path / 'plugins'
    plugins.mkdir()
    (plugins / 'waiting.py').write_text('''import asyncio
from modules.base import BaseModule
class Waiting(BaseModule):
    async def mutate(self, requests, context):
        await asyncio.sleep(30)
        return requests
''')
    path = definition(tmp_path, 'http://127.0.0.1:1', '[[steps]]\nmodule="waiting"\nmodules_dir="plugins"\n[[steps]]\nmodule="passthrough"\n')
    process = await asyncio.create_subprocess_exec(sys.executable, str(SCRIPT), '--scan', str(path), cwd=tmp_path,
                                                 stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        for _ in range(200):
            results = tmp_path / 'results.jsonl'
            if results.exists() and 'step_started' in results.read_text():
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail('scan did not start')
        process.send_signal(signal.SIGINT)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 3)
        assert process.returncode == 130, stderr.decode()
        events = [json.loads(line) for line in results.read_text().splitlines()]
        assert len([event for event in events if event['event'] == 'step_started']) == 1
        assert events[-1]['status'] == 'interrupted'
        assert 'Traceback' not in stderr.decode()
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()
