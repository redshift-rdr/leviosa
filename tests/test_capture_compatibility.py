"""Exercise old/new writer hooks without depending on one installed aiohttp API."""
import asyncio
from datetime import datetime

import aiohttp
import pytest
from yarl import URL

from core.capture import CapturedRequest
from core.config import Config
from core.models import LeviosaRequest, TrafficRecord
from core.requester import send


@pytest.mark.parametrize('captured', [False, True])
@pytest.mark.parametrize('keyword', [False, True])
async def test_extra_length_argument_forwarded_unchanged(monkeypatch, captured, keyword):
    received = []
    async def write_bytes(self, writer, conn, *args, **kwargs):
        received.append((args, kwargs))
        return 'sent'
    monkeypatch.setattr(aiohttp.ClientRequest, 'write_bytes', write_bytes)
    req = CapturedRequest('POST', URL('http://example.test/'), loop=asyncio.get_running_loop())
    if captured:
        req._traffic_record = TrafficRecord(str(req.url), req.method, datetime.now())
    class Writer:
        def _write(self, chunk):
            pass
    args, kwargs = ((), {'content_length': 3}) if keyword else ((3,), {})
    assert await req.write_bytes(Writer(), object(), *args, **kwargs) == 'sent'
    assert received == [(args, kwargs)]


@pytest.mark.parametrize('buffered', [False, True])
@pytest.mark.parametrize('fail', [False, True])
async def test_capture_vectored_writes_exactly_once_and_restore_hooks(monkeypatch, buffered, fail):
    headers = b'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n'
    class Writer:
        def __init__(self):
            self._headers_buf = headers if buffered else None
            self.wire = b'' if buffered else headers
        def _write(self, chunk):
            self.wire += bytes(chunk)
        def _writelines(self, chunks):
            # A writer is allowed to implement vectored writes using _write.
            for chunk in chunks:
                self._write(chunk)
    async def write_bytes(self, writer, conn, content_length=None):
        chunks = [b'3\r\n', b'abc', b'\r\n0\r\n\r\n']
        if writer._headers_buf:
            chunks.insert(0, writer._headers_buf)
            writer._headers_buf = None
        writer._writelines(iter(chunks))
        if fail:
            raise RuntimeError('simulated writer failure')
    monkeypatch.setattr(aiohttp.ClientRequest, 'write_bytes', write_bytes)
    req = CapturedRequest('POST', URL('http://example.test/'), loop=asyncio.get_running_loop())
    req._traffic_record = TrafficRecord(str(req.url), req.method, datetime.now(), request_raw=headers)
    writer = Writer()
    original_write, original_lines = writer._write, writer._writelines
    if fail:
        with pytest.raises(RuntimeError, match='simulated writer failure'):
            await req.write_bytes(writer, object(), 3)
    else:
        await req.write_bytes(writer, object(), 3)
    assert req._traffic_record.request_raw == writer.wire == headers + b'3\r\nabc\r\n0\r\n\r\n'
    assert writer._write == original_write
    assert writer._writelines == original_lines


async def test_all_completed_task_exceptions_are_consumed(monkeypatch):
    import core.requester as requester
    tasks = []
    async def broken(*args, **kwargs):
        tasks.append(asyncio.current_task())
        await asyncio.sleep(0)
        raise TypeError('simulated hook mismatch')
    original_wait = asyncio.wait
    async def wait_all(futures, **kwargs):
        return await original_wait(futures, return_when=asyncio.ALL_COMPLETED)
    monkeypatch.setattr(requester, '_send_one', broken)
    monkeypatch.setattr(requester.asyncio, 'wait', wait_all)
    req = LeviosaRequest('GET', 'http://example.test/', [], [])
    with pytest.raises(TypeError, match='simulated hook mismatch'):
        _ = [response async for response in send([req] * 3, Config(concurrency=3))]
    assert len(tasks) == 3 and all(task.done() for task in tasks)
    assert all(not task._log_traceback for task in tasks)


def test_bundled_aiohttp_is_within_declared_runtime_support():
    import tomllib
    from pathlib import Path
    from packaging.requirements import Requirement
    from packaging.utils import parse_wheel_filename
    root = Path(__file__).resolve().parent.parent
    with (root / 'pyproject.toml').open('rb') as stream:
        dependencies = tomllib.load(stream)['project']['dependencies']
    requirement = next(Requirement(item) for item in dependencies if Requirement(item).name == 'aiohttp')
    wheels = list((root / 'bundled_requirements').glob('aiohttp-*.whl'))
    assert wheels
    for wheel in wheels:
        _, version, _, _ = parse_wheel_filename(wheel.name)
        assert version in requirement.specifier, f'{wheel.name} is outside declared aiohttp support'
