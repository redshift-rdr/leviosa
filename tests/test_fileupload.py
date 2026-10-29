import hashlib
from dataclasses import replace
from datetime import datetime
from email.parser import BytesParser

import pytest

from core.logdb import TrafficLogger
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse, RequestBody, TrafficRecord
from modules.fileupload import FileUpload, eicar_bytes, upload_parts


def seed():
    return LeviosaRequest('POST', 'http://example.test/upload',
        ['Content-Type: multipart/form-data; boundary="test"', 'Content-Length: 999'], [],
        body=RequestBody('raw', b'--test\r\nContent-Disposition: form-data; name="csrf"\r\n\r\ntoken\r\n'
             b'--test\r\nContent-Disposition: form-data; name="file"; filename="photo.png"\r\n'
             b'Content-Type: image/png\r\n\r\noriginal\r\n--test--\r\n'))


async def variants(req=None, module=None):
    return list(await (module or FileUpload()).mutate([req or seed()], LeviosaContext()))


async def test_skip_non_uploads_and_malformed_bodies():
    req = seed()
    for other in [replace(req, body=None), replace(req, body=RequestBody('raw', b'broken')),
                  replace(req, headers=['Content-Type: application/json']),
                  replace(req, body=RequestBody('raw', req.body.value.replace(b'filename="photo.png"', b'filename=""')))]:
        assert await variants(other) == []


async def test_variants_preserve_fields_and_seed():
    req = seed()
    original = req.body.value
    probes = await variants(req)
    assert len(probes) == 8
    assert len({p.request_id for p in probes}) == 8
    assert all(p.seed_id == req.seed_id for p in probes)
    assert probes[0].body.value == original == req.body.value
    for probe in probes[1:]:
        assert 'Content-Length: 999' not in probe.headers
        message = BytesParser().parsebytes(('Content-Type: multipart/form-data; boundary=test\r\n\r\n').encode() + probe.body.value)
        fields = message.get_payload()
        assert fields[0].get_payload(decode=True) == b'token'
        assert fields[1].get_filename() == probe.metadata['fileupload']['filename']
        assert len(upload_parts(probe)) == 1


def test_eicar_is_standard_without_writing_a_file():
    assert len(eicar_bytes()) == 68
    assert hashlib.md5(eicar_bytes()).hexdigest() == '44d88612fea8a8f36de82e1278abb02f'


async def test_each_file_is_mutated_separately():
    req = seed()
    part = req.body.value[req.body.value.index(b'--test\r\nContent-Disposition: form-data; name="file"'):]
    req.body.value = req.body.value.replace(b'--test--\r\n', part)
    probes = await variants(req)
    assert len(probes) == 15
    for probe in probes[1:]:
        assert probe.body.value.count(b'original') == 1


async def test_skip_eicar():
    module = FileUpload()
    module.setup(['--upload-skip-eicar'])
    assert len(await variants(module=module)) == 6


@pytest.mark.parametrize('status,body,marker,expected', [
    (200, b'ok', None, True), (400, b'ok', None, False), (0, b'', None, False),
    (302, b'ok', None, False), (200, b'rejected', 'accepted', False),
    (201, b'accepted', 'accepted', True),
])
async def test_acceptance_is_qualified(status, body, marker, expected, capsys):
    module = FileUpload()
    module.success_text = marker
    req = (await variants(module=module))[-1]
    await module.analyze_one(LeviosaResponse(status, {}, body, req), LeviosaContext())
    output = capsys.readouterr().out
    assert bool(output) == expected
    if expected:
        assert 'unverified' in output
        assert ('marker matched' if marker else '2xx only') in output


async def test_eicar_and_echo_are_redacted_from_sqlite(tmp_path):
    req = (await variants())[-1]
    record = TrafficRecord(req.url, req.method, datetime.now())
    record.request_raw = req.body.value
    record.response_body = eicar_bytes()
    record.status = 200
    logger = TrafficLogger(str(tmp_path / 'traffic.db'))
    try:
        logger.log(LeviosaResponse(200, {}, eicar_bytes(), req, traffic=[record]))
        row = logger.conn.execute('SELECT REQUEST_RAW, RESPONSE_RAW FROM ACTIVITY').fetchone()
        assert row == ('[redacted test exchange]', '[redacted test exchange]')
        assert eicar_bytes() not in (tmp_path / 'traffic.db').read_bytes()
    finally:
        logger.close()


def test_loader():
    from core.loader import load_modules
    assert isinstance(load_modules(['fileupload'])[0], FileUpload)
