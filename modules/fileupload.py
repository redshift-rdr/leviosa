"""Probe captured multipart file uploads using inert files and in-memory EICAR."""
import argparse
import re
from dataclasses import replace
from email.parser import BytesHeaderParser
from email.policy import SMTP
from email.message import Message

from core.headers import parse_headers, without_headers
from core.models import RequestBody
from core.tooltags import BurpTool
from modules.base import BaseModule


def eicar_bytes():
    # Assemble only at runtime: never ship the complete signature in an asset.
    return b''.join((b'X5O!P%@AP[4', bytes([92]), b'PZX54(P^)7CC)7}$',
                     b'EICAR-STANDARD-', b'ANTIVIRUS-TEST-FILE!', b'$H+H*'))


def upload_parts(req):
    """Return byte spans for file parts; leave all unrelated multipart bytes intact."""
    if req.body is None or req.body.kind != 'raw':
        return []
    content_type = Message()
    content_type['Content-Type'] = parse_headers(req.headers).get('Content-Type', '')
    boundary = content_type.get_boundary()
    if content_type.get_content_type() != 'multipart/form-data' or not boundary:
        return []
    raw = req.body.value
    raw = raw.encode('utf-8') if isinstance(raw, str) else raw
    try:
        delimiter = boundary.encode('ascii')
    except UnicodeEncodeError:
        return []
    markers = list(re.finditer(rb'(?:\A|\r\n)--' + re.escape(delimiter) + rb'(--)?(?:\r\n|\Z)', raw))
    if len(markers) < 2 or not markers[-1].group(1):
        return []
    parts = []
    for start, end in zip(markers, markers[1:]):
        if start.group(1):
            break
        header_end = raw.find(b'\r\n\r\n', start.end(), end.start())
        if header_end < 0:
            return []
        headers = BytesHeaderParser().parsebytes(raw[start.end():header_end])
        filename = headers.get_filename()
        field = headers.get_param('name', header='content-disposition')
        if headers.get_content_disposition() == 'form-data' and filename and field is not None:
            parts.append((start.end(), end.start(), field, filename))
    return parts


class FileUpload(BaseModule):
    """Check filename/MIME restrictions and EICAR acceptance on multipart uploads only."""

    tool = BurpTool.SCANNER
    follow_redirects = False

    def __init__(self):
        self.success_text = None
        self.skip_eicar = False

    def option_parser(self):
        parser = argparse.ArgumentParser(prog='fileupload', add_help=False, allow_abbrev=False)
        parser.add_argument('--upload-success-text', help='Response text indicating upload acceptance (otherwise 2xx is only a possible acceptance)')
        parser.add_argument('--upload-skip-eicar', action='store_true', help='Skip the in-memory EICAR upload probes')
        return parser

    def setup(self, args):
        options, _ = self.option_parser().parse_known_args(args)
        if options.upload_success_text is not None and not options.upload_success_text.strip():
            raise ValueError('--upload-success-text must not be empty')
        self.success_text = options.upload_success_text
        self.skip_eicar = options.upload_skip_eicar

    async def mutate(self, requests, context):
        return self._variants(requests)

    def _variants(self, requests):
        for req in requests:
            parts = upload_parts(req)
            if not parts:
                continue
            yield replace(req, metadata={**req.metadata, 'fileupload': {'probe': 'baseline'}})
            raw = req.body.value
            raw = raw.encode('utf-8') if isinstance(raw, str) else raw
            for start, end, field, original_name in parts:
                probes = [
                    ('control', 'uploadprobe.txt', 'text/plain'),
                    ('script-extension', 'uploadprobe.php', 'application/octet-stream'),
                    ('double-extension', 'uploadprobe.php.jpg', 'image/jpeg'),
                    ('mime-mismatch', 'uploadprobe.jpg', 'image/jpeg'),
                    ('filename-traversal', '../uploadprobe-upload.txt', 'text/plain'),
                ]
                if not self.skip_eicar:
                    probes += [('eicar', 'uploadprobe-eicar.com', 'application/octet-stream'),
                               ('eicar-disguised', 'uploadprobe-eicar.txt', 'text/plain')]
                for probe, filename, mime in probes:
                    disposition = Message()
                    disposition.add_header('Content-Disposition', 'form-data', name=field, filename=filename)
                    disposition['Content-Type'] = mime
                    head = disposition.as_bytes(policy=SMTP)
                    payload = eicar_bytes() if probe.startswith('eicar') else b'uploadprobe inert upload probe\n'
                    metadata = {**req.metadata, 'fileupload': {
                        'probe': probe, 'field': field, 'filename': filename,
                        'original_filename': original_name, 'mime': mime}}
                    if probe.startswith('eicar'):
                        metadata['leviosa.redact_traffic'] = True
                    yield replace(req, headers=without_headers(req.headers, ['Content-Length', 'Transfer-Encoding']),
                                  body=RequestBody('raw', raw[:start] + head + payload + raw[end:]),
                                  metadata=metadata)

    async def analyze_one(self, response, context):
        probe = response.request.metadata.get('fileupload')
        if not probe or probe['probe'] in {'baseline', 'control'} or not 200 <= response.status < 300:
            return
        marker = self.success_text is not None and self.success_text.encode('utf-8') in response.body
        if self.success_text is not None and not marker:
            return
        evidence = {**probe, 'status': response.status, 'success_marker_matched': marker}
        self.report(response, context,
                    f'[FILEUPLOAD] {probe["probe"]}: ' +
                    ('upload acceptance marker matched' if marker else 'possible upload acceptance (2xx only)') +
                    f' — {response.request.url}; storage, execution and later AV scanning are unverified',
                    evidence=evidence, confidence='indicator' if marker else 'observation')
