import argparse
from dataclasses import replace
from pathlib import Path
import re
from uuid import uuid4

from core.probes import input_variants
from core.tooltags import BurpTool
from modules.base import BaseModule


_DEFAULT_PAYLOADS = (
    ';{posix};#', '&&{posix};#', '|{posix};#', '\n{posix}\n',
    '$({posix})', '`{posix}`', "';{posix};#", '";{posix};#',
    '&{cmd}&rem ', '"&{cmd}&rem ',
    ';{powershell};#', "';{powershell};#",
)
_UNIX_ID = re.compile(r'\buid=\d+\([^()\r\n]+\)[ \t]+gid=\d+\([^()\r\n]+\)')
_WINDOWS_SID = re.compile(r'\bS-1-5-(?:\d+-){2,}\d+\b')


class CommandInjection(BaseModule):
    """Payload-based OS command injection checks using output evidence."""

    tool = BurpTool.INTRUDER
    follow_redirects = False
    path_options = {'--command-payloads': 'file'}

    def __init__(self):
        self._payloads = list(_DEFAULT_PAYLOADS)
        self._markers = []

    def option_parser(self):
        parser = argparse.ArgumentParser(prog='commandinjection', add_help=False, allow_abbrev=False)
        parser.add_argument('--command-payloads', metavar='FILE',
                            help='UTF-8 payload file, one per nonblank line; supports {posix}, {cmd}, {powershell}, {marker}')
        parser.add_argument('--command-marker', metavar='TEXT', action='append', default=[],
                            help='Additional literal expected command output (repeatable)')
        return parser

    def setup(self, args):
        parsed, _ = self.option_parser().parse_known_args(args)
        self._payloads = list(_DEFAULT_PAYLOADS)
        self._markers = parsed.command_marker
        if any(not marker.strip() for marker in self._markers):
            raise ValueError('command markers must not be empty')
        if parsed.command_payloads:
            self._payloads = [line for line in Path(parsed.command_payloads).read_text(encoding='utf-8').splitlines() if line.strip()]
            if not self._payloads:
                raise ValueError('commandinjection: payload file is empty')

    @staticmethod
    def _render(template, marker):
        left, right = marker[:len(marker) // 2], marker[len(marker) // 2:]
        replacements = {
            '{posix}': f"printf '%s%s' '{left}' '{right}'",
            '{cmd}': 'echo ' + left + '^' + right,
            '{powershell}': f"Write-Output ('{left}'+'{right}')",
            '{marker}': marker,
        }
        # One pass preserves braces in user payloads and avoids recursive expansion.
        return re.sub(r'\{(?:posix|cmd|powershell|marker)\}', lambda m: replacements[m.group()], template)

    def _signatures(self, body, marker):
        text = body.decode('utf-8', 'replace')
        signatures = set()
        if marker in text:
            signatures.add('generated-command-marker')
        if _UNIX_ID.search(text):
            signatures.add('unix-id-output')
        if _WINDOWS_SID.search(text):
            signatures.add('windows-sid-output')
        for index, expected in enumerate(self._markers):
            if expected in text:
                signatures.add(f'custom-marker-{index + 1}')
        return signatures

    async def mutate(self, requests, context):
        def variants():
            for index, request in enumerate(requests):
                count = sum(1 for _ in input_variants(request, ''))
                if not count:
                    continue
                marker = 'cmdprobe' + uuid4().hex
                total = 1 + count * len(self._payloads)
                yield replace(request, metadata={**request.metadata,
                    'commandinjection': (index, None, None, None, marker, total)})
                for template in self._payloads:
                    payload = self._render(template, marker)
                    for location, name, variant in input_variants(request, payload):
                        yield replace(variant, metadata={**variant.metadata,
                            'commandinjection': (index, location, name, payload, marker, total)})
        return variants()

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('commandinjection')
        if meta is None:
            return
        index, location, name, payload, marker, total = meta
        results = context.state.setdefault('commandinjection.results', {})
        entry = results.setdefault(index, {'remaining': total, 'baseline': set(), 'baseline_status': 0, 'hits': []})
        signatures = self._signatures(response.body, marker) if response.status else set()
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
                        added = signatures - entry['baseline'] - self._signatures(payload.encode(), marker)
                        if added:
                            self.report(hit, context,
                                f'[COMMANDINJECTION] Command-output indicator via {location} {name}: {", ".join(sorted(added))}',
                                evidence={'parameter': name, 'location': location, 'payload': payload,
                                          'signatures': sorted(added), 'baseline_status': entry['baseline_status']},
                                confidence='indicator')
            finally:
                del results[index]
