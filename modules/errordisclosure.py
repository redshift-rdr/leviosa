"""Find disclosure introduced by error-provoking requests, compared with a baseline."""
import argparse
import re
from dataclasses import replace
from uuid import uuid4

from core.headers import parse_headers, without_headers
from core.models import RequestBody
from core.probes import input_variants
from core.tooltags import BurpTool
from modules.base import BaseModule
from modules.errorpages import ErrorPages, _SIGNATURES

_NAMESPACE = 'errordisclosure'
# Error context is required: technology names in normal pages are not disclosures.
_SIGNATURES = [(name, pattern) for name, pattern in _SIGNATURES
               if name not in {'python-traceback', 'dotnet-error', 'sql-error', 'debug-info'}] + [
    ('python-traceback', re.compile(r'Traceback \(most recent call last\)|File "[^"\r\n]+", line \d+, in ', re.I)),
    ('dotnet-error', re.compile(r'System\.[\w.]*Exception\b|\.cs:line \d+|Server Error in [^\r\n]{1,100} Application', re.I)),
    ('sql-error', re.compile(r'You have an error in your SQL syntax|SQLSTATE\[[\w]+\]|ORA-\d{5}|'
                           r'Unclosed quotation mark|sqlite3\.\w*Error|PSQLException|'
                           r'PostgreSQL(?:\s+ERROR\s*:|\s*:\s*ERROR\b)|quoted string not properly terminated', re.I)),
    ('debug-info', re.compile(r'Symfony Profiler|display_errors\s*[=:]\s*(?:on|1)|'
                            r'debug(?:ging)? (?:mode|information)|application trace', re.I)),
]
_PAYLOADS = ["'\"\\", '', 'errorprobe-not-a-number', '-1', '999999999999999999999999999999', '[', '%']


def disclosures(body):
    text = body.decode('utf-8', 'replace')
    return {name: match.group(0)[:180] for name, pattern in _SIGNATURES
            if (match := pattern.search(text))}


class ErrorDisclosure(BaseModule):
    """Induce errors and report new stack traces, internal paths, SQL errors and debug details."""

    tool = BurpTool.SCANNER
    follow_redirects = False

    def __init__(self):
        self.long_path = 4096

    def option_parser(self):
        parser = argparse.ArgumentParser(prog=_NAMESPACE, add_help=False, allow_abbrev=False)
        parser.add_argument('--error-disclosure-path-length', type=int, default=4096,
                            help='Oversized path probe length, 1–16384 (default: 4096)')
        return parser

    def setup(self, args):
        options, _ = self.option_parser().parse_known_args(args)
        if not 1 <= options.error_disclosure_path_length <= 16384:
            raise ValueError('--error-disclosure-path-length must be between 1 and 16384')
        self.long_path = options.error_disclosure_path_length

    async def mutate(self, requests, context):
        return self._variants(requests)

    def _variants(self, requests):
        inducer = ErrorPages()
        inducer._long_url_len = self.long_path
        for request in requests:
            group = uuid4().hex
            def tag(variant, technique, location=None, parameter=None):
                return replace(variant, metadata={**variant.metadata, _NAMESPACE: {
                    'group': group, 'technique': technique, 'location': location, 'parameter': parameter}})
            yield tag(request, 'baseline')
            for technique, variant in inducer._induce(request, {
                    'not-found', 'bad-method', 'long-url', 'special-path', 'junk-param'}):
                yield tag(variant, technique)
            for payload in _PAYLOADS:
                for location, parameter, variant in input_variants(request, payload):
                    yield tag(variant, 'invalid-value', location, parameter)
            # JSON parameters and explicit JSON bodies can exercise type confusion.
            for payload in (None, [], {}):
                for location, parameter, variant in input_variants(request, lambda: payload):
                    if location == 'json':
                        yield tag(variant, 'invalid-json-type', location, parameter)
            content_type = parse_headers(request.headers).get('Content-Type', '').split(';')[0].strip().lower()
            if ((request.body is not None and request.body.kind == 'json') or
                    any(p.type == 'json' for p in request.params) or
                    content_type == 'application/json' or content_type.endswith('+json')):
                headers = without_headers(request.headers, ['Content-Length', 'Transfer-Encoding', 'Content-Type'])
                headers.append('Content-Type: application/json')
                yield tag(replace(request, headers=headers,
                                  params=[p for p in request.params if p.type not in {'json', 'form'}],
                                  body=RequestBody('raw', b'{"errorprobe":')),
                          'malformed-json', 'body')

    async def analyze_one(self, response, context):
        metadata = response.request.metadata.get(_NAMESPACE)
        if metadata is None:
            return
        entries = context.state.setdefault(_NAMESPACE, {})
        entry = entries.setdefault(metadata['group'], {'baseline': None, 'hits': []})
        found = disclosures(response.body) if response.status else {}
        if metadata['technique'] == 'baseline':
            entry['baseline'] = (response.status, set(found))
        elif found and response.status:
            # Retain only signature excerpts and a body-free response for reporting.
            entry['hits'].append((replace(response, body=b'', traffic=[]), found))

    async def finalize(self, context):
        entries = context.state.pop(_NAMESPACE, {})
        for entry in entries.values():
            baseline = entry['baseline']
            # A failed/missing baseline cannot establish an induced disclosure.
            if baseline is None or baseline[0] == 0:
                continue
            for response, found in entry['hits']:
                added = {name: excerpt for name, excerpt in found.items() if name not in baseline[1]}
                if not added:
                    continue
                metadata = response.request.metadata[_NAMESPACE]
                self.report(response, context,
                            f'[ERRORDISCLOSURE] New disclosure via {metadata["technique"]}: '
                            f'{", ".join(sorted(added))} — {response.request.url}',
                            evidence={**{key: value for key, value in metadata.items() if key != 'group'},
                                      'status': response.status, 'baseline_status': baseline[0],
                                      'signatures': added}, confidence='indicator')
