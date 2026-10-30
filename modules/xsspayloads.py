import argparse
from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path
from uuid import uuid4

from core.probes import input_variants
from core.tooltags import BurpTool
from modules.base import BaseModule


# Common script, event-handler, URI and quote-breakout probe families, also
# represented in SecLists/Fuzzing/XSS. No external resources are required.
_DEFAULT_PAYLOADS = (
    '<script>alert("{marker}")</script>',
    '<img src=x onerror=alert("{marker}")>',
    '<svg onload=alert("{marker}")>',
    '\"><img src=x onerror=alert("{marker}")>',
    "'><svg onload=alert(\"{marker}\")>",
    '</script><script>alert("{marker}")</script>',
    "javascript:alert('{marker}')",
    "';alert('{marker}');//",
    '\";alert(\"{marker}\");//',
)


class _ExecutableContexts(HTMLParser):
    """Collect candidate code, without claiming to implement browser parsing."""

    _INERT = {'textarea', 'title', 'xmp', 'plaintext', 'template', 'noscript'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.surfaces = set()
        self.script_executable = True

    def handle_starttag(self, tag, attrs):
        blocked = bool(self._INERT.intersection(self.stack)) or tag in self._INERT
        if tag == 'script':
            script_type = dict(attrs).get('type') or ''
            self.script_executable = script_type.strip().lower() in {
                '', 'module', 'text/javascript', 'application/javascript',
                'text/ecmascript', 'application/ecmascript',
            }
        if not blocked:
            for name, value in attrs:
                if not value:
                    continue
                if name.startswith('on'):
                    self.surfaces.add(('event handler', value))
                elif name in {'href', 'src', 'action', 'formaction', 'xlink:href'} and value.lstrip().lower().startswith('javascript:'):
                    self.surfaces.add(('JavaScript URL', value.split(':', 1)[1]))
                elif tag == 'script' and name == 'src' and self.script_executable:
                    self.surfaces.add(('script source', value))
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.stack:
            self.stack = self.stack[:len(self.stack) - 1 - self.stack[::-1].index(tag)]

    def handle_data(self, data):
        if self.stack and self.stack[-1] == 'script' and self.script_executable and not self._INERT.intersection(self.stack):
            self.surfaces.add(('script text', data))


def _surfaces(text):
    parser = _ExecutableContexts()
    parser.feed(text)
    parser.close()
    return parser.surfaces


def _matches(payload, surfaces):
    snippets = {value.strip() for _, value in _surfaces(payload) if value.strip()}
    # Standalone JavaScript URI and quote-breakout payloads have no HTML tags.
    if not snippets:
        snippets = {payload.split(':', 1)[1] if payload.lower().startswith('javascript:') else payload}
    return {kind for kind, code in surfaces if any(snippet and snippet in code for snippet in snippets)}


class XssPayloads(BaseModule):
    """Payload-based reflected XSS scan; candidate execution needs browser verification."""

    tool = BurpTool.INTRUDER
    follow_redirects = False
    path_options = {'--xss-payloads': 'file'}

    def __init__(self):
        self._payloads = list(_DEFAULT_PAYLOADS)

    def option_parser(self):
        parser = argparse.ArgumentParser(prog='xsspayloads', add_help=False, allow_abbrev=False)
        parser.add_argument('--xss-payloads', metavar='FILE',
                            help='UTF-8 payload file, one per line; replaces built-ins. Optional {marker} placeholder')
        return parser

    def setup(self, args):
        parsed, _ = self.option_parser().parse_known_args(args)
        self._payloads = list(_DEFAULT_PAYLOADS)
        if parsed.xss_payloads:
            # Preserve whitespace and literal percent escapes; only strip framing.
            self._payloads = [line for line in Path(parsed.xss_payloads).read_text(encoding='utf-8').splitlines() if line.strip()]
            if not self._payloads:
                raise ValueError('xsspayloads: payload file is empty')

    async def mutate(self, requests, context):
        def variants():
            for index, request in enumerate(requests):
                inputs = sum(1 for _ in input_variants(request, ''))
                if not inputs:
                    continue
                marker = 'xssprobe' + uuid4().hex
                payloads = [payload.replace('{marker}', marker) for payload in self._payloads]
                total = 1 + inputs * len(payloads)
                yield replace(request, metadata={**request.metadata,
                    'xsspayloads': (index, None, None, None, total)})
                for payload in payloads:
                    for location, name, variant in input_variants(request, payload):
                        yield replace(variant, metadata={**variant.metadata,
                            'xsspayloads': (index, location, name, payload, total)})
        return variants()

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('xsspayloads')
        if meta is None:
            return
        index, location, name, payload, total = meta
        results = context.state.setdefault('xsspayloads.results', {})
        entry = results.setdefault(index, {'remaining': total, 'baseline': set(), 'baseline_ok': False, 'hits': []})
        media = response.headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
        is_html = response.status != 0 and media in {'text/html', 'application/xhtml+xml'}
        surfaces = _surfaces(response.body.decode('utf-8', 'replace')) if is_html else set()
        if location is None:
            entry['baseline'] = surfaces
            entry['baseline_ok'] = response.status != 0
        elif surfaces and (contexts := _matches(payload, surfaces)):
            entry['hits'].append((replace(response, body=b'', traffic=[]), payload, location, name, contexts))
        entry['remaining'] -= 1
        if entry['remaining'] == 0:
            try:
                if entry['baseline_ok']:
                    for hit, payload, location, name, contexts in entry['hits']:
                        added = contexts - _matches(payload, entry['baseline'])
                        if added:
                            self.report(hit, context,
                                f'[XSSPAYLOADS] Potential XSS via {location} {name}; browser verification required',
                                evidence={'parameter': name, 'location': location, 'payload': payload,
                                          'contexts': sorted(added), 'execution_confirmed': False},
                                confidence='indicator')
            finally:
                del results[index]
