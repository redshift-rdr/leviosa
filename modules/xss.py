from dataclasses import replace
from html.parser import HTMLParser
from uuid import uuid4

from core.probes import input_variants
from core.tooltags import BurpTool
from modules.base import BaseModule


class _Contexts(HTMLParser):
    def __init__(self, marker):
        super().__init__(convert_charrefs=False)
        self.marker = marker
        self.contexts = set()
        self.stack = []

    def handle_starttag(self, tag, attrs):
        self.stack.append(tag)
        if tag == 'leviosa-probe' and any(k == 'data-marker' and v == self.marker for k, v in attrs):
            self.contexts.add('injected HTML element')
        for name, value in attrs:
            if value and self.marker in value:
                self.contexts.add('event handler' if name.startswith('on') else
                                  'URL attribute' if name in {'href', 'src', 'action', 'formaction'} else
                                  'HTML attribute')

    def handle_endtag(self, tag):
        if tag in self.stack:
            self.stack = self.stack[:len(self.stack) - 1 - self.stack[::-1].index(tag)]

    def handle_data(self, data):
        if self.marker in data:
            self.contexts.add('script text' if self.stack and self.stack[-1] == 'script' else 'HTML text')


class ReflectedXss(BaseModule):
    """Identify reflected XSS candidates; browser execution is not confirmed."""

    tool = BurpTool.REPEATER
    follow_redirects = False

    async def mutate(self, requests, context):
        def variants():
            for request in requests:
                marker = 'leviosa' + uuid4().hex
                payload = f'\'\"><leviosa-probe data-marker="{marker}"></leviosa-probe>'
                for location, name, variant in input_variants(request, payload):
                    yield replace(variant, metadata={**variant.metadata,
                        'xss': (marker, location, name, payload)})
        return variants()

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('xss')
        media = response.headers.get('Content-Type', '').split(';')[0].strip().lower()
        if not meta or response.status == 0 or media not in {'text/html', 'application/xhtml+xml'}:
            return
        marker, location, name, payload = meta
        text = response.body.decode('utf-8', 'replace')
        if marker not in text:
            return
        parser = _Contexts(marker)
        parser.feed(text)
        # Encoded reflection in text/ordinary attributes is informational only.
        risky = parser.contexts & {'injected HTML element', 'script text', 'event handler', 'URL attribute'}
        self.report(response, context,
                    f'[XSS] {"Potential unsafe reflection" if risky else "Reflected input"} via {location} {name}; browser verification required',
                    evidence={'parameter': name, 'location': location, 'payload': payload,
                              'contexts': sorted(parser.contexts), 'execution_confirmed': False},
                    confidence='indicator' if risky else 'observation')
