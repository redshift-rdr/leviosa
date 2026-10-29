import argparse
from dataclasses import replace
from uuid import uuid4

from core.payloadchecks import Interactions, compare_response, file_signatures, payloads_from, validate_markers
from core.probes import input_variants
from core.tooltags import BurpTool
from modules.base import BaseModule


_DEFAULTS = ('file:///etc/passwd', 'file:///C:/Windows/win.ini',
             'http://127.0.0.1/', 'http://[::1]/', 'http://localhost/', '{callback}')


class Ssrf(BaseModule):
    """Payload-based SSRF checks using response evidence or correlated callbacks."""

    tool = BurpTool.INTRUDER
    follow_redirects = False
    path_options = {'--ssrf-payloads': 'file', '--ssrf-interactions': 'file'}

    def __init__(self):
        self._payloads = list(_DEFAULTS)
        self._markers = []
        self._interactions = Interactions()

    def option_parser(self):
        parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
        parser.add_argument('--ssrf-payloads', metavar='FILE', help='Payload file; optional {callback} placeholder')
        parser.add_argument('--ssrf-marker', action='append', default=[], metavar='TEXT', help='Expected controlled endpoint response text (repeatable)')
        parser.add_argument('--ssrf-callback', metavar='URL', help='Controlled HTTP(S) callback endpoint; receives a leviosa query token')
        parser.add_argument('--ssrf-interactions', metavar='FILE', help='Listener JSONL with exact token fields; checked at finalize')
        return parser

    def setup(self, args):
        opts, _ = self.option_parser().parse_known_args(args)
        self._payloads = payloads_from(opts.ssrf_payloads, _DEFAULTS, 'ssrf')
        self._markers = opts.ssrf_marker
        validate_markers(self._markers)
        self._interactions = Interactions(opts.ssrf_callback, opts.ssrf_interactions)
        if opts.ssrf_payloads and any('{callback}' in p for p in self._payloads) and not opts.ssrf_callback:
            raise ValueError('SSRF callback payloads require --ssrf-callback')

    async def mutate(self, requests, context):
        def variants():
            for index, req in enumerate(requests):
                count = sum(1 for _ in input_variants(req, ''))
                templates = [p for p in self._payloads if '{callback}' not in p or self._interactions.callback]
                if not count or not templates:
                    continue
                total = 1 + count * len(templates)
                def metadata(baseline, location='', name='', payload=''):
                    return {**req.metadata, 'ssrf': {'seed': index, 'total': total, 'baseline': baseline,
                            'location': location, 'parameter': name, 'payload': payload}}
                yield replace(req, metadata=metadata(True))
                for template in templates:
                    rendered = {}
                    def render():
                        token = uuid4().hex
                        payload = template.replace('{callback}', self._interactions.url(token))
                        rendered.update(token=token, payload=payload)
                        return payload
                    for location, name, variant in input_variants(req, render):
                        variant = replace(variant, metadata=metadata(False, location, name, rendered['payload']))
                        if '{callback}' in template:
                            self._interactions.track(rendered['token'], variant, 'ssrf')
                        yield variant
        return variants()

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('ssrf')
        if meta is None:
            return
        self._interactions.observe(response.request)
        signatures = file_signatures(response.body, self._markers) if response.status else set()
        if not meta['baseline']:
            signatures -= file_signatures(meta['payload'].encode(), self._markers)
        await compare_response(self, response, context, 'ssrf', signatures)

    async def finalize(self, context):
        self._interactions.report(self, context, 'ssrf')
