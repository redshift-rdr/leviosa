import argparse
from dataclasses import replace
import re
from secrets import randbelow
from uuid import uuid4

from core.payloadchecks import payloads_from, validate_markers
from core.probes import input_variants
from core.tooltags import BurpTool
from modules.base import BaseModule


_DEFAULTS = ('{{{expression}}}', '${{expression}}', '#{{expression}}',
             '<%= {expression} %>', '[[${{expression}}]]', '{math equation="{expression}"}')
_ARITHMETIC = re.compile(r'\b(\d{1,5})\s*([*+])\s*(\d{1,5})\b')


class Ssti(BaseModule):
    """Paired arithmetic payloads for server-side template injection."""

    tool = BurpTool.INTRUDER
    follow_redirects = False
    path_options = {'--ssti-payloads': 'file'}

    def __init__(self):
        self._payloads = list(_DEFAULTS)
        self._markers = []

    def option_parser(self):
        parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
        parser.add_argument('--ssti-payloads', metavar='FILE', help='Template payloads; {expression} expands to paired arithmetic probes')
        parser.add_argument('--ssti-marker', action='append', default=[], metavar='TEXT', help='Additional literal expected output for custom probes (repeatable)')
        return parser

    def setup(self, args):
        opts, _ = self.option_parser().parse_known_args(args)
        self._payloads = payloads_from(opts.ssti_payloads, _DEFAULTS, 'ssti')
        self._markers = opts.ssti_marker
        validate_markers(self._markers)

    async def mutate(self, requests, context):
        def variants():
            for seed, req in enumerate(requests):
                count = sum(1 for _ in input_variants(req, ''))
                if not count:
                    continue
                prefix, suffix = 'lv' + uuid4().hex + '_', '_' + uuid4().hex
                pairs = []
                for template in self._payloads:
                    match = _ARITHMETIC.search(template)
                    if '{expression}' in template or match:
                        left, right = 101 + randbelow(800), 101 + randbelow(800)
                        expressions = (f'{left}*{right}', f'{left}*{right + 1}')
                        rendered = [template.replace('{expression}', expr) if '{expression}' in template else
                                    template[:match.start()] + expr + template[match.end():] for expr in expressions]
                        pairs.append([(prefix + value + suffix, prefix + str(left * (right + i)) + suffix)
                                      for i, value in enumerate(rendered)])
                    else:
                        pairs.append([(template, None)])
                total = 1 + count * sum(map(len, pairs))
                def tagged(variant, baseline, location='', name='', payload='', pair=None, arm=None, expected=None):
                    return replace(variant, metadata={**variant.metadata, 'ssti': {
                        'seed': seed, 'total': total, 'baseline': baseline, 'location': location,
                        'parameter': name, 'payload': payload, 'pair': pair, 'arm': arm, 'expected': expected}})
                yield tagged(req, True)
                for pair, probes in enumerate(pairs):
                    for arm, (payload, expected) in enumerate(probes):
                        for input_index, (location, name, variant) in enumerate(input_variants(req, payload)):
                            yield tagged(variant, False, location, name, payload, (pair, input_index), arm, expected)
        return variants()

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('ssti')
        if meta is None:
            return
        entries = context.state.setdefault('ssti.results', {})
        entry = entries.setdefault(meta['seed'], {'remaining': meta['total'], 'baseline': '', 'status': 0, 'pairs': {}, 'custom': []})
        text = response.body.decode('utf-8', 'replace') if response.status else ''
        if meta['baseline']:
            entry['baseline'], entry['status'] = text, response.status
        else:
            hit = replace(response, body=b'', traffic=[])
            if meta['expected'] and meta['expected'] in text and meta['expected'] not in meta['payload']:
                entry['pairs'].setdefault(meta['pair'], {})[meta['arm']] = (hit, meta['expected'])
            markers = [i + 1 for i, value in enumerate(self._markers) if value in text and value not in meta['payload']]
            if markers:
                entry['custom'].append((hit, markers))
        entry['remaining'] -= 1
        if not entry['remaining']:
            try:
                if entry['status']:
                    for arms in entry['pairs'].values():
                        if set(arms) == {0, 1} and all(expected not in entry['baseline'] for _, expected in arms.values()):
                            hit, expected = arms[0]
                            m = hit.request.metadata['ssti']
                            self.report(hit, context, f'[SSTI] Paired arithmetic evaluation via {m["location"]} {m["parameter"]}',
                                        evidence={'parameter': m['parameter'], 'location': m['location'],
                                                  'payload': m['payload'], 'paired_payload': arms[1][0].request.metadata['ssti']['payload'],
                                                  'expected_results': [arms[i][1] for i in (0, 1)]}, confidence='indicator')
                    for hit, markers in entry['custom']:
                        added = [i for i in markers if self._markers[i - 1] not in entry['baseline']]
                        if added:
                            m = hit.request.metadata['ssti']
                            self.report(hit, context, f'[SSTI] Custom output indicator via {m["location"]} {m["parameter"]}',
                                        evidence={'parameter': m['parameter'], 'location': m['location'], 'payload': m['payload'],
                                                  'markers': added}, confidence='indicator')
            finally:
                del entries[meta['seed']]
