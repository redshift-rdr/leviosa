"""Bounded, baseline-aware probes for client-controlled business rules."""
import argparse
import copy
import itertools
import json
import re
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from core.headers import without_headers
from core.tooltags import BurpTool
from modules.base import BaseModule

_NUMERIC = {'quantity', 'qty', 'count', 'price', 'unitprice', 'amount', 'total', 'subtotal',
            'discount', 'discountamount', 'discountpercent', 'credit', 'credits', 'balance',
            'limit', 'duration', 'shipping', 'shippingcost', 'tax', 'taxamount'}
_FLAGS = {'isadmin', 'admin', 'ispaid', 'paid', 'verified', 'isverified', 'approved',
          'isapproved', 'authorized', 'isauthorized'}
_STATES = {'role': ['admin'], 'userrole': ['admin'], 'status': ['approved', 'completed'],
           'state': ['approved', 'completed'], 'plan': ['premium'], 'tier': ['premium'],
           'coupon': ['BUSINESSLOGIC_INVALID_COUPON'], 'couponcode': ['BUSINESSLOGIC_INVALID_COUPON'],
           'promocode': ['BUSINESSLOGIC_INVALID_COUPON'], 'currency': ['BUSINESSLOGIC_INVALID_CURRENCY']}


def leaves(value, path=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from leaves(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from leaves(child, (*path, index))
    else:
        yield path, value


def pointer(path):
    return '/'.join(str(key).replace('~', '~0').replace('/', '~1') for key in path) or '$'


def inputs(req):
    """Stable input addresses retain repeated query/form fields and nested JSON paths."""
    for index, (name, value) in enumerate(parse_qsl(urlsplit(req.url).query, keep_blank_values=True)):
        yield {'source': 'url', 'index': index, 'path': (), 'location': 'query', 'parameter': name, 'value': value, 'leaf': name}
    for index, param in enumerate(req.params):
        if param.type not in {'query', 'form', 'json'}:
            continue
        if param.type != 'json' and isinstance(param.value, (dict, list)):
            continue
        for path, value in leaves(param.value):
            name = pointer((param.name, *path)) if param.type == 'json' else param.name
            leaf = next((key for key in reversed(path) if isinstance(key, str)), param.name)
            yield {'source': 'param', 'index': index, 'path': path, 'location': param.type,
                   'parameter': name, 'value': value, 'leaf': leaf}
    if req.body is not None and req.body.kind == 'json':
        for path, value in leaves(req.body.value):
            leaf = next((key for key in reversed(path) if isinstance(key, str)), '')
            yield {'source': 'body', 'path': path, 'location': 'json', 'parameter': pointer(path), 'value': value, 'leaf': leaf}


def set_leaf(value, path, replacement, omit):
    if not path:
        return replacement
    parent = value
    for key in path[:-1]:
        parent = parent[key]
    if omit:
        del parent[path[-1]]
    else:
        parent[path[-1]] = replacement
    return value


def text_value(value):
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    return str(value)


def mutate_input(req, target, operation, value):
    variant = replace(copy.deepcopy(req))
    if target['source'] == 'url':
        parts = urlsplit(req.url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        index = target['index']
        name, _ = pairs[index]
        if operation == 'omit':
            del pairs[index]
        elif operation == 'duplicate':
            pairs.insert(index + 1, (name, text_value(value)))
        else:
            pairs[index] = (name, text_value(value))
        variant.url = urlunsplit(parts._replace(query=urlencode(pairs)))
    elif target['source'] == 'param':
        index, path = target['index'], target['path']
        param = variant.params[index]
        if target['location'] in {'query', 'form'}:
            value = text_value(value)
        if operation == 'omit' and not path:
            del variant.params[index]
        elif operation == 'duplicate':
            variant.params.insert(index + 1, replace(param, value=value))
        else:
            param.value = set_leaf(param.value, path, value, operation == 'omit')
    else:
        variant.body.value = set_leaf(variant.body.value, target['path'], value, operation == 'omit')
    variant.headers = without_headers(variant.headers, ['Content-Length', 'Transfer-Encoding'])
    return variant


def defaults(target):
    parts = re.findall(r'[^.\[\]]+', target['leaf'])
    leaf = next((part for part in reversed(parts) if not part.isdigit()), target['leaf'])
    name = re.sub('[^a-z0-9]', '', leaf.lower())
    value = target['value']
    if name in _NUMERIC:
        if isinstance(value, bool):
            return []
        try:
            float(value)
        except (TypeError, ValueError, OverflowError):
            return []
        values = [-1, 0, 0.5, 1000000000]
        return [str(item) for item in values] if isinstance(value, str) else values
    if name in _FLAGS:
        return [True] if isinstance(value, bool) else ['true', '1']
    return _STATES.get(name, [])


class BusinessLogic(BaseModule):
    """Probe business input boundaries, field omission, duplicate fields and client-controlled workflow/privilege values."""

    tool = BurpTool.SCANNER
    follow_redirects = False

    path_options = {'--logic-rules': 'file'}

    def __init__(self):
        self.rules = None
        self.success_text = None
        self.max_probes = 80

    def option_parser(self):
        parser = argparse.ArgumentParser(prog='businesslogic', add_help=False, allow_abbrev=False)
        parser.add_argument('--logic-rules', help='JSON rejection rules with method, url, location, parameter, values and success_text')
        parser.add_argument('--logic-success-text', help='Response marker required for default acceptance observations, in addition to 2xx')
        parser.add_argument('--logic-max-probes', type=int, default=80, help='Maximum probes per seed, excluding baseline (1–1000; default 80)')
        return parser

    def setup(self, args):
        options, _ = self.option_parser().parse_known_args(args)
        if not 1 <= options.logic_max_probes <= 1000:
            raise ValueError('--logic-max-probes must be between 1 and 1000')
        if options.logic_success_text is not None and not options.logic_success_text.strip():
            raise ValueError('--logic-success-text must not be empty')
        self.max_probes, self.success_text = options.logic_max_probes, options.logic_success_text
        if options.logic_rules:
            rules = json.loads(Path(options.logic_rules).read_text(encoding='utf-8'))
            if not isinstance(rules, list) or not rules:
                raise ValueError('--logic-rules must contain a nonempty array')
            allowed = {'method', 'url', 'location', 'parameter', 'values', 'omit', 'duplicate', 'success_text'}
            for rule in rules:
                if not isinstance(rule, dict) or rule.keys() - allowed:
                    raise ValueError('Invalid business logic rule keys')
                for field in ('method', 'url', 'parameter', 'success_text'):
                    if not isinstance(rule.get(field), str) or not rule[field].strip():
                        raise ValueError(f'Logic rule {field} must be nonempty text')
                if not isinstance(rule.get('location'), str) or rule['location'] not in {'query', 'form', 'json'}:
                    raise ValueError('Logic rule location must be query, form or json')
                if not isinstance(rule.get('values'), list) or not 1 <= len(rule['values']) <= 100:
                    raise ValueError('Logic rule values must contain 1–100 values')
                if any(isinstance(value, (dict, list)) for value in rule['values']):
                    raise ValueError('Logic rule values must be JSON scalars')
                json.dumps(rule['values'], allow_nan=False)
                for flag in ('omit', 'duplicate'):
                    if type(rule.get(flag, False)) is not bool:
                        raise ValueError(f'Logic rule {flag} must be true or false')
                if rule.get('duplicate') and rule['location'] == 'json':
                    raise ValueError('Duplicate probes support query/form fields only')
            self.rules = rules

    def proposals(self, req):
        rules = [rule for rule in self.rules or [] if rule['method'].upper() == req.method.upper() and rule['url'] == req.url]
        if self.rules is not None and not rules:
            return
        for target in inputs(req):
            configs = [rule for rule in rules if rule['location'] == target['location'] and rule['parameter'] == target['parameter']]
            if self.rules is None:
                values = defaults(target)
                configs = [{'values': values, 'omit': True, 'duplicate': True, 'success_text': self.success_text}] if values else []
            for rule in configs:
                # Every supplied value is a value the tester expects to be rejected.
                values = rule['values']
                for value in values:
                    if type(value) is type(target['value']) and value == target['value']:
                        continue
                    yield target, 'replace', value, rule.get('success_text')
                if rule.get('omit') and (target['source'] != 'body' or target['path']):
                    yield target, 'omit', None, rule.get('success_text')
                if rule.get('duplicate') and target['location'] in {'query', 'form'} and not target['path']:
                    yield target, 'duplicate', values[0], rule.get('success_text')

    async def mutate(self, requests, context):
        return self._variants(requests)

    def _variants(self, requests):
        for req in requests:
            proposals = iter(itertools.islice(self.proposals(req), self.max_probes))
            first = next(proposals, None)
            if first is None:
                continue
            group = uuid4().hex
            yield replace(req, metadata={**req.metadata, 'businesslogic': {'group': group, 'operation': 'baseline'}})
            for target, operation, value, marker in itertools.chain([first], proposals):
                variant = mutate_input(req, target, operation, value)
                yield replace(variant, metadata={**variant.metadata, 'businesslogic': {
                    'group': group, 'location': target['location'], 'parameter': target['parameter'],
                    'operation': operation, 'value': value, 'success_text': marker,
                    'explicit_rule': self.rules is not None}})

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('businesslogic')
        if meta is None:
            return
        entry = context.state.setdefault('businesslogic', {}).setdefault(meta['group'], {'baseline': None, 'hits': []})
        if meta['operation'] == 'baseline':
            # Keep only markers needed by rules, not a potentially large response.
            markers = {rule['success_text'] for rule in self.rules or []}
            if self.success_text:
                markers.add(self.success_text)
            entry['baseline'] = (response.status, {text for text in markers if text.encode() in response.body})
        elif 200 <= response.status < 300 and (meta['success_text'] is None or meta['success_text'].encode() in response.body):
            entry['hits'].append(replace(response, body=b'', traffic=[]))

    async def finalize(self, context):
        for entry in context.state.pop('businesslogic', {}).values():
            baseline = entry['baseline']
            if baseline is None or not 200 <= baseline[0] < 300:
                continue
            for response in entry['hits']:
                meta = response.request.metadata['businesslogic']
                if meta['success_text'] is not None and meta['success_text'] not in baseline[1]:
                    continue
                kind = 'Rejection rule potentially violated' if meta['explicit_rule'] else 'Possible acceptance; verify business outcome'
                self.report(response, context,
                            f'[BUSINESSLOGIC] {kind}: {meta["operation"]} {meta["location"]} {meta["parameter"]}',
                            evidence={key: value for key, value in meta.items() if key not in {'group', 'success_text'}} |
                                     {'baseline_status': baseline[0], 'status': response.status,
                                      'success_marker_matched': meta['success_text'] is not None},
                            confidence='indicator' if meta['explicit_rule'] else 'observation')
