"""Evidence and correlation helpers for payload modules."""
import base64
import binascii
from dataclasses import replace
import json
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.models import LeviosaResponse


_PASSWD = re.compile(r'(?m)(?:^|[>\n])root:[^:\r\n<]*:0:0:[^:\r\n<]*:[^:\r\n<]*:/[^:\r\n<]+(?=\r?$|<)')
_SECTIONS = re.compile(r'(?im)(?:^|[>\n])[ \t]*\[(fonts|extensions|mci extensions|files|windows)\][ \t]*(?=\r?$|<)')
_BASE64 = re.compile(r'(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])')


def payloads_from(path, defaults, name):
    values = list(defaults) if path is None else [
        line for line in Path(path).read_text(encoding='utf-8').splitlines() if line.strip()]
    if not values:
        raise ValueError(f'{name}: payload file is empty')
    return values


def validate_markers(markers):
    if any(not marker.strip() for marker in markers):
        raise ValueError('expected markers must not be empty')


def file_signatures(body, markers=(), decode_base64=False):
    def plain(text):
        found = set()
        if _PASSWD.search(text):
            found.add('unix-passwd')
        if len({s.lower() for s in _SECTIONS.findall(text)}) >= 2:
            found.add('windows-win.ini')
        found.update(f'custom-marker-{i + 1}' for i, marker in enumerate(markers) if marker in text)
        return found
    text = body.decode('utf-8', 'replace')
    found = plain(text)
    if decode_base64:
        for match in _BASE64.finditer(text):
            try:
                decoded = base64.b64decode(match.group(), validate=True).decode('utf-8', 'replace')
            except (ValueError, binascii.Error):
                continue
            found.update('base64:' + item for item in plain(decoded))
    return found


async def compare_response(module, response, context, namespace, signatures):
    """One baseline and a known number of probes; allow completion out of order."""
    meta = response.request.metadata.get(namespace)
    if meta is None:
        return
    results = context.state.setdefault(namespace + '.results', {})
    entry = results.setdefault(meta['seed'], {'remaining': meta['total'], 'baseline': set(), 'status': 0, 'hits': []})
    if meta['baseline']:
        entry['baseline'], entry['status'] = signatures, response.status
    elif signatures and response.status:
        entry['hits'].append((replace(response, body=b'', traffic=[]), signatures))
    entry['remaining'] -= 1
    if not entry['remaining']:
        try:
            if entry['status']:
                for hit, found in entry['hits']:
                    m = hit.request.metadata[namespace]
                    known = {item.removeprefix('base64:') for item in entry['baseline']}
                    added = {item for item in found if item.removeprefix('base64:') not in known}
                    if added:
                        module.report(hit, context, f'[{namespace.upper()}] Evidence via {m["location"]} {m["parameter"]}: {", ".join(sorted(added))}',
                                      evidence={'parameter': m['parameter'], 'location': m['location'],
                                                'payload': m['payload'], 'signatures': sorted(added),
                                                'baseline_status': entry['status']},
                                      confidence='observation' if added == {'internal-entity-expansion'} else 'indicator')
        finally:
            del results[meta['seed']]


class Interactions:
    """Match exact per-probe tokens in a user-supplied callback listener log."""

    def __init__(self, callback=None, path=None):
        self.callback, self.path = callback, path
        self.pending = {}
        self.request_tokens = {}
        if callback is not None:
            parts = urlsplit(callback)
            if (parts.scheme not in {'http', 'https'} or not parts.hostname or parts.fragment or parts.username or parts.password
                    or any(char.isspace() or char in '"<>' for char in callback)):
                raise ValueError('callback must be an HTTP(S) URL without credentials or fragment')
            parts.port
        if path is not None:
            if callback is None:
                raise ValueError('an interactions log requires a callback URL')
            self.events()  # Validate existing complete records before any traffic.

    def url(self, token):
        if self.callback is None:
            return ''
        parts = urlsplit(self.callback)
        query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != 'leviosa']
        return urlunsplit(parts._replace(query=urlencode([*query, ('leviosa', token)])))

    def track(self, token, request, namespace):
        if self.path is not None:
            self.pending[token] = request
            self.request_tokens[request.request_id] = token

    def observe(self, request):
        token = self.request_tokens.get(request.request_id)
        if token is not None:
            self.pending[token] = request

    def events(self):
        events = []
        if self.path is None:
            return events
        text = Path(self.path).read_text(encoding='utf-8')
        lines = text.splitlines()
        for number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except ValueError:
                # A listener may currently be appending the final record.
                if number == len(lines) and not text.endswith('\n'):
                    continue
                raise ValueError(f'invalid interaction JSON on line {number}') from None
            if not isinstance(event, dict) or not isinstance(event.get('token'), str) or not event['token']:
                raise ValueError(f'interaction line {number} requires a nonempty token string')
            events.append(event)
        return events

    def report(self, module, context, namespace):
        try:
            for event in self.events():
                request = self.pending.pop(event['token'], None)
                if request is not None:
                    meta = request.metadata[namespace]
                    module.report(LeviosaResponse(0, {}, b'', request), context,
                                  f'[{namespace.upper()}] Correlated callback; replay inputs to verify the requesting component',
                                  evidence={'token': event['token'], 'callback': self.url(event['token']),
                                            'payload': meta['payload'], 'location': meta['location'],
                                            'parameter': meta['parameter'], 'source': 'interaction-log'}, confidence='indicator')
        finally:
            self.pending.clear()
            self.request_tokens.clear()
