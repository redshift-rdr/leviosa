"""Run-scoped, interactive authentication health checks and credential refresh."""
import copy
import getpass
import sys
import warnings
from dataclasses import replace
from urllib.parse import urlsplit

from core.cookies import parse_cookie_header
from core.headers import parse_headers, split_header
from core.models import LeviosaRequest, Param


class AuthenticationStopped(RuntimeError):
    """Authentication recovery could not continue; stop the entire scan."""


def origin(url):
    parts = urlsplit(url)
    return parts.scheme.lower(), parts.hostname, parts.port or (443 if parts.scheme == 'https' else 80)


def bearer_from_request(req):
    headers = parse_headers(req.headers)
    for param in req.params:
        if param.type == 'header':
            headers[param.name] = str(param.value)
    value = headers.get('Authorization', '')
    if value.lower().startswith('bearer '):
        return value[7:].strip()
    return None


def request_cookies(req):
    headers = parse_headers(req.headers)
    for param in req.params:
        if param.type == 'header' and param.name.lower() == 'cookie':
            headers['Cookie'] = str(param.value)
    cookies = dict(parse_cookie_header(headers.get('Cookie', '')))
    for param in req.params:
        if param.type == 'cookie':
            cookies[param.name] = param.value
    return cookies


class AuthGuard:
    def __init__(self, config, *, prompt=None, write=None):
        config.validate_auth()
        self.config = config
        self.prompt = prompt or getpass.getpass
        self.write = write or (lambda message: print(message, file=sys.stderr))
        self.mechanism = config.auth_mechanism
        self.cookies = {}
        self.cookie_history = set()
        self.original_cookie_names = set()
        self.bearer = None
        self.bearer_history = set()
        self.bound = False
        self.ignored = False
        self.remaining = 0

    def bind(self, req):
        """Bind only to an original seed, never an intentionally mutated credential."""
        if self.bound or origin(req.url) != origin(self.config.auth_check_url):
            return
        cookies, bearer = request_cookies(req), bearer_from_request(req)
        mechanism = self.mechanism
        if mechanism == 'auto':
            mechanism = 'bearer' if bearer else 'cookies'
        if (mechanism == 'bearer' and not bearer) or (mechanism == 'cookies' and not cookies):
            return
        self.mechanism = mechanism
        self.cookies, self.bearer = cookies, bearer
        self.cookie_history.update(cookies.items())
        self.original_cookie_names = set(cookies)
        if bearer:
            self.bearer_history.add(bearer)
        self.bound = True

    def apply(self, req):
        if not self.bound or origin(req.url) != origin(self.config.auth_check_url):
            return req
        # Match values as well as names, preserving donor identities and attack probes.
        def authorization(value):
            if value.lower().startswith('bearer ') and value[7:].strip() in self.bearer_history:
                return 'Bearer ' + self.bearer
            return value
        def cookie(value):
            pairs = parse_cookie_header(value)
            return '; '.join(f'{name}={self.cookies[name] if (name, val) in self.cookie_history else val}'
                             for name, val in pairs)
        headers = []
        for raw in req.headers:
            pair = split_header(raw)
            if pair and self.mechanism == 'bearer' and pair[0].lower() == 'authorization':
                raw = pair[0] + ': ' + authorization(pair[1])
            elif pair and self.mechanism == 'cookies' and pair[0].lower() == 'cookie':
                raw = pair[0] + ': ' + cookie(pair[1])
            headers.append(raw)
        params = []
        for param in req.params:
            value = param.value
            if self.mechanism == 'cookies' and param.type == 'cookie' and (param.name, value) in self.cookie_history:
                value = self.cookies[param.name]
            if param.type == 'header':
                if self.mechanism == 'bearer' and param.name.lower() == 'authorization':
                    value = authorization(str(value))
                elif self.mechanism == 'cookies' and param.name.lower() == 'cookie':
                    value = cookie(str(value))
            params.append(replace(param, value=value))
        # Preserve request IDs and probe metadata across transport-only refreshes.
        if self.mechanism == 'cookies':
            existing = request_cookies(req)
            if (any(pair in self.cookie_history for pair in existing.items()) and
                    all((name, value) in self.cookie_history for name, value in existing.items()
                        if name in self.original_cookie_names)):
                for name in self.cookies.keys() - self.original_cookie_names - existing.keys():
                    params.append(Param('cookie', name, self.cookies[name]))
        result = copy.copy(req)
        result.headers, result.params = headers, params
        return result

    def seeds(self, requests):
        for req in requests:
            self.bind(req)
            yield self.apply(req)

    def check_request(self):
        headers = ['Cache-Control: no-cache, no-store', 'Pragma: no-cache']
        if self.bearer:
            headers.append('Authorization: Bearer ' + self.bearer)
        if self.cookies:
            headers.append('Cookie: ' + '; '.join(f'{name}={value}' for name, value in self.cookies.items()))
        return LeviosaRequest('GET', self.config.auth_check_url, headers, [],
                              metadata={'leviosa.redact_traffic': True})

    def authenticated(self, response):
        return (200 <= response.status < 300 and
                (self.config.auth_success_text is None or self.config.auth_success_text.encode() in response.body))

    async def ensure(self, check, *, force=False):
        if self.ignored:
            return
        if not self.bound:
            raise AuthenticationStopped('No original credentials available for the authentication-check URL origin')
        if not force and self.remaining > 0:
            self.remaining -= 1
            return
        response = await check(self.check_request())
        if self.authenticated(response):
            self.remaining = self.config.auth_check_interval - 1
            return
        self.write(f'[AUTH] Scan paused: session check failed (status {response.status}).')
        while True:
            label = 'Cookie: name=value; ...' if self.mechanism == 'cookies' else 'Bearer token (or Authorization: Bearer ...)'
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter('error', getpass.GetPassWarning)
                    pasted = self.prompt(f'[AUTH] Paste {label}; :ignore disables checking for this run; :abort stops: ').strip()
            except (EOFError, OSError, getpass.GetPassWarning) as exc:
                raise AuthenticationStopped('Authentication recovery requires interactive input; scan stopped') from exc
            if pasted == ':abort':
                raise AuthenticationStopped('Scan stopped during authentication recovery')
            if pasted == ':ignore':
                self.ignored = True
                self.write('[AUTH] Authentication checking ignored for the rest of this run.')
                return
            if not pasted or '\r' in pasted or '\n' in pasted:
                self.write('[AUTH] Enter a nonempty single-line credential.')
                continue
            previous_cookies, previous_bearer = self.cookies, self.bearer
            if self.mechanism == 'cookies':
                if pasted.lower().startswith('cookie:'):
                    pasted = pasted.split(':', 1)[1].strip()
                parts = [part.strip() for part in pasted.split(';') if part.strip()]
                pairs = parse_cookie_header(pasted)
                if not pairs or any('=' not in part for part in parts) or any(
                        not name or any(c.isspace() for c in name) for name, _ in pairs):
                    self.write('[AUTH] Paste cookies as name=value pairs separated by semicolons.')
                    continue
                candidate = dict(pairs)
                if not self.cookies.keys() <= candidate.keys():
                    self.write('[AUTH] Paste the full cookie set, including every captured cookie name.')
                    continue
                self.cookies = candidate
            else:
                if pasted.lower().startswith('authorization:'):
                    pasted = pasted.split(':', 1)[1].strip()
                if pasted.lower().startswith('bearer '):
                    pasted = pasted[7:].strip()
                if not pasted or any(c.isspace() for c in pasted):
                    self.write('[AUTH] Enter a single Bearer token.')
                    continue
                self.bearer = pasted
            response = await check(self.check_request())
            if not self.authenticated(response):
                self.cookies, self.bearer = previous_cookies, previous_bearer
                self.write(f'[AUTH] Replacement did not authenticate (status {response.status}); try again.')
                continue
            self.cookie_history.update(self.cookies.items())
            if self.bearer:
                self.bearer_history.add(self.bearer)
            self.remaining = self.config.auth_check_interval - 1
            self.write('[AUTH] Replacement verified; scan resuming.')
            return
