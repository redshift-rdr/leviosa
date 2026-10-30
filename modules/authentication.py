"""Login-flow audits with credential submissions gated behind --risky."""
import argparse
import copy
import itertools
import json
import re
from dataclasses import replace
from html.parser import HTMLParser
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit
from uuid import uuid4

from core.auth import origin, request_cookies
from core.headers import parse_headers, split_header, without_headers
from core.models import Param, RequestBody
from core.tooltags import BurpTool
from modules.base import BaseModule
from modules.businesslogic import inputs, mutate_input
from modules.errordisclosure import disclosures

_LOGIN_PATH = re.compile(r'(?:^|/)(?:login|signin|sign-in|sign_in|authenticate|auth|sessions?|j_security_check)(?:\.[a-z0-9]+)?/?$|(?:^|/)oauth2?/token/?$', re.I)
_USER_FIELDS = {'username', 'user', 'email', 'login', 'identifier', 'userid'}
_PASSWORD_FIELDS = {'password', 'passwd', 'pass', 'pwd'}
_CSRF = re.compile(r'csrf|xsrf|authenticity.?token|requestverificationtoken', re.I)
_STOP = re.compile(r'account (?:is |has been )?(?:temporarily )?locked|too many (?:login |failed )?attempts|rate.?limit(?:ed| exceeded)|captcha (?:required|failed|invalid)', re.I)
_UNKNOWN_USER = re.compile(r'user(?:name)? (?:does not exist|not found|unknown)|unknown (?:user|account)|no (?:such |matching )?(?:user|account)|email (?:not found|not registered)', re.I)
_BAD_PASSWORD = re.compile(r'(?:incorrect|invalid|wrong) password|password (?:is )?(?:incorrect|invalid|wrong)', re.I)
_SESSION_NAMES = {'session', 'sessionid', 'sid', 'jsessionid', 'phpsessid', 'aspnetsessionid', 'connectsid', 'aspnetcorecookies', 'authtoken', 'accesstoken'}


def normalize(name):
    return re.sub('[^a-z0-9]', '', name.lower())


def endpoint(url):
    parts = urlsplit(url)
    host = parts.hostname or ''
    if ':' in host:
        host = '[' + host + ']'
    if parts.port is not None:
        host += ':' + str(parts.port)
    return urlunsplit(parts._replace(netloc=host, query='', fragment=''))


def native_body(req):
    """Decode common captured raw login bodies without touching the seed."""
    if req.body is None or req.body.kind != 'raw':
        return req
    content_type = parse_headers(req.headers).get('Content-Type', '').split(';')[0].strip().lower()
    try:
        if content_type == 'application/json' or content_type.endswith('+json'):
            return replace(req, body=RequestBody('json', json.loads(req.body.value)))
        if content_type == 'application/x-www-form-urlencoded':
            value = req.body.value.decode('utf-8') if isinstance(req.body.value, bytes) else req.body.value
            params = [Param('form', name, val) for name, val in parse_qsl(value, keep_blank_values=True, max_num_fields=256)]
            return replace(req, body=None, params=[*req.params, *params])
    except (ValueError, UnicodeError, RecursionError):
        pass
    return req


class LoginForms(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self.current = [], None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'form':
            self.current = {'method': (attrs.get('method') or 'get').lower(), 'action': attrs.get('action') or '', 'inputs': []}
            self.forms.append(self.current)
        elif tag == 'input' and self.current is not None:
            self.current['inputs'].append(attrs)

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None


class Authentication(BaseModule):
    """Audit login endpoints without submitting credentials by default; --risky enables bounded active authentication tests."""

    tool = BurpTool.SCANNER
    follow_redirects = False
    store_response_cookies = False
    max_concurrency = 1
    path_options = {'--login-passwords': 'file'}

    def __init__(self):
        self.risky = False
        self.path_pattern = _LOGIN_PATH
        self.user_field = self.password_field = None
        self.success_text = self.success_location = None
        self.max_attempts, self.failure_attempts = 30, 5
        self.passwords = ['password', '123456', 'admin']
        self.session_names = set(_SESSION_NAMES)

    def option_parser(self):
        parser = argparse.ArgumentParser(prog='authentication', add_help=False, allow_abbrev=False)
        parser.add_argument('--risky', action='store_true', help='Enable login submissions, guessing and lockout/rate-limit probes; use disposable accounts')
        parser.add_argument('--login-path', help='Regex selecting login URL paths instead of the built-in detector')
        parser.add_argument('--login-user-field', help='Exact username input name/JSON path when auto detection is unsuitable')
        parser.add_argument('--login-password-field', help='Exact password input name/JSON path when auto detection is unsuitable')
        success = parser.add_mutually_exclusive_group()
        success.add_argument('--login-success-text', help='Authenticated response marker (required alternative for --risky)')
        success.add_argument('--login-success-location', help='Authenticated redirect Location regex (required alternative for --risky)')
        parser.add_argument('--login-passwords', help='UTF-8 password candidates for the captured user, --risky only; capped by --login-max-attempts')
        parser.add_argument('--login-max-attempts', type=int, default=30, help='Maximum risky requests per method/endpoint, including controls (2–200; default 30)')
        parser.add_argument('--login-failure-attempts', type=int, default=5, help='Repeated incorrect-password attempts in risky mode (1–50; default 5)')
        parser.add_argument('--login-session-cookie', action='append', default=[], help='Additional session cookie name to audit (repeatable)')
        return parser

    def setup(self, args):
        options, _ = self.option_parser().parse_known_args(args)
        if not 2 <= options.login_max_attempts <= 200 or not 1 <= options.login_failure_attempts <= 50:
            raise ValueError('Login attempt limits must be 2–200 total and 1–50 repeated failures')
        for field in ('login_user_field', 'login_password_field', 'login_success_text', 'login_success_location', 'login_path'):
            value = getattr(options, field)
            if value is not None and not value.strip():
                raise ValueError(f'--{field.replace("_", "-")} must not be empty')
        if options.risky and options.login_success_text is None and options.login_success_location is None:
            raise ValueError('--risky requires --login-success-text or --login-success-location to recognize successful authentication')
        if options.login_passwords and not options.risky:
            raise ValueError('--login-passwords requires --risky')
        self.risky = options.risky
        self.user_field, self.password_field = options.login_user_field, options.login_password_field
        self.success_text = options.login_success_text
        try:
            self.success_location = re.compile(options.login_success_location) if options.login_success_location is not None else None
            self.path_pattern = re.compile(options.login_path) if options.login_path is not None else _LOGIN_PATH
        except re.error as exc:
            raise ValueError('Invalid login path/success-location regex') from exc
        self.max_attempts, self.failure_attempts = options.login_max_attempts, options.login_failure_attempts
        self.session_names = _SESSION_NAMES | {normalize(name) for name in options.login_session_cookie}
        if options.login_passwords:
            with Path(options.login_passwords).open(encoding='utf-8') as stream:
                self.passwords = list(itertools.islice((line.rstrip('\r\n') for line in stream if line.strip()), self.max_attempts))
            if not self.passwords:
                raise ValueError('--login-passwords contains no candidates')

    def fields(self, req):
        targets = list(inputs(req))
        users = [target for target in targets if (target['parameter'] == self.user_field if self.user_field is not None else normalize(target['leaf']) in _USER_FIELDS)]
        passwords = [target for target in targets if (target['parameter'] == self.password_field if self.password_field is not None else normalize(target['leaf']) in _PASSWORD_FIELDS)]
        if len(users) != 1 or len(passwords) != 1:
            return None
        return users[0], passwords[0]

    def anonymous(self, req, audit):
        headers = [raw for raw in req.headers if (pair := split_header(raw)) and pair[0].lower() in {'accept', 'user-agent', 'x-requested-with'}]
        return replace(req, method='GET', url=endpoint(req.url), headers=headers, params=[], body=None,
                       metadata={**req.metadata, 'authentication': {'probe': 'page', 'audit': audit}})

    def active_probes(self, req, user, password):
        unknown, wrong = 'authprobe-' + uuid4().hex[:16], 'authprobe-invalid-' + uuid4().hex
        if isinstance(user['value'], str) and '@' in user['value']:
            unknown += '@' + user['value'].rsplit('@', 1)[1]
        def edit(target, value, operation='replace'):
            return mutate_input(req, target, operation, value)
        def pair(username, secret):
            # Replacements preserve input addresses; neither changes container size.
            return mutate_input(edit(user, username), password, 'replace', secret)
        yield 'baseline', replace(req)
        yield 'invalid-account', pair(unknown, wrong)
        yield 'known-user-wrong-password', edit(password, wrong)
        yield 'empty-password', edit(password, '')
        yield 'missing-password', edit(password, None, 'omit')
        yield 'empty-user', edit(user, '')
        yield 'missing-user', edit(user, None, 'omit')
        if password['location'] == 'json':
            yield 'null-password', edit(password, None)
        yield 'sql-authentication-bypass', pair("' OR '1'='1'-- ", wrong)
        if user['location'] == password['location'] == 'json':
            yield 'nosql-authentication-bypass', pair({'$ne': None}, {'$ne': None})
        original = password['value']
        if isinstance(original, str) and original:
            if original.swapcase() != original:
                yield 'password-case', edit(password, original.swapcase())
            yield 'password-whitespace', edit(password, original + ' ')
            yield 'password-suffix', edit(password, original + '-authprobe-invalid-suffix')
            yield 'password-nul-truncation', edit(password, original + '\x00authprobe')
        for target in inputs(req):
            if normalize(target['leaf']) in {'otp', 'totp', 'mfacode', 'verificationcode', 'captcha', 'captchatoken', 'grecaptcharesponse'}:
                yield 'missing-second-factor-or-captcha', edit(target, None, 'omit')
        for username, secret in [('admin', 'admin'), ('admin', 'password'), ('root', 'root')]:
            yield 'default-credentials', pair(username, secret)
        for secret in self.passwords:
            if secret != original:
                yield 'password-guess', edit(password, secret)
        for _ in range(self.failure_attempts):
            yield 'repeated-failure', edit(password, wrong)

    async def mutate(self, requests, context):
        return self._variants(requests, context)

    def _variants(self, requests, context):
        pages, active = set(), set()
        for original in requests:
            if not self.path_pattern.search(urlsplit(original.url).path):
                continue
            req = native_body(original)
            public_url = endpoint(req.url)
            targets = list(inputs(req))
            query_secrets = any(target['location'] == 'query' and normalize(target['leaf']) in _PASSWORD_FIELDS | _USER_FIELDS for target in targets)
            if public_url not in pages:
                pages.add(public_url)
                yield self.anonymous(req, {'http': urlsplit(req.url).scheme == 'http', 'credentials_in_query': query_secrets})
            if public_url in context.state.get('authentication.stopped_endpoints', set()):
                continue
            if not self.risky or req.method.upper() not in {'GET', 'POST'}:
                continue
            key = req.method.upper(), public_url
            if key in active:
                continue
            fields = self.fields(req)
            if fields is None:
                context.write('[AUTHENTICATION] Risky submissions skipped: missing or ambiguous username/password inputs.')
                continue
            active.add(key)
            user, password = fields
            group = uuid4().hex
            for index, (probe, variant) in enumerate(itertools.islice(self.active_probes(req, user, password), self.max_attempts)):
                if group in context.state.get('authentication.blocked', set()):
                    break
                yield replace(variant, headers=without_headers(variant.headers, ['Content-Length', 'Transfer-Encoding']),
                              metadata={**variant.metadata, 'leviosa.redact_traffic': True, 'authentication': {
                                  'group': group, 'probe': probe, 'attempt': index + 1,
                                  'username_field': user['parameter'], 'password_field': password['parameter']}})

    def success(self, response):
        if self.success_text is not None:
            return 200 <= response.status < 300 and self.success_text.encode() in response.body
        return (self.success_location is not None and 300 <= response.status < 400 and
                bool(self.success_location.search(response.headers.get('Location', ''))))

    def emit(self, response, context, message, evidence=None, confidence='observation'):
        # Even custom reporters receive no submitted credentials or credential URL.
        req = copy.copy(response.request)
        req.url, req.headers, req.params, req.body = endpoint(req.url), [], [], None
        req.metadata = {key: value for key, value in req.metadata.items() if key in {'authentication', 'leviosa.tool'}}
        safe = replace(response, request=req, body=b'', traffic=[])
        self.report(safe, context, '[AUTHENTICATION] ' + message, evidence=evidence or {}, confidence=confidence)

    def page_issues(self, response, context):
        audit = response.request.metadata['authentication']['audit']
        if audit['http']:
            self.emit(response, context, 'Login endpoint uses unencrypted HTTP; captured credentials were not submitted')
        if audit['credentials_in_query']:
            self.emit(response, context, 'Captured login request carries credentials in query parameters')
        parser = LoginForms()
        parser.feed(response.body.decode('utf-8', 'replace'))
        for form in parser.forms:
            passwords = [field for field in form['inputs'] if (field.get('type') or '').lower() == 'password' or normalize(field.get('name') or '') in _PASSWORD_FIELDS]
            if not passwords:
                continue
            if form['method'] != 'post':
                self.emit(response, context, 'Password form does not use POST')
            try:
                action = urljoin(response.request.url, form['action'])
                if urlsplit(action).scheme != 'https':
                    self.emit(response, context, 'Password form action is not HTTPS')
                if origin(action) != origin(response.request.url):
                    self.emit(response, context, 'Password form submits to a different origin; review intended authentication provider')
            except ValueError:
                self.emit(response, context, 'Password form action is malformed')
            if any((field.get('type') or 'text').lower() != 'password' for field in passwords):
                self.emit(response, context, 'Password-like form field is not masked')
            if not any(_CSRF.search(field.get('name') or '') for field in form['inputs']):
                self.emit(response, context, 'No recognizable login-form CSRF field; review other CSRF defenses')

    def cookie_issues(self, response, context, authenticated):
        before = request_cookies(response.request)
        for raw in response.headers.getall('Set-Cookie', []):
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except CookieError:
                continue
            for name, morsel in cookie.items():
                logical_name = re.sub(r'^__(?:Host|Secure)-', '', name)
                if normalize(logical_name) not in self.session_names or morsel['max-age'] == '0' or not morsel.value:
                    continue
                issues = []
                if not morsel['secure']:
                    issues.append('missing Secure')
                if not morsel['httponly']:
                    issues.append('missing HttpOnly')
                if not morsel['samesite']:
                    issues.append('missing explicit SameSite')
                elif morsel['samesite'].lower() not in {'lax', 'strict', 'none'}:
                    issues.append('invalid SameSite')
                if issues:
                    self.emit(response, context, f'Session cookie {name}: {"; ".join(issues)}', {'cookie': name, 'issues': issues})
                if authenticated and before.get(name) == morsel.value:
                    self.emit(response, context, 'Session cookie unchanged across observed login; verify it was a pre-authentication session', {'cookie': name}, 'indicator')

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('authentication')
        if meta is None:
            return
        if response.status == 0:
            context.state.setdefault('authentication.stopped_endpoints', set()).add(endpoint(response.request.url))
            if 'group' in meta:
                context.state.setdefault('authentication.blocked', set()).add(meta['group'])
            self.emit(response, context, 'Transport error; remaining endpoint probes stopped')
            return
        text = response.body.decode('utf-8', 'replace')
        found = sorted(disclosures(response.body))
        if found:
            self.emit(response, context, 'Login response discloses internal errors', {'signatures': found}, 'indicator')
        if meta['probe'] == 'page':
            if response.status in {423, 429} or 'Retry-After' in response.headers or _STOP.search(text):
                context.state.setdefault('authentication.stopped_endpoints', set()).add(endpoint(response.request.url))
                self.emit(response, context, 'Rate-limit, lockout or CAPTCHA signal on login page; risky endpoint probes skipped')
            self.page_issues(response, context)
            self.cookie_issues(response, context, False)
            return
        stopped = response.status in {423, 429} or 'Retry-After' in response.headers or bool(_STOP.search(text))
        if stopped:
            context.state.setdefault('authentication.stopped_endpoints', set()).add(endpoint(response.request.url))
            context.state.setdefault('authentication.blocked', set()).add(meta['group'])
            self.emit(response, context, 'Rate-limit, lockout or CAPTCHA signal observed; remaining endpoint probes stopped',
                      {'probe': meta['probe'], 'status': response.status})
        accepted = bool(self.success(response)) and not stopped
        if ((meta['probe'] == 'baseline' and not accepted) or
                (meta['probe'] == 'invalid-account' and (accepted or not 200 <= response.status < 500))):
            context.state.setdefault('authentication.blocked', set()).add(meta['group'])
            context.state.setdefault('authentication.stopped_endpoints', set()).add(endpoint(response.request.url))
            self.emit(response, context, 'Baseline or invalid-account success control is inconclusive; remaining risky probes stopped', {'probe': meta['probe']})
        category = 'unknown-user' if _UNKNOWN_USER.search(text) else 'wrong-password' if _BAD_PASSWORD.search(text) else 'generic'
        entry = context.state.setdefault('authentication.results', {}).setdefault(meta['group'], {})
        saved = copy.copy(response.request)
        saved.url, saved.headers, saved.params, saved.body = endpoint(saved.url), [], [], None
        entry.setdefault(meta['probe'], []).append((replace(response, request=saved, body=b'', traffic=[]), accepted, category, stopped))
        if meta['probe'] == 'baseline':
            self.cookie_issues(response, context, accepted)
            if accepted:
                cache = ','.join(response.headers.getall('Cache-Control', [])).lower()
                if 'no-store' not in [part.strip().split('=', 1)[0] for part in cache.split(',')]:
                    self.emit(response, context, 'Authenticated login response lacks Cache-Control: no-store')
                fields = self.fields(response.request)
                if fields and isinstance(fields[1]['value'], str) and len(fields[1]['value']) >= 6 and fields[1]['value'].encode() in response.body:
                    self.emit(response, context, 'Submitted password appears in the login response body', confidence='indicator')

    async def finalize(self, context):
        results = context.state.pop('authentication.results', {})
        context.state.pop('authentication.blocked', None)
        context.state.pop('authentication.stopped_endpoints', None)
        controls = {'baseline', 'invalid-account'}
        for entry in results.values():
            baseline = entry.get('baseline', [])
            negative = entry.get('invalid-account', [])
            if not baseline or not baseline[0][1] or not negative or negative[0][1] or negative[0][3] or not 200 <= negative[0][0].status < 500:
                context.write('[AUTHENTICATION] Active success comparison inconclusive: require a successful baseline and rejected invalid-account control.')
                continue
            for probe, values in entry.items():
                if probe in controls:
                    continue
                for response, accepted, _, _ in values:
                    if accepted:
                        self.emit(response, context, 'Possible authentication weakness: ' + probe,
                                  {'probe': probe, 'attempt': response.request.metadata['authentication']['attempt'],
                                   'success_signal_matched': True, 'invalid_account_rejected': True}, 'indicator')
                        break
            known = entry.get('known-user-wrong-password', [])
            if known and not known[0][1] and not known[0][3] and known[0][2] == 'wrong-password' and negative[0][2] == 'unknown-user':
                self.emit(known[0][0], context, 'Different explicit errors for known and unknown users; possible account enumeration',
                          {'known_user_error': 'wrong-password', 'unknown_user_error': 'unknown-user'}, 'indicator')
            failures = entry.get('repeated-failure', [])
            if failures and len(failures) == self.failure_attempts and all(200 <= item[0].status < 500 and not item[1] and not item[3] for item in failures):
                self.emit(failures[-1][0], context, 'No rate-limit/lockout signal in the bounded repeated-failure sample; not proof of missing protection',
                          {'sampled_failures': len(failures)})
