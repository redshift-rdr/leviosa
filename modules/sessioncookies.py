import argparse
from http.cookies import SimpleCookie, CookieError
from urllib.parse import urlsplit

from core.tooltags import BurpTool
from modules.base import BaseModule


class SessionCookies(BaseModule):
    """Audit Set-Cookie attributes without recording cookie values in findings."""

    tool = BurpTool.SCANNER
    needs_body = False
    follow_redirects = False

    def __init__(self):
        self.session_names = set()

    def option_parser(self):
        parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
        parser.add_argument('--session-cookie', action='append', default=[], metavar='NAME',
                            help='Sensitive session cookie name (repeatable); enables HttpOnly and SameSite checks')
        return parser

    def setup(self, args):
        self.session_names = set(self.option_parser().parse_known_args(args)[0].session_cookie)

    async def mutate(self, requests, context):
        return requests

    async def analyze_one(self, response, context):
        parts = urlsplit(response.request.url)
        for raw in response.headers.getall('Set-Cookie', []):
            cookie = SimpleCookie()
            try:
                cookie.load(raw)
            except CookieError:
                continue
            for name, morsel in cookie.items():
                issues = []
                sensitive = name in self.session_names
                if parts.scheme == 'https' and not morsel['secure']:
                    issues.append('missing Secure')
                if sensitive and parts.scheme == 'http':
                    issues.append('session cookie set over HTTP')
                if sensitive and not morsel['httponly']:
                    issues.append('missing HttpOnly')
                same = morsel['samesite'].lower()
                if sensitive and not same:
                    issues.append('missing explicit SameSite')
                if same and same not in {'lax', 'strict', 'none'}:
                    issues.append('invalid SameSite')
                if same == 'none' and not morsel['secure']:
                    issues.append('SameSite=None without Secure')
                if name.startswith(('__Secure-', '__Host-')) and (not morsel['secure'] or parts.scheme != 'https'):
                    issues.append('invalid secure cookie prefix')
                if name.startswith('__Host-') and (morsel['domain'] or morsel['path'] != '/'):
                    issues.append('__Host- requires Path=/ and no Domain')
                if morsel['domain']:
                    issues.append('Domain permits sharing with subdomains; review scope')
                if sensitive and morsel['path'] == '/':
                    issues.append('session cookie has site-wide Path=/; review scope')
                if issues:
                    self.report(response, context, f'[SESSIONCOOKIES] {name}: {"; ".join(issues)}',
                                evidence={'cookie': name, 'issues': issues,
                                          'session_cookie': sensitive,
                                          'domain': morsel['domain'], 'path': morsel['path']})
