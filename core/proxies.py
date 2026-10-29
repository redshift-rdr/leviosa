"""Validated, ordered upstream proxy rules and request-scoped redirect routing."""
import re
import tomllib
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

import aiohttp
from yarl import URL


@dataclass(frozen=True)
class ProxyRule:
    endpoint_regex: str
    proxy: str | None = None
    enabled: bool = True
    name: str = ''
    pattern: re.Pattern = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if not isinstance(self.endpoint_regex, str) or not self.endpoint_regex:
            raise ValueError('Proxy endpoint_regex must be nonempty text')
        if type(self.enabled) is not bool or not isinstance(self.name, str):
            raise ValueError('Proxy rule enabled must be boolean and name must be text')
        try:
            pattern = re.compile(self.endpoint_regex)
        except re.error as exc:
            raise ValueError('Invalid proxy endpoint_regex') from exc
        object.__setattr__(self, 'pattern', pattern)
        if self.proxy is not None:
            validate_proxy_url(self.proxy)


def split_proxy_auth(value):
    parts = urlsplit(value)
    if parts.username is None and parts.password is None:
        return value, None
    auth = aiohttp.BasicAuth(unquote(parts.username or ''), unquote(parts.password or ''))
    host = parts.hostname or ''
    if ':' in host:
        host = '[' + host + ']'
    if parts.port is not None:
        host += ':' + str(parts.port)
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment)), auth


def validate_proxy_url(value):
    try:
        if not isinstance(value, str) or not value or any(c.isspace() for c in value):
            raise ValueError
        url = URL(value)
        if url.scheme not in {'http', 'https'} or not url.host or url.query_string or url.fragment or url.path not in {'', '/'}:
            raise ValueError
        if url.port is not None and not 1 <= url.port <= 65535:
            raise ValueError
        _, auth = split_proxy_auth(value)
        if auth is not None:
            auth.encode()
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError('Proxy URL must be HTTP(S) with a host, valid port and optional Basic credentials; no path/query/fragment') from exc


def load_proxy_file(path):
    with Path(path).open('rb') as stream:
        data = tomllib.load(stream)
    if data.keys() - {'default_proxy', 'rules'}:
        raise ValueError('Unknown proxy configuration key')
    default = data.get('default_proxy')
    if default is not None:
        validate_proxy_url(default)
    raw_rules = data.get('rules', [])
    if not isinstance(raw_rules, list):
        raise ValueError('Proxy rules must be an array of tables')
    rules = []
    for index, rule in enumerate(raw_rules, 1):
        if not isinstance(rule, dict) or rule.keys() - {'endpoint_regex', 'proxy', 'direct', 'enabled', 'name'}:
            raise ValueError(f'Invalid proxy rule {index} keys')
        if type(rule.get('direct', False)) is not bool:
            raise ValueError(f'Proxy rule {index} direct must be boolean')
        if ('proxy' in rule) == rule.get('direct', False):
            raise ValueError(f'Proxy rule {index} requires either proxy or direct=true')
        rules.append(ProxyRule(rule.get('endpoint_regex'), rule.get('proxy'), rule.get('enabled', True), rule.get('name', '')))
    return tuple(rules), default


def prepare_proxies(config):
    if type(config.burp) is not bool or type(config.no_proxy) is not bool:
        raise ValueError('burp and no_proxy must be true or false')
    if not isinstance(config.burp_host, str) or not config.burp_host or any(c.isspace() for c in config.burp_host):
        raise ValueError('burp_host must be a nonempty host')
    if type(config.burp_port) is not int or not 1 <= config.burp_port <= 65535:
        raise ValueError('burp_port must be between 1 and 65535')
    try:
        URL.build(scheme='http', host=config.burp_host, port=config.burp_port)
    except (ValueError, TypeError) as exc:
        raise ValueError('Invalid burp_host') from exc
    for value in (config.proxy_url, config.proxy_default_url):
        if value is not None:
            validate_proxy_url(value)
    if config.proxy_config_path is not None:
        if not isinstance(config.proxy_config_path, str) or not config.proxy_config_path:
            raise ValueError('proxy_config_path must be a file path')
        path = str(Path(config.proxy_config_path).expanduser().resolve())
        if path != config._proxy_config_loaded:
            config.proxy_rules, config.proxy_default_url = load_proxy_file(path)
            config._proxy_config_loaded = path
    if not isinstance(config.proxy_rules, (list, tuple)) or any(not isinstance(rule, ProxyRule) for rule in config.proxy_rules):
        raise ValueError('proxy_rules must contain ProxyRule objects')


def resolve_proxy(config, use_burp=False, *, url=None):
    """no-proxy > explicit Burp mode > first endpoint rule > fallback > direct.

    Legacy module use_burp attributes are accepted but no longer enable routing.
    """
    if config.no_proxy:
        return None, None
    if config.burp:
        return str(URL.build(scheme='http', host=config.burp_host, port=config.burp_port)), None
    if url is not None:
        endpoint = str(url)
        for rule in config.proxy_rules:
            if rule.enabled and rule.pattern.search(endpoint):
                return split_proxy_auth(rule.proxy) if rule.proxy is not None else (None, None)
    default = config.proxy_url or config.proxy_default_url
    return split_proxy_auth(default) if default else (None, None)


# aiohttp rebuilds ClientRequest for every redirect; the request class uses this
# context to re-select a proxy from each destination without changing redirects.
current_proxy_route = ContextVar('proxy_route', default=None)
