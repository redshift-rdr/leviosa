"""Immutable input mutation shared by active application probes."""
from copy import deepcopy
from dataclasses import replace
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def input_variants(request, payload):
    """Yield one scalar input at a time; a callable supplies a fresh value per input."""
    parts = urlsplit(request.url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    for index, (name, _) in enumerate(query):
        values = list(query)
        values[index] = (name, payload() if callable(payload) else payload)
        yield 'query', name, replace(request, url=urlunsplit(parts._replace(query=urlencode(values))))
    for index, param in enumerate(request.params):
        if param.type not in {'query', 'json', 'form'} or isinstance(param.value, (dict, list)):
            continue
        params = list(request.params)
        params[index] = replace(param, value=payload() if callable(payload) else payload)
        yield param.type, param.name, replace(request, params=params)
    if request.body is not None and request.body.kind == 'json':
        def leaves(value, path=()):
            if isinstance(value, dict):
                for key, child in value.items():
                    yield from leaves(child, (*path, key))
            elif isinstance(value, list):
                for key, child in enumerate(value):
                    yield from leaves(child, (*path, key))
            else:
                yield path
        for path in leaves(request.body.value):
            injected = payload() if callable(payload) else payload
            value = deepcopy(request.body.value)
            if path:
                parent = value
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = injected
            else:
                value = injected
            yield 'json', '/'.join(map(str, path)) or '$', replace(
                request, body=replace(request.body, value=value))
