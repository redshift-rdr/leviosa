from dataclasses import replace
from urllib.parse import urljoin, urlsplit
from uuid import uuid4

from core.probes import input_variants
from core.tooltags import BurpTool
from modules.base import BaseModule


class OpenRedirect(BaseModule):
    """Probe scalar query/form/JSON inputs for external HTTP redirects."""

    tool = BurpTool.SCANNER
    needs_body = False
    follow_redirects = False

    async def mutate(self, requests, context):
        def variants():
            for request in requests:
                host = f'{uuid4().hex}.redirectprobe.invalid'
                for payload in (f'https://{host}/', f'//{host}/'):
                    for location, name, variant in input_variants(request, payload):
                        yield replace(variant, metadata={**variant.metadata,
                            'openredirect': (host, location, name, payload)})
        return variants()

    async def analyze_one(self, response, context):
        meta = response.request.metadata.get('openredirect')
        if not meta or response.status not in {301, 302, 303, 307, 308}:
            return
        host, location, name, payload = meta
        destination = response.headers.get('Location', '')
        try:
            target = urlsplit(urljoin(response.request.url, destination))
            external = target.scheme in {'http', 'https'} and target.hostname == host
        except ValueError:
            return
        if external:
            self.report(response, context, f'[OPENREDIRECT] External redirect via {location} {name}',
                        evidence={'parameter': name, 'location': location,
                                  'payload': payload, 'destination': destination},
                        confidence='indicator')
