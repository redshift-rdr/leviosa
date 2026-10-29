from modules.authz import Authz


class Idor(Authz):
    """Replay known owned-object requests across identities using explicit access rules."""

    def setup(self, args):
        super().setup(args)
        if not self._rules or any('contains' not in rule for rule in self._rules):
            raise ValueError('idor requires --access-rules with an object-specific contains marker for every rule')

    async def mutate(self, requests, context):
        # Only test known object requests with an explicit ownership expectation.
        selected = (request for request in requests if any(
            request.method.upper() == rule['method'].upper() and request.url == rule['url']
            for rule in self._rules))
        return await super().mutate(selected, context)
