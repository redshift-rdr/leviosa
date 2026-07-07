from modules.base import BaseModule


class PassthroughModule(BaseModule):
    """Sends requests unchanged and produces no output. Use as a copy-paste template."""

    async def mutate(self, requests, context):
        return requests
