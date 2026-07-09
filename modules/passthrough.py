from modules.base import BaseModule


class PassthroughModule(BaseModule):
    """Sends requests unchanged and produces no output. Use as a copy-paste template."""

    # Passthrough replays requests as-is, so its (typically low-volume) traffic
    # is routed through burp for manual inspection.
    use_burp = True

    async def mutate(self, requests, context):
        return requests
