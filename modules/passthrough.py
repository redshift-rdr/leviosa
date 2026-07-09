from modules.base import BaseModule


class PassthroughModule(BaseModule):
    """Sends requests unchanged and produces no output. Use as a copy-paste template."""

    # Passthrough replays requests as-is, so its (typically low-volume) traffic
    # is routed through burp for manual inspection.
    use_burp = True

    def setup(self, args):
        # Enable the standard request filters (--method/--path/--sample/...).
        self.parse_request_filters(args)

    async def mutate(self, requests, context):
        return requests
