import argparse

from core.filters import add_filter_args, filters_from_args
from modules.base import BaseModule


class PassthroughModule(BaseModule):
    """Sends requests unchanged and produces no output. Use as a copy-paste template."""

    # Passthrough replays requests as-is, so its (typically low-volume) traffic
    # is routed through burp for manual inspection.
    use_burp = True

    def __init__(self):
        self._filters = []

    def setup(self, args):
        # Reference wiring of the standard request filters: --method, --path,
        # --sample, --sample-seed (see core.filters).
        parser = argparse.ArgumentParser(prog="passthrough", add_help=False)
        add_filter_args(parser)
        parsed, _ = parser.parse_known_args(args)
        self._filters = filters_from_args(parsed)

    def request_filters(self):
        return self._filters

    async def mutate(self, requests, context):
        return requests
