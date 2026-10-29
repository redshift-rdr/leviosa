from core.tooltags import BurpTool
from modules.base import BaseModule


class PassthroughModule(BaseModule):
    """Sends requests unchanged and produces no output. Use as a copy-paste template."""

    tool = BurpTool.REPEATER

    # Legacy hint retained for compatibility; routing requires global --burp.
    use_burp = True

    def setup(self, args):
        # Enable the standard request filters (--method/--path/--sample/...).
        self.parse_request_filters(args)

    async def mutate(self, requests, context):
        return requests
