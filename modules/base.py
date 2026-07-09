import argparse
from abc import ABC, abstractmethod
from collections.abc import Iterable

from core.filters import RequestFilter, add_filter_args, filters_from_args
from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse


class BaseModule(ABC):
    # Whether analyze_one needs the response body. When False the engine skips
    # reading the body entirely (body is b""), keeping status-only modules cheap
    # and avoiding downloading large artefacts.
    needs_body: bool = True

    # Whether this module's traffic should be routed through the burp proxy.
    # Default False: burp is opt-in per module now, since high-volume scans
    # bloat the .burp file. When False the module uses --proxy if set, else goes
    # direct. All traffic is recorded in the sqlite log regardless.
    use_burp: bool = False

    def setup(self, args: list[str]) -> None:
        """Called once with remaining CLI args after main parsing. Override to handle module-specific flags."""

    def parse_request_filters(self, args: list[str]) -> None:
        """
        Parse the standard request-filter flags (--method / --path / --sample /
        --sample-seed) from the CLI args and store them for request_filters().

        Call this from setup() (one line) to give a module input sampling and
        restriction. The flags are orthogonal to a module's own argparse parser,
        so both can read the same args list independently.
        """
        parser = argparse.ArgumentParser(add_help=False)
        add_filter_args(parser)
        parsed, _ = parser.parse_known_args(args)
        self._filters = filters_from_args(parsed)

    def request_filters(self) -> list[RequestFilter]:
        """
        Filters applied, in order, to the input requests before mutate() sees
        them — for sampling or restricting a module's inputs (e.g. only POSTs,
        or a random sample of 5). Default: none.

        Populated by parse_request_filters() (typically called in setup()).
        Filters are plain Iterable->Iterable objects, so they can also be applied
        by hand to a module's own output inside mutate().
        """
        return getattr(self, "_filters", [])

    @abstractmethod
    async def mutate(
        self,
        requests: Iterable[LeviosaRequest],
        context: LeviosaContext,
    ) -> Iterable[LeviosaRequest]:
        """
        Return the requests to send as a sync iterable (a list, or a generator
        for laziness so variants are produced on demand rather than all at once).
        May be the same requests, modified, or expanded.
        """
        ...

    async def analyze_one(
        self,
        response: LeviosaResponse,
        context: LeviosaContext,
    ) -> None:
        """
        Called once per response, as each one completes (completion order, not
        input order). Print findings to stdout. Aggregate across responses by
        stashing state on context.data and acting in finalize(). Default no-op.
        """

    async def finalize(self, context: LeviosaContext) -> None:
        """Called once after all responses have been analysed. Default no-op."""
