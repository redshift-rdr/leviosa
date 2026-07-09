from abc import ABC, abstractmethod
from collections.abc import Iterable

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
