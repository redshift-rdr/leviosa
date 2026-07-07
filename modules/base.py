from abc import ABC, abstractmethod

from core.models import LeviosaContext, LeviosaRequest, LeviosaResponse


class BaseModule(ABC):
    def setup(self, args: list[str]) -> None:
        """Called once with remaining CLI args after main parsing. Override to handle module-specific flags."""

    @abstractmethod
    async def mutate(
        self,
        requests: list[LeviosaRequest],
        context: LeviosaContext,
    ) -> list[LeviosaRequest]:
        """Return the requests to send. May be the same list, modified, or expanded."""
        ...

    async def analyze(
        self,
        responses: list[LeviosaResponse],
        context: LeviosaContext,
    ) -> None:
        """Called after all responses are received. Print findings to stdout."""
