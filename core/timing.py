"""Run-scoped pacing for sequential Repeater actions."""
import sys
from asyncio import sleep
from random import uniform
from time import monotonic


class HumanPacer:
    """Share between sequential send() calls in a run, never between runs."""

    def __init__(self):
        self._completed_at: float | None = None

    async def wait(self, minimum: float, maximum: float, verbose: bool = False) -> None:
        if self._completed_at is None:
            return
        remaining = self._completed_at + uniform(minimum, maximum) - monotonic()
        if remaining > 0:
            if verbose:
                print(f"[leviosa] human-mode: sleeping {remaining:.2f}s (Repeater)", file=sys.stderr)
            await sleep(remaining)

    def completed(self) -> None:
        self._completed_at = monotonic()
