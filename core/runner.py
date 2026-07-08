from collections.abc import Callable, Iterable
from contextlib import aclosing

from core.config import Config
from core.models import LeviosaContext, LeviosaRequest
from core.requester import send
from modules.base import BaseModule


async def run_modules(
    modules: list[BaseModule],
    requests_factory: Callable[[], Iterable[LeviosaRequest]],
    config: Config,
    context: LeviosaContext,
) -> None:
    for module in modules:
        # mutate() returns a sync iterable (often a lazy generator); the engine
        # pulls it one request at a time, so nothing is fully materialised here.
        mutated = await module.mutate(requests_factory(), context)
        stream = send(mutated, config, read_body=module.needs_body)
        # aclosing guarantees the engine's finally block runs (cancelling any
        # in-flight tasks, closing the session) even if analyze_one raises or a
        # KeyboardInterrupt lands mid-stream.
        async with aclosing(stream) as responses:
            async for resp in responses:
                await module.analyze_one(resp, context)
        await module.finalize(context)
