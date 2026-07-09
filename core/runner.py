from collections.abc import Callable, Iterable
from contextlib import aclosing

from core.config import Config
from core.logdb import TrafficLogger
from core.models import LeviosaContext, LeviosaRequest
from core.requester import resolve_proxy, send
from modules.base import BaseModule


async def run_modules(
    modules: list[BaseModule],
    requests_factory: Callable[[], Iterable[LeviosaRequest]],
    config: Config,
    context: LeviosaContext,
    logger: TrafficLogger | None = None,
) -> None:
    for module in modules:
        # mutate() returns a sync iterable (often a lazy generator); the engine
        # pulls it one request at a time, so nothing is fully materialised here.
        mutated = await module.mutate(requests_factory(), context)
        # Proxy is resolved per module: a module that opts into burp routes
        # there, everything else follows --proxy / direct.
        proxy, proxy_auth = resolve_proxy(config, module.use_burp)
        stream = send(
            mutated,
            config,
            read_body=module.needs_body,
            proxy=proxy,
            proxy_auth=proxy_auth,
            logger=logger,
            module=type(module).__name__,
        )
        # aclosing guarantees the engine's finally block runs (cancelling any
        # in-flight tasks, closing the session) even if analyze_one raises or a
        # KeyboardInterrupt lands mid-stream.
        async with aclosing(stream) as responses:
            async for resp in responses:
                await module.analyze_one(resp, context)
        await module.finalize(context)
