from collections.abc import Callable, Iterable
from contextlib import aclosing

from core.config import Config
from core.logdb import TrafficLogger
from core.models import LeviosaContext, LeviosaRequest
from core.requester import resolve_proxy, send
from modules.base import BaseModule
from core.tooltags import resolve_module_tool
from core.timing import HumanPacer


async def run_modules(
    modules: list[BaseModule],
    requests_factory: Callable[[], Iterable[LeviosaRequest]],
    config: Config,
    context: LeviosaContext,
    logger: TrafficLogger | None = None,
    *,
    pacer: HumanPacer | None = None,
) -> None:
    config.validate_timing()
    if pacer is None:
        pacer = HumanPacer()
    # Validate all categories before consuming inputs or sending any traffic.
    tools = [resolve_module_tool(module, config) for module in modules]
    for module, tool in zip(modules, tools):
        module_context = context.for_module()
        # Apply the module's request filters to a fresh view of the inputs before
        # mutate() sees them (e.g. keep only POSTs, or a random sample). Filters
        # compose in declared order; default is none.
        seeds = requests_factory()
        for request_filter in (*module.cli_filters, *module.request_filters()):
            seeds = request_filter.apply(seeds)
        # mutate() returns a sync iterable (often a lazy generator); the engine
        # pulls it one request at a time, so nothing is fully materialised here.
        mutated = await module.mutate(seeds, module_context)
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
            tool=tool,
            pacer=pacer,
        )
        # aclosing guarantees the engine's finally block runs (cancelling any
        # in-flight tasks, closing the session) even if analyze_one raises or a
        # KeyboardInterrupt lands mid-stream.
        async with aclosing(stream) as responses:
            async for resp in responses:
                await module.analyze_one(resp, module_context)
        await module.finalize(module_context)
