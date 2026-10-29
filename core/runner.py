from collections.abc import Callable, Iterable
from dataclasses import replace
from contextlib import aclosing

from core.config import Config
from core.logdb import TrafficLogger
from core.models import LeviosaContext, LeviosaRequest
from core.requester import resolve_proxy, send
from modules.base import BaseModule
from core.tooltags import resolve_module_tool, validate_repeater_preview
from core.timing import HumanPacer


async def run_modules(
    modules: list[BaseModule],
    requests_factory: Callable[[], Iterable[LeviosaRequest]],
    config: Config,
    context: LeviosaContext,
    logger: TrafficLogger | None = None,
    *,
    pacer: HumanPacer | None = None,
    repeater_preview: int = 0,
    auth_guard=None,
) -> None:
    config.validate_timing()
    config.validate_auth()
    if config.auth_check and auth_guard is None:
        from core.auth import AuthGuard
        auth_guard = AuthGuard(config, write=context.write)
    validate_repeater_preview(repeater_preview)
    if pacer is None:
        pacer = HumanPacer()
    # Validate categories before consuming any seed stream.
    tools = [resolve_module_tool(module, config) for module in modules]
    if auth_guard is not None and not auth_guard.bound:
        for seed in requests_factory():
            auth_guard.bind(seed)
            if auth_guard.bound:
                break
        if not auth_guard.bound:
            from core.auth import AuthenticationStopped
            raise AuthenticationStopped('No captured credentials on the authentication-check URL origin')
    for module, tool in zip(modules, tools):
        module_context = context.for_module()
        # Apply the module's request filters to a fresh view of the inputs before
        # mutate() sees them (e.g. keep only POSTs, or a random sample). Filters
        # compose in declared order; default is none.
        seeds = requests_factory()
        if auth_guard is not None:
            seeds = auth_guard.seeds(seeds)
        for request_filter in (*module.cli_filters, *module.request_filters()):
            seeds = request_filter.apply(seeds)
        # mutate() returns a sync iterable (often a lazy generator); the engine
        # pulls it one request at a time, so nothing is fully materialised here.
        mutated = await module.mutate(seeds, module_context)
        # Proxy is resolved per module: a module that opts into burp routes
        # there, everything else follows --proxy / direct.
        proxy, proxy_auth = resolve_proxy(config, module.use_burp)
        module_config = (config if module.follow_redirects is None else
                         replace(config, follow_redirects=module.follow_redirects))
        stream = send(
            mutated,
            module_config,
            read_body=module.needs_body,
            proxy=proxy,
            proxy_auth=proxy_auth,
            logger=logger,
            module=type(module).__name__,
            tool=tool,
            pacer=pacer,
            store_response_cookies=module.store_response_cookies,
            repeater_preview=repeater_preview,
            **({"auth_guard": auth_guard} if auth_guard is not None else {}),
        )
        # aclosing guarantees the engine's finally block runs (cancelling any
        # in-flight tasks, closing the session) even if analyze_one raises or a
        # KeyboardInterrupt lands mid-stream.
        async with aclosing(stream) as responses:
            async for resp in responses:
                await module.analyze_one(resp, module_context)
        await module.finalize(module_context)
