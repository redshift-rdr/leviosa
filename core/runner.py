from core.config import Config
from core.models import LeviosaContext, LeviosaRequest
from core.requester import send
from modules.base import BaseModule


async def run_modules(
    modules: list[BaseModule],
    requests: list[LeviosaRequest],
    config: Config,
    context: LeviosaContext,
) -> None:
    for module in modules:
        mutated = await module.mutate(requests, context)
        responses = await send(mutated, config)
        await module.analyze(responses, context)
