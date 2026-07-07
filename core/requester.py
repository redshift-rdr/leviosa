import asyncio
import sys

import aiohttp

from core.config import Config
from core.models import LeviosaRequest, LeviosaResponse, Param


def _parse_headers(raw_headers: list[str]) -> dict[str, str]:
    """Convert raw header strings to a dict, skipping the HTTP request line."""
    headers = {}
    for h in raw_headers:
        if ": " in h:
            name, _, value = h.partition(": ")
            # The request line ("GET /path HTTP/1.1") has spaces in the name part
            if " " not in name:
                headers[name] = value
    return headers


def _build_kwargs(params: list[Param]) -> tuple[dict, dict[str, str]]:
    """
    Returns (request_kwargs, extra_headers).
    request_kwargs: keys cookies/json/params/data, populated only when non-empty.
    extra_headers: header-type params merged into the headers dict by the caller.
    """
    cookies, json_body, query_params, form_data, extra_headers = {}, {}, {}, {}, {}
    for param in params:
        match param.type:
            case "cookie":
                cookies[param.name] = param.value
            case "json":
                json_body[param.name] = param.value
            case "query":
                query_params[param.name] = param.value
            case "form":
                form_data[param.name] = param.value
            case "header":
                extra_headers[param.name] = param.value
    kwargs: dict = {}
    if cookies:
        kwargs["cookies"] = cookies
    if json_body:
        kwargs["json"] = json_body
    if query_params:
        kwargs["params"] = query_params
    if form_data:
        kwargs["data"] = form_data
    return kwargs, extra_headers


async def send(requests: list[LeviosaRequest], config: Config) -> list[LeviosaResponse]:
    proxy = f"http://{config.proxy_host}:{config.proxy_port}" if config.proxy_enabled else None
    semaphore = asyncio.Semaphore(config.concurrency)
    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=False)

    async def _send_one(session: aiohttp.ClientSession, request: LeviosaRequest) -> LeviosaResponse:
        async with semaphore:
            headers = _parse_headers(request.headers)
            kwargs, extra_headers = _build_kwargs(request.params)
            headers.update(extra_headers)
            try:
                async with session.request(
                    method=request.method,
                    url=request.url,
                    headers=headers,
                    proxy=proxy,
                    **kwargs,
                ) as resp:
                    body = await resp.read()
                    return LeviosaResponse(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        request=request,
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if config.verbose:
                    print(
                        f"[leviosa] error: {request.method} {request.url}: {e}",
                        file=sys.stderr,
                    )
                return LeviosaResponse(status=0, headers={}, body=b"", request=request)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [_send_one(session, req) for req in requests]
        return list(await asyncio.gather(*tasks))
