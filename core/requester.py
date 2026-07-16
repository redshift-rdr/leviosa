import asyncio
import random
import sys
from collections.abc import AsyncIterator, Iterable
from urllib.parse import urlsplit, urlunsplit

import aiohttp

# handle weird characters in cookie key error
import http.cookies
http.cookies._is_legal_key = lambda key: bool(key) and not any(
    c in ' \t\n\r' for c in key
)

from core.config import Config
from core.logdb import TrafficLogger
from core.models import LeviosaRequest, LeviosaResponse, Param


def resolve_proxy(
    config: Config, use_burp: bool
) -> tuple[str | None, aiohttp.BasicAuth | None]:
    """
    Decide the proxy for a batch of traffic. Precedence:

    1. --no-proxy forces every request direct.
    2. A module that opts in (use_burp=True) routes through the burp endpoint.
    3. Otherwise --proxy (config.proxy_url), if set, is used.
    4. Otherwise the request goes direct.

    Returns (proxy_url, proxy_auth). Any credentials embedded in --proxy are
    split into a BasicAuth object and stripped from the returned URL, so the
    URL is safe to log.
    """
    if config.no_proxy:
        return None, None
    if use_burp:
        return f"http://{config.burp_host}:{config.burp_port}", None
    if config.proxy_url:
        return _split_proxy_auth(config.proxy_url)
    return None, None


def _split_proxy_auth(url: str) -> tuple[str, aiohttp.BasicAuth | None]:
    parts = urlsplit(url)
    if not (parts.username or parts.password):
        return url, None
    auth = aiohttp.BasicAuth(parts.username or "", parts.password or "")
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    clean = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return clean, auth


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


async def _read_capped(resp: aiohttp.ClientResponse, cap: int) -> bytes:
    """
    Read a response body with an optional size cap.

    cap <= 0 reads the whole body. Otherwise the body is streamed in chunks and
    accumulation stops once the cap is reached, so a hostile/huge body (e.g. a
    backup.zip probed by sensitivefiles) never fully materialises in memory.
    """
    if cap <= 0:
        return await resp.read()
    chunks: list[bytes] = []
    total = 0
    async for chunk in resp.content.iter_chunked(65536):
        chunks.append(chunk)
        total += len(chunk)
        if total >= cap:
            break
    return b"".join(chunks)[:cap]


async def _send_one(
    session: aiohttp.ClientSession,
    request: LeviosaRequest,
    config: Config,
    read_body: bool,
    proxy: str | None,
    proxy_auth: aiohttp.BasicAuth | None,
) -> LeviosaResponse:
    headers = _parse_headers(request.headers)
    kwargs, extra_headers = _build_kwargs(request.params)
    headers.update(extra_headers)
    try:
        async with session.request(
            method=request.method,
            url=request.url,
            headers=headers,
            proxy=proxy,
            proxy_auth=proxy_auth,
            allow_redirects=config.follow_redirects,
            **kwargs,
        ) as resp:
            body = await _read_capped(resp, config.max_body_bytes) if read_body else b""
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


async def send(
    requests: Iterable[LeviosaRequest],
    config: Config,
    read_body: bool = True,
    *,
    proxy: str | None = None,
    proxy_auth: aiohttp.BasicAuth | None = None,
    logger: TrafficLogger | None = None,
    module: str | None = None,
) -> AsyncIterator[LeviosaResponse]:
    """
    Send requests and yield each LeviosaResponse as it completes.

    Streaming, sliding-window engine: at most `config.concurrency` requests are
    in flight at once, and responses are yielded in completion order (not input
    order). Peak memory is therefore O(concurrency), not O(total requests) — the
    caller consumes and drops each response before the next slot is refilled.

    When `config.random_timing` is True requests are sent strictly sequentially
    with a random pause (uniform between `random_timing_min` and
    `random_timing_max` seconds) between each one, mimicking the cadence of a
    human tester manually reviewing responses.

    Only this coroutine touches the request iterator and the in-flight task set,
    so there is no cross-task sharing, no sentinel bookkeeping, and StopIteration
    is caught locally (PEP 479 safe).

    `proxy`/`proxy_auth` are applied to every request (resolve_proxy decides
    them per batch). If `logger` is given, every completed response is written to
    the sqlite traffic log — this is the one choke point all traffic passes
    through, so traffic that bypasses burp is still recorded.
    """
    timeout = aiohttp.ClientTimeout(total=config.timeout)
    connector = aiohttp.TCPConnector(ssl=False, limit=config.concurrency)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        if config.random_timing:
            first = True
            for req in requests:
                if not first:
                    delay = random.uniform(config.random_timing_min, config.random_timing_max)
                    if config.verbose:
                        print(f"[leviosa] random-timing: sleeping {delay:.2f}s", file=sys.stderr)
                    await asyncio.sleep(delay)
                first = False
                resp = await _send_one(session, req, config, read_body, proxy, proxy_auth)
                if logger is not None:
                    logger.log(resp, module=module, proxy=proxy)
                yield resp
            return

        def _spawn(req: LeviosaRequest) -> asyncio.Task:
            return asyncio.create_task(
                _send_one(session, req, config, read_body, proxy, proxy_auth)
            )

        req_iter = iter(requests)
        inflight: set[asyncio.Task] = set()
        try:
            # Prime the window.
            for _ in range(config.concurrency):
                try:
                    req = next(req_iter)
                except StopIteration:
                    break
                inflight.add(_spawn(req))

            while inflight:
                done, inflight = await asyncio.wait(
                    inflight, return_when=asyncio.FIRST_COMPLETED
                )
                for t in done:
                    resp = t.result()
                    if logger is not None:
                        logger.log(resp, module=module, proxy=proxy)
                    yield resp
                # Refill one slot per completed task.
                for _ in range(len(done)):
                    try:
                        req = next(req_iter)
                    except StopIteration:
                        break
                    inflight.add(_spawn(req))
        finally:
            # Deterministic cleanup: cancel any in-flight tasks before the
            # session closes so an early break / exception / Ctrl-C in the
            # consumer never leaks tasks or an unclosed session.
            for t in inflight:
                t.cancel()
            await asyncio.gather(*inflight, return_exceptions=True)
