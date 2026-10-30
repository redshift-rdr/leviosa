import asyncio
import copy
from itertools import islice
import json
import random
import sys
from collections.abc import AsyncIterator, Iterable
from datetime import datetime

import aiohttp
from multidict import CIMultiDict, MultiDict

# handle weird characters in cookie key error
import http.cookies
http.cookies._is_legal_key = lambda key: bool(key) and not any(
    c in ' \t\n\r' for c in key
)

from core.config import Config
from core.capture import Capture, CapturedRequest, current_capture, trace_config
from core.headers import parse_headers as _parse_headers, transport_headers
from core.logdb import TrafficLogger
from core.models import LeviosaRequest, LeviosaResponse, Param, TrafficRecord
from core.tooltags import BurpTool, validate_repeater_preview
from core.timing import HumanPacer


# Compatibility exports for callers of the original transport helpers.
from core.proxies import resolve_proxy, split_proxy_auth as _split_proxy_auth, current_proxy_route
from yarl import URL


class RoutedRequest(CapturedRequest):
    """Choose upstream per prepared URL, including redirects and query params."""
    def __init__(self, method, url, *args, **kwargs):
        super().__init__(method, url, *args, **kwargs)
        route = current_proxy_route.get()
        if route is not None:
            config, fallback, fallback_auth = route
            if config.no_proxy or config.burp or config.proxy_rules or config.proxy_url or config.proxy_default_url:
                proxy, auth = resolve_proxy(config, url=self.url)
            else:
                proxy, auth = fallback, fallback_auth
            self.update_proxy(URL(proxy) if proxy else None, auth, kwargs.get('proxy_headers'))


def _build_kwargs(params: list[Param]) -> tuple[dict, CIMultiDict[str]]:
    """
    Returns (request_kwargs, extra_headers).
    request_kwargs: keys cookies/json/params/data, populated only when non-empty.
    extra_headers: header-type params merged into the headers dict by the caller.
    """
    cookies, json_body = {}, {}
    query_params, form_data, extra_headers = MultiDict(), MultiDict(), CIMultiDict()
    for param in params:
        match param.type:
            case "cookie":
                cookies[param.name] = param.value
            case "json":
                json_body[param.name] = param.value
            case "query":
                query_params.add(param.name, param.value)
            case "form":
                form_data.add(param.name, param.value)
            case "header":
                extra_headers.add(param.name, param.value)
            case _:
                raise ValueError(f"Unsupported parameter type: {param.type!r}")
    kwargs: dict = {}
    if cookies:
        kwargs["cookies"] = cookies
    if json_body and form_data:
        raise ValueError("JSON and form parameters cannot be combined in one body")
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


def _request_options(request: LeviosaRequest):
    """Prepare headers and payload options for sending or offline validation."""
    headers = _parse_headers(request.headers)
    kwargs, extra_headers = _build_kwargs(request.params)
    headers.update(extra_headers)
    if request.body is not None:
        if "json" in kwargs or "data" in kwargs:
            raise ValueError("An explicit body cannot be combined with JSON/form parameters")
        if request.body.kind == "json":
            kwargs["data"] = json.dumps(request.body.value).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        else:
            kwargs["data"] = request.body.value
    # Captured framing describes the original wire representation. JSON/form
    # serialization and module mutations can change its byte length. Remove all
    # copies after merging header parameters and let aiohttp frame the payload.
    # This also avoids stale chunked encoding or a nonzero length with no body.
    for name in ("Content-Length", "Transfer-Encoding"):
        headers.popall(name, None)
    return transport_headers(headers), kwargs


async def _send_one(
    session: aiohttp.ClientSession,
    request: LeviosaRequest,
    config: Config,
    read_body: bool,
    proxy: str | None,
    proxy_auth: aiohttp.BasicAuth | None,
    capture_traffic: bool = False,
) -> LeviosaResponse:
    headers, kwargs = _request_options(request)
    capture = Capture(config.max_body_bytes, _read_capped) if capture_traffic else None
    token = current_capture.set(capture)
    route_token = current_proxy_route.set((config, proxy, proxy_auth))
    attempted_at = datetime.now()
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
            body = await _read_capped(resp, config.max_body_bytes) if read_body or capture_traffic else b""
            if capture is not None and capture.active is not None:
                capture.active.status = resp.status
                capture.active.response_body = body
                capture.active.response_encoding = resp.charset
            return LeviosaResponse(
                status=resp.status,
                headers=CIMultiDict(resp.headers),
                body=body if read_body else b"",
                request=request,
                traffic=capture.records if capture else [],
            )
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        if config.verbose:
            print(
                f"[leviosa] error: {request.method} {request.url}: {e}",
                file=sys.stderr,
            )
        if capture is not None and capture.active is None:
            capture.records.append(TrafficRecord(request.url, request.method, attempted_at))
        return LeviosaResponse(status=0, headers={}, body=b"", request=request,
                               traffic=capture.records if capture else [])
    finally:
        current_capture.reset(token)
        current_proxy_route.reset(route_token)


async def send(
    requests: Iterable[LeviosaRequest],
    config: Config,
    read_body: bool = True,
    *,
    proxy: str | None = None,
    proxy_auth: aiohttp.BasicAuth | None = None,
    logger: TrafficLogger | None = None,
    module: str | None = None,
    tool: BurpTool | str | None = None,
    pacer: HumanPacer | None = None,
    store_response_cookies: bool = True,
    repeater_preview: int = 0,
    auth_guard=None,
) -> AsyncIterator[LeviosaResponse]:
    """
    Send requests and yield each LeviosaResponse as it completes.

    Streaming, sliding-window engine: at most `config.concurrency` requests are
    in flight at once, and responses are yielded in completion order (not input
    order). Peak memory is therefore O(concurrency), not O(total requests) — the
    caller consumes and drops each response before the next slot is refilled.

    Human mode paces Repeater traffic sequentially, using a shared run-scoped
    pacer across module batches. Intruder and Scanner use the normal window.
    The first Repeater action is immediate; elapsed analysis/scan time counts
    towards the next interval. Redirects remain part of the same action.

    When `config.random_timing` is True it overrides human mode: all requests
    are sent strictly sequentially
    with a random pause (uniform between `random_timing_min` and
    `random_timing_max` seconds) between each one, mimicking the cadence of a
    human tester manually reviewing responses.

    Only this coroutine touches the request iterator and the in-flight task set,
    so there is no cross-task sharing, no sentinel bookkeeping, and StopIteration
    is caught locally (PEP 479 safe).

    `proxy`/`proxy_auth` are fallback transport arguments; explicit global Burp
    mode and ordered endpoint rules are resolved for each prepared redirect hop.
    If `logger` is given, prepared requests and capped response
    bodies are captured for each HTTP exchange (including redirect hops), even
    with read_body=False. Captures are discarded after their ACTIVITY rows are
    persisted; modules still receive an empty body when read_body=False.

    `tool` selects BURP_TOOL for every exchange in this batch. An explicit
    value overrides config.tool; raw dispatch otherwise defaults to Repeater.
    repeater_preview consumes the first N requests sequentially as Repeater,
    then continues the same iterator/session with the resolved tool. Requests
    are never duplicated; normal Repeater batches retain their existing pacing.
    """
    config.validate_timing()
    config.validate_auth()
    config.validate_proxies()
    validate_repeater_preview(repeater_preview)
    if tool is None:
        tool = config.tool if config.tool is not None else BurpTool.REPEATER
    tool = BurpTool(tool)
    human = config.human_mode and not config.random_timing and tool == BurpTool.REPEATER
    preview_human = config.human_mode and not config.random_timing and repeater_preview > 0
    if (human or preview_human) and pacer is None:
        pacer = HumanPacer()
    timeout = aiohttp.ClientTimeout(total=config.timeout)
    connector = aiohttp.TCPConnector(ssl=False, limit=config.concurrency)

    capture_options = {"request_class": RoutedRequest}
    if logger:
        capture_options["trace_configs"] = [trace_config()]
    # Identity matrices must never carry Set-Cookie values between users.
    cookie_options = {} if store_response_cookies else {"cookie_jar": aiohttp.DummyCookieJar()}
    async with aiohttp.ClientSession(connector=connector, timeout=timeout,
                                    **capture_options, **cookie_options) as session:
        req_iter = iter(requests)

        def tagged(req, category):
            if not repeater_preview:
                return req
            # Keep request identity/correlation intact and leave the input intact.
            result = copy.copy(req)
            result.metadata = {**req.metadata, 'leviosa.tool': str(category)}
            return result

        # Auth-enabled dispatch is sequential: no pending requests can leak past
        # a recovery prompt. Normal scans keep their sliding-window concurrency.
        if config.auth_check:
            from core.auth import AuthGuard
            auth_guard = auth_guard or AuthGuard(config)

            async def check_auth(request):
                check_config = copy.copy(config)
                check_config.follow_redirects = False
                # A fresh cookie jar keeps probe Set-Cookie responses from
                # authenticating the health check or undoing pasted credentials.
                async with aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False), timeout=timeout,
                    cookie_jar=aiohttp.DummyCookieJar(), **capture_options,
                ) as check_session:
                    response = await _send_one(check_session, request, check_config, True,
                                               proxy, proxy_auth, logger is not None)
                if logger is not None:
                    logger.log(response, tool=BurpTool.REPEATER)
                    response.traffic.clear()
                return response

            for index, original in enumerate(req_iter):
                auth_guard.bind(original)
                await auth_guard.ensure(check_auth)
                request = auth_guard.apply(original)
                category = BurpTool.REPEATER if index < repeater_preview else tool
                paced = config.human_mode and not config.random_timing and category == BurpTool.REPEATER
                if paced:
                    await pacer.wait(config.human_timing_min, config.human_timing_max, config.verbose)
                elif config.random_timing and index:
                    await asyncio.sleep(random.uniform(config.random_timing_min, config.random_timing_max))
                # Response cookies from a prior request must not supersede a
                # verified replacement, particularly raw Cookie headers.
                session.cookie_jar.clear()
                request = tagged(request, category)
                response = await _send_one(session, request, config, read_body, proxy,
                                           proxy_auth, logger is not None)
                if paced:
                    pacer.completed()
                if logger is not None:
                    logger.log(response, tool=category)
                    response.traffic.clear()
                # A deliberate denial is not proof the session expired. Verify
                # the independent health endpoint before prompting.
                if response.status in {401, 403} or 300 <= response.status < 400:
                    await auth_guard.ensure(check_auth, force=True)
                yield response
            return

        async def random_pause():
            delay = random.uniform(config.random_timing_min, config.random_timing_max)
            if config.verbose:
                print(f"[leviosa] random-timing: sleeping {delay:.2f}s", file=sys.stderr)
            await asyncio.sleep(delay)

        preview_sent = False
        if tool != BurpTool.REPEATER:
            for req in islice(req_iter, repeater_preview):
                if preview_human:
                    await pacer.wait(config.human_timing_min, config.human_timing_max, config.verbose)
                elif config.random_timing and preview_sent:
                    await random_pause()
                resp = await _send_one(session, tagged(req, BurpTool.REPEATER), config,
                                       read_body, proxy, proxy_auth, logger is not None)
                if preview_human:
                    pacer.completed()
                preview_sent = True
                if logger is not None:
                    logger.log(resp, tool=BurpTool.REPEATER)
                    resp.traffic.clear()
                yield resp

        if config.random_timing or human:
            first = not preview_sent
            for req in req_iter:
                if human:
                    await pacer.wait(config.human_timing_min, config.human_timing_max, config.verbose)
                elif not first:
                    await random_pause()
                first = False
                resp = await _send_one(session, tagged(req, tool), config, read_body, proxy, proxy_auth, logger is not None)
                if human:
                    pacer.completed()
                if logger is not None:
                    logger.log(resp, tool=tool)
                    resp.traffic.clear()
                yield resp
            return

        def _spawn(req: LeviosaRequest) -> asyncio.Task:
            return asyncio.create_task(
                _send_one(session, tagged(req, tool), config, read_body, proxy, proxy_auth, logger is not None)
            )

        inflight: set[asyncio.Task] = set()
        completed: set[asyncio.Task] = set()
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
                completed = set(done)
                for t in done:
                    resp = t.result()
                    completed.discard(t)
                    if logger is not None:
                        logger.log(resp, tool=tool)
                        resp.traffic.clear()
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
            remaining = inflight | completed
            for t in remaining:
                t.cancel()
            await asyncio.gather(*remaining, return_exceptions=True)
