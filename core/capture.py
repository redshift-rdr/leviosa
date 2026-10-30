"""Capture prepared aiohttp requests without changing module request objects."""
from contextvars import ContextVar
from datetime import datetime

import aiohttp

from core.models import TrafficRecord


class Capture:
    def __init__(self, body_limit, read_body):
        self.records = []
        self.active = None
        self.body_limit = body_limit
        self.read_body = read_body
        self.request_target = ""


current_capture: ContextVar[Capture | None] = ContextVar("traffic_capture", default=None)


class CapturedRequest(aiohttp.ClientRequest):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        capture = current_capture.get()
        if capture is not None:
            self._traffic_record = TrafficRecord(str(self.url), self.method, datetime.now())
            capture.active = self._traffic_record
            capture.records.append(self._traffic_record)

    async def send(self, conn):
        capture = current_capture.get()
        # aiohttp creates internal proxy handshakes with its base ClientRequest,
        # so this subclass sees only application requests.
        if capture is not None:
            address = conn.transport.get_extra_info("sockname") if conn.transport else None
            capture.active = self._traffic_record
            capture.active.sent_at = datetime.now()
            capture.active.local_source_ip = str(address[0]) if address else ""
            if self.method == "CONNECT":
                host = self.url.raw_host
                host = f"[{host}]" if ":" in host else host
                capture.request_target = f"{host}:{self.url.port}"
            else:
                capture.request_target = str(self.url) if self.proxy and not self.is_ssl() else self.url.raw_path_qs
        return await super().send(conn)

    async def write_bytes(self, writer, conn, *args, **kwargs):
        # aiohttp 3.12+ also supplies content_length. Forward it unchanged so
        # the base writer keeps its own payload-length semantics.
        record = getattr(self, "_traffic_record", None)
        if record is None:
            return await super().write_bytes(writer, conn, *args, **kwargs)
        # Newer writers coalesce buffered headers and body through _writelines;
        # older ones send headers first and use _write for framed body chunks.
        if getattr(writer, "_headers_buf", None):
            record.request_raw = b""
        write = writer._write
        writelines = getattr(writer, "_writelines", None)
        depth = 0

        def captured_write(chunk):
            nonlocal depth
            raw = bytes(chunk)
            depth += 1
            try:
                result = write(chunk)
            finally:
                depth -= 1
            if depth == 0:
                record.request_raw += raw
            return result

        def captured_writelines(chunks):
            nonlocal depth
            chunks = tuple(chunks)
            raw = b"".join(bytes(chunk) for chunk in chunks)
            depth += 1
            try:
                result = writelines(chunks)
            finally:
                depth -= 1
            if depth == 0:
                record.request_raw += raw
            return result

        writer._write = captured_write
        if writelines is not None:
            writer._writelines = captured_writelines
        try:
            return await super().write_bytes(writer, conn, *args, **kwargs)
        finally:
            writer._write = write
            if writelines is not None:
                writer._writelines = writelines


def trace_config():
    trace = aiohttp.TraceConfig()

    async def headers_sent(session, context, params):
        capture = current_capture.get()
        if capture is not None and capture.active is not None:
            record = capture.active
            lines = [f"{params.method} {capture.request_target} HTTP/1.1"]
            lines.extend(f"{name}: {value}" for name, value in params.headers.items())
            record.request_raw = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")

    async def redirected(session, context, params):
        capture = current_capture.get()
        if capture is not None and capture.active is not None:
            record = capture.active
            record.status = params.response.status
            record.response_encoding = params.response.charset
            record.response_body = await capture.read_body(params.response, capture.body_limit)

    trace.on_request_headers_sent.append(headers_sent)
    trace.on_request_redirect.append(redirected)
    return trace
