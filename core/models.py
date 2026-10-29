from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING
from uuid import uuid4
from datetime import datetime

from multidict import CIMultiDict

if TYPE_CHECKING:
    from core.reporting import Reporter


@dataclass
class Param:
    type: str
    name: str
    value: Any


@dataclass
class RequestBody:
    """Explicit raw (str/bytes) or JSON body, mutually exclusive with body params."""

    kind: str
    value: Any

    def __post_init__(self):
        if self.kind not in ("raw", "json"):
            raise ValueError("body kind must be 'raw' or 'json'")
        if self.kind == "raw" and not isinstance(self.value, (str, bytes)):
            raise ValueError("raw body must be text or bytes")


@dataclass
class LeviosaRequest:
    method: str
    url: str
    headers: list[str]
    params: list[Param]
    hashkey: int | None = None
    body: RequestBody | None = None
    request_id: str = field(default_factory=lambda: uuid4().hex, init=False, compare=False)
    seed_id: str | None = field(default=None, compare=False)
    metadata: dict = field(default_factory=dict, compare=False)

    def __post_init__(self):
        if self.seed_id is None:
            self.seed_id = self.request_id
        self.metadata = dict(self.metadata)


@dataclass
class TrafficRecord:
    """One attempted HTTP exchange, including individual redirect hops."""
    target_url: str
    method: str
    sent_at: datetime
    local_source_ip: str = ""
    request_raw: bytes = b""
    status: int = 0
    response_body: bytes = b""
    response_encoding: str | None = None


@dataclass
class LeviosaResponse:
    status: int
    headers: CIMultiDict[str] | dict[str, str]
    body: bytes
    request: LeviosaRequest
    traffic: list[TrafficRecord] = field(default_factory=list, repr=False, compare=False)

    def __post_init__(self):
        self.headers = CIMultiDict(self.headers)


@dataclass
class LeviosaContext:
    # Explicit cross-module data; private invocation state belongs in state.
    data: dict = field(default_factory=dict)
    state: dict = field(default_factory=dict)
    reporter: "Reporter | None" = None

    def __post_init__(self):
        if self.reporter is None:
            from core.reporting import TerminalReporter
            self.reporter = TerminalReporter()

    def for_module(self):
        """Fresh private state, shared explicit data and output sink."""
        return LeviosaContext(data=self.data, reporter=self.reporter)

    def write(self, message: str):
        self.reporter.write(message)
