from dataclasses import dataclass, field


@dataclass
class Param:
    type: str
    name: str
    value: str


@dataclass
class LeviosaRequest:
    method: str
    url: str
    headers: list[str]
    params: list[Param]
    hashkey: int | None = None


@dataclass
class LeviosaResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    request: LeviosaRequest


@dataclass
class LeviosaContext:
    data: dict = field(default_factory=dict)
