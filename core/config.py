import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    proxy_enabled: bool = True
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    concurrency: int = 20
    max_body_bytes: int = 1_048_576
    timeout: int = 30
    modules: list[str] = field(default_factory=list)
    verbose: bool = False


def load_config(toml_path: str = "leviosa.toml") -> Config:
    config = Config()
    path = Path(toml_path)
    if not path.exists():
        return config
    with open(path, "rb") as f:
        data = tomllib.load(f)
    proxy = data.get("proxy", {})
    if "enabled" in proxy:
        config.proxy_enabled = proxy["enabled"]
    if "host" in proxy:
        config.proxy_host = proxy["host"]
    if "port" in proxy:
        config.proxy_port = proxy["port"]
    concurrency = data.get("concurrency", {})
    if "limit" in concurrency:
        config.concurrency = concurrency["limit"]
    body = data.get("body", {})
    if "max_bytes" in body:
        config.max_body_bytes = body["max_bytes"]
    request = data.get("request", {})
    if "timeout" in request:
        config.timeout = request["timeout"]
    return config
