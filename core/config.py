import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # Burp endpoint. Burp is no longer used by default: only modules that opt in
    # via `use_burp = True` route their traffic here.
    burp_host: str = "127.0.0.1"
    burp_port: int = 8080
    # Arbitrary proxy (optionally with embedded credentials, e.g.
    # http://user:pass@host:8081) set via --proxy. Applies to all traffic that
    # is not routed through burp.
    proxy_url: str | None = None
    # Force every request direct, overriding both per-module burp opt-in and
    # --proxy (set by --no-proxy).
    no_proxy: bool = False
    concurrency: int = 20
    max_body_bytes: int = 1_048_576
    timeout: int = 30
    modules: list[str] = field(default_factory=list)
    verbose: bool = False
    # Local sqlite traffic log. Captures every request/response the tool sends,
    # so traffic that bypasses burp is still recorded for the engagement.
    log_enabled: bool = True
    log_db_path: str = "leviosa.db"


def load_config(toml_path: str = "leviosa.toml") -> Config:
    config = Config()
    path = Path(toml_path)
    if not path.exists():
        return config
    with open(path, "rb") as f:
        data = tomllib.load(f)
    burp = data.get("burp", {})
    if "host" in burp:
        config.burp_host = burp["host"]
    if "port" in burp:
        config.burp_port = burp["port"]
    proxy = data.get("proxy", {})
    if "url" in proxy:
        config.proxy_url = proxy["url"]
    concurrency = data.get("concurrency", {})
    if "limit" in concurrency:
        config.concurrency = concurrency["limit"]
    body = data.get("body", {})
    if "max_bytes" in body:
        config.max_body_bytes = body["max_bytes"]
    request = data.get("request", {})
    if "timeout" in request:
        config.timeout = request["timeout"]
    log = data.get("log", {})
    if "enabled" in log:
        config.log_enabled = log["enabled"]
    if "path" in log:
        config.log_db_path = log["path"]
    return config
