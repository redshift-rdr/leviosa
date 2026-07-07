import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    proxy_enabled: bool = True
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    concurrency: int = 20
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
    return config
