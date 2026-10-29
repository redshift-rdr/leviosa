import tomllib
import math
from dataclasses import dataclass, field
from pathlib import Path

from core.tooltags import BurpTool


@dataclass
class Config:
    # Burp is an explicit global mode; module use_burp hints do not enable it.
    burp: bool = False
    burp_host: str = "127.0.0.1"
    burp_port: int = 8080
    # Arbitrary proxy (optionally with embedded credentials, e.g.
    # http://user:pass@host:8081) set via --proxy. Fallback after endpoint rules.
    proxy_url: str | None = None
    proxy_config_path: str | None = None
    proxy_rules: tuple = field(default_factory=tuple)
    proxy_default_url: str | None = None
    _proxy_config_loaded: str | None = field(default=None, repr=False, compare=False)
    # Force every request direct, overriding Burp mode and every proxy rule.
    no_proxy: bool = False
    concurrency: int = 20
    max_body_bytes: int = 1_048_576
    timeout: int = 30
    # Follow HTTP redirects. Off by default so a scan sees the actual response
    # at each URL (status, headers) rather than the redirect target.
    follow_redirects: bool = False
    modules: list[str] = field(default_factory=list)
    tool: BurpTool | None = None
    module_tools: dict[str, BurpTool] = field(default_factory=dict)
    verbose: bool = False
    # Local sqlite traffic log. Captures every request/response the tool sends,
    # so traffic that bypasses burp is still recorded for the engagement.
    log_enabled: bool = True
    log_db_path: str = "leviosa.db"
    # Random inter-request delay to mimic human tester cadence. When enabled,
    # requests are sent sequentially with a random pause between each one.
    random_timing: bool = False
    random_timing_min: float = 2.0
    random_timing_max: float = 8.0
    human_mode: bool = False
    human_timing_min: float = 2.0
    human_timing_max: float = 8.0

    auth_check: bool = False
    auth_check_url: str | None = None
    auth_success_text: str | None = None
    auth_mechanism: str = "auto"
    auth_check_interval: int = 20

    def validate_proxies(self) -> None:
        from core.proxies import prepare_proxies
        prepare_proxies(self)

    def validate_auth(self) -> None:
        from urllib.parse import urlsplit
        if type(self.auth_check) is not bool:
            raise ValueError("auth_check must be true or false")
        if not isinstance(self.auth_mechanism, str) or self.auth_mechanism not in {"auto", "cookies", "bearer"}:
            raise ValueError("auth_mechanism must be auto, cookies or bearer")
        if type(self.auth_check_interval) is not int or self.auth_check_interval < 1:
            raise ValueError("auth_check_interval must be a positive integer")
        if self.auth_success_text is not None and (not isinstance(self.auth_success_text, str) or not self.auth_success_text.strip()):
            raise ValueError("auth_success_text must be nonempty text")
        if self.auth_check or self.auth_check_url is not None:
            if not isinstance(self.auth_check_url, str):
                raise ValueError("auth_check requires auth_check_url")
            url = urlsplit(self.auth_check_url)
            if url.scheme not in {"http", "https"} or not url.hostname or url.username is not None or url.password is not None or url.fragment or any(c.isspace() for c in self.auth_check_url):
                raise ValueError("auth_check_url must be an HTTP(S) URL without credentials or fragment")
            url.port

    def validate_timing(self) -> None:
        for name in ("human_mode", "random_timing"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be true or false")
        for prefix in ("human_timing", "random_timing"):
            minimum, maximum = getattr(self, prefix + "_min"), getattr(self, prefix + "_max")
            for value in (minimum, maximum):
                try:
                    valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
                except OverflowError:
                    valid = False
                if not valid:
                    raise ValueError(f"{prefix} bounds must be finite, non-negative numbers")
            if minimum > maximum:
                raise ValueError(f"{prefix}_min must not exceed {prefix}_max")


def load_config(toml_path: str = "leviosa.toml") -> Config:
    config = Config()
    path = Path(toml_path)
    if not path.exists():
        return config
    with open(path, "rb") as f:
        data = tomllib.load(f)
    burp = data.get("burp", {})
    if "enabled" in burp:
        config.burp = burp["enabled"]
    if "host" in burp:
        config.burp_host = burp["host"]
    if "port" in burp:
        config.burp_port = burp["port"]
    proxy = data.get("proxy", {})
    if "url" in proxy:
        config.proxy_url = proxy["url"]
    if "config_file" in proxy:
        if not isinstance(proxy["config_file"], str) or not proxy["config_file"]:
            raise ValueError("proxy.config_file must be a file path")
        config.proxy_config_path = str((path.resolve().parent / proxy["config_file"]).resolve())
    concurrency = data.get("concurrency", {})
    if "limit" in concurrency:
        config.concurrency = concurrency["limit"]
    body = data.get("body", {})
    if "max_bytes" in body:
        config.max_body_bytes = body["max_bytes"]
    request = data.get("request", {})
    if "timeout" in request:
        config.timeout = request["timeout"]
    if "follow_redirects" in request:
        config.follow_redirects = request["follow_redirects"]
    auth = data.get("auth", {})
    if not isinstance(auth, dict):
        raise ValueError("auth must be a TOML table")
    names = {"enabled": "auth_check", "url": "auth_check_url", "success_text": "auth_success_text",
             "mechanism": "auth_mechanism", "interval": "auth_check_interval"}
    if auth.keys() - names.keys():
        raise ValueError("unknown auth configuration option")
    for key, value in auth.items():
        setattr(config, names[key], value)
    log = data.get("log", {})
    if "enabled" in log:
        config.log_enabled = log["enabled"]
    if "path" in log:
        config.log_db_path = log["path"]
    timing = data.get("timing", {})
    if not isinstance(timing, dict):
        raise ValueError("timing must be a TOML table")
    if "random" in timing:
        config.random_timing = timing["random"]
    if "min" in timing:
        config.random_timing_min = timing["min"]
    if "max" in timing:
        config.random_timing_max = timing["max"]
    if "human" in timing:
        config.human_mode = timing["human"]
    if "human_min" in timing:
        config.human_timing_min = timing["human_min"]
    if "human_max" in timing:
        config.human_timing_max = timing["human_max"]
    tools = data.get("tools", {})
    if not isinstance(tools, dict) or not isinstance(tools.get("modules", {}), dict):
        raise ValueError("tools and tools.modules must be TOML tables")
    if "default" in tools:
        config.tool = BurpTool(tools["default"])
    config.module_tools = {name: BurpTool(value) for name, value in tools.get("modules", {}).items()}
    return config
