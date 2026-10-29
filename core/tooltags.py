"""Burp-equivalent activity categories, independent of proxies and HTTP headers."""
from enum import StrEnum


class BurpTool(StrEnum):
    REPEATER = "Repeater"
    INTRUDER = "Intruder"
    SCANNER = "Scanner"


def parse_module_tools(assignments: list[str]) -> dict[str, BurpTool]:
    overrides = {}
    for assignment in assignments:
        name, sep, value = assignment.partition("=")
        if not sep or not name.isidentifier() or name.startswith("_") or name == "base":
            raise ValueError("--module-tool expects NAME=Repeater|Intruder|Scanner")
        if name in overrides:
            raise ValueError(f"duplicate --module-tool override for {name!r}")
        try:
            overrides[name] = BurpTool(value)
        except ValueError:
            raise ValueError(f"invalid tool {value!r} for {name!r}; use Repeater, Intruder or Scanner") from None
    return overrides


def resolve_module_tool(module, config) -> BurpTool:
    name = module.module_name or type(module).__module__.rsplit(".", 1)[-1]
    override = config.module_tools.get(name)
    if override is None:
        override = config.tool
    return BurpTool(module.tool if override is None else override)
