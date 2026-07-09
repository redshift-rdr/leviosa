# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**leviosa** is a lightweight Python CLI web penetration testing helper. It is currently in the early implementation stage — no source files exist yet.

## Planned Architecture

### Core Design

- **CLI entry point**: accepts a single URL, a list of URLs, or a JSON file of HTTP request objects
- **Core request component**: threaded HTTP request sender — the only non-module functionality
- **Module system**: modules are loaded at runtime; each module (1) optionally mutates the incoming requests, (2) sends them via the core request component, and (3) optionally analyzes/acts on responses
- **Proxy**: traffic is direct by default. BurpSuite is opt-in per module via the `use_burp` class attribute (kept off by default so high-volume scans don't bloat the `.burp` file). `--proxy URL` routes non-burp traffic through any proxy (credentials supported, split into `aiohttp.BasicAuth` by `resolve_proxy` and stripped from the returned URL). `--no-proxy` forces everything direct, overriding both `use_burp` and `--proxy`. Precedence: `--no-proxy` > `use_burp` > `--proxy` > direct, computed by `core.requester.resolve_proxy` and threaded into `send(..., proxy=, proxy_auth=)`.
- **Traffic logging**: `core.logdb.TrafficLogger` writes every request/response to a local sqlite db (`traffic` table) inside `send()` — the single choke point all traffic passes through — so traffic bypassing burp is still recorded. Path via `--log-db` (default `leviosa.db`); disable with `--no-log`. Inspect the log with `traffic.py` (entry point `leviosa-traffic`): stackable AND filters (`--after/--before`, `--status`, `--status-class`, `--method`, `--module`, `--path`, `--errors-only`) rendered as a table.
- **Request filters**: `core.filters` defines a pluggable `RequestFilter` abstraction (`apply(requests) -> requests`) with built-ins (`MethodFilter`, `PathFilter`, `TakeFilter`, `SampleFilter`). A module declares filters via `request_filters()`; `run_modules` applies them to the input seeds before `mutate()`. `BaseModule.parse_request_filters(args)` wires the standard `--method/--path/--sample/--sample-seed` flags in one line — all shipped modules call it.
- **Design constraint**: keep the core minimal — all scan-specific logic belongs in modules

### JSON Input File Schema

`example_requests_input_file.json` is the reference for the HTTP request object format:

```json
{
  "method": "GET",
  "url": "http://target/path",
  "headers": ["Header-Name: value", "..."],
  "params": [
    {"type": "cookie", "name": "session", "value": "abc"},
    {"type": "json",   "name": "email",   "value": "x@x.com"}
  ],
  "hashkey": -1295339830
}
```

`params.type` values seen in the example: `cookie`, `json`. Additional types (e.g. `query`, `form`) should follow the same pattern.

## Development Setup

No dependencies are declared yet. When adding them, use a `pyproject.toml` (with `[project.dependencies]`) and a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running / Testing

No build system or test suite exists yet. Once the entry point is created, the expected invocation is:

```bash
python leviosa.py <url|url-list|requests.json> [--module <name>] [--proxy URL] [--no-proxy] [--log-db PATH] [--no-log] [--follow-redirects]
```
