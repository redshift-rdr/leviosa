# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**leviosa** is a lightweight Python CLI web penetration testing helper. It is currently in the early implementation stage — no source files exist yet.

## Planned Architecture

### Core Design

- **CLI entry point**: accepts a single URL, a list of URLs, or a JSON file of HTTP request objects
- **Core request component**: threaded HTTP request sender — the only non-module functionality
- **Module system**: modules are loaded at runtime; each module (1) optionally mutates the incoming requests, (2) sends them via the core request component, and (3) optionally analyzes/acts on responses
- **Proxy**: routes through BurpSuite by default; `--no-proxy` flag disables it
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
python leviosa.py <url|url-list|requests.json> [--module <name>] [--no-proxy]
```
