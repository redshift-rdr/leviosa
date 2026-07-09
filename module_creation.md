# leviosa — Module Creation Reference

This document contains everything needed to write a module for **leviosa**, a Python async CLI web penetration testing tool. Modules live in `modules/<name>.py` and are loaded at runtime.

---

## Project layout (relevant parts)

```
modules/
    base.py          # BaseModule ABC — import from here
    <name>.py        # your module goes here
core/
    models.py        # LeviosaRequest, LeviosaResponse, LeviosaContext, Param
    analysers.py     # reusable response analysers
```

---

## Data models

```python
# core/models.py

@dataclass
class Param:
    type: str    # "cookie" | "json" | "query" | "form" | "header"
    name: str
    value: str

@dataclass
class LeviosaRequest:
    method: str            # "GET", "POST", etc.
    url: str
    headers: list[str]     # raw strings, e.g. ["Host: example.com", "Accept: */*"]
    params: list[Param]
    hashkey: int | None = None

@dataclass
class LeviosaResponse:
    status: int            # HTTP status code; 0 means a network/connection error
    headers: dict[str, str]
    body: bytes
    request: LeviosaRequest  # back-reference to the request that produced this response

@dataclass
class LeviosaContext:
    data: dict             # shared mutable dict across all modules in a run
```

`LeviosaContext.data` is a plain dict shared across every module in a single run. Use namespaced keys to avoid collisions, e.g. `context.data["mymodule.found_urls"]`.

---

## BaseModule ABC

```python
# modules/base.py

class BaseModule(ABC):
    # Whether analyze_one needs the response body. When False the engine skips
    # reading bodies entirely (response.body is b""), keeping status-only
    # modules cheap and avoiding downloading large artefacts. Default True.
    needs_body: bool = True

    # Whether this module's traffic is routed through burpsuite. Default False:
    # burp is opt-in per module, so high-volume scans don't bloat the .burp file.
    # When False, traffic uses --proxy if set, else goes direct. Either way every
    # request/response is recorded in the sqlite traffic log.
    use_burp: bool = False

    def setup(self, args: list[str]) -> None:
        """
        Called once before mutate/analyze, with any CLI args not consumed by
        the main leviosa parser. Override to parse module-specific flags.
        Default implementation is a no-op.
        """

    @abstractmethod
    async def mutate(
        self,
        requests: Iterable[LeviosaRequest],
        context: LeviosaContext,
    ) -> Iterable[LeviosaRequest]:
        """
        Return the requests to send as a *sync iterable* (a list, or — better —
        a lazy generator so the whole set never resides in memory). You may
        return the original requests unchanged, modify them, or expand them
        (one input → many fuzz variants). Never return an async generator: the
        engine pulls the iterable with next().
        """
        ...

    async def analyze_one(
        self,
        response: LeviosaResponse,
        context: LeviosaContext,
    ) -> None:
        """
        Called once per response, as each one completes. Print findings to
        stdout. Default implementation is a no-op.
        """

    async def finalize(self, context: LeviosaContext) -> None:
        """
        Called once after all responses have been analysed. Emit aggregate
        findings here. Default implementation is a no-op.
        """
```

### Rules

- **One subclass per file.** The loader scans for exactly one `BaseModule` subclass in the file. Defining two raises a `ValueError`.
- **File name = module name.** A module at `modules/sqli.py` is loaded with `--module sqli`.
- **`mutate` is required.** It is the only abstract method. If you have nothing to mutate, `return requests`.
- **Each module receives the original requests**, not the output of a previous module. Mutations do not chain between modules.
- **`analyze_one` output goes to stdout.** Use `print()`. Prefix lines with `[MODULENAME]` by convention.
- **Responses stream in completion order, one at a time.** `analyze_one` never sees the whole list. To compare across responses (baseline, counts, diffs) accumulate on `context.data` during `analyze_one`, then act in `finalize`.
- **Set `needs_body = False`** if you only inspect status/headers — the engine then never reads the body (`response.body` is `b""`). With the default `needs_body = True`, bodies are read up to `config.max_body_bytes` (the `--max-body-bytes` cap, default 1 MB), so a very large body may be truncated.
- **Set `use_burp = True`** to route this module's traffic through burpsuite. Default `False` sends it direct (or through `--proxy`). Reserve burp for low-volume modules whose traffic you want to inspect manually — high-volume fuzzers left on burp bloat the `.burp` file. Regardless of this setting, every request/response is recorded in the sqlite traffic log, and `--no-proxy` overrides `use_burp` to force direct.

---

## Request filters

A module can restrict or sample the requests it receives *before* `mutate()`
sees them by declaring **request filters**. A filter is a lazy stream
transformer, `Iterable[LeviosaRequest] -> Iterable[LeviosaRequest]`; the runner
applies a module's `request_filters()` (in order) to the input requests.

Built-in filters live in `core.filters`:

```python
from core.filters import (
    RequestFilter,      # ABC: implement apply(requests) -> requests
    PredicateFilter,    # ABC for per-request keep/drop: implement keep(request) -> bool
    MethodFilter,       # keep requests with a given HTTP method (case-insensitive)
    PathFilter,         # keep requests whose URL path matches a regex
    TakeFilter,         # keep the first N (lazy, stops early)
    SampleFilter,       # uniform random sample of N (reservoir; optional seed)
)
```

Most modules just wire the **standard filter flags** (`--method` (repeatable),
`--path`, `--sample`, `--sample-seed`) with two helpers, then return the result
from `request_filters()`:

```python
import argparse
from core.filters import add_filter_args, filters_from_args
from modules.base import BaseModule

class MyModule(BaseModule):
    def __init__(self):
        self._filters = []

    def setup(self, args):
        parser = argparse.ArgumentParser(prog="mymodule", add_help=False)
        add_filter_args(parser)                    # registers the standard flags
        parsed, _ = parser.parse_known_args(args)
        self._filters = filters_from_args(parsed)  # -> list[RequestFilter]

    def request_filters(self):
        return self._filters

    async def mutate(self, requests, context):
        return requests
```

Now `leviosa reqs.json --module mymodule --method POST --sample 5` sends a random
5 of the POST requests. `filters_from_args` orders selective filters (method,
path) before sampling, so `--sample` draws from the already-narrowed set.

Notes:

- **New filters are just subclasses.** Per-request ones subclass `PredicateFilter`
  and implement `keep()`; whole-stream ones subclass `RequestFilter` and
  implement `apply()`. Instantiate them directly in `request_filters()` if you
  don't want the standard flags.
- **Filters run on the input seeds** (the requests handed to the module), not on
  the module's expanded output. To cap your own output, apply a filter object by
  hand inside `mutate()` — e.g. `return TakeFilter(100).apply(self._variants(...))`.
- **`SampleFilter` is eager** (reservoir sampling drains its input) — fine for the
  small seed set, but don't stack it on a huge expanded stream.
- The standard flags are parsed from the shared arg tail, so if two active
  modules both call `add_filter_args` they filter identically. A module needing
  independent control should define its own flag names and build filters directly.

See `modules/passthrough.py` for the reference wiring.

---

## Module-specific CLI flags

The main leviosa parser uses `parse_known_args`. Any flags it does not recognise are collected into a `remaining` list and passed as-is to every loaded module's `setup(remaining)`.

Inside `setup`, use `argparse` with `parse_known_args` so that flags belonging to other modules are silently ignored:

```python
def setup(self, args: list[str]) -> None:
    parser = argparse.ArgumentParser(prog="mymodule", add_help=False)
    parser.add_argument("--my-flag", required=True)
    parser.add_argument("--optional", default="default_value")
    parsed, _ = parser.parse_known_args(args)   # _ discards unknown flags

    self._my_flag = parsed.my_flag
    self._optional = parsed.optional
```

CLI invocation example:

```bash
leviosa target.json --module mymodule --my-flag value --optional other
```

If a required flag is missing, raise `RuntimeError` with a helpful message (the runner surfaces it to the user without a traceback).

---

## Response analysers

Importable from `core.analysers`. Each analyser has a single method:

```python
analyser.matches(response: LeviosaResponse) -> str | None
```

Returns a human-readable description string on match, `None` on no match. The string is ready to embed directly in `print()` output.

### Available analysers

```python
from core.analysers import (
    StatusCodeAnalyser,
    TextMatchAnalyser,
    RegexAnalyser,
    ResponseSizeAnalyser,
    HeaderAnalyser,
)

# Match if response status is in the given list
StatusCodeAnalyser(codes: list[int])
# → "status=403"

# Match if response body contains the literal string
TextMatchAnalyser(text: str, case_sensitive: bool = True)
# → "body contains 'root:x:0:0'"

# Match if response body matches the regex pattern
RegexAnalyser(pattern: str, flags: int = 0)   # flags: re.IGNORECASE, re.MULTILINE, etc.
# → "body matches /syntax.*error/"

# Match if response body length is within [min_size, max_size] (inclusive)
# At least one bound must be provided; omit the other to leave it unbounded
ResponseSizeAnalyser(min_size: int | None = None, max_size: int | None = None)
# → "size=1842"

# Match if a response header is present / has a specific value / matches a pattern
# pattern takes priority over value if both are given
HeaderAnalyser(name: str, value: str | None = None, pattern: str | None = None)
# → "header Server: Apache/2.4"
```

Header name lookup is case-insensitive. Text and value comparisons respect `case_sensitive` / are case-insensitive by default for `HeaderAnalyser`.

### Using analysers in analyze_one()

```python
async def analyze_one(self, response, context):
    for analyser in self._analysers:
        if hit := analyser.matches(response):
            print(f"[MYMODULE] {hit} — {response.request.method} {response.request.url}")
```

Analysers are stateless — safe to instantiate once in `setup()` and reuse across all responses.

---

## Minimal module (no mutation, no CLI flags)

```python
# modules/headercheck.py
from modules.base import BaseModule
from core.analysers import HeaderAnalyser


class HeaderCheck(BaseModule):
    needs_body = False  # only inspects headers — engine skips reading bodies

    def __init__(self):
        self._analysers = [
            HeaderAnalyser("Server"),
            HeaderAnalyser("X-Powered-By"),
            HeaderAnalyser("X-AspNet-Version"),
        ]

    async def mutate(self, requests, context):
        return requests  # send original requests unchanged

    async def analyze_one(self, response, context):
        for analyser in self._analysers:
            if hit := analyser.matches(response):
                print(f"[HEADERCHECK] {hit} — {response.request.url}")
```

---

## Full module example (mutation + CLI flags + analysers)

```python
# modules/paramfuzz.py
import argparse
import copy

from modules.base import BaseModule
from core.analysers import StatusCodeAnalyser, TextMatchAnalyser


class ParamFuzzer(BaseModule):
    def __init__(self):
        self._wordlist: list[str] | None = None
        self._param_name: str | None = None
        self._analysers = []

    def setup(self, args: list[str]) -> None:
        parser = argparse.ArgumentParser(prog="paramfuzz", add_help=False)
        parser.add_argument("--wordlist", required=True)
        parser.add_argument("--param", required=True, help="Param name to fuzz")
        parser.add_argument("--match-text", default=None)
        parsed, _ = parser.parse_known_args(args)

        with open(parsed.wordlist) as f:
            self._wordlist = [l.strip() for l in f if l.strip()]
        self._param_name = parsed.param

        self._analysers = [StatusCodeAnalyser([200, 500])]
        if parsed.match_text:
            self._analysers.append(TextMatchAnalyser(parsed.match_text, case_sensitive=False))

    async def mutate(self, requests, context):
        if self._wordlist is None:
            raise RuntimeError("paramfuzz requires --wordlist and --param")
        # A generator keeps memory flat: variants are produced on demand as the
        # engine pulls them, never all at once.
        return self._variants(requests)

    def _variants(self, requests):
        for req in requests:
            for word in self._wordlist:
                # This module mutates param.value in place, so it MUST deepcopy:
                # dataclasses.replace() only shallow-copies and would alias the
                # params/Param objects across variants, corrupting siblings.
                new_req = copy.deepcopy(req)
                for param in new_req.params:
                    if param.name == self._param_name:
                        param.value = word
                yield new_req

    async def analyze_one(self, response, context):
        hits = [a.matches(response) for a in self._analysers if a.matches(response)]
        if hits:
            desc = ", ".join(hits)
            print(f"[PARAMFUZZ] {desc} — {response.request.method} {response.request.url}")
```

> **Copying variants — `replace` vs `deepcopy`.** For a **url-only** mutation
> (path fuzzers that only rewrite `req.url`), `dataclasses.replace(req, url=...)`
> is the right tool: it makes a fresh request while safely sharing the unmutated
> `headers`/`params` (the engine only reads them). But when you mutate a `Param`
> value or a header — as `paramfuzz` does — you **must** `copy.deepcopy(req)`
> (or deep-copy just the touched `Param`), because `replace` aliases the params
> list and mutating one variant's param would silently change every sibling.

---

## Checklist

- [ ] File is at `modules/<name>.py`
- [ ] Exactly one class inheriting `BaseModule`
- [ ] `mutate` is implemented (even if it just returns `requests`) and returns a **sync iterable** — a list or a lazy generator, never an async generator
- [ ] `setup` uses `parse_known_args` (not `parse_args`) to ignore other modules' flags
- [ ] Missing required flags raise `RuntimeError` with a usage hint
- [ ] Copying variants: `dataclasses.replace(req, url=...)` for **url-only** mutation; `copy.deepcopy(req)` when mutating `params`/headers
- [ ] Cross-response logic accumulates on `context.data` in `analyze_one` and emits in `finalize` (responses stream one at a time, in completion order)
- [ ] `needs_body = False` set if only status/headers are inspected
- [ ] `use_burp = True` set only if this module's (typically low-volume) traffic should be routed through burpsuite
- [ ] Request filters (via `request_filters()`) wired if the module should sample or restrict its inputs — `add_filter_args`/`filters_from_args` for the standard `--method/--path/--sample` flags
- [ ] Findings printed to stdout; prefix with `[MODULENAME]`
- [ ] `status == 0` means a network error — handle or filter as appropriate
