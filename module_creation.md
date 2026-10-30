# leviosa — Module Creation Reference

This document contains everything needed to write a module for **leviosa**, a Python async CLI web penetration testing tool. Built-ins live in the installed `modules` package. Custom modules load from an explicit `--modules-dir PATH`, independently of the working directory.

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
    value: Any   # JSON values can be nested or typed

@dataclass
class LeviosaRequest:
    method: str            # "GET", "POST", etc.
    url: str
    headers: list[str]     # raw strings, e.g. ["Host: example.com", "Accept: */*"]
    params: list[Param]
    hashkey: int | None = None
    body: RequestBody | None = None  # RequestBody("raw", str/bytes) or RequestBody("json", value)
    request_id: str        # generated for each request, including replace() copies
    seed_id: str           # shared across variants of a seed
    metadata: dict         # private probe labels; copied by replace()

@dataclass
class LeviosaResponse:
    status: int            # HTTP status code; 0 means a network/connection error
    headers: CIMultiDict[str]  # case-insensitive get(); getall() preserves duplicates
    body: bytes
    request: LeviosaRequest  # back-reference to the request that produced this response

@dataclass
class LeviosaContext:
    data: dict             # explicitly shared across modules
    state: dict            # fresh private state for each module invocation
    reporter: Reporter     # report(Finding) and write(str) output sink
```

Use `context.state` for private aggregation. The runner isolates it for every
module invocation, including repeated runs of the same instance. Use namespaced
`context.data` keys only for intentional cross-module sharing.

Emit findings with `self.report(response, context, observation, evidence={...},
confidence="observation")`. `Finding` includes the module, affected request,
observation, evidence and confidence. The default reporter keeps terminal output;
programmatic callers can supply `LeviosaContext(reporter=custom_reporter)`.
Reporters implement `report(finding)` and `write(message)`; `context.write()`
emits summary text. They need not retain findings in memory.

Use `dataclasses.replace(req, ...)` to create variants. It generates a new
request ID, retains the seed ID and copies the metadata dictionary. Put probe
labels in `variant.metadata` and read `response.request.metadata` on completion.
Copy nested values before modifying them. Do not correlate through `id(req)`.
Explicit bodies are mutually exclusive with JSON/form params. Repeated query,
form and header fields retain their order; response headers provide `getall()`.
Existing request-file syntax remains valid; README shows explicit body syntax.
The transport removes captured Content-Length/Transfer-Encoding after merging
raw headers and header params; aiohttp computes framing from the final payload.
Module variants may share unmodified captured headers without causing stale
length truncation. This normalization does not mutate seed/header objects.
Raw bodies are entity bytes/text, not pre-chunked HTTP framing.

---

## BaseModule ABC

```python
# modules/base.py

class BaseModule(ABC):
    # Whether analyze_one needs the response body. When False the engine skips
    # passing bodies to the module (response.body is b""), while traffic
    # logging still captures a capped body. With --no-log, reads are skipped.
    needs_body: bool = True

    # Legacy compatibility attribute, ignored by routing.
    # --burp / proxy configuration control routing globally.
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
        Called once per response, as each one completes. Emit findings with
        self.report(response, context, message). Default implementation is a no-op.
        """

    async def finalize(self, context: LeviosaContext) -> None:
        """
        Called once after all responses have been analysed. Emit aggregate
        findings here. Default implementation is a no-op.
        """
```

### Rules

- **One subclass per file.** The loader scans for exactly one concrete `BaseModule` subclass defined in the file; imported parents are ignored. Defining two raises a `ValueError`.
- **File name = module name.** A module at `modules/sqli.py` is loaded with `--module sqli`.
- **`mutate` is required.** It is the only abstract method. If you have nothing to mutate, `return requests`.
- **Each module receives the original requests**, not the output of a previous module. Mutations do not chain between modules.
- **Emit through the reporter.** Use `self.report(response, context, message)` for findings and `context.write(message)` for summaries. Prefix terminal messages with `[MODULENAME]` by convention.
- **Responses stream in completion order, one at a time.** `analyze_one` never sees the whole list. To compare across responses (baseline, counts, diffs) accumulate on `context.state` during `analyze_one`, then act in `finalize`.
- **Set `needs_body = False`** if you only inspect status/headers: modules receive `response.body == b""`. Traffic logging still reads and stores bodies up to `config.max_body_bytes` (default 1 MB); `--no-log` skips those reads. The same cap applies when the module needs the body. SQLite stores only the eight Burp `ACTIVITY` columns; findings and summaries go through the console reporter.
- **Proxy routing is global.** Default traffic is direct; `--burp` explicitly routes all traffic to Burp. Ordered endpoint regex rules, `--proxy` and `--no-proxy` configure upstream routing. Legacy module `use_burp` attributes are ignored. Traffic logging is independent of routing.

---

## Tool category

Declare the Burp-equivalent activity type on the module:

```python
from core.tooltags import BurpTool

class MyCheck(BaseModule):
    tool = BurpTool.SCANNER
    # ... mutate/analyze_one ...
```

`BaseModule` defaults to `BurpTool.REPEATER` for backwards-compatible custom
modules. Choose `INTRUDER` for systematic path/parameter/identity iteration and
`SCANNER` for automated security checks. Classification does not count requests,
consume the seed stream or select a proxy. Global proxy routing is independent.

The loader sets `module.module_name` to the file name so CLI
`--module-tool NAME=TAG` overrides use the public module name, even when its class
has a different name. Both the loader and runner validate categories before
traffic is sent. The runner resolves named configuration overrides, then global
configuration overrides, then the module's default, without changing the class
attribute. The CLI applies command-line precedence before invoking the runner.

For direct transport callers, `send(..., tool=BurpTool.INTRUDER)` explicitly
chooses the category; otherwise `config.tool` or `Repeater` is used. Every
redirect hop and failed request attempt uses that same category. It is persisted
only in `ACTIVITY.BURP_TOOL`, with no HTTP header or SQLite schema changes.

With `config.human_mode=True`, resolved Repeater traffic is sequential and paced;
Intruder/Scanner retain normal concurrency. `run_modules()` creates one
`HumanPacer` per run and shares it across module batches. No per-module sleep
logic is needed. Analysis/finalisation and intervening scans count towards the
next interval. `config.random_timing` overrides human mode and retains legacy
all-category pacing.

Direct callers making several sequential `send()` calls can share a
`core.timing.HumanPacer` via `send(..., pacer=pacer)`. Without one, each direct
call starts fresh. Do not share a pacer across concurrent streams or unrelated
runs. Config fields are `human_mode`, `human_timing_min` and `human_timing_max`;
`Config.validate_timing()` is called before consuming inputs. Cancellation during
a human wait propagates normally without sending the next request.

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

The CLI parses the **standard filter flags** (`--method`, `--path`, `--sample`,
`--sample-seed`) centrally and applies them before a module's custom filters.
Every module supports these without setup boilerplate, including modules that
override `request_filters()`. For direct Python callers outside the CLI,
`parse_request_filters(args)` remains a compatibility helper.

`leviosa reqs.json --module mymodule --method POST --sample 5` selects a random
5 POST requests. Selective filters run before sampling.

For custom behaviour, build filters yourself and return them from
`request_filters()` (the low-level `add_filter_args` / `filters_from_args`
helpers in `core.filters` are also available):

```python
from core.filters import MethodFilter, TakeFilter

class WriteProbe(BaseModule):
    def request_filters(self):
        return [MethodFilter(["POST", "PUT", "PATCH"]), TakeFilter(50)]
    ...
```

Notes:

- **New filters are just subclasses.** Per-request ones subclass `PredicateFilter`
  and implement `keep()`; whole-stream ones subclass `RequestFilter` and
  implement `apply()`. Instantiate them directly in `request_filters()`.
- **Filters run on the input seeds** (the requests handed to the module), not on
  the module's expanded output. To cap your own output, apply a filter object by
  hand inside `mutate()` — e.g. `return TakeFilter(100).apply(self._variants(...))`.
- **`SampleFilter` is eager** (reservoir sampling drains its input) — fine for the
  small seed set, but don't stack it on a huge expanded stream.
- Standard flags apply to every selected module. For independent control,
  define module-specific flag names and return custom filters.

See `modules/passthrough.py` for the reference wiring.

---

## Module-specific CLI flags

The main parser collects module arguments, validates them against the selected
modules' declared parsers, and rejects unused arguments before setup or traffic.
Duplicate option names between modules or shared CLI options are rejected;
modules with conflicting flags must run separately. Declare every option in
`option_parser()`, use `allow_abbrev=False`, and choose descriptive names.
After validation, setup receives the module argument tail; use `parse_known_args`
so arguments declared by other selected modules pass through.

Build the parser in `option_parser()` (with `add_help=False`) and let `setup()`
parse with it. Keeping the parser in `option_parser()` means `--list-modules` can
introspect and display your options without running `setup()`:

```python
def option_parser(self):
    parser = argparse.ArgumentParser(prog="mymodule", add_help=False, allow_abbrev=False)
    parser.add_argument("--my-flag", required=True, help="What it does")
    parser.add_argument("--optional", default="default_value", help="...")
    return parser

def setup(self, args: list[str]) -> None:
    parsed, _ = self.option_parser().parse_known_args(args)  # _ discards unknown flags
    self._my_flag = parsed.my_flag
    self._optional = parsed.optional
```

`parse_known_args` (not `parse_args`) lets flags belonging to other modules pass
through silently. Give every argument a `help=` string — `--list-modules` shows
it. A module with no options simply doesn't override `option_parser()` (the base
returns `None`).

CLI invocation example:

```bash
leviosa target.json --module mymodule --my-flag value --optional other
```

If a required flag is missing, raise `RuntimeError` with a helpful message (the runner surfaces it to the user without a traceback).

---

## Scan files and module lifecycle

`--scan FILE` prepares every step before sending any traffic. It creates a new
module instance for each occurrence, validates its declared options, and calls
`setup()` once. Keep setup to option/resource validation and loading; do network
work through the runner. An invalid setup aborts preflight for the entire scan.
Runtime errors in `mutate()`, iteration, `analyze_one()` or `finalize()` are
recorded and later steps continue. Cancellation/KeyboardInterrupt propagate;
output-device failures stop execution.

Each step gets original seed copies and fresh private `context.state`.
`context.data` remains available for intentional sharing. Emit findings through
`self.report()` and summaries through `context.write()` so both console and
optional JSONL output receive them. Evidence should use JSON-compatible values;
bytes are supported through a base64 wrapper. Invalid evidence encoding fails
that step and is recorded before continuing.

Declare file-valued option spellings so their values resolve relative to the
scan file, rather than relying on changing the process's working directory:

```python
class MyProbe(BaseModule):
    path_options = {"--wordlist": "file", "--session": "session"}
    # option_parser() declares these options as usual.
```

`"file"` resolves a complete value; `"session"` preserves the optional label in
`LABEL=FILE`. Declare any aliases used in scan args as well. These are input
files: preflight verifies they exist and prevents outputs from aliasing them.
Do not mark regexes, URLs or literal payload strings as paths. All shipped
modules with file-valued options provide this metadata.

`core.scans.read_scan`, `scan_config` and `prepare_scan` implement preparation;
`run_scan` executes a prepared plan. `core.scanoutput.ScanReporter` sends output
to the terminal and an optional `JsonlResults` sink. The CLI owns and closes
these outputs; programmatic callers supply their own logger/results lifetimes.
`run_scan` shares one `HumanPacer` across all steps via `run_modules(...,
pacer=pacer)`. It never stores findings, step status or run metadata in SQLite.

---

## Response analysers

Importable from `core.analysers`. Each analyser has a single method:

```python
analyser.matches(response: LeviosaResponse) -> str | None
```

Returns a human-readable description string on match, `None` on no match. The string is ready to embed in a reported observation.

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
            self.report(response, context, f"[MYMODULE] {hit} — {response.request.method} {response.request.url}")
```

Analysers are stateless — safe to instantiate once in `setup()` and reuse across all responses.

---

## Minimal module (no mutation, no CLI flags)

```python
# modules/headercheck.py
from modules.base import BaseModule
from core.analysers import HeaderAnalyser


class HeaderCheck(BaseModule):
    needs_body = False  # only inspects headers; logging still captures a capped body

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
                self.report(response, context, f"[HEADERCHECK] {hit} — {response.request.url}")
```

---

## Full module example (mutation + CLI flags + analysers)

```python
# modules/paramfuzz.py
import argparse
import copy
from dataclasses import replace

from modules.base import BaseModule
from core.analysers import StatusCodeAnalyser, TextMatchAnalyser


class ParamFuzzer(BaseModule):
    def __init__(self):
        self._wordlist: list[str] | None = None
        self._param_name: str | None = None
        self._analysers = []

    def option_parser(self):
        parser = argparse.ArgumentParser(prog="paramfuzz", add_help=False, allow_abbrev=False)
        parser.add_argument("--wordlist", required=True, help="Wordlist file")
        parser.add_argument("--param", required=True, help="Param name to fuzz")
        parser.add_argument("--match-text", default=None, help="Flag responses containing this text")
        return parser

    def setup(self, args: list[str]) -> None:
        parsed, _ = self.option_parser().parse_known_args(args)

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
                new_req = replace(copy.deepcopy(req))
                for param in new_req.params:
                    if param.name == self._param_name:
                        param.value = word
                yield new_req

    async def analyze_one(self, response, context):
        hits = [a.matches(response) for a in self._analysers if a.matches(response)]
        if hits:
            desc = ", ".join(hits)
            self.report(response, context, f"[PARAMFUZZ] {desc} — {response.request.method} {response.request.url}")
```

> **Copying variants — `replace` vs `deepcopy`.** For a **url-only** mutation
> (path fuzzers that only rewrite `req.url`), `dataclasses.replace(req, url=...)`
> is the right tool: it makes a fresh request while safely sharing the unmutated
> `headers`/`params` (the engine only reads them). But when you mutate a `Param`
> value or a header — as `paramfuzz` does — you **must** `replace(copy.deepcopy(req))`
> (or deep-copy just the touched `Param`), because `replace` aliases the params
> list and mutating one variant's param would silently change every sibling.

---

## Checklist

- [ ] File is at `modules/<name>.py`
- [ ] Exactly one class inheriting `BaseModule`
- [ ] `mutate` is implemented (even if it just returns `requests`) and returns a **sync iterable** — a list or a lazy generator, never an async generator
- [ ] CLI options built in `option_parser()` (so `--list-modules` can show them), parsed in `setup` with `parse_known_args` (not `parse_args`); every argument has a `help=` string
- [ ] Missing required flags raise `RuntimeError` with a usage hint
- [ ] Copying variants: `dataclasses.replace(req, url=...)` for **url-only** mutation; `replace(copy.deepcopy(req))` when mutating `params`/headers
- [ ] Cross-response logic accumulates on `context.state` in `analyze_one` and emits in `finalize` (responses stream one at a time, in completion order)
- [ ] `needs_body = False` set if only status/headers are inspected
- [ ] Routing is left to global `--burp` / upstream proxy settings; module `use_burp` hints are ignored
- [ ] Shared filters are automatic; any custom filters are returned from `request_filters()`
- [ ] Findings emitted through `self.report()`; summaries through `context.write()`
- [ ] `status == 0` means a network error — handle or filter as appropriate

Modules that need to inspect the initial response can declare
`follow_redirects = False`; the runner applies this per module without changing
the shared configuration. The default `None` inherits the global setting.
`core.probes.input_variants(request, payload)` provides immutable one-at-a-time
mutations of scalar query/form/JSON parameters, URL query entries (including
repeated keys), and nested scalar leaves in explicit JSON bodies.

Identity-sensitive modules can set `store_response_cookies = False` to use a
dummy cookie jar. Explicit captured cookies are still sent, while response
Set-Cookie headers cannot contaminate subsequent identities.

Configured scans send the first five generated requests per step as Repeater by
default, then continue with the normal tool. Baselines count toward this prefix;
modules still mutate/finalize once and analyze each response exactly once. The
stream and HTTP session are shared across phases. Scan files can set
`repeater_preview` globally or per step (0 disables it). Generated-request order
therefore also controls preview order. `request.metadata["leviosa.tool"]` is
reserved for the sender's actual per-request category; the sender preserves the
request ID and does not modify input metadata.

Modules whose probes depend on prior responses may set `max_concurrency = 1`.
The runner caps that module's transport concurrency at the smaller of the global
limit and `max_concurrency`, without changing other modules or shared config.
The value must be a positive integer or `None`. This allows a lazy generator to
consult `context.state` after each response and stop yielding further requests;
`authentication` uses it to stop active login tests on lockout/rate-limit signals.
