# leviosa — Implementation Plan

## Design Principles

- **Core stays thin**: the core does exactly three things — parse input, send requests, load modules. No scan logic lives there.
- **Modules are self-contained**: a module receives requests and a shared context, sends what it needs through the core engine, and prints its own findings to stdout.
- **Progressive elaboration**: each phase produces a runnable tool. Nothing is left half-finished at the end of a phase.
- **asyncio over threads**: use `asyncio` + `aiohttp` for the request engine. It handles high concurrency with minimal overhead and keeps the module interface clean (async/await throughout).

---

## Directory Structure

```
leviosa/
├── leviosa.py              # CLI entry point
├── leviosa.toml            # optional user config file
├── pyproject.toml
├── core/
│   ├── models.py           # Request, Response, Context dataclasses
│   ├── parsers.py          # input parsing (URL, URL list, JSON file)
│   ├── requester.py        # asyncio/aiohttp request engine
│   ├── config.py           # config loading (toml + CLI overrides)
│   └── loader.py           # module discovery and loading
└── modules/                # all modules live here (built-in and user-added)
    ├── base.py             # BaseModule ABC
    └── fuzzer.py           # Phase 5
```

User-written modules are dropped into `modules/` and referenced by filename stem (`--module mymodule`).

---

## Core Data Model

Defined once in `core/models.py` and used everywhere. Never modified after Phase 1.

```python
@dataclass
class Param:
    type: str       # "cookie", "json", "query", "form", "header", ...
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
    """Mutable state shared across all requests and all modules in a run."""
    data: dict = field(default_factory=dict)
```

`LeviosaContext.data` is a plain dict. Modules use namespaced keys (`"fuzzer.findings"`, `"auth.token"`) to avoid collisions.

---

## Testing Infrastructure

Add to `pyproject.toml` dev dependencies: `pytest`, `pytest-asyncio`, `aioresponses`, `pytest-cov`.

```
tests/
├── conftest.py             # shared fixtures: sample LeviosaRequest list, default Config, tmp wordlist
├── test_models.py          # Phase 1
├── test_parsers.py         # Phase 1
├── test_config.py          # Phase 2
├── test_cli.py             # Phase 2
├── test_requester.py       # Phase 3
├── test_loader.py          # Phase 4
├── test_module_runner.py   # Phase 4
└── test_fuzzer.py          # Phase 5
```

Run tests: `pytest --cov=core --cov=modules`. Run a single file: `pytest tests/test_parsers.py`.

`conftest.py` should define reusable fixtures for the objects that appear across every phase: a list of `LeviosaRequest` objects (derived from `example_requests_input_file.json`), a default `Config` with proxy disabled, and a `tmp_path`-backed wordlist file. This avoids repetition and ensures tests use consistent, realistic data.

---

## Phase 1 — Project Scaffold and Data Model

**Goal**: importable package with data model and input parsing. No networking yet.

### Steps

1. **`pyproject.toml`** — declare the project, Python ≥ 3.11, and direct dependencies:
   - `aiohttp` — async HTTP client
   - `tomli` (Python < 3.11 fallback) or stdlib `tomllib` — config parsing

2. **`core/models.py`** — implement the dataclasses above. Keep them pure data; no methods beyond `__repr__`.

3. **`core/parsers.py`** — three input parsers, all returning `list[LeviosaRequest]`:
   - `parse_url(url: str) -> list[LeviosaRequest]` — single GET request
   - `parse_url_file(path: str) -> list[LeviosaRequest]` — one URL per line
   - `parse_request_file(path: str) -> list[LeviosaRequest]` — the JSON schema from `example_requests_input_file.json`

4. **Input detection logic** — determine which parser to call based on whether the argument is a URL, a plain text file, or a `.json` file.

**Deliverable**: `python -c "from core.parsers import parse_request_file; print(parse_request_file('example_requests_input_file.json'))"` works.

### Tests (`test_models.py`, `test_parsers.py`)

- **Models**: construct each dataclass with valid data and assert field values; confirm `LeviosaContext.data` defaults to an empty dict (not a shared mutable default).
- **`parse_request_file`**: parse `example_requests_input_file.json` and assert 6 requests returned, correct methods (`GET`/`POST`/`HEAD`), correct URLs, and that the POST request has both `cookie` and `json` params.
- **`parse_url`**: assert returns a single `LeviosaRequest` with method `GET`, the given URL, and empty params.
- **`parse_url_file`**: write a temp file with 3 URLs (including a blank line) via `tmp_path`; assert 3 requests returned, blank line ignored.
- **Input detection**: assert a `http://` string routes to `parse_url`, a `.json` path routes to `parse_request_file`, and a `.txt` path routes to `parse_url_file`.
- **Error cases**: assert `parse_request_file` raises a clear exception on malformed JSON; assert `parse_url_file` raises on a missing file.

---

## Phase 2 — Config and CLI

**Goal**: a runnable `leviosa.py` that parses arguments and config, prints the parsed requests, and exits. No requests sent yet.

### Steps

1. **`core/config.py`** — load `leviosa.toml` if it exists, then apply CLI overrides. Expose a single `Config` dataclass:

   ```python
   @dataclass
   class Config:
       proxy_enabled: bool = True
       proxy_host: str = "127.0.0.1"
       proxy_port: int = 8080
       concurrency: int = 20
       modules: list[str] = field(default_factory=list)
       verbose: bool = False
   ```

   `leviosa.toml` example:
   ```toml
   [proxy]
   host = "127.0.0.1"
   port = 8080

   [concurrency]
   limit = 20
   ```

2. **`leviosa.py` CLI** — `argparse` with:
   - Positional `target` — URL, URL-list file, or JSON request file
   - `--module <name>` — repeatable; module stem names to load from `modules/`
   - `--no-proxy` — disables BurpSuite proxy
   - `--concurrency <n>` — override config value
   - `--verbose` — debug output to stderr

3. **Config merge order**: defaults → `leviosa.toml` → CLI flags (CLI always wins).

**Deliverable**: `python leviosa.py http://example.com --no-proxy --module fuzzer` prints the parsed config and request list.

### Tests (`test_config.py`, `test_cli.py`)

- **Defaults**: instantiate `Config()` and assert all default values (`proxy_enabled=True`, `concurrency=20`, etc.).
- **TOML loading**: write a temp `leviosa.toml` with a non-default proxy port via `tmp_path`; assert `Config` picks it up.
- **CLI overrides**: assert `--no-proxy` sets `proxy_enabled=False` even when the TOML has `proxy.enabled = true`; assert `--concurrency 5` overrides the TOML value.
- **`--module` accumulation**: assert passing `--module a --module b` produces `config.modules == ["a", "b"]`.
- **CLI integration** (subprocess): run `python leviosa.py --help` and assert exit code 0 and that expected flag names appear in stdout.
- **Missing TOML**: assert `Config` loads successfully with all defaults when no `leviosa.toml` exists.

---

## Phase 3 — Async Request Engine

**Goal**: `leviosa.py` sends real HTTP requests (no modules yet, just raw dispatch).

### Steps

1. **`core/requester.py`** — implement `async def send(requests, config) -> list[LeviosaResponse]`:
   - Creates a single `aiohttp.ClientSession` for the run (connection pooling, shared headers)
   - Proxy: `aiohttp` accepts a proxy URL directly — build it from `config.proxy_host/port` when enabled
   - Concurrency: `asyncio.Semaphore(config.concurrency)` wraps each request
   - Converts `LeviosaRequest` headers list (`"Name: value"`) into a dict before sending
   - Builds the aiohttp call from `method`, `url`, and relevant `params` by type:
     - `cookie` params → `cookies=` kwarg
     - `json` params → `json=` kwarg
     - `query` params → `params=` kwarg
   - Returns a `LeviosaResponse` for every request, including failures (catches `aiohttp.ClientError`, stores a synthetic 0-status response so modules don't have to handle `None`)

2. **Error handling**: connection errors and timeouts are logged to stderr when `--verbose` is set; the run continues.

3. **Main dispatch** in `leviosa.py`: parse inputs → `asyncio.run(send(requests, config))` → print response count to stdout.

**Deliverable**: `python leviosa.py example_requests_input_file.json --no-proxy` sends all 6 requests and prints their status codes.

### Tests (`test_requester.py`)

Use `aioresponses` to mock all HTTP calls — no real network in tests.

- **Basic dispatch**: mock 3 URLs to return `200`; assert `send()` returns 3 `LeviosaResponse` objects with correct statuses and the originating `LeviosaRequest` attached.
- **Cookie params**: assert a request with `type="cookie"` params sends them as cookies (inspect the captured request in `aioresponses`).
- **JSON params**: assert a `POST` request with `type="json"` params sends a JSON body with correct keys and values.
- **Query params**: assert `type="query"` params appear in the request URL.
- **Header conversion**: assert the `"Name: value"` header list format is correctly converted to a dict before sending.
- **Error resilience**: mock one URL to raise `aiohttp.ClientConnectionError`; assert `send()` still returns a response for every input request, with `status=0` for the failed one, and does not raise.
- **Concurrency limit**: send 10 requests with `concurrency=2`; assert no more than 2 are in-flight simultaneously (track with a counter incremented/decremented around each mock call).
- **Proxy URL construction**: assert when `proxy_enabled=True`, the aiohttp session is created with the correct proxy URL string.

---

## Phase 4 — Module System

**Goal**: modules are loaded, chained, and run. A no-op module can be dropped into `modules/` and exercised end-to-end.

### Steps

1. **`modules/base.py`** — define `BaseModule`:

   ```python
   class BaseModule(ABC):
       @abstractmethod
       async def mutate(
           self,
           requests: list[LeviosaRequest],
           context: LeviosaContext,
       ) -> list[LeviosaRequest]:
           """Return the requests to send (may be the same list, modified, or expanded)."""
           ...

       async def analyze(
           self,
           responses: list[LeviosaResponse],
           context: LeviosaContext,
       ) -> None:
           """Called after responses are received. Print findings to stdout."""
           ...
   ```

   `mutate` receives the **full list** of input requests and returns a (possibly larger) list of requests to send. This allows a fuzzer to return 100 variants of each input request. `analyze` is called once with all responses from that module's send.

2. **`core/loader.py`** — `load_modules(names: list[str]) -> list[BaseModule]`:
   - For each name, looks for `modules/{name}.py`
   - Uses `importlib` to load the file as a module
   - Finds the single `BaseModule` subclass defined in it and instantiates it
   - Raises a clear error if the file is missing or defines no subclass

3. **Module runner** in `leviosa.py` — when modules are specified, replace the raw dispatch with:

   ```
   for module in modules:
       mutated_requests = await module.mutate(original_requests, context)
       responses = await send(mutated_requests, config)
       await module.analyze(responses, context)
   ```

   Each module gets the **original** input requests (not the previous module's mutations), but shares the same `context`. This avoids combinatorial explosion while still allowing modules to communicate via context.

4. **No-module fallback**: if `--module` is not specified, requests are sent as-is with no analysis (useful for basic reachability checks).

5. **`modules/base.py` passthrough implementation**: ship a concrete `PassthroughModule` that returns requests unchanged and prints nothing — useful as a copy-paste template.

**Deliverable**: `python leviosa.py url.txt --module passthrough` runs without errors and sends all requests.

### Tests (`test_loader.py`, `test_module_runner.py`)

- **Module discovery**: write a minimal valid module `.py` file to `tmp_path/modules/`; assert `load_modules(["mymodule"])` returns one instance of the correct class.
- **Missing module**: assert `load_modules(["nonexistent"])` raises with a message that names the missing file.
- **Invalid module** (no subclass): write a `.py` with no `BaseModule` subclass; assert `load_modules` raises a clear error.
- **`PassthroughModule.mutate`**: assert it returns exactly the input list, unchanged, with no copies or mutations.
- **Module runner — ordering**: use two spy modules (subclasses that record call order); assert `mutate` is called before `analyze` for each module, and module 1 completes fully before module 2 starts.
- **Original requests preserved**: use two modules where module 1's `mutate` returns a modified request list; assert module 2's `mutate` still receives the original unmodified requests.
- **Context sharing**: module 1 writes `context.data["test"] = 1` in `analyze`; assert module 2 reads `1` from the same key in its `mutate`.

---

## Phase 5 — Fuzzer Module

**Goal**: a working `modules/fuzzer.py` that injects payloads into request parameters.

### Steps

1. **CLI extension** — add `--wordlist <path>` and `--fuzz-params <name,...>` (default: all params). These are global CLI args passed through `Config` rather than module-specific flags, keeping the module interface clean.

2. **`modules/fuzzer.py` — `mutate`**:
   - Loads the wordlist (one payload per line)
   - For each request × each targeted param × each payload: create a copy of the request with that param's value replaced
   - Returns the full expanded list (e.g. 6 requests × 3 params × 100 payloads = 1800 requests)
   - Use `copy.deepcopy` on the request to avoid mutation aliasing

3. **`modules/fuzzer.py` — `analyze`**:
   - Groups responses by original request (use `hashkey` or build one from method+url+param)
   - Prints anomalies to stdout: status code deviations from baseline, significant body-length differences, and configurable error strings (e.g. `"SQL syntax"`, `"stack trace"`)
   - Format: `[FUZZER] POST /login | param=email | payload='' OR 1=1-- | status=500 (baseline: 200) | len=4821`

4. **Baseline**: before sending fuzzed requests, `mutate` can return the original unmodified requests first (prepended). `analyze` treats the first response per request as the baseline for comparison.

**Deliverable**: `python leviosa.py example_requests_input_file.json --module fuzzer --wordlist wordlists/sqli.txt --no-proxy` prints fuzzer findings to stdout.

### Tests (`test_fuzzer.py`)

- **Request expansion**: call `mutate` with 2 requests (each with 2 params) and a 3-payload wordlist; assert the returned list has the correct count (2 requests × 2 params × 3 payloads, plus 2 baseline requests prepended = 14 total).
- **Payload injection**: assert each fuzzed request has exactly one param replaced with a payload value, and all other params are unchanged.
- **No aliasing**: assert mutating a returned fuzzed request's params does not affect any other request in the list (deep copy verification).
- **`--fuzz-params` filtering**: assert only the named params are targeted; untargeted params are never replaced.
- **`analyze` — status anomaly**: build a response list where the baseline is `200` and one fuzzed response is `500`; assert the anomaly is printed to stdout with the correct format.
- **`analyze` — body-length anomaly**: baseline body length 100 bytes, one response 4000 bytes; assert it is flagged.
- **`analyze` — no false positives**: all responses identical to baseline; assert nothing is printed to stdout.
- **Wordlist loading**: write a temp wordlist with 5 payloads via `tmp_path`; assert `mutate` uses all 5.

---

## Phase 6 — Polish and Robustness

**Goal**: production-quality CLI experience. No new features.

### Steps

1. **Graceful Ctrl+C**: wrap `asyncio.run(...)` in a `KeyboardInterrupt` handler that cancels in-flight tasks and prints a summary of how many requests completed before exit.

2. **Verbose mode**: when `--verbose` is passed, log to stderr (not stdout) at key points: config loaded, modules loaded, requests sent (with URL), errors encountered. Stdout stays clean for module findings.

3. **Input validation**: clear, actionable error messages for bad inputs — missing file, malformed JSON, unknown module name, unreachable proxy.

4. **`pyproject.toml` entry point**: add `[project.scripts] leviosa = "leviosa:main"` so `pip install -e .` makes `leviosa` available as a command.

5. **README update**: add usage examples covering all three input modes, module chaining, and the fuzzer.

**Deliverable**: the tool is installable, handles bad inputs gracefully, and is documented.

### Tests (additions to existing test files + integration)

- **Error messages**: assert each bad-input scenario (missing file, malformed JSON, unknown module name) exits with a non-zero code and prints a human-readable message to stderr — not a raw Python traceback.
- **Verbose to stderr**: run a full dispatch with `--verbose` and assert all diagnostic output goes to stderr, with stdout containing only module findings.
- **`pip install -e .` entry point**: assert the installed `leviosa` command is on `PATH` and exits `0` with `--help`.
- **End-to-end integration test**: wire together parsers → config → requester (mocked via `aioresponses`) → module runner → fuzzer; assert the complete stdout output matches a known-good snapshot for a fixed input and wordlist. This is the "golden path" test that catches regressions across phase boundaries.

---

## Extension Points (Future Phases)

These are not in scope yet but the design above accommodates them cleanly:

- **New modules**: drop a `.py` into `modules/` implementing `BaseModule`. No changes to core required.
- **Auth token chaining**: a module writes a token to `context.data["auth.token"]`; a subsequent module in the same run reads it. The shared context already supports this.
- **Response differ module**: `mutate` returns `[baseline_request, modified_request]`; `analyze` diffs the two responses. No core changes needed.
- **Module-specific CLI args**: pass `sys.argv` or a config subsection into `BaseModule.__init__` if modules eventually need their own flags. Defer until a concrete need arises.
