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
    def setup(self, args: list[str]) -> None:
        """
        Called once before mutate/analyze, with any CLI args not consumed by
        the main leviosa parser. Override to parse module-specific flags.
        Default implementation is a no-op.
        """

    @abstractmethod
    async def mutate(
        self,
        requests: list[LeviosaRequest],
        context: LeviosaContext,
    ) -> list[LeviosaRequest]:
        """
        Return the list of requests to send. You may return the original list
        unchanged, modify requests in-place (use copy.deepcopy to be safe),
        or return an expanded list (e.g. one input → many fuzz variants).
        """
        ...

    async def analyze(
        self,
        responses: list[LeviosaResponse],
        context: LeviosaContext,
    ) -> None:
        """
        Called after all responses are received. Print findings to stdout.
        Default implementation is a no-op.
        """
```

### Rules

- **One subclass per file.** The loader scans for exactly one `BaseModule` subclass in the file. Defining two raises a `ValueError`.
- **File name = module name.** A module at `modules/sqli.py` is loaded with `--module sqli`.
- **`mutate` is required.** It is the only abstract method. If you have nothing to mutate, `return requests`.
- **Each module receives the original requests**, not the output of a previous module. Mutations do not chain between modules.
- **`analyze` output goes to stdout.** Use `print()`. Prefix lines with `[MODULENAME]` by convention.

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

### Using analysers in analyze()

```python
async def analyze(self, responses, context):
    for resp in responses:
        for analyser in self._analysers:
            if hit := analyser.matches(resp):
                print(f"[MYMODULE] {hit} — {resp.request.method} {resp.request.url}")
```

Analysers are stateless — safe to instantiate once in `setup()` and reuse across all responses.

---

## Minimal module (no mutation, no CLI flags)

```python
# modules/headercheck.py
from modules.base import BaseModule
from core.analysers import HeaderAnalyser


class HeaderCheck(BaseModule):
    def __init__(self):
        self._analysers = [
            HeaderAnalyser("Server"),
            HeaderAnalyser("X-Powered-By"),
            HeaderAnalyser("X-AspNet-Version"),
        ]

    async def mutate(self, requests, context):
        return requests  # send original requests unchanged

    async def analyze(self, responses, context):
        for resp in responses:
            for analyser in self._analysers:
                if hit := analyser.matches(resp):
                    print(f"[HEADERCHECK] {hit} — {resp.request.url}")
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
        variants = []
        for req in requests:
            for word in self._wordlist:
                new_req = copy.deepcopy(req)
                for param in new_req.params:
                    if param.name == self._param_name:
                        param.value = word
                variants.append(new_req)
        return variants

    async def analyze(self, responses, context):
        for resp in responses:
            hits = [a.matches(resp) for a in self._analysers if a.matches(resp)]
            if hits:
                desc = ", ".join(hits)
                print(f"[PARAMFUZZ] {desc} — {resp.request.method} {resp.request.url}")
```

---

## Checklist

- [ ] File is at `modules/<name>.py`
- [ ] Exactly one class inheriting `BaseModule`
- [ ] `mutate` is implemented (even if it just returns `requests`)
- [ ] `setup` uses `parse_known_args` (not `parse_args`) to ignore other modules' flags
- [ ] Missing required flags raise `RuntimeError` with a usage hint
- [ ] `copy.deepcopy(req)` used before mutating a request object
- [ ] Findings printed to stdout; prefix with `[MODULENAME]`
- [ ] `status == 0` means a network error — handle or filter as appropriate
