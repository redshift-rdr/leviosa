# leviosa
## a lightweight web pentest helper tool

### infrastructure
- runs on python
- runs as a command line tool
- highly modular, different scan types are loaded in as individual 'modules'

### features
- a core async web request component which streams requests concurrently
- can take in a URL, a list of URLs, or a JSON file of HTTP requests
- can specify 'modules' which are loaded in at runtime. modules perform some action/mutation on the http requests provided to it, then use the web request component to send the requests, then can optionally perform some action/analysis on the responses
- runs through burpsuite by default, with a --no-proxy to turn it off
- emphasis on lightweight. the core should be lightweight, no bloat and unnecesary features. functionality should be added in modules.

### memory efficiency (streaming)

The pipeline is fully **streaming**, so peak memory is **O(concurrency)** — not
O(total requests). This lets very long scans (tens of thousands of requests) run
in memory-constrained environments:

- `mutate()` produces request variants lazily; the engine pulls them one at a
  time rather than materialising the whole fuzz set up front.
- The request engine keeps at most `--concurrency` requests in flight (a sliding
  window) and **yields each response as it completes**. Output is therefore in
  **completion order, not input order**.
- Each response is analysed (`analyze_one`) and dropped before the next slot is
  refilled, so responses never accumulate.
- Response bodies are read with a size cap (`--max-body-bytes`, default **1 MB**;
  `0` = unlimited) so a module that deliberately probes large artefacts (e.g.
  `sensitivefiles` fetching `backup.zip`) never fully downloads a huge body.

### installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### usage

```bash
# Single URL (raw dispatch, no module)
leviosa http://target.local/path --no-proxy

# List of URLs (one per line)
leviosa urls.txt --no-proxy

# JSON file of HTTP request objects
leviosa requests.json --no-proxy

# Verbose output (proxy, target, module names go to stderr)
leviosa http://target.local --no-proxy --verbose

# Cap response body reads at 64 KB (0 = unlimited; default 1 MB)
leviosa requests.json --no-proxy --max-body-bytes 65536
```

#### config file (`leviosa.toml`)

CLI flags always win over the TOML file. Relevant blocks:

```toml
[concurrency]
limit = 20          # max requests in flight (== --concurrency)

[body]
max_bytes = 1048576 # response-body read cap in bytes, 0 = unlimited (== --max-body-bytes)

[request]
timeout = 30        # per-request total timeout in seconds
```

### modules

Modules are `.py` files in the `modules/` directory. Pass `--module <name>` (repeatable)
to load them at runtime. Module-specific flags are passed after the leviosa flags and
are consumed by the module's own argument parser.

```bash
# pathfuzz — keyword mode: replace FUZZ in the URL with each wordlist entry
leviosa http://target.local/FUZZ --no-proxy --module pathfuzz --wordlist wordlists/common.txt

# pathfuzz — custom keyword
leviosa "http://target.local/api/INJECT/data" --no-proxy \
    --module pathfuzz --wordlist wordlists/common.txt --keyword INJECT

# pathfuzz — recursive mode: fuzz every path depth level
#   given /home/next, generates /word/, /home/word/, /home/next/word/, …
leviosa http://target.local/home/next --no-proxy \
    --module pathfuzz --wordlist wordlists/common.txt --recursive

# Chain multiple modules (each receives the original requests; context is shared)
leviosa requests.json --no-proxy --module pathfuzz --module passthrough \
    --wordlist wordlists/common.txt
```

### writing a module

Drop a `.py` file into `modules/` that defines exactly one `BaseModule` subclass:

```python
from modules.base import BaseModule

class MyModule(BaseModule):
    # Set False if you only need the status code — the engine then skips
    # reading response bodies entirely (resp.body will be b"").
    needs_body = True

    def setup(self, args: list[str]) -> None:
        # parse module-specific CLI args here (optional)
        pass

    async def mutate(self, requests, context):
        # Return a sync iterable of requests to send. Return `requests` as-is,
        # or yield variants lazily from a helper generator (keeps memory flat).
        return requests

    async def analyze_one(self, response, context):
        # Called once per response, as each completes (completion order).
        if response.status == 200:
            print(f"[MYMODULE] {response.request.url}")

    async def finalize(self, context):
        # Optional: called once after all responses. Emit aggregate findings
        # accumulated on context.data here.
        pass
```

`analyze_one` sees one response at a time and the responses arrive in completion
order, so for anything that needs to compare across responses (a baseline, a
count, a diff) stash state on `context.data` during `analyze_one` and act in
`finalize`.

### json request file format

See `example_requests_input_file.json` for a full example. Each object in the array:

```json
{
  "method": "GET",
  "url": "http://target/path",
  "headers": ["Header-Name: value"],
  "params": [
    {"type": "cookie", "name": "session", "value": "abc"},
    {"type": "json",   "name": "email",   "value": "x@x.com"}
  ],
  "hashkey": -1295339830
}
```

Supported `params.type` values: `cookie`, `json`, `query`, `form`, `header`.
