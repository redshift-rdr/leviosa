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
- sends traffic **direct by default**. burpsuite is opt-in per module (`use_burp`), so high-volume scans don't bloat the `.burp` file. a `--proxy` flag routes non-burp traffic through any proxy (credentials supported), and `--no-proxy` forces everything direct.
- **logs all traffic** (every request/response) to a local sqlite db, so traffic that bypasses burp is still recorded for the engagement. path is configurable (`--log-db`, default `leviosa.db`); disable with `--no-log`.
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
pip install --no-index --find-links=./bundled_requirements aiohttp
```

### usage

```bash
# Single URL (raw dispatch, no module) — sent direct
leviosa http://target.local/path

# List of URLs (one per line)
leviosa urls.txt

# JSON file of HTTP request objects
leviosa requests.json

# Verbose output (proxy, traffic log, target, module names go to stderr)
leviosa http://target.local --verbose

# Cap response body reads at 64 KB (0 = unlimited; default 1 MB)
leviosa requests.json --max-body-bytes 65536

# Follow HTTP redirects (off by default — redirects are reported as-is)
leviosa http://target.local --follow-redirects   # or -L
```

#### proxying

By default nothing is proxied. Modules opt into burpsuite individually (via the
`use_burp` class attribute), so only the traffic you care to inspect ends up in
burp. Everything else is sent direct — or through a proxy of your choosing.

```bash
# Route non-burp traffic through a proxy (credentials optional)
leviosa requests.json --proxy http://127.0.0.1:8081
leviosa requests.json --proxy http://user:pass@127.0.0.1:8081

# Force everything direct, overriding both per-module burp opt-in and --proxy
leviosa requests.json --no-proxy
```

Precedence per request: `--no-proxy` (direct) > module `use_burp` (burp) >
`--proxy` (custom proxy) > direct. Credentials in a `--proxy` URL are sent as
proxy auth and are **not** written to the traffic log.

#### traffic logging

Every request/response the tool sends is recorded in a local sqlite db — even
traffic that bypasses burp — so the full engagement is captured. The `traffic`
table stores timestamp, module, proxy used, method, url, request headers/params,
status, response headers, response body, and an error flag.

```bash
# Custom log path (default: leviosa.db in the current directory)
leviosa requests.json --log-db engagement.db

# Disable logging entirely
leviosa requests.json --no-log
```

#### refreshing timed-out session cookies

Captured requests go stale when their session cookie expires. Refresh the
cookies **by name** across every request (and every module) without re-editing
the input file:

```bash
# Paste a fresh Cookie header (e.g. copied from browser devtools)
leviosa requests.json --cookies "session=NEW; csrf=NEW"

# ...or pull fresh cookies from a freshly captured request file
leviosa requests.json --cookie-from fresh_capture.json
```

Both replace matching cookies wherever they appear in the captured request — the
structured cookie params **and** the raw `Cookie:` header — leaving all other
cookies and everything else untouched. Only cookies already present are replaced
(matched by name); if both flags are given, `--cookies` values win over
`--cookie-from`.

#### config file (`leviosa.toml`)

CLI flags always win over the TOML file. Relevant blocks:

```toml
[burp]
host = "127.0.0.1"  # burp endpoint used by modules that opt in via use_burp
port = 8080

[proxy]
url = "http://user:pass@127.0.0.1:8081"  # proxy for non-burp traffic (== --proxy)

[concurrency]
limit = 20          # max requests in flight (== --concurrency)

[body]
max_bytes = 1048576 # response-body read cap in bytes, 0 = unlimited (== --max-body-bytes)

[request]
timeout = 30            # per-request total timeout in seconds
follow_redirects = false # follow HTTP redirects (== --follow-redirects / -L)

[log]
enabled = true      # write the sqlite traffic log (== --no-log to disable)
path = "leviosa.db" # traffic log path (== --log-db)
```

### modules

Modules are `.py` files in the `modules/` directory. Pass `--module <name>` (repeatable)
to load them at runtime. Module-specific flags are passed after the leviosa flags and
are consumed by the module's own argument parser.

```bash
# pathfuzz — keyword mode: replace FUZZ in the URL with each wordlist entry
leviosa http://target.local/FUZZ --module pathfuzz --wordlist wordlists/common.txt

# pathfuzz — custom keyword
leviosa "http://target.local/api/INJECT/data" \
    --module pathfuzz --wordlist wordlists/common.txt --keyword INJECT

# pathfuzz — recursive mode: fuzz every path depth level
#   given /home/next, generates /word/, /home/word/, /home/next/word/, …
leviosa http://target.local/home/next \
    --module pathfuzz --wordlist wordlists/common.txt --recursive

# versiondisclosure — passively fingerprint software/versions from response headers
#   reports curated disclosing headers (Server, X-Powered-By, X-AspNet-Version, …)
#   plus any other header whose value carries a product/version token (Foo/1.2.3)
leviosa requests.json --module versiondisclosure

# versiondisclosure — add a custom header name; curated-only (no heuristic scan)
leviosa http://target.local --module versiondisclosure \
    --extra-header X-My-Version --no-heuristic

# errorpages — induce error pages and flag information disclosure in them
#   emits variants per request (missing path, invalid method, oversized/malformed
#   URL, hostile param values) and reports 4xx/5xx responses + body signatures
#   (stack traces, SQL errors, filesystem paths, debug pages)
leviosa requests.json --module errorpages

# errorpages — restrict to specific techniques, shrink the long-url payload
leviosa http://target.local/app --module errorpages \
    --techniques not-found,param-injection,bad-method --long-url-len 1024

# Chain multiple modules (each receives the original requests; context is shared)
leviosa requests.json --module pathfuzz --module passthrough \
    --wordlist wordlists/common.txt
```

The `errorpages` module induces errors several ways — `not-found` (nonexistent
path → 404), `bad-method` (invalid verb → 405/501), `long-url` and
`special-path` (malformed URL → 414/400/500), `param-injection` (breaks existing
params) and `junk-param` (adds hostile params so it works even with none).
Restrict the set with `--techniques`. Each response is reported with the
technique that induced it, plus any information-disclosure signatures found in
the body; a per-status / per-signature summary prints at the end. Note that
parameter injection only mutates params parsed into request objects (e.g. from a
JSON request file) — for a bare URL carrying a `?query=...` string, `junk-param`
provides the coverage.

The `versiondisclosure` module sends requests unchanged and inspects only
response headers (no bodies downloaded). Each response with a disclosure is
reported as it arrives, and a deduplicated inventory of every distinct
`Header: value` — effectively a technology-stack summary — is printed at the end.

### writing a module

Drop a `.py` file into `modules/` that defines exactly one `BaseModule` subclass:

```python
from modules.base import BaseModule

class MyModule(BaseModule):
    # Set False if you only need the status code — the engine then skips
    # reading response bodies entirely (resp.body will be b"").
    needs_body = True

    # Set True to route this module's traffic through burpsuite. Default False:
    # traffic goes direct (or through --proxy). All traffic is logged either way.
    use_burp = False

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
