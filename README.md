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

The transport streams requests with **O(concurrency)** in-flight responses.
Modules can retain additional aggregation state: authorisation matrices grow
with endpoints, and SQLi retains comparisons only for seeds still in progress.
JSON input and wordlists are loaded into memory; URL-list input streams from disk:

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

On Windows, `.\install.ps1` does the same (creates `.venv` and installs aiohttp
from the bundled wheels).

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
`--proxy` (custom proxy) > direct. Credentials in a `--proxy` URL are passed as proxy authentication. The traffic
log records actual application request headers, including authentication headers
when present.

#### traffic logging

Traffic is saved in the format used by Burp's **Log Requests to SQLite**
extension. The database contains exactly one table, `ACTIVITY`, with eight
nullable `TEXT` columns and no additional keys, tables or columns:

| Column | Stored value |
| --- | --- |
| `LOCAL_SOURCE_IP` | Local address of the outgoing connection; empty if no connection was established |
| `TARGET_URL` | Effective URL, including query parameters |
| `HTTP_METHOD` | Sent HTTP method |
| `BURP_TOOL` | `Repeater`, `Intruder` or `Scanner`, resolved from module defaults and overrides |
| `REQUEST_RAW` | Prepared request line, headers and transmitted body, using CRLF framing |
| `SEND_DATETIME` | Local send time in `YYYY-MM-DD HH:MM:SS` format, without timezone suffix |
| `HTTP_STATUS_CODE` | Status as text, or `"0"` for a failed exchange |
| `RESPONSE_RAW` | Response body only, matching the example extension database |

Findings and module summaries remain on the console. They are not written to
SQLite. Each followed redirect gets its own traffic row. Writes commit per row,
so traffic is visible during a run and idle scans do not hold database write locks.

```bash
# New output file, or an existing compatible Burp database
leviosa requests.json --log-db engagement.sqlite

# Disable traffic capture
leviosa requests.json --no-log
```

Existing compatible `ACTIVITY` databases are appended to without changing their
schema. The old Leviosa `traffic` schema remains readable but is not migrated or
written to: choose a new `--log-db` path when upgrading. Incompatible output
schemas produce an error before requests are sent.

The logger captures actual prepared headers, cookies, encoded parameters and
request bodies. Response bodies are read for logging even for status-only
modules, up to `--max-body-bytes` (default 1 MB, `0` for unlimited). Modules with
`needs_body=False` still receive an empty body. Use `--no-log` to retain the
status-only behaviour that skips body reads. A capped body is a prefix; the fixed
Burp schema has no field for recording truncation.

Text uses the response's declared charset when available, otherwise UTF-8;
un-decodable bytes fall back to a one-to-one Latin-1 mapping. Request bytes use
UTF-8 with the same fallback. No base64 wrappers or metadata are added to the
extension's text columns. A connection failure with no transmitted request has
empty raw fields and source address.

##### tool categories and overrides

Categories describe how the activity is used, independently of proxy routing.
They are stored only in `ACTIVITY.BURP_TOOL`; no tagging headers are sent to the
target or Burp. Defaults do not depend on request counts:

| Category | Default activity |
| --- | --- |
| `Repeater` | Raw dispatch and `passthrough`: replaying requests |
| `Intruder` | `pathfuzz`, `adminfinder`, `sensitivefiles`, `authz`: iterating paths or identities |
| `Scanner` | `sqli`, `cors`, `csp`, `securityheaders`, `versiondisclosure`, `methodtamper`, `errorpages`: checking security conditions |

```bash
# Override every selected module (or raw dispatch)
leviosa requests.json --module sqli --tool Repeater

# Override one module while others retain their defaults
leviosa requests.json -m passthrough -m securityheaders --module-tool securityheaders=Repeater

# A named override takes precedence over the run-wide CLI override
leviosa requests.json -m passthrough -m securityheaders --tool Intruder --module-tool securityheaders=Scanner
```

`--module-tool NAME=TAG` is repeatable for different selected modules. Unknown
tags, duplicate overrides and overrides for unselected modules are rejected
before traffic or database creation. `leviosa --list-modules` shows defaults.

Optional defaults in `leviosa.toml`:

```toml
[tools]
# default = "Scanner"  # optional run-wide override

[tools.modules]
sqli = "Repeater"     # exception for this module
```

Precedence is CLI module override > CLI run-wide override > TOML module override
> TOML run-wide override > module default. TOML module entries can describe
modules that are not selected for the current run. Raw dispatch defaults to
`Repeater` and uses only the run-wide override. Human mode uses the resolved
category to decide which requests to pace.

#### human mode and random timing

`--human-mode` sends **Repeater** actions sequentially, with a fresh random idle
interval of 2–8 seconds between them by default. **Intruder** and **Scanner**
traffic retain the configured `--concurrency` and have no human-mode delay.
Tool overrides apply before this decision.

```bash
# Pace raw replay (Repeater by default)
leviosa requests.json --human-mode

# Only passthrough is paced; securityheaders retains normal concurrency
leviosa requests.json -m passthrough -m securityheaders --human-mode

# Custom Repeater interval
leviosa requests.json --human-mode --human-timing-min 1.5 --human-timing-max 5

# Temporarily treat a small SQLi probe as Repeater activity
leviosa requests.json -m sqli --module-tool sqli=Repeater --human-mode

# Override a TOML setting
leviosa requests.json --no-human-mode
```

The first Repeater action starts immediately. Subsequent intervals run from the
previous Repeater action's completion; analysis, module finalisation and time
spent in intervening scans count towards the interval. Cadence is shared across
module boundaries within one run and starts fresh for the next run. There is no
wait after the last action. Failed attempts still advance the cadence, and
followed redirects remain part of the same action.

`--human-timing-min`/`--human-timing-max` also enable human mode unless explicitly
combined with `--no-human-mode`. Bounds must be finite, non-negative numbers with
minimum <= maximum; zero is allowed and still keeps Repeater actions sequential.

The existing **`--random-timing` takes precedence** over human mode. It keeps the
legacy behaviour of sending every category sequentially, using its own
`--random-timing-min`/`--random-timing-max` range (also 2–8 seconds by default).
Its interval starts after analysis, and resets at each module as before. Use
`--no-random-timing` to disable it when enabled in TOML:

```bash
leviosa requests.json --human-mode --no-random-timing
leviosa requests.json --random-timing --random-timing-min 2 --random-timing-max 4
```

Timing ranges alone enable their associated mode; an explicit `--no-...` flag
wins over those ranges. If both modes remain enabled, random timing wins.
`--verbose` shows the effective policy and actual human-mode waits on stderr.
SQLite output remains only the eight traffic columns.

##### inspecting the log

`traffic.py` (installed as `leviosa-traffic`) reads both formats without modifying
them. Filters combine with AND:

```bash
python traffic.py engagement.sqlite --desc
python traffic.py engagement.sqlite --after "2026-10-29 11:00" --status 500
python traffic.py engagement.sqlite --status-class 5xx --path /api --tool Scanner
python traffic.py engagement.sqlite --errors-only --count
```

Filters include `--after`/`--before`, repeatable `--status`, `--status-class`,
`--method`, `--tool`, `--path` and `--errors-only`. `--tool` filters `BURP_TOOL`
in `ACTIVITY`; the legacy-only `--module` filter is unavailable because module
names are not stored in the Burp schema. Legacy databases retain `--module` and
UTC datetime labels. `ACTIVITY` output shows local time and tool names; its byte
count is the UTF-8 size of the stored response text. Pass a database path or use
the configured default. Output defaults to 100 rows, controlled with `--limit`.

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

[timing]
human = false      # --human-mode / --no-human-mode
human_min = 2.0    # --human-timing-min
human_max = 8.0    # --human-timing-max
random = false     # --random-timing / --no-random-timing; overrides human mode
min = 2.0          # --random-timing-min
max = 8.0          # --random-timing-max
```

### modules

Built-in modules load from the installed package, regardless of the working
directory. Pass `--module <name>` (repeatable) to select them. To load your own
modules, use `--modules-dir PATH`; this explicitly selects that directory instead
of the built-ins. It also works with `--list-modules`.

Selected modules declare their flags in `option_parser()`. The CLI rejects
unknown arguments and conflicting option names before sending requests. Standard
request filters are handled centrally, including for modules without a setup
hook. Modules with conflicting flags must be run separately.

Run `leviosa --list-modules` to see every available module, its default tool
category, what it does and its command-line options (plus the standard request filters every module accepts):

```bash
leviosa --list-modules
```

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
response headers. Bodies are captured only for traffic logging. Each response with a disclosure is
reported as it arrives, and a deduplicated inventory of every distinct
`Header: value` — effectively a technology-stack summary — is printed at the end.

#### request filters

A module can restrict or sample the requests it receives before it runs, via
**request filters** (`core/filters.py`). **All shipped modules** support the
standard flags — `--method` (repeatable), `--path` (regex on the URL path),
`--sample N` and `--sample-seed` — which compose (selective filters first, then
sampling):

```bash
# Fuzz admin paths on only the POST requests from a captured set
leviosa requests.json --module adminfinder --method POST

# Run errorpages against a reproducible random sample of 5 requests to /api paths
leviosa requests.json --module errorpages --path '^/api' --sample 5 --sample-seed 7
```

Filters run on a module's input requests (a module can also apply one to its own
output). They're pluggable: a new one is just a `RequestFilter` (or
`PredicateFilter`) subclass. See the "Request filters" section in
`module_creation.md`.

### unattended scans

A TOML scan file runs modules in the order of its `[[steps]]` entries. Each
step receives fresh copies of the original target requests, with independent
module options and filters. Steps do not consume the previous step's mutations.
The same module may appear repeatedly, including with different options or tags.

```bash
# Validate every step and input before execution; no traffic or output files
leviosa --scan examples/review-scan.toml --validate-scan

# Run all steps without prompts
leviosa --scan examples/review-scan.toml

# Override the target and output locations from the CLI
leviosa https://target.local/app --scan examples/review-scan.toml --log-db engagement.sqlite --results engagement.jsonl
```

See [examples/review-scan.toml](examples/review-scan.toml) for a complete example.
A minimal definition is:

```toml
name = "application-review"
target = "requests.json"       # URL, URL-list file or captured request JSON
database = "engagement.sqlite"
# Optional; omit for console-only findings and progress:
results = "engagement.jsonl"
human_mode = true
on_error = "continue"

[[steps]]
name = "baseline"
module = "passthrough"

[[steps]]
name = "header audit"
module = "securityheaders"
filters = { methods = ["GET"], path = "^/api", sample = 10, sample_seed = 7 }

[[steps]]
module = "pathfuzz"
args = ["--wordlist", "paths.txt", "--recursive"]
tool = "Intruder"

[[steps]]
name = "core headers as a manual check"
module = "securityheaders"
args = ["--no-recommended"]
tool = "Repeater"
```

Paths declared in the scan file resolve relative to that file, including target
files, database/results files, `modules_dir`, wordlists, payload files and
`--session LABEL=FILE` paths. Paths supplied on the CLI resolve from the current
working directory. Existing `leviosa.toml` defaults are loaded from the working
directory as before. An explicit scan-file value overrides those defaults; CLI
settings override the scan file.

Optional root settings are `concurrency`, `max_body_bytes`, `timeout`,
`follow_redirects`, `no_proxy`, `proxy_url`, `burp_host`, `burp_port`, `log_enabled`,
`verbose`, `tool`, `human_mode`, `human_timing_min`, `human_timing_max`,
`random_timing`, `random_timing_min` and `random_timing_max`. Use `no_proxy=true`
for a direct scan. `modules_dir` selects custom modules globally, or put it on
individual steps to mix custom and built-in modules.

Steps accept `name`, `module`, `args`, `filters`, `tool` and `modules_dir`. Filters
can instead be expressed as standard filter flags in `args`; mixing the two
forms within a step is rejected. CLI request filters apply first, followed by
step filters. Put module options in step `args`; `--module` and loose module
arguments cannot be combined with `--scan`.

Tool precedence for scans is CLI module override > CLI run-wide override > step
`tool` > scan-file `tool` > `leviosa.toml` module/default overrides > module
class default. `--module-tool NAME=TAG` applies to every occurrence of that
module. Human cadence is shared across steps, including repeated modules.

Preflight checks the full definition, all module options and setup resources,
all input seeds, existing database compatibility and output paths before any
HTTP dispatch. It streams URL lists without materialising generated probes.
Unknown fields, invalid later steps, missing files and output/input path aliases
are errors for the entire scan. Validation runs module setup, but does not run
mutation or analysis. Output directories must already exist.

Runtime module failures are printed, optionally recorded in JSONL, and execution
continues to the next step. `on_error` defaults to `"continue"` and currently
accepts only that value. Output-storage failures stop the scan. Ctrl-C closes the
current request stream, records interruption when possible and skips remaining
steps. Exit codes are **0** for completed scans, **1** for runtime/output failures
(including scans completed with module failures), **2** for invalid definitions
or arguments, and **130** for interruption. Network failures retain status `"0"`
in `ACTIVITY`; they do not by themselves fail a module.

The optional results file is append-only JSONL and is separate from SQLite.
Events include `scan_started`, `step_started`, `finding`, `message`,
`step_finished` and `scan_finished`, with UTC timestamps and a unique run ID.
Step records include the index, name, public module name and resolved tool;
findings include observation, confidence, evidence and request identifiers,
method and URL. Binary evidence is represented using base64. Each event is
flushed so progress is inspectable during execution. Reusing a file appends a
new run rather than replacing earlier results. SQLite still contains **only
traffic in the unchanged eight-column `ACTIVITY` table**.

### writing a module

Create a `.py` file defining exactly one concrete `BaseModule` subclass. Imported
parent classes do not count. Load it with `--modules-dir PATH --module NAME`:

```python
from modules.base import BaseModule

class MyModule(BaseModule):
    # Set False if you only need the status code (resp.body will be b"").
    # Logging still reads capped bodies; --no-log skips those reads.
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
            self.report(response, context, f"[MYMODULE] {response.request.url}")

    async def finalize(self, context):
        # Optional: called once after all responses. Emit aggregate findings
        # accumulated on context.state here.
        pass
```

`analyze_one` sees one response at a time and the responses arrive in completion
order, so for anything that needs to compare across responses (a baseline, a
count, a diff) stash private state on `context.state` during `analyze_one` and
act in `finalize`. The runner creates fresh state for every module invocation;
`context.data` remains available for intentional cross-module sharing.

Findings carry the module, affected request, observation, evidence and confidence.
`context.reporter` defaults to terminal output. Programmatic callers can supply
an object implementing `report(finding)` and `write(message)` to collect or
export findings without parsing terminal text. Use `context.write()` for summary
text and `self.report(response, context, message, evidence={...})` for findings.

Requests have a unique `request_id`, a shared `seed_id` across their variants,
and a `metadata` dictionary for probe labels. `dataclasses.replace(req, ...)`
creates a new request ID, preserves the seed ID and copies metadata. Responses
retain that request, so comparisons do not depend on Python object identities.

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


An optional explicit `body` supports nested JSON, arrays and raw data:

```json
{"method": "POST", "url": "http://target/api", "body": {"kind": "json", "value": {"items": [1, true, null]}}}
```

For raw text use `{"kind": "raw", "value": "text"}`; for binary data use
`{"kind": "raw", "value": "AP8=", "encoding": "base64"}`. An explicit body
cannot be combined with JSON/form params. Existing param-based inputs continue
to work. Query and form params preserve repeated names, and headers accept both
`Name:value` and `Name: value`. Response headers support case-insensitive
`get()` and `getall()` for repeated fields. This remains HTTP replay through
aiohttp, rather than byte-for-byte replay of an entire captured HTTP message.

Traffic logs use only the Burp-compatible `ACTIVITY` schema described above.
Request IDs, probe metadata, findings and response headers are not added to it.
