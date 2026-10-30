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
- sends traffic **direct by default**. `--burp` explicitly routes all traffic through Burp. Ordered endpoint regex rules select upstream proxies with direct exceptions; `--no-proxy` forces everything direct.
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
python -m pip install -e .
```

For offline Windows installation, `.\install.ps1` creates `.venv` and installs
all dependencies from `bundled_requirements` using the version constraints in
`pyproject.toml`. It stops if installation fails. The bundled native wheels target
64-bit Windows CPython 3.12; other platforms/Python versions need matching wheels
or the online installation above.

The capture hook supports aiohttp 3.9 through 3.14, including the bundled 3.14.1
writer's extra content-length argument and coalesced header/body writes. If an
older checkout reports `CapturedRequest.write_bytes() takes 3 positional arguments
but 4 were given`, its capture hook predates the installed aiohttp writer API.
Use the updated capture code and dependency constraints together; replacing
captured requests is not the remedy for that error.

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

By default every module and raw request goes direct. `--burp` enables Burp
for the entire run; legacy module `use_burp` attributes no longer enable it.

```bash
# Explicit Burp mode (default listener: 127.0.0.1:8080)
leviosa requests.json --burp
leviosa requests.json --module securityheaders --burp

# Ordered upstream proxy rules, or one fallback proxy
leviosa requests.json --proxy-config examples/proxies.toml
leviosa requests.json --proxy http://user:pass@127.0.0.1:8081

# Force direct connections, overriding Burp mode, rules and fallbacks
leviosa requests.json --no-proxy
```

Precedence per prepared endpoint: `--no-proxy` > `--burp` > first enabled
matching proxy rule > `--proxy` / `[proxy].url` > proxy-file `default_proxy` > direct.
`--no-burp` disables Burp enabled in configuration. Burp mode sends requests to
Burp as the single outbound proxy; configure further upstream chaining inside
Burp itself. This file configures leviosa's upstream selection, not Burp's settings.

Proxy configuration is TOML, with ordered `[[rules]]`:

```toml
# Optional fallback; omit for direct connections when no rule matches.
# default_proxy = "http://fallback.example:8080"

[[rules]]
name = "Private paths bypass proxies"
endpoint_regex = '^https://app\.example/private(?:/|$)'
direct = true

[[rules]]
name = "Application upstream"
endpoint_regex = '^https://app\.example/'
proxy = "http://user:password@upstream.example:8080"
enabled = true

[[rules]]
name = "Catch-all upstream"
endpoint_regex = '.*'
proxy = "http://fallback.example:8080"
```

The first enabled matching rule wins, like
[Burp's ordered upstream proxy rules](https://portswigger.net/burp/documentation/desktop/settings/network/connections).
Specific exceptions belong above broad rules. Matchers are Python regular
expressions searched against the complete prepared URL: scheme, host, port when
present, path and query, including structured query parameters. URLs use aiohttp's
normalization/escaping; default ports may be omitted. Anchor patterns when you
want a host/path boundary. TOML literal strings (`'...'`) preserve regex backslashes.
Each rule requires `endpoint_regex` and exactly one of `proxy` or `direct=true`;
`name` and `enabled` are optional. Regexes, URLs and field types are validated
before traffic, even for disabled rules.

HTTP and HTTPS upstream proxies are supported, including HTTPS targets through
CONNECT. Optional URL credentials use Basic proxy authentication; percent-encode
reserved characters in usernames/passwords. SOCKS, NTLM, Burp configuration
imports and multi-proxy chains are not implemented. Proxy authentication is kept
separate from target authentication. Verbose routing summaries omit proxy
credentials; normal wire traffic logs may contain authentication headers.

Rules are re-evaluated for every redirect hop and authentication health-check
endpoint. Selected proxy failures produce normal transport errors; there is no
silent fallback to a direct connection or another upstream. Routing does not
change activity categories, pacing, findings, or the ACTIVITY schema. See
[examples/proxies.toml](examples/proxies.toml) for an editable example.

In `leviosa.toml`, set `[burp].enabled = true` to enable Burp, configure its
`host`/`port`, and/or set `[proxy].config_file = "proxies.toml"`. That path is
relative to `leviosa.toml`. Scan TOML root settings support `burp = true` and
`proxy_config_path = "proxies.toml"` (relative to the scan file), alongside the
existing `proxy_url`, `burp_host`, `burp_port`, and `no_proxy`. CLI flags override
configuration; `--proxy-config FILE` paths are relative to the working directory.
`--validate-scan` checks the proxy file offline and protects it from being used
as a traffic/results output file. A configured `no_proxy=true` still takes
precedence over Burp mode.

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
| `Repeater` | Raw dispatch, `passthrough`, and `xss`: replay and reflection checks |
| `Intruder` | `pathfuzz`, `adminfinder`, `sensitivefiles`, `authz`, `idor`, `xsspayloads`, `traversal`, `commandinjection`, `ssti`, `ssrf`, `xxe`: iterating paths, identities or payloads |
| `Scanner` | `sqli`, `cors`, `csp`, `securityheaders`, `versiondisclosure`, `methodtamper`, `errorpages`, `sessioncookies`, `openredirect`: checking security conditions |

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
enabled = false       # --burp / --no-burp
host = "127.0.0.1"  # listener used only when Burp mode is enabled
port = 8080

[proxy]
# Optional fallback proxy (== --proxy):
# url = "http://user:pass@127.0.0.1:8081"
# config_file = "proxies.toml" # ordered upstream rules (== --proxy-config)

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
repeater_preview = 5           # first five generated requests per step use Repeater
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
`random_timing`, `random_timing_min`, `random_timing_max` and `repeater_preview`. Use `no_proxy=true`
for a direct scan. `modules_dir` selects custom modules globally, or put it on
individual steps to mix custom and built-in modules.

Steps accept `name`, `module`, `args`, `filters`, `tool`, `modules_dir` and
`repeater_preview`. Filters
can instead be expressed as standard filter flags in `args`; mixing the two
forms within a step is rejected. CLI request filters apply first, followed by
step filters. Put module options in step `args`; `--module` and loose module
arguments cannot be combined with `--scan`.

Configured scans default to a **five-request Repeater preview for every step**.
The first five generated requests are sent sequentially as Repeater, then the
remaining requests use the resolved normal tool and its usual concurrency. This
uses the module's existing generation order: baseline requests count toward the
five, and payload lists retain their configured order. These are the first five
requests, not five distinct payloads or five requests per input. A short step can
therefore run entirely as Repeater. Already-Repeater steps retain their normal
Repeater behavior.

Preview requests are analyzed once as part of the same module run. The request
stream, baseline comparisons and HTTP session continue across the transition;
requests are not replayed. With human mode enabled, preview requests use the
shared Repeater cadence, including the interval between steps. Explicit random
timing still applies to every request. Traffic rows and finding events record
the actual request category, including redirect hops. Proxy routing continues to
follow the module's existing settings.

Set `repeater_preview = N` at the root of a scan file to change the default, or
inside a `[[steps]]` table to override it for that step. Use `0` to disable the
preview globally or for a particular step. Counts must be non-negative integers.
For example:

```toml
repeater_preview = 5

[[steps]]
module = "traversal"
repeater_preview = 3

[[steps]]
module = "commandinjection"
repeater_preview = 0
```

The preview applies to `--scan` runs by default; direct `-m` runs keep their
usual tags. Tool overrides select the normal phase's category; enabled previews
remain Repeater. Disable the preview when every request must use an override.

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
Step records include the index, name, public module name, resolved normal tool
and configured preview count; finding events use the actual request tool;
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

Captured `Content-Length` and `Transfer-Encoding` headers (including copies in
header parameters) are removed from the prepared request. aiohttp calculates
framing from the actual outgoing payload, so JSON/form reserialization, Unicode
encoding and module mutations cannot retain a shorter captured body length or
conflicting chunked headers. Original input objects and files are preserved;
the traffic log records the recalculated wire headers and full transmitted body.
Explicit raw bodies represent entity data, not pre-chunked HTTP wire framing.
`--max-body-bytes` limits response reads only, not outgoing request bodies.

Traffic logs use only the Burp-compatible `ACTIVITY` schema described above.
Request IDs, probe metadata, findings and response headers are not added to it.

### application testing modules

The first application-testing batch adds `sessioncookies`, `openredirect`, `xss`,
and `idor`, and extends `authz`. All five inspect the initial response even when
`--follow-redirects` is enabled, so redirects to login pages cannot hide the
original status or an external redirect destination.

```bash
# Declare sensitive cookie names explicitly; repeat for multiple session cookies.
leviosa requests.json -m sessioncookies --session-cookie sessionid

# Mutate one query/form/JSON input at a time, including query strings in URLs
# and nested scalar fields in explicit JSON bodies.
leviosa requests.json -m openredirect
leviosa requests.json -m xss  # Repeater: existing reflection/context check
leviosa requests.json -m xsspayloads  # Intruder: built-in payload scan
leviosa requests.json -m xsspayloads \
  --xss-payloads /usr/share/seclists/Fuzzing/XSS/XSS-Somdev.txt

# Donor captures supply cookies, Authorization, X-API-Key and X-Tenant-ID.
# Add custom credential or tenant headers explicitly.
leviosa requests.json -m authz \
  --session alice=alice.json --session bob=bob.json \
  --identity-header X-Workspace-ID --anonymous --compare-body

# Replay known owned-object requests against other identities.
leviosa object-requests.json -m idor \
  --session alice=alice.json --session bob=bob.json \
  --access-rules examples/object-access-rules.json --anonymous
```

`sessioncookies` checks Secure, SameSite validity, secure cookie prefixes and
Domain scope. HttpOnly, missing explicit SameSite, HTTP transport and site-wide
Path reviews apply only to cookie names selected with `--session-cookie`; it
does not guess which cookies authenticate users. Domain and Path observations
are review prompts, not proof of a vulnerability. Findings exclude cookie values.
Only response Set-Cookie headers are audited, so include login/refresh requests
in the input to observe cookies being issued.

`openredirect` sends unique HTTPS and scheme-relative destinations under
`leviosa.invalid`. A finding requires a 301/302/303/307/308 Location resolving to
the exact probe hostname. It never follows that redirect. It does not test
JavaScript or HTML meta refresh redirects.

`xss` injects unique markers and a harmless custom HTML element. It distinguishes
encoded/plain reflection from injected HTML elements, script text, event handler
attributes and URL attributes in HTML responses. Results are **potential reflected
XSS**, not confirmed script execution. URL-attribute reflection may be benign;
verify the encoding and browser behavior. DOM XSS and stored XSS need separate
browser/workflow testing. Raw request bodies and cookie/header inputs are not
mutated by these two modules.

`authz` replaces configured identity headers in both raw headers and header
parameters, and replaces all cookies. A header absent from a donor is removed,
so the captured user's bearer token cannot survive a swap. Unconfigured custom
credential headers remain unchanged: select them with `--identity-header`.
Donor captures should contain a consistent identity; later captured values win.
Response cookies are not stored between identities, including anonymous requests.
Anonymous mode strips cookies and configured identity headers. Body comparison
uses canonical JSON or whitespace-normalized text fingerprints, reports matching
successful nonempty responses as observations, and exposes fingerprints in
structured results. Matching responses alone do not establish unauthorized access.
Body comparisons and access markers use the captured body prefix, subject to
`--max-body-bytes`.

Access rules are a JSON list. Each rule matches the captured request's exact
`method` (case-insensitive) and `url`, specifies allowed session labels, and may
specify a case-sensitive `contains` response marker. For example:

```json
[
  {
    "method": "GET",
    "url": "https://app.example/api/documents/42",
    "allowed": ["alice"],
    "contains": "document-owned-by-alice-42"
  }
]
```

`authz --access-rules FILE` reports an indicator when a disallowed identity gets
2xx and the marker matches, if provided. `idor` requires an object-specific marker
on every rule and only replays requests matching those rules. It tests captured
object identifiers in paths, queries or bodies without guessing new identifiers.
Choose a marker that identifies the owned object rather than generic page chrome.
These checks verify response access; they do not verify write side effects.
Run `authz` and `idor` as separate scan steps because they share option names.

`xss` retains its reflection checking behavior and defaults to **Repeater**.
`xsspayloads` defaults to **Intruder** and sends a baseline followed by each
payload in each supported input separately. The built-in set covers script
elements, image/SVG event handlers, quote breakouts and JavaScript URLs. Use
`--xss-payloads FILE` to replace it with a local SecLists or custom UTF-8 file,
one payload per nonblank line. Payloads are preserved literally, including
percent escapes and whitespace; optional `{marker}` tokens become a unique
per-request marker. Files are loaded during setup, so they must fit in memory.
Both modules can run together with `-m xss -m xsspayloads`.

The payload scan looks for injected code in script text, event handlers,
JavaScript URLs and script sources in HTML responses. It suppresses matching
contexts already present in the baseline and skips findings if that baseline
request failed. Encoded reflections, ordinary text, and inert HTML containers do
not by themselves produce payload-scan findings. This is a heuristic HTTP scan:
JavaScript string boundaries, browser-specific parsing, CSP, and user interaction
can affect exploitability. Findings remain indicators requiring browser
verification. Stored/DOM XSS and payload transformations that defeat literal code
matching are outside its coverage. User-supplied lists may contain external
resource URLs; the scan does not render or execute returned HTML.

As with other modules, explicit `--tool` and `--module-tool` settings can override
the default categories. Human mode paces the Repeater reflection check while
the Intruder payload scan uses normal concurrency.

### traversal and local file inclusion

`traversal` is a combined **Intruder** module for path traversal and local file
inclusion (LFI). It sends a baseline, then replaces one scalar query, form or
JSON input at a time with each payload. It supports query strings embedded in
URLs, repeated query keys, and nested fields in explicit JSON bodies. Requests
without supported inputs are skipped. URL path segments, raw bodies, cookies
and headers are not mutated.

```bash
# Built-in Linux and Windows payloads
leviosa requests.json -m traversal

# Replace the built-ins with a local payload list
leviosa requests.json -m traversal \
  --traversal-payloads /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt

# For other files, supply a unique literal expected in the file's contents
leviosa requests.json -m traversal \
  --traversal-payloads canary-paths.txt \
  --traversal-marker 'leviosa-owned-test-file-7392'
```

The built-in set includes absolute paths, relative paths at several depths,
backslash variants, encoded/double-encoded traversal, nested traversal sequences,
a null-byte suffix, a `file://` URI and a PHP base64-filter wrapper. File targets
are `/etc/passwd` and Windows `win.ini`. Payload lists are UTF-8, one payload per
nonblank line; spaces and percent escapes are preserved literally. Normal HTTP
parameter encoding still applies, so percent-escaped payloads test an additional
application decoding layer rather than sending raw HTTP bytes. Lists are loaded
into memory during setup. In scan files, `--traversal-payloads` paths resolve
relative to the scan file.

Findings require newly introduced recognizable file contents: a complete root
passwd record, multiple characteristic `win.ini` section names, or a configured
literal marker. `--traversal-marker` is repeatable; choose text identifying the
controlled file's contents rather than its filename or a generic error message.
When the payload list includes `convert.base64-encode`, the module also checks
base64 text for these file signatures. This supports PHP-filter responses
embedded in HTML. Custom files without a known signature need an explicit marker.

The module suppresses evidence already in the baseline or in the submitted
payload itself, compares raw/base64 versions of the same signature consistently,
and skips findings when the baseline request fails to connect. It handles
responses arriving out of order and keeps redirects visible. HTTP status changes,
include warnings, reflected filenames and body-length differences alone do not
produce findings. Results are file-access indicators; they do not distinguish
file reads from execution through an include operation. Body checks are subject
to `--max-body-bytes`. Explicit tool overrides work as for other modules.

### OS command injection

`commandinjection` is an **Intruder** payload module. It sends an unchanged
baseline followed by one payload per scalar query/form/JSON input, including URL
query strings and nested fields in explicit JSON bodies. Redirects are not
followed. Raw bodies, URL path segments, headers and cookies are not mutated.

```bash
# Built-in POSIX shell, Windows cmd and PowerShell probes
leviosa requests.json -m commandinjection

# Replace the built-ins with a UTF-8 payload list
leviosa requests.json -m commandinjection \
  --command-payloads command-payloads.txt

# A local SecLists list can also be replayed
leviosa requests.json -m commandinjection \
  --command-payloads /usr/share/seclists/Fuzzing/command-injection-commix.txt
```

Built-in payloads cover shell separators, pipes, command substitution, newline
separation and quoted contexts. They print a unique generated marker using
`printf`, `echo`, or `Write-Output`. The marker is split in the command text so
simple reflection cannot look like command execution. They do not use timing
delays, network callbacks or file writes.

Custom files contain one payload per nonblank line. Whitespace, percent escapes
and ordinary braces are preserved; normal HTTP parameter encoding still applies.
Files are loaded during setup, and paths in scan definitions resolve relative to
the scan file. These optional placeholders are expanded for each input request:

| Placeholder | Expansion |
| --- | --- |
| `{posix}` | POSIX printf command producing the generated marker |
| `{cmd}` | Windows cmd echo command producing the generated marker |
| `{powershell}` | PowerShell Write-Output command producing the generated marker |
| `{marker}` | Literal generated marker for custom command construction |

For example, `;{posix};#` and `&{cmd}&rem ` are complete payload lines. The three
command placeholders keep the complete expected marker out of the submitted
payload. A literal `{marker}` echoed back cannot establish execution and is
suppressed. Lists without placeholders are sent unchanged. They can produce
findings from full Unix `id` output, Windows account SIDs, or additional literal
expected output supplied with repeatable `--command-marker TEXT` options. Choose
custom output markers that are absent from the submitted payload and baseline;
`whoami` usernames or hostnames alone are too ambiguous to detect automatically.

Findings require new command-output evidence beyond the baseline and the payload
itself. Network failures, shell errors, HTTP status changes and response-length
differences alone do not produce findings. Responses can arrive out of order;
failed baseline connections suppress findings for that seed. Results remain
indicators for review, particularly static account-output signatures. This module
covers output-visible command injection; blind timing-based or callback-based
injection needs separate checks. Body matching is subject to `--max-body-bytes`.

### template injection, SSRF and XXE

`ssti`, `ssrf` and `xxe` are payload-based **Intruder** modules. Configured scans
apply the normal Repeater preview before continuing as Intruder. All three keep
redirects visible, compare evidence against a baseline, handle responses arriving
out of order, and support UTF-8 payload files with one payload per nonblank line.
Payload paths in scan definitions resolve relative to the scan file. Files are
loaded into memory during setup; body checks use the `--max-body-bytes` prefix.

```bash
leviosa requests.json -m ssti
leviosa requests.json -m ssrf
leviosa requests.json -m xxe

# Replace built-in template probes with the example payload set
leviosa requests.json -m ssti --ssti-payloads examples/ssti-payloads.txt
```

`ssti` tests common double-brace, dollar/hash expression, ERB/JSP-style,
Thymeleaf-style and Smarty arithmetic forms. Each template gets two different
arithmetic expressions wrapped in unique delimiters. A finding requires **both**
expected evaluated outputs, absent from the baseline and submitted payloads.
Simple reflection, a single arithmetic result or a template error is insufficient.
The module reports evaluation indicators rather than claiming a particular engine
or code execution capability.

Custom SSTI templates can contain `{expression}`. A literal arithmetic example
such as `{{7*7}}` is also converted into paired randomized expressions. Other
custom templates are replayed literally; repeatable `--ssti-marker TEXT` options
can specify expected output for them. Select output text absent from both the
payload and baseline. Whitespace and unrelated template braces are preserved.

`ssrf` replaces scalar query/form/JSON inputs with absolute URL payloads; URL
query strings and nested explicit JSON bodies are supported. Built-ins include
loopback HTTP URLs, IPv6 loopback, local-file URLs and an optional controlled
callback URL. Newly introduced passwd/win.ini contents or repeatable
`--ssrf-marker TEXT` values provide response evidence. Loopback HTTP status or
connection errors alone do not establish SSRF. File-content results can overlap
with LFI; verify that the endpoint performs a server-side fetch. The module does
not scan ports or automatically query cloud metadata services.

For a controlled fetch check, configure an endpoint that returns unique text:

```bash
leviosa requests.json -m ssrf \
  --ssrf-payloads examples/ssrf-payloads.txt \
  --ssrf-callback https://listener.example/callback \
  --ssrf-marker 'unique-response-from-your-listener'
```

`xxe` tests external general entities reading Linux/Windows files, XInclude, a
bounded internal-entity expansion probe, and optional HTTP external entities.
For UTF-8 raw XML bodies, built-ins preserve the root, XML declaration and
surrounding envelope, replacing one paired-element text value or self-closing
element per request. Comments and processing instructions are left intact.
Existing DOCTYPE bodies are skipped by built-in body mutation. Captured body
length/digest headers are removed so changed payloads are transmitted correctly.
Raw bodies without Content-Type receive `application/xml; charset=utf-8`.

XML payload documents can also be placed in scalar query/form/JSON inputs for
endpoints that accept embedded XML. `--xxe-payloads FILE` replaces the built-ins
with complete XML documents, one per line; on raw XML input these replace the
whole body. `{callback}`, `{left}`, `{right}` and `{marker}` are optional custom
placeholders. `{left}` and `{right}` are halves of a unique marker and can be
joined through entity expansion. A literal reflected `{marker}` is suppressed.
The scanner constructs XML text without resolving or fetching entities locally.

New external file contents, PHP-filter base64-encoded file contents, or repeatable
`--xxe-marker TEXT` values are external-access indicators. **Internal entity
expansion is reported only as an observation**, since it does not demonstrate
external entity access. Parse errors or DOCTYPE rejection alone do not generate
findings. Non-UTF-8 raw bodies and XML attribute-value injection are outside the
built-in body mutation coverage.

For blind SSRF/XXE, connect your own HTTP callback listener using
`--ssrf-callback URL` / `--xxe-callback URL`. Each injected input gets an independent
random token in the callback URL's `leviosa` query parameter. The supplied listener
must record that query value in a local JSONL file, for example:

```json
{"token":"value-of-the-leviosa-query-parameter"}
```

Create the log before the scan, then let the listener append complete JSON lines.
Pass it using `--ssrf-interactions FILE` or `--xxe-interactions FILE`. For example:

```bash
leviosa requests.json -m ssrf \
  --ssrf-payloads examples/ssrf-payloads.txt \
  --ssrf-callback https://listener.example/callback \
  --ssrf-interactions listener.jsonl

leviosa requests.json -m xxe \
  --xxe-payloads examples/xxe-payloads.txt \
  --xxe-callback https://listener.example/callback \
  --xxe-interactions listener.jsonl
```

Interaction logs are checked once when the module finalizes; this integration
does not start a listener, poll a hosted provider, or wait for delayed callbacks.
Only exact tokens from this invocation match; old events and duplicates are
ignored. Matches identify the input and retain its actual Repeater/Intruder tag,
even when the original HTTP request failed. They remain callback indicators:
verify which application component made the request. A callback URL without an
interaction log can still support response markers or manual listener review,
but it does not automatically produce blind findings. Custom payload files using
`{callback}` require the corresponding callback option.

### Unsafe file upload checks

```bash
leviosa captured-requests.json --module fileupload
leviosa captured-requests.json --module fileupload --upload-success-text 'Upload successful'
```

`fileupload` only sends requests whose explicit raw body contains a valid
`multipart/form-data` file part with a nonempty filename. Other requests are
skipped. Capture the complete multipart body and its Content-Type boundary in
the request input; ordinary form or JSON parameters are not treated as uploads.
Each matching seed gets a baseline, then each file part is tested independently
with an inert text control, script/double extensions, a JPEG MIME mismatch,
a relative traversal filename, and EICAR under `.com` and `.txt` filenames.
Other parts (including CSRF fields) are retained. These probes can create files
on the target; remove test uploads afterwards.

EICAR's standard 68-byte antivirus test content is assembled in memory only;
no EICAR file is created locally and the complete signature is not shipped in
source. Both request and response raw traffic for EICAR probes are redacted
before SQLite persistence, including redirect exchanges. Results contain probe
labels rather than payloads. External proxies, target systems, and memory
scanners can still inspect or retain the traffic. Use `--upload-skip-eicar` to
omit those probes. The module does not opt into Burp routing.

A 2xx response is reported as **possible acceptance**, since applications may
return errors with status 200. Set `--upload-success-text` to require an
application-specific success marker as well as 2xx. Redirects are not followed
and do not count as success. Findings do not prove storage, execution, traversal,
or absence of asynchronous antivirus scanning. No retrieval or execution of
uploaded content is attempted. See the [official EICAR test description](https://www.eicar.org/download-anti-malware-testfile/).

### Error-induced information disclosure

```bash
leviosa requests.json --module errordisclosure
```

`errordisclosure` sends an unchanged baseline followed by missing, malformed and
oversized paths, an invalid method, junk query parameters, and invalid values
in existing query/form/JSON inputs. Repeated URL query parameters and nested
explicit JSON scalar values are tested independently. JSON requests also get
null/array/object input probes and an intentionally malformed JSON body.
Use `--error-disclosure-path-length N` to adjust the oversized path probe
(default 4096, maximum 16384).

Findings identify stack traces, internal filesystem paths, database errors and
debug details introduced by a probe. Signature categories already present in
the baseline are suppressed. Generic 4xx/5xx responses alone are not findings;
disclosures on 200 responses are detected too. Redirects are not followed.
A failed or missing baseline prevents a claim of induced disclosure. Findings
include the technique, input location, status and bounded matching excerpts.
These are heuristic indicators requiring review; evidence excerpts may contain
sensitive internal details. The existing `errorpages` module remains available
for broader error-page inventory, including ordinary HTTP error statuses.

### JWT security checks

```bash
leviosa requests.json --module jwt
leviosa requests.json --module jwt --jwt-success-text 'account-data'
leviosa requests.json --module jwt --jwt-secrets secrets.txt --jwt-public-key public.pem
```

`jwt` skips requests without recognizable three-part JWTs containing JSON object
headers and payloads. It discovers tokens in raw headers (including Bearer and
Cookie), parameter values, URL query values, nested JSON bodies, and raw bodies.
Encrypted five-part JWEs and opaque tokens are skipped. Each distinct JWT gets
an unchanged baseline, an invalid-token control, and independent probes. Repeated
copies of the same JWT in a request are replaced together; other tokens and
credentials remain present.

Checks include corrupted/empty signatures, `alg=none` casing variants, payload
tampering, attacker-supplied symmetric `jwk`, and an empty `kid` with an empty
HMAC key. A small default secret list is checked **offline** against HS256,
HS384 and HS512 signatures. `--jwt-secrets FILE` replaces that list. When a
secret is recovered, correctly signed expired, future-not-before, wrong-audience
and wrong-issuer variants test claim enforcement (audience/issuer probes require
those claims in the original). Without a signing key, claim enforcement is not
claimed as tested. `--jwt-public-key FILE` enables asymmetric-to-HS256 confusion
probes using the file's exact bytes. The module does not fetch key URLs or test
remote `jku`/`x5u`, RSA embedded keys, key-ID injection, or token revocation.

A bypass **indicator** requires a successful baseline, a distinguishable
invalid-token response, and a probe matching the baseline's exact status/body.
Alternatively, `--jwt-success-text TEXT` requires that protected-response marker
in successful baseline/probe responses and its absence from the control.
Network failures, 5xx controls, missing controls and redirects cannot establish
a bypass. Generic public pages, other authentication credentials, response body
caps, caching and dynamic content can still make results inconclusive; choose
a protected resource and a specific success marker for meaningful results.
Redirects are not followed and response cookies are not reused.

Local token audits flag unsigned JWTs, missing expiration/audience claims, weak
HMAC secrets, HTTP transport and query-string tokens. Missing claims require
application-specific review. Findings omit token payloads and recovered secret
values; normal traffic logging and request URLs can still contain credentials.
The signature probes follow the classes described in the
[PortSwigger JWT testing guide](https://portswigger.net/web-security/jwt).

### Pause and refresh expired authentication

Enable authenticated-session checking with a protected, read-only GET endpoint:

```bash
leviosa requests.json --module errordisclosure \
  --auth-check --auth-check-url https://app.example/api/me \
  --auth-success-text '"authenticated":true'
```

The same flags work with `--scan`. Choose an endpoint that rejects expired
credentials, and use a specific success marker when a login/error page might
return HTTP 200. Success requires 2xx and, when configured, the marker in the
capped response body. Health-check redirects are never followed.

The guard checks before the first scan request and every 20 requests afterwards.
`--auth-check-interval 1` checks before every request. Scan responses with 401,
403 or a redirect also trigger the independent health check; an intentional
JWT/authz denial does not pause the scan when the real session remains healthy.
A failed health check (including a connection failure) pauses dispatch and
prompts for a replacement credential with terminal echo disabled:

- Cookies: paste the full `name=value; name2=value2` set, optionally prefixed
  with `Cookie:`. Include all cookie names from the captured session.
- Bearer: paste the token, `Bearer TOKEN`, or `Authorization: Bearer TOKEN`.
- Enter `:ignore` to disable checking for the remainder of the run, or `:abort`
  to stop the entire scan. Ctrl-C also stops. Unavailable interactive input
  stops the scan rather than continuing silently.

Every candidate is tested against the protected endpoint before it is adopted.
Failed candidates keep the scan paused and prompt again. Auto detection prefers
Bearer when the captured request contains both mechanisms; select
`--auth-mechanism cookies` or `--auth-mechanism bearer` explicitly if necessary.
Both captured credentials are sent to the health endpoint, but only the selected
mechanism is refreshed. Capture a request with the required credentials on the
same origin as the health endpoint. Custom authentication schemes and JWTs in
query/body fields are not refreshed by this guard.

With checking enabled, scan dispatch is **sequential**, regardless of concurrency,
so no in-flight queue can continue through a prompt. Source credentials are
updated before module mutation, and unchanged stale credential values in queued
variants are refreshed at dispatch. Intentionally changed/removed credentials,
other credential values and other origins are preserved. Verified replacements
persist across modules and scan steps, without modifying captured input files.
The guard tracks one captured session on one origin, not multiple independent
users. It does not log in automatically, rotate CSRF body fields, or rebuild
already-generated token mutations. Response cookies are not carried between
scan requests in this mode; paste refreshed cookie values when needed.

A request that already received an authentication failure is reported as received
and is not replayed automatically, avoiding duplicate state-changing actions.
Requests between periodic checks can encounter expiry; use interval 1 to reduce
that window. After `:ignore`, scanning continues with the last verified or
original credentials. Health-check request/response raw traffic is redacted in
SQLite; ordinary scan traffic still uses normal credential-containing logs.

In `leviosa.toml`:

```toml
[auth]
enabled = true
url = "https://app.example/api/me"
success_text = '"authenticated":true'
mechanism = "auto" # auto, cookies, bearer
interval = 20
```

Or use root-level settings in a scan TOML file (before `[[steps]]`):

```toml
auth_check = true
auth_check_url = "https://app.example/api/me"
auth_success_text = '"authenticated":true'
auth_mechanism = "auto"
auth_check_interval = 20
```

CLI settings override scan settings, which override `leviosa.toml`.
`--no-auth-check` disables a configured guard. Checking is off by default.
`--validate-scan` validates the settings and captured credential availability
without making health requests or prompting.

### Business logic checks

```bash
leviosa requests.json --module businesslogic
leviosa requests.json --module businesslogic --logic-success-text '"order_id"'
leviosa requests.json --module businesslogic --logic-rules examples/business-logic-rules.json
```

`businesslogic` skips requests without relevant inputs. Default probes target
common price, total, amount, quantity, discount, balance and limit fields with
negative, zero, fractional and large values. It also tests client-supplied
admin/paid/verified flags, role/status/state/plan/tier values, invalid coupon
codes and an invalid currency. It omits recognized fields and inserts
conflicting duplicates for query/form inputs. These tests replay the original
HTTP method and can create orders, change account state or consume credits;
use disposable test data for state-changing endpoints.

Inputs cover URL queries (including repeated names), query/form/JSON parameters,
nested JSON parameters, and explicit JSON bodies. Form bracket names such as
`items[0][quantity]` are recognized. Each probe changes one input; unrelated
fields, authentication and CSRF values are preserved. Raw bodies are not parsed.
There is one baseline per applicable seed and at most 80 probes, adjustable with
`--logic-max-probes 1..1000`. The first matching inputs consume that budget.

Default findings are **possible acceptance observations**: the original and
mutated requests returned 2xx. `--logic-success-text TEXT` also requires that
marker in both responses. A 2xx, matching response, or reflected value does not
prove an order was placed, a price honored, or a workflow bypassed. Verify the
resulting application state. Redirects, connection failures and failed baselines
do not establish acceptance; redirects are not followed.

For application-specific checks, `--logic-rules FILE` replaces the default
heuristics with a nonempty JSON array of rejection expectations:

```json
[
  {
    "method": "POST",
    "url": "https://app.example/api/orders",
    "location": "json",
    "parameter": "items/0/quantity",
    "values": [-1, 0, 0.5],
    "omit": true,
    "success_text": "\"order_id\""
  }
]
```

This declares that the listed values, and omission when enabled, should be
rejected. A successful baseline and probe containing the required success marker
produce a **potential rejection-rule violation indicator**, still requiring
business-state verification. Choose a marker specific to successful completion,
not text shared with validation errors. Both `method` and the complete seed
`url` match exactly; unmatched endpoints/fields are skipped. Locations are
`query`, `form`, or `json`. `parameter` is the field name for query/form, or a
JSON path without a leading slash (`items/0/quantity`). In JSON paths, escape
`~` as `~0` and `/` as `~1`; structured JSON params prefix the path with the
parameter name. Array indexes identify individual elements.

`values` requires 1–100 finite JSON scalar values. Optional `omit` and `duplicate`
flags default to false; `duplicate` applies only to query/form and appends the
first configured value after the existing field. URL/form values are serialized
as text (`true`, `false`, `null` for those JSON scalars), while JSON values retain
their types. Values identical to the original are skipped for replacement.
Rules may target custom fields beyond the built-in names. Rule file paths resolve
relative to the scan TOML when used in step args.

These are single-request input-trust checks. The module does not infer business
policy, orchestrate multi-step workflows, test races, or verify coupon reuse,
refund accounting, server-side totals or other persistent invariants automatically.

### HTTP security headers

All five HTTP header checks are provided by the single `securityheaders` module:

```bash
leviosa requests.json --module securityheaders --no-recommended
```

| Header | Checks |
| --- | --- |
| `Strict-Transport-Security` | Missing on HTTPS, absent/invalid/duplicate `max-age`, disabled or short lifetime, missing or malformed `includeSubDomains` |
| `X-Frame-Options` | Missing framing protection, values other than `DENY`/`SAMEORIGIN`, duplicate header fields |
| `X-Content-Type-Options` | Missing or non-`nosniff` value, duplicate header fields |
| `Referrer-Policy` | Missing/empty/unrecognized values and weak effective policies, including comma-separated fallback lists and repeated header fields |
| `Permissions-Policy` | Missing/empty/malformed policies, invalid allowlists/origins, repeated features, unrestricted or wildcard allowlists requiring review |

The module replays requests without injecting payloads, inspects response headers,
and emits structured findings plus a deduplicated summary. Redirects are not
followed, so findings describe the initial response. Network failures are skipped.
The module does not need response bodies; normal traffic logging can still read
and retain capped bodies.

HSTS absence is not flagged over HTTP, where browsers ignore it. The default
minimum lifetime is one year; use `--hsts-min-age SECONDS` to change that threshold.
Subdomain coverage is a hardening observation: verify every subdomain supports
HTTPS before enabling it. Preload is not required or independently verified.

A recognized restrictive enforcing CSP `frame-ancestors` policy can provide
framing protection when X-Frame-Options is absent. Empty, bare-wildcard and
report-only policies do not satisfy this fallback. This is a conservative check,
not a complete browser CSP evaluator; the separate `csp` module audits CSP.

Referrer fallback lists use the last recognized policy. Permissions-Policy
supports empty allowlists, `self`, quoted origins, wildcard policies and reporting
parameters. Repeated Permissions-Policy fields are combined; duplicate features
are flagged. Unknown feature names are not rejected because browser support
varies. Missing Permissions-Policy does not imply that every browser capability
is enabled: individual features still have browser defaults. Broad allowlists
are review observations, not proof of exploitability.

`--no-recommended` retains **all five** checks and skips the existing additional
Cross-Origin-* and deprecated X-XSS-Protection checks. Without it, those extra
checks continue to run too.

Parsing references: [HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security),
[X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options),
[Referrer-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy),
and [Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy).

### Login authentication testing

```bash
# Default: inspect login pages without submitting captured credentials
leviosa login-requests.json --module authentication

# Active checks, using a disposable test account and a reliable success signal
leviosa login-requests.json --module authentication --risky \
  --login-success-text '"authenticated":true'

# For a login whose successful response redirects to /account
leviosa login-requests.json --module authentication --risky \
  --login-success-location '^/account(?:/|$)'
```

`authentication` is restricted to login-like URL paths: login/signin,
authenticate/auth, sessions, j_security_check, and OAuth token endpoints.
Unrelated endpoints are skipped. Override detection with `--login-path REGEX`
(applied to the URL path), or combine it with standard request filters.
Password reset, registration, logout and account-management paths are not
selected automatically.

**Default mode makes no credential submissions or password guesses.** It sends
one anonymous GET per selected endpoint, removing query parameters, body, cookies
and credential headers. It audits:

- HTTP transport and credentials already present in the captured URL query.
- Password forms using GET, insecure or cross-origin actions, and unmasked
  password-like fields. Cross-origin actions may be intentional identity providers.
- Missing recognizable login-form CSRF fields as a review observation; JavaScript,
  SameSite, Origin validation and other defenses are not inferred from HTML.
- Common session-cookie security attributes and exposed internal-error signatures.

The captured POST is not replayed in default mode. This applies to this module;
other modules selected in the same run keep their own replay/mutation behavior.
POST-only APIs may answer the
anonymous GET with 405; their credential validation is tested only in risky mode.
There are no wrong-password attempts against the captured user in default mode.

**`--risky` enables all implemented active checks.** A nonempty
`--login-success-text` (in a 2xx body) or `--login-success-location` (matching a 3xx
Location header) is required. Redirects are not followed. Provide a current,
known-good captured login for a disposable account: risky mode can lock it out,
trigger alerts, authenticate other accounts, or consume one-time tokens.
The suite includes:

- A captured-credential baseline and a random nonexistent-user negative control.
- A wrong password for the captured user, empty/missing user or password, and
  JSON null-password checks.
- SQL-style and JSON NoSQL-style authentication-bypass payloads.
- Password case/whitespace handling, appended suffixes and NUL truncation.
- Omission of recognized existing MFA/CAPTCHA fields (no CAPTCHA solving or evasion).
- A small default-credential set (`admin/admin`, `admin/password`, `root/root`) and
  common-password candidates for the captured user.
- Explicit known/unknown-user error differences and a bounded repeated-failure
  sample for observable lockout/rate-limit behavior.
- On an accepted baseline: session-cookie rotation observations, missing no-store
  cache directives, and literal password reflection. Cookie rotation findings
  need confirmation that the captured cookie was an unauthenticated session.

Username/password inputs are detected in query, form and JSON parameters, nested
JSON, and raw JSON or URL-encoded bodies. Use `--login-user-field NAME_OR_PATH`
and `--login-password-field NAME_OR_PATH` for custom names; JSON paths use the
same escaped path convention as `businesslogic`. Missing or ambiguous fields
skip active submission. Only captured GET/POST login flows are submitted.
API refresh/auth-code requests without a username/password pair are not mutated.
Other captured fields, including CSRF tokens and pre-login cookies, are retained
in active requests. Response cookies are never carried into later probes.

Active requests are sequential even when global concurrency is higher. By
default at most 30 risky requests (including baseline and control) are generated
per method/endpoint per module invocation, plus one anonymous page GET. Duplicate captures of that
method/endpoint do not multiply attempts; the first usable capture is used.
`--login-max-attempts 2..200` changes the cap, and
`--login-failure-attempts 1..50` changes the final repeated-failure sample (default
5). The total cap still applies, so a small cap may omit later test families.
`--random-timing` can add the existing configurable delays between requests.

`--login-passwords FILE` replaces the small common-password candidate list for
the captured user and requires `--risky`; the default-credential pairs remain.
Only the first `--login-max-attempts` nonempty UTF-8 lines are loaded, and the
request cap also applies. Paths resolve relative to scan TOML for step args.
There is no unbounded brute-force or credential-stuffing mode.

The module stops remaining endpoint probes on HTTP 423/429, Retry-After, recognized
English lockout/rate-limit/CAPTCHA error messages, transport errors, or inconclusive
baseline/control checks. A signal on the anonymous page skips active probes too.
These stops cannot guarantee avoiding lockout: earlier risky failures may already
have triggered it. Unrecognized/localized messages can only be bounded by the
configured request cap.

A possible authentication weakness requires both an accepted baseline and a
rejected invalid-account control, followed by a successful probe under the
configured marker. HTTP 200 alone is not treated as successful login. Findings
remain indicators: a reflected marker or a redirect is not independently verified
protected-resource access. The bounded sample cannot prove a missing lockout
policy, and differently worded errors are only an enumeration indicator.

Active login request/response raw traffic is redacted in local SQLite, and
findings omit submitted credentials, response bodies and query values. Ordinary
proxy/server logs can still record submitted credentials. Default anonymous page
traffic uses normal logging. Captured input files are never rewritten.

The module does not orchestrate browser/SSO flows, refresh CSRF tokens, change or
reset passwords, enroll/disable MFA, spray arbitrary users, or test every possible
authentication weakness. Its risk separation reflects OWASP's notes on
[enumeration lockout risks](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/03-Identity_Management/04-Account_Enumeration_and_Guessable_User_Account/)
and [lockout testing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/04-Authentication/03-Weak_Lock_Out_Mechanism/).

### Full hands-off scan profile

[examples/hands-off/scan.toml](examples/hands-off/scan.toml) runs all 27 current
built-in modules once, with sequential human pacing (2–4 seconds), short payload
sets and bounded seed sampling. All steps use Repeater so human mode applies to
every module. Risky authentication checks and write-method tampering are disabled;
other modules exclude captured authentication/account-management paths.

Provide curated requests, two fresh user sessions and object-ownership rules
using the [setup instructions and templates](examples/hands-off/README.md), then:

```bash
leviosa --scan examples/hands-off/scan.toml --validate-scan
leviosa --scan examples/hands-off/scan.toml
```

Required application inputs are intentionally not populated with dummy sessions.
Preflight fails until they exist. Once set up, no interactive refresh prompts
are enabled. The profile is still an active scan: POST, upload and business-logic
probes can change state, so use disposable test data. It does not run a scan merely
by being added to the repository.

### Quick SQLite samples and full console dumps

`sqlite_sample.py` is a standalone standard-library script. It opens the database
read-only and prints column-labelled tables, wrapping multiline/long values.
Wide schemas use a column/value table per row. Values are not truncated; binary
cells use hex and terminal control sequences are escaped.

```bash
python sqlite_sample.py leviosa.db                 # 5 random rows per table
python sqlite_sample.py leviosa.db -n 10           # 10 random rows per table
python sqlite_sample.py leviosa.db --first 10      # first 10 rows per table
python sqlite_sample.py leviosa.db --last 10       # last 10, newest/highest key first
python sqlite_sample.py leviosa.db --dump          # all user tables and all rows
python sqlite_sample.py leviosa.db --table ACTIVITY --width 160
```

`--all` aliases `--dump`; `--table` is repeatable. Without `--table`, all user
tables are printed. First/last use rowid order, or primary-key order for
WITHOUT ROWID tables, rather than a timestamp column. The dump is table data
for the console, not a schema/SQL backup. The default path is `leviosa.db`.
