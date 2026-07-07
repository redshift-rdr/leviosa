# leviosa
## a lightweight web pentest helper tool

### infrastructure
- runs on python
- runs as a command line tool
- highly modular, different scan types are loaded in as individual 'modules'

### features
- a core web request component which uses threads to make web requests
- can take in a URL, a list of URLs, or a JSON file of HTTP requests
- can specify 'modules' which are loaded in at runtime. modules perform some action/mutation on the http requests provided to it, then use the web request component to send the requests, then can optionally perform some action/analysis on the responses
- runs through burpsuite by default, with a --no-proxy to turn it off
- emphasis on lightweight. the core should be lightweight, no bloat and unnecesary features. functionality should be added in modules.

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

# Verbose output (proxy, request count, module names go to stderr)
leviosa http://target.local --no-proxy --verbose
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
    def setup(self, args: list[str]) -> None:
        # parse module-specific CLI args here (optional)
        pass

    async def mutate(self, requests, context):
        # return the list of requests to send (may be expanded)
        return requests

    async def analyze(self, responses, context):
        # print findings to stdout
        for resp in responses:
            if resp.status == 200:
                print(f"[MYMODULE] {resp.request.url}")
```

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
