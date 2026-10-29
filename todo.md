# Completed features

- [x] Save traffic using the Burp **Log Requests to SQLite** `ACTIVITY` schema, with exactly its eight TEXT columns and no other tables. Findings and scan status remain on the console, with optional separate JSONL results.
- [x] Store equivalent tool names (`Repeater`, `Intruder`, `Scanner`) only in `BURP_TOOL`, with module defaults and explicit overrides.
- [x] Human mode: randomised Repeater cadence across modules, while Intruder and Scanner retain normal concurrency. Preserve the explicit all-category random-timing option.
- [x] File-configured unattended scans: run ordered module steps with independent options and filters, validate before traffic, record module failures and continue, and handle interruption cleanly.

See [README.md](README.md) and [examples/review-scan.toml](examples/review-scan.toml).
