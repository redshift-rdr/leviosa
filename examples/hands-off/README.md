# Hands-off application review

`scan.toml` includes every current built-in module exactly once (27 steps).
It is an unattended **active** review profile for a single application origin.
It does not send any traffic until you invoke the scan; all examples use fake
credentials and the reserved `app.example` hostname.

## One-time application setup

Four application-specific inputs are required. They are deliberately absent from
`inputs/` so the scan fails preflight instead of using dummy identities.

From the repository root:

```bash
mkdir -p examples/hands-off/inputs
cp examples/hands-off/templates/requests.example.json examples/hands-off/inputs/requests.json
cp examples/hands-off/templates/user-a.example.json examples/hands-off/inputs/user-a.json
cp examples/hands-off/templates/user-b.example.json examples/hands-off/inputs/user-b.json
cp examples/hands-off/templates/ownership-rules.example.json examples/hands-off/inputs/ownership-rules.json
```

Replace the templates with real engagement inputs before scanning:

| Input | Required contents |
| --- | --- |
| `inputs/requests.json` | Curated captured requests for the application: read endpoints, authorized read-only POSTs, applicable XML/multipart bodies, and a login capture if available. Preserve parameters and headers; remove stale Content-Length/digest headers when editing bodies. |
| `inputs/user-a.json` | A fresh request authenticated as test user A, carrying their real cookies and/or Authorization header. |
| `inputs/user-b.json` | A fresh request authenticated as a different test user B. Use two ordinary users with independently owned objects for horizontal access checks. |
| `inputs/ownership-rules.json` | Exact method/URL matches, allowed labels `user-a`/`user-b`, and an object-specific `contains` marker for **every** rule. Include actual ownership expectations, not just names. |

`authz` uses these sessions/rules for its matrix and `idor` uses the explicit
ownership expectations. You cannot infer real authorization from usernames or
roles alone. To add an administrator, add a labelled `--session` argument to
**both** steps and update each rule's allowed labels according to application
policy. Do not assume an administrator must be denied access to every user object.

The templates are schema examples, not usable credentials or access policies.
Offline validation checks structure and files; it does not verify a session is
valid, prove a marker is specific, or validate business ownership. Include the
owned-object URLs in the captured request set. Rules do not generate those URLs.

Real input files, SQLite output/sidecars and JSONL results in this directory are
ignored by git. Keep the request set focused on the application under test;
discovery samples one GET seed and assumes that set represents one origin.

## Validate, then run

```bash
leviosa --scan examples/hands-off/scan.toml --validate-scan
leviosa --scan examples/hands-off/scan.toml
```

To keep a captured request file elsewhere, override only the target:

```bash
leviosa /absolute/path/captured-requests.json --scan examples/hands-off/scan.toml --validate-scan
leviosa /absolute/path/captured-requests.json --scan examples/hands-off/scan.toml
```

Sessions, rules and payload paths remain relative to `scan.toml`. The validation
command is offline, creates no scan outputs, and does not prompt. Missing inputs,
invalid module options or invalid rules abort preflight for the entire scan.

Output defaults to `traffic.sqlite` and `results.jsonl` next to `scan.toml`.
Normal module runtime failures are recorded and later steps continue; output
failures and interruption stop the run. Existing files are appended to; choose
new `--log-db` and `--results` paths to keep separate runs.

## Defaults and coverage

- Each step starts with up to five generated requests tagged as `Repeater`,
  paced with a 2–4 second idle interval (`human_mode=true`). Remaining requests
  use the module's native Repeater/Scanner/Intruder category. Native Repeater
  traffic stays human-paced; Scanner/Intruder traffic has no human-mode delay.
  Concurrency remains one. Steps generating five requests or fewer run entirely
  as Repeater. Explicit tool overrides still apply after the preview.
- A five-second pause separates modules (`module_delay = 5.0`). Set it to zero
  to disable it, or replace it with `module_delay_min = 3.0` and
  `module_delay_max = 8.0` for a fresh random pause between modules. These are
  root settings before the first `[[steps]]`; do not combine fixed and range settings.
- Requests time out after 15 seconds and response reads are capped at 256 KiB.
- Burp is off by default. Explicit `--burp`, `--proxy`, `--proxy-config` and
  `--no-proxy` remain available; proxy settings in your `leviosa.toml` can also
  apply. No network credentials or proxy addresses are embedded in this profile.
- Interactive authentication checking is disabled (`auth_check=false`). No
  credential-paste prompts occur. Captured sessions can expire during a long run;
  expiration is not automatically repaired and can reduce authenticated coverage.
  Refresh all relevant input sessions before a run. If you enable `--auth-check`
  with a protected URL and success marker, recovery can become interactive.
- Authentication stays in its default anonymous-page audit mode. No `--risky`,
  default-password guesses, wrong-password attempts or lockout testing are enabled.
- Other steps filter out captured login, logout, reset/registration/MFA paths and
  obvious destructive action names. This avoids replaying captured login POSTs
  through injection modules. Filters apply to input paths, not generated variants;
  discovery can still visit login pages with GET. Unusual endpoint names require
  adjusting the filters. Path matching is not a guarantee of read-only behavior.
- Method tampering uses only OPTIONS, TRACE and an invalid verb. Write methods and
  override-header probes are disabled.
- Passive/header checks sample up to 15–40 input seeds. Discovery uses one GET seed
  and small local wordlists. Injection/error checks sample 3–8 seeds with short
  payload sets. Sampling is reproducible (`sample_seed=27`). These caps limit seed
  coverage, **not total generated requests**; runtime grows with parameter count,
  path depth and payload expansion. Keep captures small and representative.
- JWT, multipart uploads and rule-selected IDOR have no sampling cap so applicable
  seeds are not lost to random sampling. Unsupported request types still skip.
- Session-cookie checks include common framework session names; add your application's
  actual cookie names with additional `--session-cookie` arguments on that step.
- JWT uses its default checks and small offline weak-secret set. Add an actual
  `--jwt-public-key` file to enable supported asymmetric-key confusion probes, and
  application-specific success markers where appropriate.
- Business logic is capped at 12 probes per sampled seed, using heuristic field
  names. Supply application-specific rejection rules/markers for stronger evidence.
- Upload checks include in-memory EICAR; local EICAR exchanges are redacted. Add
  `--upload-skip-eicar` to that step if antivirus testing is outside the engagement.
- SSRF uses a short in-band set, including loopback HTTP and local-file URIs.
  XXE uses the built-in bounded entity/XInclude probes. No external callback service
  or interactions file is required. Blind SSRF/XXE coverage needs controlled
  callbacks configured in those steps. No cloud metadata credentials are targeted.
- Command injection payloads only print generated markers; SSTI uses paired
  arithmetic. They still exercise command/template execution if a vulnerability
  exists. Traversal, SSRF and XXE can read recognizable local files.

All modules being included does not mean every endpoint or exploit family is
covered. Applicable-request skips, sampling, truncated bodies, missing callbacks,
expired sessions and missing application success markers can all limit findings.

## Curate state-changing inputs

This is not a read-only profile: POST injection, business-logic and file-upload
checks can change application state, create files/objects or trigger antivirus
alerts. Use approved, disposable test data and read-only validation/search POSTs
where possible. Exclude purchases, payments, resets, account deletion and other
irreversible actions from the **captured input set**, even when their paths look
ordinary. Remove test uploads and artifacts afterwards.

No password or credential guessing is enabled, but a safe authentication step
does not make unrelated application requests risk-free. To omit a test family,
remove its step; to increase coverage, adjust samples/payloads and add controlled
application-specific markers or rules. The separate `review-scan.toml` remains a
shorter introductory example.
