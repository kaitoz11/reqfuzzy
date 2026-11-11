# payint-kvar — Design Spec

**Status:** historical; superseded by implementation in [reqfuzzy](https://github.com/kaitoz11/reqfuzzy) on 2026-10-28. The separate Python engine proposed below is no longer the implementation plan. Current contracts live in reqfuzzy's `docs/superpowers/` directory.
**Date:** 2026-09-27
**Origin:** clean rewrite of payintv3 ideas; corpus ported from payintv3

---

## 1. Purpose & positioning

payint-kvar ("kvar") is a CLI-first, agent-ready web/API security scanning tool
covering **technical payload fuzzing** (SQLi, NoSQL, SSTI, CMDi, SSRF, XSS, XXE,
path traversal, log4j/CVE families, fuzz) against authorized targets.

Two design principals throughout:

1. **High usability for AI agents** — every capability is drivable through the
   CLI with machine-readable output, deterministic exit codes, agent-facing
   docs (`AGENT.md`), and built-in explanations (`kvar explain`).
2. **High usability for humans** — the same commands produce readable tables
   and live progress; configuration is data (YAML), not Python.

> ⚠️ **Authorized testing only.** kvar sends attack payloads at live targets.
> The CLI refuses to run against a project until authorization is acknowledged
> (Section 9).

**Relationship to payintv3:** clean rewrite. The *ideas* carry over (raw HTTP
request input, YAML attack templates, matcher DSL, base-response diffing,
normal/scan proxy split); the code does not. The template **schema and DSL
semantics are kept compatible** so the payintv3 `payint_templates/scan/` +
`matcher/` corpus ports over unchanged.

## 2. Decisions (from brainstorming)

| # | Decision |
|---|----------|
| 1 | CLI foundation + agent layer on top |
| 2 | Clean rewrite in a new repo (`~/workspace/payint-kvar`) |
| 3 | v1 scope: injection core only; IDOR/unauthen/mass-assignment/upload deferred to v2 |
| 4 | Auth: declarative YAML profiles + optional Python hook scripts |
| 5 | Input: raw request files (payint-style); curl-style construction flags deferred; proxy split retained |
| 6 | Agent layer: agent-ready CLI (`--json`, exit codes, `explain`) + `AGENT.md` + pi skill |
| 7 | Traffic ingestion: import captured traffic (HAR / mitmproxy / raw) **and** flow inference |

## 3. Architecture & project layout

One installable Python package, one binary (`kvar`). CLI is a thin shell over
a clean core; the engine never imports the CLI. Everything the CLI does is
also doable as a Python import of `kvar.engine`.

```
payint-kvar/
├── kvar/                      # the package
│   ├── cli.py                 # typer app — all commands, thin
│   ├── engine/                # the pipeline (Section 5)
│   │   ├── raw_request.py     # raw .txt parser -> HttpRequest model
│   │   ├── http_model.py      # immutable request, builder API
│   │   ├── http_client.py     # httpx wrapper; normal/scan proxy split
│   │   ├── payloads.py        # template expansion -> payload plan
│   │   ├── matchers.py        # matcher evaluation (port of payint matcher semantics)
│   │   ├── dsl.py             # template DSL: rand_base, variables, substitution
│   │   └── findings.py        # finding model + collection
│   ├── templates/             # ported payintv3 scan/matcher corpus (YAML)
│   ├── profiles.py            # auth profile loader (Section 6)
│   └── hooks.py               # hook script discovery/loading (Section 6)
├── kvar_skill/                # SKILL.md — pi agent skill (Section 8)
├── AGENT.md                   # agent-facing docs
├── USAGE.md                   # human-facing docs
├── tests/                     # unit + golden + e2e (Section 10)
├── pyproject.toml             # pip-installable, `kvar` entry point
└── docs/
```

**Design rules:**

- Layered one-way dependency flow: `cli → engine`.
- Small single-purpose units; every unit drivable and testable in isolation.
- Templates are data, not code; built-in corpus + project `custom_templates/`
  overlay (payint `TemplateManager` parity).
- **No sample-project copying** (payint's biggest usability cost). The kvar
  project directory holds only *data*: config.yaml, requests/, profiles/,
  flows/, custom_templates/, hooks/ — plus optional Python hook scripts.

## 4. CLI command surface

Every command accepts `--json`; without it, human-readable output. Global
flags: `--project DIR` (default `./`), `--json`, `--verbose`.

```
kvar init [DIR]                     # scaffold project (config.yaml, requests/,
                                    #  profiles/, flows/, custom_templates/, hooks/)
kvar show request <file>            # parsed view of a raw request
kvar show params <file>             # attackable parameter map by location
kvar show templates [--tags t1,t2] [--search <text>]
kvar show template <id>
kvar show profiles
kvar explain <topic>                # topics: built-in agent docs
kvar scan <request-file> \
    --profile attacker \
    --tags sql,ssti_java,ssrf \
    --params body:EncryptStr:ToAccount query:page \
    [--all-params body,query] [--exclude body:RequestID] \
    [--resume <seq-id>] [--plan] [--max-requests N] [--timeout N] \
    [--flow <name>] [--set body:txnId:{{txn_id}}]
kvar send <request-file> --profile <p>
kvar import <file-or-dir> [--watch 127.0.0.1:8084] [--filter host:...] [--infer-flows]
kvar requests list [--expand] [--json]
kvar requests show <file>
kvar flow run <name> [--json]
kvar flows show <name>
kvar flows suggest <files...>
kvar findings [--id <id>] [--json]
```

**Exit codes (deterministic):**

| Code | Meaning |
|------|---------|
| 0 | ran clean, no findings |
| 3 | ran, findings found |
| 1 | usage / CLI error |
| 2 | runtime error (target down, malformed request file) |

**Output contract:** `--json` always prints exactly one well-defined JSON
document per invocation. `scan --json` ends with
`{request, profile, flow_vars, plan_summary, requests_sent, findings[],
artifacts_dir, scan_state}`. Findings always carry on-disk evidence pointers.
Human mode: tables + live progress lines.

**Resume:** every scan writes `runs/<timestamp>/scan_state.json` holding the
plan cursor; `--resume <seq-id>` replays from a payload sequence ID.

**`--plan`:** print the payload plan without sending anything — review what
will be fired before it fires (agents and humans).

**`--set` overrides:** `body:`/`query:`/`header:`/`cookie:` prefixed paths
patch the request before scanning (payint builder API, on the CLI).

**v1 omissions (deliberate):** `--url/--method/--data` request construction;
batch manifests over many requests; concurrency.

## 5. Engine pipeline

```
raw request file ──parse──▶ HttpRequest
templates + params + profile ──▶ Payload Plan (ordered, stable sequence IDs)
                          ┌── send #1..N ──▶ Response ──▶ match ──▶ Finding?
                          └── evidence + scan state → runs/<timestamp>/
per send: inject profile → before_send hook → httpx (normal|scan proxy split)
```

1. **Raw request parsing** — full raw HTTP request text (Burp paste) →
   immutable `HttpRequest`: method, host/port/SSL, path, headers, cookies,
   query, body (JSON / form / multipart + files), nested parameter paths
   (`A:B:C`). Round-trip fidelity is a test requirement.
2. **Template loading** — built-in ported corpus + `custom_templates/`
   overlay, indexed by `tags` and `id`; `default_variables.yaml`
   (`attacker_domain`, `sleep_time`, …) merges with project variables.
3. **Payload plan** — deterministic expansion of *(parameter × template ×
   test_case)* into an ordered list of concrete attack requests, each with a
   stable sequence ID. Actions (`append`/`prepend`/`replace`/`overwrite`/…)
   apply payload values to base parameter values; DSL resolved at expansion
   time with the *resolved* value recorded in the plan. Dedup hashing skips
   `--exclude`d volatile params (payint
   `ignore_parameters_when_computing_hash` parity).
4. **Sending** — sequential by default (time-based/OOB payloads require it;
   concurrency is a v2 flag gated per-template). Per send: profile injection →
   `before_send` hook → httpx. Normal and scan traffic use separate httpx
   clients (separate proxies). `require_base_response` sends the untouched
   request first for diffing.
5. **Matching** — faithful port of payint matcher semantics:
   `matcher_template_ref_tags` → reusable matcher templates; DSL expressions
   comparing `current_response` vs `base_response`; `matcher_condition:
   and/or`. payintv3's `process_template/` implementation is the spec; a
   golden test set is derived from its behavior.
6. **Findings & run artifacts** — a finding records: template id/tag, severity,
   parameter + location, payload *as sent*, matched DSL rule, evidence
   pointers (request/response pair). Every scan writes
   `runs/<timestamp>/`: evidence files, `scan_state.json`, `findings.json`.

## 6. Auth profiles & hook scripts

**Profiles are data** — one YAML per identity in `profiles/`:

```yaml
name: attacker
description: "primary test account"
credentials:
  username: "0337738730"
  session_id: "cff3e991..."
  token: "eyJhbGci..."
credentials_from: profiles/secrets.yaml#attacker   # optional shared-secret import
inject:                       # location -> param -> template ({{ credential }})
  headers:
    tl-user: "{{ username }}"
    Authorization: "Bearer {{ token }}"
  cookies:
    session: "{{ session_id }}"
  body:
    session_id: "{{ session_id }}"
    user_id: "{{ username }}"
hooks:
  before_send: sign_body      # by name, auto-discovered in hooks/
  refresh: get_session
```

- Injection overwrites the named field if present, adds if not (payint
  parity). All five locations supported: headers, cookies, body, query, files.
- No profile = send as-is (unauthenticated).

**Hooks are escape hatches** — Python files in `hooks/`, auto-discovered,
zero boilerplate:

```python
# hooks/sign_body.py
def sign_body(request, profile):
    return request.with_body(encrypt(request.body))
```

Two v1 events:

1. **`before_send(request, profile) -> request`** — mutate the final request
   (signing, encryption, checksum headers). Runs after profile injection,
   right before send.
2. **`refresh(profile) -> profile`** — called when the profile is loaded, and
   re-called when a scan response looks unauthenticated (401/403): re-login,
   fetch fresh tokens, update credentials. Failure disables the profile with
   a clear error.

Hook signature reference lives in `kvar explain writing-hooks`. Hook errors
fail loudly with the traceback — never silently skip.

## 7. Flows (prepare steps)

A flow is an ordered list of steps; each step sends a request and may extract
values from the response for later use. Flows are YAML in `flows/`.

Two use cases covered:

- **Mid-flow requests** — send preceding requests to get the session/business
  state into the right position (e.g. initiate a pending transfer) before
  attacking the real target request.
- **Data preparation** — seed the target with the data the attacked request
  needs (e.g. satisfy an OTP step).

```yaml
# flows/prepare_transfer.yaml
name: prepare_transfer
steps:
  - id: login
    request: requests/login.txt
    profile: attacker
  - id: initiate_transfer
    request: requests/initiate_transfer.txt
    profile: attacker
    extract:
      txn_id: { json: "data.transactionId" }
      otp_ref: { regex: 'ref=([A-Z0-9]+)' }
  - id: confirm_otp
    request: requests/confirm_otp.txt
    profile: attacker
    set:
      body:otpRef: "{{ otp_ref }}"
      body:txnId: "{{ txn_id }}"
    extract:
      session_state: { json: "data.state" }
```

- **Extraction** — `json:` (dot-path), `regex:` (first group), `header:` →
   named flow variables, usable by later steps (`set:`), the scan request
   (`--set`), hooks (context object), and the scan run.
- **`--flow <name>` on `kvar scan`** runs the flow, then applies its variables
   + `--set` overrides to the scan request before parameter selection.
- Optional `expect:` status/contains check per step; a failed step (transport
   error or failed `expect`) aborts the flow with a clear error naming the
   step — never proceeds to a half-prepared scan.
- Flows compose with the `refresh` hook: a flow step hitting 401/403 →
   profile `refresh` hook re-auths → step retried once → proceed.
- `kvar flow run <name>` runs standalone (debug); prints extracted variables
   (`--json` too) so agents can chain manually.

## 8. Traffic ingestion & mapping

**Sources:**

```
kvar import navigation.har        # HAR (devtools export, playwright/CDP capture)
kvar import dump.mitm            # mitmproxy flow dump
kvar import burp_export/         # dir of raw request files (Burp copy/paste)
kvar import --watch 127.0.0.1:8084   # live listener; navigate, watch requests appear
```

**Ingestion rules:**

- Every entry → a raw request file in `requests/` with a stable generated
  name `<seq>_<METHOD>_<host><path>.txt` (sanitized, deduped with a counter),
  stable across re-imports.
- `--filter host:api.target.com`, `--filter path:/api/` to drop noise;
  static assets / CONNECT noise dropped automatically.
- Captured cookies/auth preserved (replayable state) but the importer warns
  about captured secrets.

**Inventory (`kvar requests list`):** file, method, host, path, param counts
per location, content-type. Same host+path+method with different params
collapse into one row with a count (`--expand` to break out). Agent pick-loop:
`import` → `requests list` → `requests show` → `scan`.

**Flow inference (`kvar flows suggest`, or `import --infer-flows`):**

- Walks the captured sequence **in order**, looking for **value taint**: a
  scalar in response *N* (JSON dot-path or regex-extractable string) that
  re-appears in request *M > N* (body/query/header/cookie/path).
- Matches become draft flow steps (`extract:` on N → `set:` on M), written to
  `flows/suggested-<name>.yaml` with confidence notes (exact match = high;
  encoded/normalized match = lower).
- Suggestions are drafts, never auto-executed; reviewed via
  `kvar flows show`, edited, then run.

Closes the agent loop end-to-end:
**navigate → import → inventory → infer flows → scan → findings**, all through
the CLI, all inspectable before anything fires.

## 9. Agent layer

1. **`AGENT.md`** (repo root) — command reference with examples; exact JSON
   schema of every `--json` output; workflow recipes (attack-a-request
   end-to-end, write a hook, write a flow, pick params from a raw request);
   ground rules (v1 limits, exit codes, resume); authorization gate.
2. **`kvar explain <topic>`** — same content family, shell-reachable:
   `how-scanning-works`, `dsl`, `matchers`, `writing-hooks`, `writing-flows`,
   `finding-schema`, `exit-codes`; `kvar explain topics` lists all.
3. **`kvar_skill/SKILL.md`** — pi skill wrapping the end-to-end workflow;
   points at `AGENT.md` / `kvar explain` for depth instead of duplicating.
4. **Authorization gate** — CLI refuses to run against a project until
   `authorized: true` is set in config.yaml (or `--authorized` passed once);
   deliberate speed bump, stated in `AGENT.md`.

**Finding JSON shape (contract):**

```json
{
  "id": "...", "template_id": "SQLDNSInteraction", "tags": ["sql"],
  "severity": "high", "location": "body", "parameter": "A:B",
  "payload_as_sent": "'||UTL_HTTP.REQUEST('http://...')||'",
  "matched_rule": "{{current_response.status_code == base_response.status_code}}",
  "evidence": { "request_file": "runs/.../req_0007.txt", "response_file": "runs/.../resp_0007.txt" }
}
```

## 10. Testing

- **Unit tests per engine module** — raw parser round-trip; payload-plan
  determinism (same input → same sequence IDs); profile injection; hook
  contracts; DSL golden set (expressions → expected results, derived from
  payintv3 `process_template/` behavior).
- **Golden corpus tests** — ported corpus loads and expands cleanly; a fixed
  representative template set produces byte-stable plans across runs.
- **End-to-end against a local mock target** — `tests/mock_target/` server
  with predictable vulnerable endpoints (reflected SQLi error, time delay,
  echoed SSTI); proves import → flow → scan → findings → artifacts, in CI,
  no internet.
- **Agent-loop test** — drives the CLI exactly as `AGENT.md` documents (JSON
  shapes, exit codes), so docs cannot silently drift from behavior.

## 11. Error handling

- Every failure names the unit: `raw request file: line 12: malformed header`;
  `flow step 2 (confirm_otp): expected 200, got 403`;
  `profile attacker: refresh hook raised …(traceback)`.
- Fail-stop per request on transport errors, but **recording**: transport
  failures mark the payload `not_sent` in scan state; `--resume` retries them.
- HTTP error responses (500 …) are *results*, matched like any response.
- Partial run artifacts always stay on disk; `--resume` picks up from them.
- Hook errors fail loudly with traceback, never silently skip.

## 12. Roadmap (explicitly out of v1)

- `--url/--method/--data` request construction flags
- Concurrency (gated per-template: safe only for non-time-based families)
- IDOR / unauthen / mass-assignment / upload scan types (v2 — the pipeline
  generalizes; corpus porting is the work)
- MCP server wrapping the CLI (v2, if driven from MCP agents)
- OOB interaction server integration (auto-polling the interaction domain for
  DNS / log4j callbacks)

## 13. Deliverables

The `payint-kvar` repo: package + CLI + ported corpus + `AGENT.md` + pi skill
+ `USAGE.md` + tests, pip-installable (`pipx install -e .` → `kvar` on PATH).
