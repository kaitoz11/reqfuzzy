# 01 — Decision Sheet

**Status:** PROPOSED — reviewer defaults filled in, awaiting ratification
**Rule:** a decision is "ratified" only when **Ratified** is filled. A semantic sub-spec
blocked by an unratified decision must not be written. To override a proposal, replace the
**Answer (proposed)** text and note why.
**Evidence:** `../../reviews/2026-09-27-payint-kvar-design-review.md`
**Proposal date:** 2026-09-27

Legend — Impact: [B]locker, [H]igh, [M]edium. A "proposed" answer is the reviewer's default,
not a mandate. Items marked **(confirm)** need your explicit yes because they set a
security or compatibility posture.

---

## Proposal summary (ratify these first)

| ID | Decision | Proposed | Impact |
|----|----------|----------|--------|
| D1 | OOB in v1 | **B** — ship OOB payloads, mark findings `unconfirmed`; interaction server is a named v2 feature | B |
| D2 | Determinism | **A** — guarantee stable IDs/ordering; `--seed` for byte reproducibility | B |
| D3 | Corpus compatibility | **B** — supported subset + loud failures + compatibility matrix | B |
| D4 | Resume | **A** — persist resolved `plan.json`, replay, refuse on input-hash change | B |
| D5 | Custom template override | **B** default refuse-duplicate; **C** `--override-templates` escape hatch | B |
| D6 | TLS default | **A** — `verify=True`, `--insecure` opt-in **(confirm)** | B |
| D7 | Proxy config | **A** — `config.yaml` normal/scan + CLI overrides; split optional | B |
| D8 | Authorization gate | Gate socket-opening commands; persisted + per-run; offline exempt | M |
| D9 | Host scope allowlist | **A** — v1, enforced at send time **(confirm)** | H |
| D10 | Destructive templates | **A** — require `--allow-destructive`, default exclude, plan warns **(confirm)** | B |
| D11 | Finding dedup | **A** — one finding per (endpoint, param, template family) with trigger list | H |
| D12 | Flow inference sources | **A** — response-bearing sources only; reject raw dirs | H |
| D13 | Parser dependency | **A** — keep `ply` behind a parser interface for v1; document quirks; rewrite is v2 | H |
| D14 | Watch transport | **A** — optional `kvar[watch]` extra using mitmproxy | M |
| D15 | Report export | **A** — `jsonl` + `markdown` in v1 | M |
| D16 | Sync vs async | **A** — sync httpx in v1; freeze scheduler interface now | B |
| D17 | Runtime & pins | Python 3.11+; exact-pin `jellyfish`/`deepdiff`; lockfile | H |
| D18 | Secrets | `secrets.yaml` + `${ENV:VAR}`, `.gitignore`, redaction, never persist resolved creds **(confirm)** | H |
| D19 | Severity scale | Add `critical` | M |
| D20 | Custom base request | Internal by default; visible in `--plan`/evidence | M |
| D21 | Observed timeout | **A** — synthesize pseudo-response with `error:"timeout"` | H |
| D22 | Hook set | v1 = `before_send` + `refresh`; reserve `after_response`/`on_finding` | M |
| D23 | Safety metadata | `safety: safe\|aggressive\|destructive` (default safe) + `concurrency: safe\|not_safe` | H |
| D24 | Artifact versioning | `format_version` in run/plan/findings; `schema_version` in templates | M |
| D25 | Concurrency placeholder | **Yes** — add the field now | M |

**Conflict watch:** D1+B and D3+B together mean many `sql_dns_interaction`/`ssrf`/`xss`
templates will be classified **supported-but-unconfirmed**. The compatibility matrix in
`04` must show `confidence` behavior per family, or the subset becomes a lie.

---

## D1 — OOB detection in v1 or shipped as unconfirmed
- **Question:** Do SSRF/log4j/DNS/XSS families get an interaction server in v1, or ship as
  payloads whose findings are explicitly `unconfirmed`?
- **Options:**
  - A. v1 includes OOB (integrate interactsh or a minimal DNS/HTTP sink).
  - B. v1 ships OOB payloads as `confidence: unconfirmed`; confirmation external/manual;
    auto-polling is a named v2 feature.
  - C. v1 excludes OOB-only templates entirely.
- **Answer (proposed):** **B.** Add `confidence: confirmed | unconfirmed | timeout-observed`
  to the finding schema in v1. `kvar scan` may report `unconfirmed` findings; `AGENT.md` and
  the human output must label them clearly. Remove the vague "OOB integration" from the v2
  roadmap and replace it with a named feature: "interaction server + poller".
- **Rationale:** keeps v1 shippable, avoids a false-confirmation bug, and makes OOB an
  additive change rather than a schema migration.
- **Blocked sub-specs:** 00, 04, 06, 13, 14
- **Ratified:** _pending_

## D2 — Determinism axis and `--seed`
- **Question:** What is guaranteed given `rand_base`/`rand_token`/`rand_number_range`/
  `rand_uppercase`, and is there a seed?
- **Options:** A. stable IDs/ordering only + `--seed` for bytes; B. always byte-stable.
- **Answer (proposed):** **A.** Guarantee: deterministic ordering and stable `seq_id` for a
  given (request, templates, params, seed). Add `--seed` and project `random_seed`; persist
  the effective seed in `run.json`. Tests assert IDs/structure by default; byte-equality only
  under a fixed seed.
- **Rationale:** matches reality; makes `--resume` (D4) coherent.
- **Blocked sub-specs:** 05, 07, 14
- **Ratified:** _pending_

## D3 — Corpus compatibility: full parity vs supported subset
- **Question:** Full payintv3 schema parity, or a documented subset with loud failures?
- **Options:** A. full parity ("ports unchanged"); B. supported subset + compatibility matrix.
- **Answer (proposed):** **B.** Own a `04-template-schema.md` compatibility matrix classifying
  every built-in template `supported | partial | unsupported`. The loader **fails loudly** on
  unsupported constructs (never silent `None` as in `payintv3/process_template/template_helper.parse_template`).
  Close gaps family by family.
- **Rationale:** "ports unchanged" is currently unkeepable; a loud subset is honest and
  testable. Revisit A after the matrix exists.
- **Blocked sub-specs:** 00, 04, 05, 06
- **Ratified:** _pending_

## D4 — Resume semantics
- **Question:** `--resume` recomputes the plan or replays a stored plan?
- **Options:** A. persist resolved plan and replay; B. recompute from cursor.
- **Answer (proposed):** **A.** Persist `runs/<id>/plan.json` (fully resolved). `--resume`
  replays it and refuses if any input hash changed (request file, templates, seed, relevant
  config). `scan_state.json` holds the cursor and `not_sent` set only.
- **Rationale:** recomputation breaks under random values and dedup ordering.
- **Blocked sub-specs:** 07, 11
- **Ratified:** _pending_

## D5 — Custom template override
- **Question:** `custom_templates/` id collides with a built-in — what happens?
- **Options:** A. custom overrides; B. refuse duplicate loudly (payintv3 parity, but loud);
  C. B by default, A behind `--override-templates`.
- **Answer (proposed):** **C.** Default: refuse with a clear error and a `show templates`
  conflict report. `--override-templates` enables deliberate shadowing. Never silently skip
  (payintv3 silently logs and skips — do not reproduce the silence).
- **Blocked sub-specs:** 04
- **Ratified:** _pending_

## D6 — TLS verification default **(confirm)**
- **Question:** payintv3 hardcodes `verify=False`. kvar default?
- **Options:** A. `verify=True`, `--insecure` opt-in; B. payint parity `verify=False`.
- **Answer (proposed):** **A.** Default `verify=True`. Provide `--insecure` and
  `config.yaml: tls.verify: false` for staging/self-signed targets. Print a one-line warning
  when disabled. This is a security posture change from payintv3 — confirm.
- **Blocked sub-specs:** 03, 13
- **Ratified:** _pending_

## D7 — Proxy configuration and split
- **Question:** Where are proxies configured, and is the split required in v1?
- **Options:** A. `config.yaml` `proxy.normal`/`proxy.scan` + CLI `--proxy`/`--scan-proxy`,
  split optional (scan falls back to normal); B. single proxy v1.
- **Answer (proposed):** **A.** If `proxy.scan` unset, scan traffic uses `proxy.normal`.
  Warn when a scan proxy is configured but normal is not (base/normal traffic would be
  un-proxied). `--insecure` and proxy are independent.
- **Blocked sub-specs:** 02, 03, 10
- **Ratified:** _pending_

## D8 — Authorization gate scope and persistence
- **Question:** Which commands require the gate, and is acknowledgment persisted?
- **Answer (proposed):** Gate every command that opens an outbound socket to a target:
  `scan`, `send`, `flow run`, and `import --watch` (capture only — gate optional there, since
  it sends nothing; propose **not** gated). Offline/read-only commands
  (`show *`, `explain`, `init`, `import <file>`, `requests list/show`, `flows *`, `findings`)
  are never gated. Persisted `config.yaml: authorized: true` plus per-run `--authorized` for
  CI. Blocked command ⇒ exit code 1 with a structured error naming the config key.
- **Blocked sub-specs:** 10, 13
- **Ratified:** _pending_

## D9 — Host scope allowlist in v1 **(confirm)**
- **Question:** Is `scope: [patterns]` v1 or v2?
- **Answer (proposed):** **A — v1.** Enforce at send time; out-of-scope host ⇒ refusal (not
  silent skip). Protects against imported HAR third-party hosts and redirects. A boolean
  authorization flag alone is not a safety control.
- **Blocked sub-specs:** 13
- **Ratified:** _pending_

## D10 — Destructive-template policy **(confirm)**
- **Question:** The corpus ships `scan/dos/*` and `fuzz`. What gates them?
- **Answer (proposed):** **A.** Add `safety: safe|aggressive|destructive` to the template
  schema (D23). Default scans **exclude** destructive templates even if their tag matches.
  `--allow-destructive` enables them. `--plan` counts and warns. Apply rate limit + request
  budget to aggressive/destructive families.
- **Blocked sub-specs:** 00, 04, 13
- **Ratified:** _pending_

## D11 — Finding dedup granularity
- **Question:** N payloads hit one vulnerability — N findings or one?
- **Answer (proposed):** **A.** One finding per
  `(host, method, path, location, parameter, template family)`, with a `triggers[]` list of
  `{payload, seq_id, evidence}`. Deterministic `finding_id`. Keep per-payload evidence for
  every trigger. Honor `skip_current_parameter_if_match` to stop early.
- **Blocked sub-specs:** 06, 11
- **Ratified:** _pending_

## D12 — Flow inference sources
- **Question:** Inference needs responses; raw request dirs have none. Support raw dirs?
- **Answer (proposed):** **A.** Inference only from response-bearing sources (HAR, mitmproxy
  dump, `--watch`). `flows suggest <raw files>` is rejected with a clear error. Never re-send
  to synthesize responses (would violate scope/authorization expectations).
- **Blocked sub-specs:** 12
- **Ratified:** _pending_

## D13 — Parser dependency
- **Question:** Keep `ply` or rewrite the DSL parser?
- **Options:** A. keep `ply`, port semantics, isolate behind an interface; B. rewrite now.
- **Answer (proposed):** **A.** Keep `ply` for v1 behind a `DSLBackend` interface. Document
  every known quirk: doubled-quote strings `""...""`, `functools.partial` argument ordering,
  `t_AND = r'and'` substring matching, `DSLMatcher.__post_init__` sorting. Because D3 = B,
  only supported functions need semantic parity. A rewrite becomes a v2 candidate evaluated
  against the golden tests ported in `14`.
- **Rationale:** rewrite now couples two risks (compat + new parser). Isolation makes it a
  later, contained change.
- **Blocked sub-specs:** 02, 05, 15
- **Ratified:** _pending_

## D14 — Watch transport
- **Question:** `import --watch` via optional `mitmproxy` extra, or built-in proxy?
- **Answer (proposed):** **A.** Optional extra `kvar[watch]` using mitmproxy. Clearly
  documented as opt-in; core install stays light. Revisit built-in only if weight is a
  problem. Define the address/port as the **proxy port to configure in the browser**, not a
  bind address (fixes the original doc's ambiguity).
- **Blocked sub-specs:** 12, 15
- **Ratified:** _pending_

## D15 — Report export formats
- **Question:** Is `findings export` in v1, and which formats?
- **Answer (proposed):** **A.** v1 `findings export --format jsonl|markdown` (and `json` via
  the global `--json`). CSV/HTML later if requested. Agents consume JSONL; humans get
  Markdown.
- **Blocked sub-specs:** 10
- **Ratified:** _pending_

## D16 — Sync vs async send architecture
- **Question:** sync `httpx.Client` or `asyncio`?
- **Answer (proposed):** **A.** Sync in v1. Freeze a `Scheduler`/worker interface over the
  plan so v2 can add workers by swapping the driver, not the engine. Time-based families are
  marked sequential forever via the template `concurrency` field (D25). SIGINT and
  `--max-requests` handled by the scheduler.
- **Blocked sub-specs:** 02, 07
- **Ratified:** _pending_

## D17 — Python version and dependency pinning
- **Question:** Minimum Python and pins for detection-affecting deps.
- **Answer (proposed):** Python **3.11+** (`StrEnum`). Exact-pin `jellyfish` and `deepdiff`
  (their scores directly change findings). Pin `httpx`, `pyyaml`, `typer`, `flatdict`, and the
  parser dep. Ship a lockfile. Record dep versions in `run.json` for reproducibility.
- **Blocked sub-specs:** 14, 15
- **Ratified:** _pending_

## D18 — Secret handling **(confirm)**
- **Question:** How are credentials stored/resolved/kept out of git and evidence?
- **Answer (proposed):** `profiles/secrets.yaml` referenced via `credentials_from: <file>#<anchor>`.
  Support `${ENV:VAR}` indirection. `kvar init` scaffolds a `.gitignore` covering `secrets.yaml`
  and `runs/`. Redact credentials in `show`, logs, and run evidence; **never write resolved
  credentials to `runs/`**. Warn when imported traffic contains secrets. `--show-secrets` only
  for interactive `show`.
- **Blocked sub-specs:** 08, 13
- **Ratified:** _pending_

## D19 — Severity scale
- **Question:** Keep `info|low|medium|high` or add `critical`?
- **Answer (proposed):** Add `critical`. Extend the enum to
  `info|low|medium|high|critical`; map payintv3 templates (they use high/medium/info).
  Document that severity is template-authored, not CVSS-derived.
- **Blocked sub-specs:** 06, 11, 15
- **Ratified:** _pending_

## D20 — Custom base request exposure
- **Question:** The internal control request (`create_custom_request_info`) is required for
  boolean detection. User-visible or internal?
- **Answer (proposed):** Internal by default. Visible in `--plan` (as control entries) and in
  run evidence. Reserve a user-facing `--baseline` flag for later; do not conflate it with the
  internal control request.
- **Blocked sub-specs:** 07, 10
- **Ratified:** _pending_

## D21 — Observed-timeout representation
- **Question:** A read timeout has no `httpx.Response`. How is it represented?
- **Options:** A. synthesize a pseudo-response `{status: null, response_time: elapsed,
  error: "timeout"}`; B. separate finding signal.
- **Answer (proposed):** **A.** Synthesize a pseudo-response so `response_time` matchers work
  (time-based detection and the `HttpResponseTimeout` matcher depend on it). Finding evidence
  records `kind: timeout`. Distinguish `timeout` from `not_sent` (transport failure) and from
  real 5xx.
- **Blocked sub-specs:** 06, 07, 11
- **Ratified:** _pending_

## D22 — Hook set
- **Question:** v1 hooks limited to `before_send` and `refresh`, or also `after_response`?
- **Answer (proposed):** v1 = `before_send(request, profile) -> request|None` and
  `refresh(profile, reason) -> profile`. Reserve `after_response`/`on_finding` names in the
  loader for v2. Document `before_send` as the per-request nonce/CSRF mechanism. `refresh`
  takes a `reason` (401/403/flow-failure) and the retry counter lives in the runner so it
  cannot loop.
- **Blocked sub-specs:** 08
- **Ratified:** _pending_

## D23 — Template safety metadata
- **Question:** Field name/shape for danger and concurrency classification.
- **Answer (proposed):** `safety: safe | aggressive | destructive` on every template,
  default `safe` for legacy corpus (then explicitly reclassify `dos/*` as `destructive` and
  time-based/fuzz as `aggressive`). Add `concurrency: safe | not_safe`, default `safe` except
  time-based families.
- **Blocked sub-specs:** 04, 13
- **Ratified:** _pending_

## D24 — Run-artifact versioning
- **Question:** Version storage formats?
- **Answer (proposed):** Yes. `format_version` in `run.json`, `plan.json`,
  `findings.json`; `schema_version` in templates. Loader refuses unknown major versions with
  a clear migration message.
- **Blocked sub-specs:** 11, 15
- **Ratified:** _pending_

## D25 — Concurrency placeholder
- **Question:** Add `concurrency: safe|not_safe` in v1 even though concurrency is v2?
- **Answer (proposed):** **Yes.** Avoids a future schema migration; pairs with D16's scheduler
  interface and D23's `safety` field. Time-based templates set `not_safe`.
- **Blocked sub-specs:** 04, 07
- **Ratified:** _pending_
