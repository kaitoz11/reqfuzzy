# payint-kvar Design Spec — Critical Review

**Reviewed document:** `docs/superpowers/specs/2026-09-27-payint-kvar-design.md`
**Reviewer role:** critical design review / pre-implementation gate
**Basis of review:** the spec itself plus the actual `~/workspace/payintv3` source it claims to be compatible with (`model/`, `process_template/`, `creators/`, `matchers/`, `scanner/`, `web/`, `payint_templates/`, `test_scripts/`, `USAGE.md`).
**Verdict:** The spec is an excellent **product/positioning document** — clear goals, good UX instincts, and a sensible architecture direction. It is **not yet an implementation-ready technical specification.** Several central claims ("corpus ports unchanged", "faithful port of matcher semantics", "deterministic/byte-stable plans", "resume") cannot be executed as written without the implementer inventing large, load-bearing semantics. Those inventions become technical debt within days. This must be closed before coding.

---

## 0. How to read this report

- **Section A — Contradictions / internal flaws (blockers).** The spec contradicts itself or reality. Fix before anything else.
- **Section B — Missing features the user will almost certainly want.** Not necessarily v1, but must be consciously scoped.
- **Section C — Under-designed areas.** The spec names the area but not the semantics. Each needs its own sub-spec.
- **Section D — Open questions to answer with the user** (decision-requiring, not research).
- **Section E — Recommended document restructure** so an executor has zero ambiguity.
- **Section F — Inputs required for the follow-up coding-layout + architectural-design session.**
- **Appendix — Concrete evidence from `payintv3`** that grounds each claim.

Priority tags used: **[B]** blocker, **[H]** high, **[M]** medium, **[L]** low.

---

## A. Contradictions and internal flaws (blockers)

### A1. **[B] v1 scope includes OOB-only attacks, but the OOB interaction server is deferred to v2.**
Section 1 lists **SSRF, log4j/CVE families**; Section 3 keeps the full corpus including `sql_dns_interaction.yaml`, `ssrf`, `xss`; yet the roadmap (Section 12) explicitly defers *"OOB interaction server integration (auto-polling the interaction domain for DNS / log4j callbacks)"*.

The corpus proves these detections are **OOB-only**:
- `payintv3/payint_templates/scan/sql/sql_dns_interaction.yaml` — every payload is a DNS/HTTP callback to `{{attacker_domain}}`; its inline DSL only references `error_message` + `http_response_timeout`.
- `SSTIJavaRCE` (`scan/ssti/ssti_java.yaml`) — payloads call `InetAddress.getByName("...attacker_domain")`, i.e. detection depends on the callback.
- XSS corpus is a single template and standard XSS detection is callback based (`xss_hunter` in `default_variables.yaml`).

**Consequence:** In v1 as written, SSRF/DNS/log4j/XSS payloads are **sent but can never be confirmed automatically**. That is a different product than "scanning": it is a payload cannon. The spec must choose one and say so:

1. **v1 = OOB-capable**: bring the interaction server (or integrate an existing one, e.g. interactsh) into scope now; or
2. **v1 = OOB-blind**: explicitly downgrade these families to "payload sent, confirmation manual/external", mark findings as `unconfirmed`, and remove the *auto* OOB polling from the roadmap into an explicit supported/external workflow.

Either answer changes the plan, the finding schema (`confidence: confirmed|unconfirmed|timeout-observed`), the matcher engine, and the test suite. **This is the single biggest gap.**

### A2. **[B] "Deterministic expansion" / "byte-stable plans across runs" contradicts random DSL.**
Section 5 says the payload plan is a "deterministic expansion"; Section 10 requires "byte-stable plans across runs". But the corpus is full of non-deterministic generators: `rand_base`, `rand_token`, `rand_number_range`, `rand_uppercase` (`process_template/dsl_parser.py`), e.g. `sql/boolean_based.yaml`, `sql/time_based.yaml`, `ssti/ssti_java.yaml`.

You cannot have both unless you define the axis of determinism precisely. Recommended clarification:

- **Ordering is deterministic** (parameter order × template order × test-case order × action order × value order) → **sequence IDs are stable**.
- **Resolved values are not deterministic** unless a **seed** is provided. Add `--seed` / project `random_seed`, and persist the seed in the run.
- Tests asserting "byte-stable plans" must run with a fixed seed, or assert only on **structure/IDs**, not payload bytes.

Without this, the stated tests are unwritable, and `--resume` (A4) cannot work.

### A3. **[B] "Corpus ports over unchanged" is not true against the real schema.**
The spec's Section 5 alludes to actions as "(`append`/`prepend`/`replace`/`overwrite`/…)". The real `ScanPayloadAction` enum (`model/enum_type.py`) is:

```
prepend, append, replace, overwrite, json_transform,
add_number_to_base, multiply_number_to_base, remove,
parameter_pollution, traverse_update_json
```

And that is only **one** of the schema dimensions. The corpus also depends on, none of which the spec specifies:

| payintv3 construct | Where it lives | Spec coverage |
|---|---|---|
| `create_custom_request_info` + special index `-1` (`SepcialTestCaseValueIndex.ForCreateCustomRequest`) | `model/template.py`, `creators/scan_payload_creator/__init__.py`, `scanner/payload_scanner.py` | **absent** |
| `value_type`: `int,float,bytes,str,bool,dict,list,one_string,big_number,repeat_str,reserved_string` | `ValueProcessor` | **absent** |
| `$$` repeat marker, `PayIntBigNumber[...]`, `PayIntReservedStr[...]`, `PayIntPollution[...]` | `value_processor.py`, `enum_type.py` | **absent** |
| `levenshtein_distance` per test case | `ScanTestCase` | **absent** |
| `skip_current_parameter_if_match` | `ScannerTemplate`/`UploadTemplate` | **absent** |
| `matcher_template_ref_tags` → load-time matcher-merge | `TemplateManager._resolve_matcher_template_ref` | **only named**, semantics unspecified |
| `nfc` key silently deleted from variables | `variable_processor.py` | **absent** |
| `current_test_case_value`, `current_test_case_parameter_name` response vars | `enum_type.py` | **absent** |
| `base_response_object` / `custom_base_response_object` / `current_response_object` | `MatcherDSLParser` | **absent** (see A5) |
| custom base response sent before the real payload `-1` | `payload_scanner.create_custom_base_response` | **absent** |
| `json_transform` special keys `__overwrite__`, `__overwrite_dict__`, `__update_root__` | `enum_type.py` | **absent** |

"The corpus ports unchanged" is a **hard compatibility contract** that the spec does not define. Either (a) commit to full schema compatibility and write the schema spec (Section C2), or (b) scope v1 to a subset and explicitly quarantines templates the engine cannot run. Silent partial compatibility will corrupt scan results.

### A4. **[B] `--resume` is unspecified and collides with random values, dedup, and plan recomputation.**
Section 4: `scan_state.json` "holding the plan cursor; `--resume <seq-id>` replays from a payload sequence ID". But:
- Sequence IDs are produced by a **generator** that depends on parameter order, template order, *and* random DSL values (`creators/scan_payload_creator/__init__.py`), plus dedup state (`state.is_payload_existed` increments `sequence_payload_id` **even for skipped duplicates**).
- If the plan is recomputed on resume, random values differ, dedup decisions differ, and the cursor points at the wrong payload.
- The custom-base-request stream has a **separate** counter (`sequence_custom_payload_id`).

**Required decision:** persist the **fully resolved plan** (`runs/<ts>/plan.json`) and `--resume` must **replay the stored plan**, never recompute. Specify: cursor semantics, `not_sent` retry semantics (Section 11 mentions it but no format), interaction with `--max-requests`, and what happens if the request file or templates changed since the plan was written (hash + refusal).

### A5. **[B] Base-response model is conflated and incomplete.**
The spec says `require_base_response` "sends the untouched request first for diffing". The real engine has **two** baselines:

1. `base_response`: the untouched request, once per scan (`base_scanner.create_base_response`).
2. `custom_base_response`: per *parameter*, a request where only a **control** value (`create_custom_request_info`, e.g. a bare `'`) is appended — this is what `SQLBooleanBased` compares against (`sql_detect_diff_response(base_response_object, custom_base_response_object)`).

The spec mentions neither the custom baseline nor the `-1` control-send stream. Without it, boolean-based SQLi and several other templates produce **false positives or no detections**. Section C6 must be written.

### A6. **[B] "custom_templates overlay" vs payintv3 first-wins behavior.**
Section 3: "built-in corpus + project `custom_templates/` overlay (payint TemplateManager parity)". In payintv3, `TemplateManager._load(default)` runs first, then custom; `add_template` raises `ExistedTemplateInDataSet` if the id already exists, and the loader **logs and skips** it (`process_template/__init__.py`). So payintv3 is **first-wins / no override** — the opposite of "overlay". Decide explicitly:
- **Override** (custom wins by id) → useful, but dangerous (shadowing built-ins silently), or
- **No-override** (payint parity) → warn loudly.
Either way, specify `schema_version`, id-namespace rules, and a `kvar show templates` conflict report.

### A7. **[B] "Normal/scan proxy split retained" has no configuration surface.**
Section 5 keeps the split; the CLI surface (Section 4) has no `--proxy`, `--scan-proxy`, `--insecure`, or config keys; there is no `config.yaml` schema. payintv3 drives it from Python (`browser.update_httpx_scan_proxy(...)`, `verify=False`, `retries=3`). The executor cannot implement "retained" without knowing:
- where proxies are configured (config.yaml? env? flags?),
- TLS verification policy (payintv3 hardcodes `verify=False` — must decide, this is a security-relevant default),
- redirect policy, retries/backoff, connection/read timeouts, HTTP/1.1 vs HTTP/2, keep-alive,
- whether the scan proxy is also the OOB sink (some workflows rely on Burp Collaborator).

### A8. **[M] Authorization gate scope is ambiguous.**
Section 9: "CLI refuses to run against a project until `authorized: true`". Which commands? `import` and `show` don't send payloads; `send` does. `scan --plan` does not. The gate should be:
- required for any command that **makes network requests** (`scan`, `send`, `flow run`, `import --watch` may or may not),
- **not** required for read-only/offline commands (`show`, `requests list`, `explain`, `init`, `import` file mode).
Also define whether `--authorized` is persisted, interactive prompt behavior, and the exact error + exit code when blocked. And add a **target scope allowlist** (see B6) — a boolean flag is not an authorization model.

### A9. **[M] `--json` "always exactly one JSON document" vs error handling.**
Section 4 promises one well-defined JSON document per invocation; Section 11 describes human-readable failure messages but never an **error JSON schema**. Agents need `{ok:false, error:{code, unit, message, details}}`. Define:
- the envelope (`{ok, version, command, data..., error?}`),
- exit-code **precedence** when findings + runtime errors coexist (e.g., some payloads `not_sent` + findings found),
- that progress/logs go to **stderr**, never stdout, so `--json` stdout stays parseable.

### A10. **[L] Document hygiene.**
- "Two design principals" → "principles".
- The `kvar/` layout is illustrative but incomplete (no `config.py`, `logging`, exceptions, `state`, `run_store`, `__init__`, versioning); `profiles.py`/`hooks.py` sit at package root while their consumers are in `engine/`. This will be resolved in the coding-layout session but should be flagged now.
- `templates/` is *data* inside the Python package; packaging data files needs a decision (Section C16).

---

## B. Missing features / capabilities the user will want

These are not necessarily all v1, but each is a "you'll regret not deciding" item. Mark them explicitly in a scope table.

1. **[B] Safety/danger gating for destructive templates.** The corpus contains `payint_templates/scan/dos/` (`json_recursion_crash`, `markdown_recursion_crash`, `regex_dos`) and `fuzz` families. A default `--tags`-less scan, or naive `--tags all`, can take down a target. Add template `severity`/`safety: safe|aggressive|destructive`, require `--allow-destructive`, and rate-limit destructive families. This is an authorization/legal issue, not a nice-to-have.
2. **[H] Rate limiting / inter-request delay / jitter / backoff.** Sequential ≠ polite. Add `--delay`, `--rate`, retry/backoff policy, and a global request cap (beyond `--max-requests`).
3. **[H] Cookie/session jar semantics.** Flow login sets cookies; later flow steps and the scan request must reuse them. payintv3 relies on the httpx client cookie jar (`browser.send` does `self.user.update_httpx_cookies(self.get_client().cookies)`). Specify: one client per profile, Set-Cookie propagation across flow steps and scan requests, how profile `inject.cookies` interact with the jar, and cross-host cookie behavior.
4. **[H] Redirect / timeout / TLS / encoding policy.** See A7. Also body size limit for evidence, decompression, and charset handling for `response.text` (matchers compare text).
5. **[H] Findings dedup + triage.** Same vulnerability found by N payloads → N findings? payintv3 has per-payload hash dedup and `skip_current_parameter_if_match`, but no finding-level dedup. Define a finding identity key (endpoint+param+template family?) and `skip_current_parameter_if_match` support. Add severity scale (current enum lacks `critical`) and optionally CWE/OWASP mapping.
6. **[H] Target scope allowlist.** Authorization is not `true/false`; it is "hosts I may attack". `config.yaml: scope: [api.target.com, '*.target.com']`; refuse out-of-scope hosts at send time. This also protects against a captured HAR importing a third-party host.
7. **[M] Secret handling.** `credentials_from`, `profiles/secrets.yaml`, captured cookies in imported requests. Define: env-var indirection (`${ENV:VAR}`), scaffolded `.gitignore`, `kvar show profiles --redact`, redaction in evidence, and a warning when secrets are written to `requests/`.
8. **[M] Response/after hooks and observability hooks.** v1 has only `before_send` and `refresh`. Real engagements need `after_response(response, context)` (log/assert/chain) and possibly `on_finding`. At minimum, state they are deferred and that the hook loader is extensible.
9. **[M] Structured run selection / report export.** `kvar findings` needs a `--run <id>` (or `--latest`) and a defined index of `runs/`. Add `findings export --format jsonl|csv|md` for humans/agents. Also deterministic `--run-id` for reproducible artifact paths.
10. **[M] Config schema + precedence.** `config.yaml` is referenced but never defined. Specify keys, defaults, precedence (CLI flag > env > project config > built-in), project discovery (walk up? explicit?), and whether there is a user-global config.
11. **[M] Template metadata for reporting.** `info` currently has name/author/description/tags/severity/references. Add optional `cwe`, `owasp`, `remediation`, `confidence`, `schema_version`.
12. **[M] Baseline / "custom base request" as a user-facing control.** Beyond the internal SQLi control request, users may want `--baseline` (send untouched, store, diff manually) — partly covered, but name it.
13. **[M] Concurrency design placeholder even if deferred.** Section 5 says concurrency is "gated per-template: safe only for non-time-based families". Put `concurrency: safe|not_safe` in the template schema now so the v2 flag is not a schema migration. Also design the async boundary now (sync httpx vs asyncio) — retrofitting is expensive.
14. **[M] Inter-request state / CSRF tokens.** Flow extraction covers this, but the scan of a single request may need a fresh nonce per payload. Add an optional per-request `pre_send` hook (or document that this is what `before_send` is for, with flow vars in context).
15. **[L] Import/watch dependency and lifecycle.** `--watch` implies mitmproxy (or a built-in proxy). Decide: optional extra `kvar[watch]` depending on `mitmproxy`, or a minimal built-in HTTP/1.1 CONNECT proxy. Define the watcher's output (same `requests/` naming), dedup, and shutdown.
16. **[L] Versioning/migration.** `kvar --version`, template `schema_version`, run-artifact `format_version`. Cheap now, painful later.
17. **[L] Progress/ETA and `--quiet`.** Since agents parse stdout, define progress-vs-result channels and quiet modes.
18. **[L] Offline `--plan` fidelity.** `--plan` should not even resolve network-dependent templates? It should resolve DSL and show counts, dangerous families, estimated request count (including control requests and base requests).

---

## C. Under-designed areas — each needs a dedicated sub-spec

For each: the spec names it, but an executor would have to invent semantics. Recommended as separate doc sections (or ADRs).

### C1. **[B] HTTP request model & raw parser (`engine/raw_request.py`, `http_model.py`)**
Missing: exact grammar acceptance (request line, header folding, blank-line handling, CRLF vs LF), **round-trip fidelity rules**, content-type inference algorithm, multipart parsing (fields vs files, charset, `filename*`), body when method is GET, chunked/`Transfer-Encoding`, binary/non-UTF-8 bodies, duplicate headers, header case, whitespace preservation, path segment indexing, query parsing (repeated keys, arrays, bracket notation), JSON nested-path representation, `flatdict`-style delimiter (`:`), and the canonical immutable builder API (the spec says "builder API" but defines none of its methods). payintv3's behavior to port or deliberately break: `web/factory.py` (dpkt-based, strips Content-Length, `DEFAULT_IGNORE_HEADERS` incl. `Cookie`), `web/http_encoder.py` (JSON/URLENCODED/MULTIPART/XML/NONE), `HttpRequest` (immutable `.with_*()`).
**DoD:** grammar (EBNF), round-trip test vectors (including Burp pastes with CRLF, duplicate headers, multipart, non-UTF8), and a documented list of deliberate divergences.

### C2. **[B] Template schema + versioning**
Full field-by-field schema for scan + matcher templates: `id`, `info{...}`, `type`, `variables`, `test_cases[], values[], value_type, actions[], create_custom_request_info`, `matchers[]`, `matcher_condition`, `matcher_template_ref_tags`, `levenshtein_distance`, `skip_current_parameter_if_match`, `safety`, `concurrency`, `schema_version`. Plus the **action catalog** and each action's exact mutation semantics (`json_transform` with `__overwrite__`/`__overwrite_dict__`/`__update_root__`; `parameter_pollution`; `traverse_update_json`; `remove`; `add_number_to_base`; `multiply_number_to_base`), the **value-type** processing (`repeat_str` with `$$`, `big_number`, `reserved_string`, `one_string`, `dict`/`list` via literal eval), and the special-prefix unwrap at send time (`remove_special_value_prefix`). Define corpus compatibility as a test (load all 60 scan + 30 matcher templates, expand, assert no skips).
**DoD:** JSON Schema (or Pydantic) for both template kinds; a compatibility matrix listing every built-in template and whether v1 supports it; a loader that fails loudly on unsupported constructs rather than silently skipping (`parse_template` currently silently returns `None`).

### C3. **[B] DSL specification (`engine/dsl.py`)**
The spec names 3 functions; the real DSL has ~20 (`dsl_parser.SupportedVariableDSLFunction`) plus matcher-only helpers (`sql_detect_diff_response`, `idor_detect_diff_response`, `is_mass_assignment_vuln`). Missing: full grammar (comparison operators, `and`/`or`/`!`, precedence, parentheses), string literal syntax (**doubled quotes** `""...""`), special constants `[EMPTY]`, `[DOUBLE_QUOTES]`, type coercion rules, argument-order quirks (the PLY implementation applies `functools.partial` in a non-obvious order — a true port must match or be documented as fixed), variable substitution order (top-down, `template_helper`/`variable_processor`), the distinction between variable expansion and function evaluation, and error policy (silently skip vs raise).
**Also decide:** **bug-for-bug compatibility** or a cleaned-up DSL with a migration note. The golden-test-from-payintv3 approach (Section 10) will freeze existing bugs; that must be a conscious choice.
**DoD:** EBNF grammar, function catalog with signatures + examples, escaping rules, `kvar explain dsl` generated from the same source of truth, and a golden test corpus ported from `test_scripts/unit_test/test_dsl_parser.py` + `variable_processor_test.py`.

### C4. **[B] Matcher engine semantics (`engine/matchers.py`)**
Missing: merge semantics of inline matchers + `matcher_template_ref_tags` (load-time `list.extend`, ordering), `matcher_condition` AND/OR evaluation quirks (`MatcherProcess.execute` returns `(is_vuln, matcher, sequence_matcher)`; AND returns `matcher=None`), DSL list **sorting** (`DSLMatcher.__post_init__` sorts `dsl`), which expression index is recorded in the finding, response variable extraction (`content_length, status_code, headers, body, response_time, raw_request`), diff algorithm (`jellyfish.jaro_winkler_similarity`, threshold `diff_text_ratio_constant=0.05`, `deepdiff` for JSON), and how a **timeout/no-response** maps into `HttpResponseTimeout`/`response_time`.
**DoD:** truth table for conditions × matchers; pinned diff algorithm + dependency version; explicit recording of the matched expression; false-positive test cases; timeout representation.

### C5. **[B] Payload planning (`engine/payloads.py`)**
Missing: **ordering** (parameter → template → test case → action → value), template ordering (`TemplateManager.get_template_by_tags` returns `sorted(...)` by `__lt__` = `str(self)`), sequence ID format (payintv3: `scan_id.payload_id-custom_id.sent_id`), dedup hashing (`get_hash_id` + `ignore_parameters_when_computing_hash` + `flatten_scan_parameter_names`), multi-dict behaviors (`json_transform`, `parameter_pollution`), the **separate control/custom stream** (`sequence_custom_payload_id`), the special index `-1`, and `skip_current_parameter` early-exit. Also `--max-requests` as a plan truncation vs a send cap.
**DoD:** the plan is enumerated as data (list of `{seq_id, param, template, test_case_idx, action, value, is_control}`); a determinism test with fixed seed; a dedup test; a `--plan` renderer.

### C6. **[B] Base / custom-base response lifecycle**
Define: when `base_response` is sent (post-profile-injection?), for which scans it is required, how `custom_base_response` is generated from `create_custom_request_info`, storage of both in evidence, and how templates that reference `base_response_object` / `custom_base_response_object` / `current_response_object` behave when a baseline is absent (payintv3 logs and skips the matcher). Specify the guard against a missing baseline producing a false finding.

### C7. **[H] Auth profiles, secrets, and injection**
Define: the profile YAML schema exactly (`credentials`, `credentials_from`, `inject` for headers/cookies/body/query/files), **nested path syntax** for body injection, overwrite-vs-add rules (payintv3 `with_update_*_existing_*` vs `with_update_*`), how `inject` interacts with the raw request's existing auth, multi-profile support (attacker/victim are needed in v2 but the schema should not preclude it), secret indirection and redaction, and profile/`refresh` failure semantics.

### C8. **[H] Hook contract (`engine/hooks.py`)**
Define: discovery rules (filename → function name), load order, the **context object** passed to hooks (request/profile/run/flow vars), immutability requirements, return contract (`None` = no change vs must return request), exception policy (spec says fail loudly — confirm it aborts the run vs aborts the scan), sandboxing/import errors, and the `refresh` loop guard (spec says re-call on 401/403, retried once; define exactly where the retry counter lives so it cannot infinite-loop, and how the refreshed profile propagates to the in-flight scan and to the client cookie jar). Note the spec's `refresh(profile) -> profile` signature lacks response/context — is that sufficient to decide re-login?

### C9. **[H] Flows (`engine` + `flow.py`)**
Define: step schema (`id`, `request`, `profile`, `set`, `extract`, `expect`), extraction types (`json` dot-path, `regex` first group, `header`), **value typing** (a txn_id extracted as a string then written into a JSON body changes its type — this breaks real APIs), variable scoping (global vs step-local), interpolation syntax and escaping, cookie/session propagation, `expect` failure semantics, retry/refresh interaction, and `flow run` output schema.
**DoD:** typed extraction (`as: str|int|float|bool|raw`), JSON-path dialect, examples for login → transfer → OTP, and error messages naming the step (already stated in Section 11 — good).

### C10. **[H] CLI contract & JSON schemas**
Section 4 gives the command list but not the per-command contract. Need, for every command: arguments, defaults, behavior, exact `--json` schema, exit codes, stderr/stdout split, and side effects. Pay special attention to `scan` (`--params` syntax and precedence with `--all-params`/`--exclude`, `--set`, `--flow`, `--resume`, `--plan`, `--max-requests`, `--timeout`), `send`, `import`, `requests *`, `flow*`, `findings`, `explain`. The finding JSON in Section 9 is a good start; the **scan envelope** in Section 4 is only a list of keys, not a schema (no types, no nullability, no nested shapes).

### C11. **[H] Run artifacts & state store**
Define `runs/<timestamp>/` fully: exact directory layout, evidence file naming (the finding example says `req_0007.txt` but the engine needs `seq_id` correlation), how request bytes are encoded/preserved, response size limits/truncation, `scan_state.json` schema (**and `plan.json`**, per A4), `findings.json` schema, `run.json` metadata (target scope, profile, seed, kvar version, template hashes), secret redaction, retention/rotation, and a `runs` index/manifest so `findings`/`--resume` can find runs.

### C12. **[H] Authorization & safety model**
Beyond A8/B1: define scope allowlist, destructive-template gating, per-run request budget, rate limit, a clear "this host is out of scope" refusal, and the legally relevant wording in `AGENT.md`/`USAGE.md`. Consider a `--yes-i-am-authorized` non-persisted flag for CI and a persisted project acknowledgment.

### C13. **[H] Traffic ingestion (`import`)**
Define source formats precisely: HAR (which version, entries with/without response, cookies, `postData` mime types), mitmproxy flow dump (format/version; `-r` takes a dump file, `.mitm` could also mean a directory), raw request dir. Define: stable naming + collision counter, dedup key, filter grammar (`host:`, `path:` — exact syntax, glob vs substring), automatic static/CONNECT dropping rules, secret warnings, progress for large files (streaming, memory bounds), and idempotent re-import. For `--watch`: transport (mitmproxy addon vs built-in proxy), port semantics (`127.0.0.1:8084` is currently a proxy port, not a capture address), and shutdown.

### C14. **[H] Flow inference algorithm**
This is the most research-flavored feature and is under-specified. Define: input pairing (HAR/mitm have responses; a raw-request directory **does not** — so `kvar flows suggest <files...>` on raw files is impossible as written; restrict to response-bearing sources), the taint scan (which scalar types, how deep in JSON, regex extraction patterns, header/cookie/path search), normalization/scoring (exact = high, URL/JSON/base64-encoded = lower — specify the normalizers), false-positive controls (skip common values: booleans, `0/1`, timestamps, generic ids), output schema for `flows/suggested-*.yaml` (must be directly edible by the flow runner), and performance bounds (streaming, top-K, response size caps). Also state that suggestions are never auto-run (good) and how they are reviewed (`flows show`).

### C15. **[H] Testing strategy**
Section 10 is directionally right but not executable. Add: python version, test runner, fixture generation with a **fixed seed**, a porting plan for payintv3 unit tests (`test_scripts/unit_test/{test_dsl_parser,variable_processor_test,value_processor_test,parse_template_test,scan_payload_test}.py`), corpus-wide load test (all templates), a mock target with deterministic timing (time-based tests must not sleep 20s), OOB test double (a local DNS/HTTP sink) **if** A1 chooses OOB-in-v1, agent-loop golden JSON tests, and a "docs drift" test (Section 10 already suggests this — keep it). Also add fuzzing for the raw parser and DSL.

### C16. **[H] Packaging, dependencies, and Python runtime**
Not mentioned at all. Decide Python version (`StrEnum` → 3.11+), dependency set and pins (`httpx`, `pyyaml`, `typer`, `flatdict`, `ply`, `jellyfish`, `deepdiff`, `dpkt`/parser choice, optional `mitmproxy`), because **detection fidelity depends on `jellyfish`/`deepdiff` versions**. Decide package data inclusion for `templates/`, extras (`kvar[watch]`), lockfile, and the `kvar` entry point. Decide whether to keep `ply` (a rewrite with a hand-written parser or Lark is a real option — the current grammar has known quirks; either choice must be documented).

### C17. **[M] `explain` / `AGENT.md` single source of truth**
Section 9 says the three doc surfaces share a "content family". Duplicated docs drift. Define a single source (e.g., structured topic files shipped as package data) rendered by both `kvar explain` and used to build `AGENT.md`, with the agent-loop test enforcing consistency.

### C18. **[M] Error taxonomy**
Section 11 gives examples but not a taxonomy. Define stable error codes/units (`raw_request.parse`, `flow.step`, `profile.refresh`, `hook.load`, `http.transport`, `template.load`, `template.unsupported`), where each is raised, the human format, the JSON format, and exit-code mapping.

### C19. **[M] Logging & verbosity**
`--verbose` levels undefined, no log file, no debug trace/replay. Define levels, destination (stderr/file), and whether a raw HTTP trace (à la `store_payint_log`) is written for debugging (payintv3 has `LogLauncher`). This matters for false-positive debugging.

### C20. **[L] Concurrency architecture (freeze now, implement v2)**
Pick sync vs asyncio now. Time-based detection needs sequential per family, but OOB and fuzz can parallelize later. Design the send loop as a scheduler over the plan so adding workers is not a rewrite.

---

## D. Open questions (decisions needed from the user)

1. **OOB**: v1 includes an interaction/callback server, or ships OOB payloads as unconfirmed? (A1)
2. **Determinism**: is `--seed` acceptable, and are "byte-stable plans" required or only stable IDs/ordering? (A2)
3. **Corpus compatibility**: full schema parity (and therefore a bigger engine) or a documented supported subset with loud failures? (A3)
4. **Resume**: persist and replay a stored plan (recommended) — agreed? (A4)
5. **Custom templates**: override built-ins or refuse duplicates? (A6)
6. **TLS**: default `verify=True` (safe) or payint parity `verify=False`? (A7)
7. **Proxies**: configured via config.yaml, env, or flags; is the split required in v1 or can it be one proxy + optional scan proxy? (A7)
8. **Auth gate**: which commands require authorization; persisted or per-run? (A8)
9. **Scope allowlist**: is a host-scope list in v1, or only in v2? (B6)
10. **Destructive templates**: v1 ships `dos`/`fuzz`, or gates/quarantines them? (B1)
11. **Findings dedup**: one finding per (endpoint, param, template)? (B5)
12. **Raw-request-only projects**: acceptable that `flows suggest` requires response-bearing imports? (C14)
13. **Parser dependency**: keep `ply`, or rewrite? (C16)
14. **Watch transport**: `mitmproxy` optional extra, or a built-in proxy? (C13)
15. **Report formats**: is `findings export` in v1? (B9)

---

## E. Recommended document restructure

The spec should be split so the executor has one contract per concern. Proposed:

1. **00-overview.md** — purpose, positioning, scope table (in/out for v1/v2) with the questions above resolved.
2. **01-architecture.md** — process/package layout, dependency direction, module responsibilities, extension points, sync/async decision.
3. **02-http-model.md** — raw parser grammar, encoding rules, immutability/builder API, content types, round-trip test vectors. *(C1)*
4. **03-template-schema.md** — full schema, action catalog, value types, matcher refs, versioning, corpus compatibility matrix. *(C2)*
5. **04-dsl.md** — EBNF, function catalog, escaping, error policy, compatibility stance. *(C3)*
6. **05-matchers.md** — matcher types, condition semantics, ref merge, diff algorithms + pins, timeout modeling. *(C4)*
7. **06-payload-plan.md** — ordering, IDs, dedup, control stream, `--plan`, `--max-requests`. *(C5, C6)*
8. **07-auth-hooks.md** — profile schema, secrets, hook contract, refresh loop. *(C7, C8)*
9. **08-flows.md** — step schema, typed extraction, interpolation, cookies, errors. *(C9)*
10. **09-cli-contract.md** — every command with args/defaults/behavior/**JSON schema**/exit codes/stderr. *(C10)*
11. **10-artifacts-resume.md** — run layout, plan/state/findings schemas, resume algorithm, redaction. *(C11)*
12. **11-import-inference.md** — source formats, watch, naming/dedup, inference algorithm + scoring. *(C13, C14)*
13. **12-safety-authz.md** — authorization gate, scope allowlist, danger gating, rate/budget. *(C12, B1, B2)*
14. **13-testing.md** — fixtures/seed, ported tests, mock target, OOB double, agent-loop, fuzzing. *(C15)*
15. **14-packaging-errors-logging.md** — deps/pins, extras, error taxonomy, logging. *(C16, C18, C19)*

Add **ADRs** for the irreversible/expensive decisions: OOB, sync/async, parser dependency, DSL compatibility, persistence format, template override semantics.

---

## F. Inputs required for the follow-up coding-layout + architectural-design session

To make that session produce an unambiguous layout, bring:

1. **Resolved answers to Section D** (at least OOB, determinism, compatibility, resume, TLS/proxy, safety).
2. **The module responsibilities above**, especially the new modules missing from the spec layout: `run_store`, `config`, `logging`, `errors`, `scope`/`authz`, `importers/`, `flows/`, `state`.
3. **Data-flow diagrams** for: scan plan generation → send → match → finding; flow execution → variable extraction → scan injection; import → inventory → inference.
4. **Interface stubs** (function/class signatures) for every module boundary that an executor will implement: `parse_raw_request`, `load_templates`, `build_plan`, `send`, `evaluate_matchers`, `apply_profile`, `run_hook`, `run_flow`, `write_finding`, `resume_scan`, `import_traffic`, `infer_flows`.
5. **Schema artifacts** as executable truth: Pydantic models / JSON Schema for template, profile, flow, config, run state, and every `--json` output.
6. **A test-vector bundle** for the parser, DSL, and matchers ported from `payintv3/test_scripts/unit_test/` before writing engine code.
7. **The scope table** (v1/v2) updated with everything from Section B, so "deferred" is explicit rather than accidental.

**Recommended sequence:** finalize A1–A6 in the overview → write C1–C5 sub-specs (they gate the most code) → snapshot test vectors from payintv3 → then do the coding layout/architecture session → then implement.

---

## Appendix — Evidence from `payintv3`

| Claim in report | Evidence |
|---|---|
| OOB-only detection for SQL DNS / SSTI | `payint_templates/scan/sql/sql_dns_interaction.yaml`, `payint_templates/scan/ssti/ssti_java.yaml` (callbacks to `attacker_domain`) |
| `attacker_domain`/`xss_hunter` are static vars | `payint_templates/default_variables.yaml` |
| Random DSL generators | `process_template/dsl_parser.py` (`rand_base`, `rand_token`, `rand_number_range`, `rand_uppercase`) |
| Action enum | `model/enum_type.py` `ScanPayloadAction` |
| Value types / special prefixes | `process_template/value_processor.py`, `model/enum_type.py` `ValueType`, `SpecialPrefixValue` |
| `create_custom_request_info` / control index `-1` | `model/template.py` `ScanTestCase`, `model/enum_type.py` `SepcialTestCaseValueIndex`, `creators/scan_payload_creator/__init__.py`, `scanner/payload_scanner.py` |
| `skip_current_parameter_if_match` | `model/template.py` `ScannerTemplate` |
| Matcher ref tag merge at load | `process_template/__init__.py` `_resolve_matcher_template_ref` |
| Dedup hashing / ignore params | `model/scan_payload_creator_data.py` `get_hash_id`, `creators/state.py` `add_payload_data`/`is_payload_existed` |
| Ordering of templates | `process_template/__init__.py` `get_template_by_tags` → `sorted(...)` |
| Sequence IDs | `creators/state.py` `get_req_id` |
| Base vs custom base response | `scanner/base_scanner.py` `create_base_response`, `scanner/payload_scanner.py` `create_custom_base_response` |
| Diff algorithms + constants | `utils/dsl_utils.py` (`jellyfish.jaro_winkler_similarity`, `deepdiff`), `config/__init__.py` `diff_text_ratio_constant=0.05` |
| Matcher response vars + execute quirks | `utils/matcher_utils.py`, `matchers/matcher_process.py` `execute` |
| DSL list sorting | `model/template.py` `DSLMatcher.__post_init__` |
| Content types + ignore headers | `web/constant.py`, `web/http_encoder.py`, `web/factory.py` |
| TLS/retries/proxy hardcoded | `web/browser.py` (`verify=False`, `retries=3`, `update_httpx_scan_proxy`) |
| Cookie jar propagation | `web/browser.py` `send` (`update_httpx_cookies`) |
| Destructive templates | `payint_templates/scan/dos/*.yaml` |
| Ported test seeds | `test_scripts/unit_test/*.py` |
| payintv3 no-override template load | `process_template/__init__.py` `add_template` + `_load` |
