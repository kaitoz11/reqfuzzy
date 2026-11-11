# 07 — Payload Plan, Sequence IDs & Resume

**Status:** stub
**Depends on:** D2 (determinism), D4 (resume), D16 (scheduler), D20 (control visibility),
D25 (concurrency)
**Supersedes:** Sections 4 (`--plan`, `--resume`, `--max-requests`) and 5.3–5.4

## Purpose

Define how (parameter × template × test case × action × value) becomes an ordered list of
concrete requests, how IDs are assigned, how duplicates are skipped, and how resume replays.

## Required content

### 1. Plan structure
- [ ] Iteration order: parameter → template → test case → action → value.
- [ ] Template ordering rule (deterministic; payintv3 sorts).
- [ ] Parameter ordering and selection (cross-ref `10` CLI semantics).
- [ ] Plan entry fields: `{seq_id, parameter, location, template_id, test_case_index, action,
      value, is_control, payload_hash, safety}`.
- [ ] Estimated counts in `--plan` (including baseline + control requests).

### 2. Sequence IDs
- [ ] Format (payintv3: `scan_id.payload_id-custom_id.sent_id`), the separate control
      counter, and stability guarantees under D2.

### 3. Deduplication
- [ ] Hash function and inputs.
- [ ] `ignore_parameters_when_computing_hash` / `--exclude` semantics (which params, which
      locations, flattening rules).
- [ ] Ordering effect of counter increments for skipped duplicates.

### 4. Special/control requests
- [ ] Baseline (`require_base_response`) and custom base (`create_custom_request_info`,
      index `-1`), including whether each is in the plan list and rendered by `--plan`.
- [ ] `skip_current_parameter_if_match` early exit semantics.

### 5. `--max-requests` and budget
- [ ] Truncate plan vs stop sending; interaction with resume; interaction with control/baseline.
- [ ] Request budget / rate limit hooks (cross-ref `13`).

### 6. Resume
- [ ] Persist `plan.json` (resolved) — never recompute (D4).
- [ ] `scan_state.json` cursor schema.
- [ ] Input-hash validation (request file, templates, seed, config) and refusal behavior.
- [ ] `not_sent` retry semantics and how retried entries re-enter the evidence stream.

## Interfaces / artifacts
- [ ] `PlanEntry` model (JSON Schema).
- [ ] `build_plan(request, params, templates, config, seed) -> Iterator[PlanEntry]`
- [ ] `plan.json` / `scan_state.json` schemas (shared with `11`).

## DoD

- A determinism test with fixed seed produces identical `seq_id` sequences.
- A resume test stops mid-plan, resumes, and sends exactly the remaining entries.

## TODO

- [ ] Resolve D2, D4, D20, D25.
