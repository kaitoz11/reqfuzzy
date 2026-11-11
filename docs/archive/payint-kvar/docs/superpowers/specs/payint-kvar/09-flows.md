# 09 — Flows (Prepare Steps)

**Status:** stub
**Depends on:** D12 (inference sources, shared semantics)
**Supersedes:** Section 7 of the single-document spec

## Purpose

Define the flow DSL: steps, extraction, variable scoping, injection into the scan request, and
failure/retry behavior.

## Required content

### 1. Flow schema
- [ ] `name`, `steps[]`.
- [ ] Step fields: `id`, `request`, `profile`, `set`, `extract`, `expect`, optional
      `retry`/`on_fail`.
- [ ] Reference to raw request files; path resolution relative to project.

### 2. Extraction
- [ ] Kinds: `json` (dot-path dialect), `regex` (first group), `header`.
- [ ] **Typed extraction** (`as: str|int|float|bool|raw`) so JSON body injection preserves
      types (critical for real APIs).
- [ ] Multiple extracts per step; collision/override rules.
- [ ] Extraction failure behavior (abort vs null).

### 3. Variable interpolation & scope
- [ ] Interpolation syntax (`{{ var }}`) and escaping.
- [ ] Scope: global flow vars vs step-local; precedence with `--set` and profile credentials.
- [ ] Type preservation when interpolating into JSON vs form bodies.

### 4. Execution semantics
- [ ] `expect` (status / contains) and failure semantics (abort naming the step).
- [ ] `refresh` hook integration (401/403 → re-auth → retry once).
- [ ] Cookie/session propagation across steps.
- [ ] Timeouts / transport errors.

### 5. Scan integration
- [ ] `kvar scan --flow <name>`: when the flow runs, how vars reach the scan request,
      precedence with `--set`, and interaction with parameter selection.
- [ ] `kvar flow run <name>` output schema (human + `--json`).
- [ ] `kvar flows show` / `flows suggest` wiring.

### 6. Suggested flows (cross-ref `12`)
- [ ] The exact schema written by inference must be directly consumable here.

## Interfaces / artifacts
- [ ] Flow Pydantic model.
- [ ] `run_flow(name, context) -> FlowResult{vars, steps[]}`.
- [ ] Flow output JSON schema.
- [ ] `kvar explain writing-flows` generated from this doc.

## DoD

- Worked examples (login → transfer → OTP) parse and run against the mock target.
- Typed extraction test proves a numeric `txn_id` stays numeric in a JSON body.

## TODO

- [ ] Decide dot-path dialect (own parser vs a library) and pin it.
- [ ] Define `--set` vs flow `set` precedence.
