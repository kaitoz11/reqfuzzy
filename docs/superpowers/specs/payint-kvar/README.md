# payint-kvar — Specification Set (index)

> Historical specification set. Implementation now extends the Go [reqfuzzy](https://github.com/kaitoz11/reqfuzzy) project. Its current designs replace the Python architecture and pending-decision gates below. Retained for requirements history.

**Status:** skeleton / pre-implementation. Each sub-spec is a stub with a required-content
checklist and a Definition of Done (DoD). Fill these in order (see "Reading order").
**Supersedes:** the single-document spec `../2026-09-27-payint-kvar-design.md` once all
stubs are complete. Until then, the single document remains the product-level summary.
**Critical review that produced this structure:**
`../../reviews/2026-09-27-payint-kvar-design-review.md`

## How to use this set

- `01-decisions.md` is the **gate**. Do not write semantic sub-specs for items blocked by an
  unanswered decision.
- Each stub lists **Required content** (what must be specified) and a **DoD** (what "done"
  looks like). An executor should be able to implement from a completed sub-spec without
  inventing behavior.
- Prefer **executable truth** over prose: Pydantic models / JSON Schema for data, typed
  function signatures for module boundaries. Prose explains; schema/type enforces.
- Port `payintv3` test vectors **before** writing the corresponding engine code.
- Anything marked `TODO` is a hole. A sub-spec with open `TODO`s is not ready.

## Reading order

1. `00-overview.md` — scope, positioning, in/out table.
2. `01-decisions.md` — answer every blocking decision (D*).
3. `02-architecture.md` — module map, dependency direction, sync/async.
4. `03-http-model.md` — raw parser + request model (gates everything).
5. `04-template-schema.md` — template schema + action catalog.
6. `05-dsl.md` — grammar + function catalog + compatibility stance.
7. `06-matchers.md` — matcher semantics + diff algorithms.
8. `07-payload-plan.md` — planning, IDs, dedup, control stream, resume format.
9. `08-auth-hooks.md` — profiles, secrets, hooks.
10. `09-flows.md` — flow execution + typed extraction.
11. `10-cli-contract.md` — every command, JSON schema, exit codes.
12. `11-artifacts-resume.md` — run store, plan/state/findings schemas.
13. `12-import-inference.md` — traffic import, watch, flow inference.
14. `13-safety-authz.md` — authorization gate, scope, danger gating, rate limits.
15. `14-testing.md` — fixtures, ported tests, mock target, agent-loop.
16. `15-packaging-errors-logging.md` — deps/pins, error taxonomy, logging.

## Status board

| # | Sub-spec | Status | Blocked by | Owner |
|---|----------|--------|-----------|-------|
| 00 | Overview & scope | stub | D1–D10 | — |
| 01 | Decisions | **proposed** (awaiting ratification) | — | — |
| 02 | Architecture & layout | stub | D16, D13, D7 | — |
| 03 | HTTP model & raw parser | stub | D6 | — |
| 04 | Template schema | stub | D3, D5, D10, D23 | — |
| 05 | DSL | stub | D2, D3, D13 | — |
| 06 | Matchers | stub | D3, D21 | — |
| 07 | Payload plan & resume | stub | D2, D4 | — |
| 08 | Auth profiles & hooks | stub | D18, D22 | — |
| 09 | Flows | stub | — | — |
| 10 | CLI contract | stub | D8, D15, D20 | — |
| 11 | Run artifacts & resume | stub | D4, D24 | — |
| 12 | Import & flow inference | stub | D12, D14 | — |
| 13 | Safety & authorization | stub | D1, D8, D9, D10 | — |
| 14 | Testing | stub | D2, D17 | — |
| 15 | Packaging/errors/logging | stub | D17, D19 | — |
