# Bounded flow control implementation plan

> Use superpowers:executing-plans inline and request a read-only review. Continue under the existing authorized tooling scope and standing merge policy.

**Goal:** Execute conditional stateful API journeys with bounded repetition and unambiguous evidence.

**Architecture:** Extend flow definitions and install a per-visit context controller shared by the runner and staged script adapter. Propagate visit-aware semantics through campaign selection/proof, request planning, traces, and the existing visual editor.

**Spec:** `docs/superpowers/specs/2026-11-01-flow-control-design.md`.

## Constraints

Go 1.24; legacy one-visit behavior; explicit routes and limits; no hidden target traffic; checked budget arithmetic; preserve exact scalar types, per-actor session state, staged script edits, evidence redaction, replay fingerprints, and existing editor exports.

## Tasks

- [x] Add failing real-HTTP/script tests for refresh branching, repeated mutations, self-polling, limit exhaustion, and skipped mutation targets. Extend strict definition validation and implement `CurrentVisit` / `CheckNext` / `SetNext`, `RequestUpperBound`, status sets, and optional extraction.
- [x] Convert runner execution to indexed visits with output clearing, fresh request preparation, visit bounds, route metadata, and staged `ctx.flow` response navigation. Verify the new tests and script atomicity.
- [x] Add failing campaign tests for repeated targets and `visit: last|N|all`. Select the last target status, prove every mutated occurrence, retain intermediate evidence, and update CLI request planning with checked arithmetic.
- [x] Extend visual core/editor for route validation/edges, accepted status sets, visit limits, and optional extraction; round-trip through Go and exercise actual browser editing.
- [x] Extend the reference API and runnable recovery example, connect actual CLI test/replay acceptance, and document operator behavior.
- [x] Run appropriate race/vet/floor/build/browser checks, fix substantive review findings, publish, wait on the specific CI run, and merge after passing checks. Update status and keep the broader goal active while payload/template coverage remains.

Delivered in PR #18, merged at `262f566`. CI run `41322587579` passed both Go jobs and actual browser checks. Native recovered test/replay evidence is in `.reqfuzzy/recovery-delivery-20261101/` and `.reqfuzzy/recovery-delivery-replay-20261101/`. The integrated editor preview is `.reqfuzzy/recovery-flow-preview.html`.
