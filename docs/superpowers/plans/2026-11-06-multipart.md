# Multipart implementation plan

> Execute inline using existing TDD/review/verification skills and standing integration approval.

**Goal:** Make multipart fields and file uploads first-class stateful mutation targets with byte-exact signing and proof.

**Spec:** `docs/superpowers/specs/2026-11-06-multipart-design.md`.

**Architecture:** A shared raw multipart package owns bounded parsing, part selection, atomic editing, and boundary-safe framing. Flow/campaign/capture reuse it; the script adapter supplies explicit binary representations and crypto. The existing CLI/map/evidence interfaces expose the new locations.

- [x] Write failing multipart byte/metadata tests and implement shared parsing/selection/editing while preserving untouched bytes.
- [x] Connect bindings, mutations, preflight, current-value templates, conservative inference, and observed proof; verify actual HTTP behavior and invalid-input refusal.
- [x] Add binary request/response script representations and byte crypto with atomic conflict checks and real signature tests.
- [x] Add multipart locations to map authoring, exports, help, docs, and an independently specified local upload journey; prove capture/campaign/replay and source-input protections.
- [x] Run appropriate race/vet/floor/build/browser gates, resolve review findings, publish, observe the specific CI run, and merge after passing checks.
- [x] Audit original requirements and current authoritative evidence for completion; keep the goal active if any required outcome remains unproven.

Completed: [PR #20](https://github.com/kaitoz11/reqfuzzy/pull/20), merge `70715c1`, after [CI run 42180327626](https://github.com/kaitoz11/reqfuzzy/actions/runs/42180327626) passed both Go jobs and browser acceptance. The [workflow audit](../../operator-workflow-audit.md) closes the initial tooling goal; broader corpus parity remains future work.
