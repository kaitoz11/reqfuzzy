# Payload/template implementation plan

> Execute inline with the existing superpowers execution/TDD/review workflow and standing integration approval.

**Goal:** Generate reusable deterministic cases and morph values from fresh API state without handwritten case duplication.

**Spec:** `docs/superpowers/specs/2026-11-06-payload-templates-design.md`.

**Architecture:** Campaign owns bounded source expansion and safe template evaluation; flow owns selected-value access and exact JSON arithmetic. CLI owns contained file loading, fingerprints, offline planning, and source metadata. The map preserves payload-variable constraints without embedding values.

- [x] Write failing behavior tests for typed source expansion, files/libraries/ranges, stable IDs, bounded malformed inputs, runtime base/variable rendering, and exact arithmetic. Implement separate source/template/decimal helpers with strict validation.
- [x] Connect resolved mutations to campaign preflight/run and declare renderer variable dependencies before the target. Retain per-visit proof and source/index metadata.
- [x] Add contained CLI resolver/fingerprints and `flow plan`; prove no target/hook execution, bounded counts, generated-case reconstruction, and input drift refusal.
- [x] Extend map reference metadata for payload variables; add reusable finance/text examples and operator documentation.
- [ ] Complete meaningful race/vet/floor/build/browser checks, read-only review, and actual existing-journey acceptance. Publish, poll the specific CI run, and merge after passing checks. Update status and leave broader multipart work active.

Local race/vet/Go-1.24/build/browser gates and native generated-case run/replay passed. Review's memory and null-encoder findings were fixed and verified. Publication/CI/integration is the remaining delivery step.
