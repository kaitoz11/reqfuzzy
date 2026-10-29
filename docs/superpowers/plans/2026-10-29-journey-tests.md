# Stateful journey tests implementation plan

Use the approved active-goal scope and `executing-plans` inline. Follow the design at `docs/superpowers/specs/2026-10-29-journey-tests-design.md` and request a read-only code review before delivery.

- [x] Add seeded flow validation/run variables and sent/response metadata with local session/trace tests. Retain current APIs.
- [x] Extend mutation construction with null set, remove, append, and prepend, protecting repeated fields and JSON scalar types. Exercise real request bytes.
- [x] Add strict campaign definitions, exact typed assertion evaluation, baseline/case orchestration, shared-session verification, and partial-result recording. Prove secure/vulnerable/invalid-session outcomes against an independently specified reference API.
- [x] Add protected evidence artifacts, redaction and logical fingerprints; preserve partial trials and refuse overwrites.
- [x] Connect `flow test` and `flow replay` to the CLI with input preflight, limits, output/exit contracts, and end-to-end reconstruction/drift tests.
- [x] Extend the runnable reference example, document the operator workflow, update the product-goal audit, and run race/vet/Go-1.24/build checks.
- [x] Review substantive findings, verify the final source and artifact behavior, and publish a draft change stacked on PR #12. Keep the overall goal active while required capabilities remain unproved.

Delivery: PR #13 was retargeted and merged into `feat/req-fuzzer` after PR #12, following user approval. Review fixes, local race/vet/Go-1.24/build checks, actual CLI reference outcomes, artifact privacy, binary provenance, and reconstruction are verified. The full product goal remains active.
