# Stateful journey tests implementation plan

Use the approved active-goal scope and `executing-plans` inline. Follow the design at `docs/superpowers/specs/2026-10-29-journey-tests-design.md` and request a read-only code review before delivery.

- [ ] Add seeded flow validation/run variables and sent/response metadata with local session/trace tests. Retain current APIs.
- [ ] Extend mutation construction with null set, remove, append, and prepend, protecting repeated fields and JSON scalar types. Exercise real request bytes.
- [ ] Add strict campaign definitions, exact typed assertion evaluation, baseline/case orchestration, shared-session verification, and partial-result recording. Prove secure/vulnerable/invalid-session outcomes against an independently specified reference API.
- [ ] Add protected evidence artifacts, redaction and logical fingerprints; preserve partial trials and refuse overwrites.
- [ ] Connect `flow test` and `flow replay` to the CLI with input preflight, limits, output/exit contracts, and end-to-end reconstruction/drift tests.
- [ ] Extend the runnable reference example, document the operator workflow, update the product-goal audit, and run race/vet/Go-1.24/build checks.
- [ ] Review substantive findings, verify the final source and artifact behavior, and publish a draft change stacked on PR #12. Keep the overall goal active while required capabilities remain unproved.
