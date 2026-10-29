# Current delivery status — 2026-10-30

The PayInt rework is implemented in **reqfuzzy**, using its existing Go runtime. This repository holds historical requirements and the delivery pointer; no separate Python kvar runtime is being built here.

## Integrated into reqfuzzy development

- HAR import and conservative response-to-request dependency inference for headers, query values, and JSON scalars.
- Authored sequential flows with extracted variables, actor sessions, and before/after JavaScript hooks for dynamic request preparation.
- CLI flow execution and mutation of headers, query values, and JSON bodies.
- Reusable mutation cases, downstream invariant checks, redacted evidence, and reconstruction of a selected case with fresh state.

The CLI ([PR #12](https://github.com/kaitoz11/reqfuzzy/pull/12)) and journey campaigns/evidence ([PR #13](https://github.com/kaitoz11/reqfuzzy/pull/13)) are now merged into `feat/req-fuzzer` after user approval. Both had passing Go 1.24/stable CI. PR #13's merge is `619a0f8`.

## Acceptance reached

The local reference API demonstrated cookie/token state, changing nonces, final-body signing, rejected mutations, and downstream balance checks. Independent acceptance now uses a pinned local OWASP Juice Shop v20.3.0: capture → import → fresh account/login → dynamic basket/item IDs → quantity mutation → checkout → persisted order check. Negative quantity produced total −19.90, and fresh-state reconstruction reproduced it. The acceptance commit is `95a3723`; the sibling worktree `../reqfuzzy-juice-shop` now continues on `feat/path-dependencies`.

There is enough evidence for the current delivery slice. Additional acceptance variants are not the immediate priority.

## Next product work, in order

1. Integrate [PR #14](https://github.com/kaitoz11/reqfuzzy/pull/14): explicit dynamic path bindings and conservative path inference are implemented, reviewed, and have passing Go 1.24/stable CI. Juice Shop's item/basket IDs are visible graph edges instead of URL hooks.
2. Expand mutation and binding locations toward PayInt requirements, starting with path mutations, cookie and form fields.
3. Provide a visual dependency view for inferred and authored API flows.

The broader project goal remains active. Current runtime coverage does not yet provide full PayInt payload parity, cookie/form/multipart inference, flexible flow control, or a visual flow editor. Detailed implementation plans and capability evidence live in reqfuzzy's `docs/` directory.
