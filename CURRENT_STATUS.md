# Current delivery status — 2026-10-30

The PayInt rework is implemented in **reqfuzzy**, using its existing Go runtime. This repository holds historical requirements and the delivery pointer; no separate Python kvar runtime is being built here.

## Integrated into reqfuzzy development

- HAR import and conservative response-to-request dependency inference for path segments, headers, query values, JSON scalars, and URL-encoded form fields.
- Authored sequential flows with extracted variables, actor sessions, and before/after JavaScript hooks for dynamic request preparation.
- CLI flow execution and set/remove/append/prepend mutations of path segments, headers, query values, JSON bodies, and UTF-8 URL-encoded form fields.
- Reusable mutation cases, downstream invariant checks, redacted evidence, and reconstruction of a selected case with fresh state.

The CLI ([PR #12](https://github.com/kaitoz11/reqfuzzy/pull/12)), journey campaigns/evidence ([PR #13](https://github.com/kaitoz11/reqfuzzy/pull/13)), path dependencies ([PR #14](https://github.com/kaitoz11/reqfuzzy/pull/14)), and path/form morphing ([PR #15](https://github.com/kaitoz11/reqfuzzy/pull/15)) are merged into `feat/req-fuzzer` after review and passing Go 1.24/stable CI. The latest merge is `624d38e`.

The user authorized these and future reviewed changes with passing CI to merge into `feat/req-fuzzer`. That approval persists; do not request it again for subsequent development integrations.

## Acceptance reached

The local reference API demonstrated cookie/token state, changing nonces, final-body signing, rejected mutations, and downstream balance checks. Independent acceptance now uses a pinned local OWASP Juice Shop v20.3.0: capture → import → fresh account/login → dynamic basket/item IDs → quantity mutation → checkout → persisted order check. Negative quantity produced total −19.90, and fresh-state reconstruction reproduced it. The acceptance commit is `95a3723`; the sibling worktree `../reqfuzzy-juice-shop` now starts the next slice on `feat/cookie-locations`.

There is enough evidence for the current delivery slice. Additional acceptance variants are not the immediate priority.

## Next product work, in order

1. Add named cookie binding/mutation support with correct session-jar behavior.
2. Provide a visual dependency view for inferred and authored API flows.
3. Extend flow control and payload/template breadth from realistic operator journeys.

The broader project goal remains active. Current runtime coverage does not yet provide full PayInt payload parity, named cookie/multipart inference, flexible flow control, or a visual flow editor. Detailed implementation plans and capability evidence live in reqfuzzy's `docs/` directory.
