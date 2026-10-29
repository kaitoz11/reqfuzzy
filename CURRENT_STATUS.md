# Current delivery status — 2026-10-30

The PayInt rework is implemented in **reqfuzzy**, using its existing Go runtime. This repository holds historical requirements and the delivery pointer; no separate Python kvar runtime is being built here.

## Available on feature branches

- HAR import and conservative response-to-request dependency inference for headers, query values, and JSON scalars.
- Authored sequential flows with extracted variables, actor sessions, and before/after JavaScript hooks for dynamic request preparation.
- CLI flow execution and mutation of headers, query values, and JSON bodies.
- Reusable mutation cases, downstream invariant checks, redacted evidence, and reconstruction of a selected case with fresh state.

The CLI is in [PR #12](https://github.com/kaitoz11/reqfuzzy/pull/12). Journey campaigns and evidence are in [PR #13](https://github.com/kaitoz11/reqfuzzy/pull/13), stacked on it. Both remain draft rather than integrated into `feat/req-fuzzer`; their latest CI checks passed.

## Acceptance reached

The local reference API demonstrated cookie/token state, changing nonces, final-body signing, rejected mutations, and downstream balance checks. Independent acceptance now uses a pinned local OWASP Juice Shop v20.3.0: capture → import → fresh account/login → dynamic basket/item IDs → quantity mutation → checkout → persisted order check. Negative quantity produced total −19.90, and fresh-state reconstruction reproduced it. This acceptance work is on `feat/juice-shop-acceptance` in the local sibling worktree `../reqfuzzy-juice-shop`.

There is enough evidence for the current delivery slice. Additional acceptance variants are not the immediate priority.

## Next product work, in order

1. Integrate the existing CLI and journey slices into reqfuzzy's development branch.
2. Add explicit dynamic path bindings and dependency metadata. Juice Shop currently needs scripts for item/basket IDs, and those dependencies are invisible in the flow graph.
3. Expand mutation and binding locations toward PayInt requirements, starting with cookie and form fields.
4. Provide a visual dependency view for inferred and authored API flows.

The broader project goal remains active. Current runtime coverage does not yet provide full PayInt payload parity, path/cookie/form/multipart inference, flexible flow control, or a visual flow editor. Detailed implementation plans and capability evidence live in reqfuzzy's `docs/` directory.
