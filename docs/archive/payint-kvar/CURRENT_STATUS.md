# Current delivery status — 2026-11-12

The initial scriptable API-testing tooling is delivered in **reqfuzzy**, using its existing Go runtime. This repository remains the historical requirements/delivery pointer. The current development revision is `70715c16d8f356972c086c058cb7a5312f48875d` on `feat/req-fuzzer` after [PR #20](https://github.com/kaitoz11/reqfuzzy/pull/20).

## Delivered operator workflow

Capture/import → infer or visually author dependencies → script preparation/authentication/signing → run with fresh state → morph a selected request → check downstream effects → retain evidence and reconstruct a case.

- Offline HAR import and conservative response-scalar/Set-Cookie inference, with explicit authoring for short/ambiguous values.
- Ten binding/mutation locations: JSON, header, query, path, URL-encoded form, named cookie, multipart text, file bytes, full filename, and part media type. Set/remove/append/prepend are supported; JSON also supports exact add/multiply.
- Fresh trial/actor sessions, changing nonce/token/key state, before/after JavaScript hooks, binary body representations, and byte SHA/HMAC signing.
- Declared branching, bounded repetition/recovery/polling, optional/status-gated extraction, every-attempt mutation proof, occurrence-aware assertions, and checked request budgets.
- Reusable typed/file/range payloads, shared libraries, fresh-state templates/encoders, stable generated IDs, and offline planning.
- Offline visual mapping/authoring with actor lanes, data/control edges, journey/verification editors, validation and export. The browser sends no requests.
- Same-session downstream checks, explicit pass/fail/inconclusive outcomes, protected/redacted evidence, source fingerprints, and fresh-state reconstruction.

The [operator-workflow audit](https://github.com/kaitoz11/reqfuzzy/blob/feat/req-fuzzer/docs/operator-workflow-audit.md) maps the requirements to implementation and executable evidence. The runtime and examples are in `../reqfuzzy` on `feat/req-fuzzer`; the linked `../reqfuzzy-juice-shop` checkout also contains the merged implementation. Build from that repository with `go build -o .reqfuzzy/bin/reqfuzzy ./cmd/reqfuzzy`.

## Review and integration

PRs [#12](https://github.com/kaitoz11/reqfuzzy/pull/12)–[#20](https://github.com/kaitoz11/reqfuzzy/pull/20) are integrated into `feat/req-fuzzer`. The final multipart/binary change passed independent code review and [Go 1.24/stable CI](https://github.com/kaitoz11/reqfuzzy/actions/runs/42180327626), including full race tests, vet, build, and actual browser checks. Review corrected a named-form-field proof bug: changing a part's disposition to attachment now makes the named mutation unassessable rather than verified.

The user authorized these and future reviewed changes with passing CI to merge into `feat/req-fuzzer`. That standing approval persists. Development integration does not authorize a release or merge into `main`.

## Application evidence

The signed reference API and recovery journey demonstrate fresh sessions/nonces, rotating token/key state, final-byte signing, rejected mutations, downstream balance checks, every-attempt proof, request exhaustion, generated payloads, and reconstruction.

Independent acceptance uses pinned local OWASP Juice Shop v20.3.0: actual capture → import → fresh signup/login → dynamic basket/item IDs → quantity mutation → checkout → persisted order check. Negative quantity produced total −19.90 and fresh-state reconstruction reproduced it. The user delegated target selection; no operator-provided capture was available.

The [multipart project](https://github.com/kaitoz11/reqfuzzy/blob/feat/req-fuzzer/examples/multipart/README.md) adds actual captured/imported uploads, binary file binding/signing, a binary response hook, generated filename mutations, and downstream checks. Secure mode rejects unsafe names; vulnerable mode accepts them and fails the invariant with verified proof. Native CLI campaign/replay artifacts are under `.reqfuzzy/upload-delivery-20261106/` and `.reqfuzzy/upload-replay-20261106/` in reqfuzzy, with bounds nine/six. The local fixture was stopped. Browser checks passed with zero network requests.

Open `../reqfuzzy-juice-shop/.reqfuzzy/upload-flow-preview.html` for the upload editor, `flow-map-preview.html` for Juice Shop, or `recovery-flow-preview.html` for conditional recovery. Generate an editor with `flow map --project examples/multipart --test tests.yaml --out FILE` from reqfuzzy.

## Scope after delivery

The initial goal—turn reqfuzzy into a scriptable tool for testing stateful API journeys—has implementation and application evidence for every audited requirement. There is no remaining required feature in that delivery plan.

Broader application compatibility, full legacy PayInt corpus/DSL parity, live proxy capture, distributed/concurrent execution, and complete Postman API/collection compatibility remain future projects. This delivery provides the required scripting/flow workflow and operator-authored assertions; it does not claim universal vulnerability detection or production compatibility with every API. A release into `main` remains a separate decision.

## Local wrap-up — 2026-11-12

The main reqfuzzy checkout was advanced to the integrated development revision after its older local demo edit was committed to `archive/local-fuzzing-demo-2026-11-12`. Unpublished legacy request work is preserved on `archive/legacy-request-json-2026-11-12` with captured identifiers and demo targets replaced by placeholders; the original local commits remain available.

This planning repository's origin points to `kaitoz11/reqfuzzy`, with local `main` publishing specifically to `archive/payint-kvar`. That branch preserves the complete planning history. Its documentation snapshot is archived under `docs/archive/payint-kvar` in reqfuzzy. Generated private captures/evidence remain ignored local artifacts.
