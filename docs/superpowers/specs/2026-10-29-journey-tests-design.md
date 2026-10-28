# Stateful mutation tests and evidence

This implements the next gap in the active product goal: turn successful replay into an assessable stateful API test. Existing authored flows and CLI commands stay compatible.

## Test definition

`reqfuzzy flow test --project DIR --base-url URL --test tests.yaml --out RUN_DIR` reads a strict version-1 YAML definition inside the project:

```yaml
version: 1
name: transfer-amount
target:
  step: transfer
  location: json
  path: amount
observe_statuses: [201, 400, 422, 500]
verify: verify.yaml
cases:
  - id: negative
    action: set
    value: -10
  - id: missing
    action: remove
checks:
  - id: no-balance-increase
    phase: verify
    step: balance
    select: json
    path: balance
    op: lte
    variable: initial_balance
```

Cases have unique filename-safe IDs; `baseline` is reserved. Actions are `set`, `remove`, `append`, and `prepend`. A set may change a JSON scalar type, including null. Append/prepend require existing unique string values and string payloads; they never silently stringify a JSON number or collapse repeated fields. Remove requires an existing field. Header and query operations retain unrelated fields and encodings. Invalid definitions and mutation constructors fail before any target requests.

Checks select a step's `status`, scalar `json` path, or UTF-8 `body`, from `phase: flow|verify`. The right-hand side is exactly one of literal `value`, named `variable`, or `baseline: true` selecting the same observation from the baseline. Operators are `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `contains`, `not_contains`, and `matches`. Numeric comparison uses exact rational arithmetic, not float64. Missing observations/variables, incompatible types, and unsupported values are inconclusive, never a pass. Regexes compile during validation.

## Trial lifecycle and verdicts

Add optional initial variables to `flow.Runner` and seeded flow validation/loading. Each run deep-copies those values. A test trial uses a fresh actor-client cache, runs the main flow, then an optional verification flow with the same clients and the main flow's variables. The verification flow may refer to declared main-flow variables; references whose runtime value is missing still fail clearly.

Run one unchanged baseline, then each mutation in file order. The baseline must complete its main and verification flows and pass its checks; otherwise no mutations are sent and the result is inconclusive. Every case replays all prerequisites with fresh clients. A target HTTP status/extraction failure can be an observation if that target returned a response whose status is explicitly listed in `observe_statuses`. Verification still runs in that trial's session. Other execution failures, an unlisted target status, or failed verification make the trial inconclusive. This distinguishes an expected input rejection from expired authentication or a broken preparation flow.

A check failure is a user-defined invariant violation, not an automatic universal vulnerability classification. A valid trial is `pass` when all checks pass and `fail` when any check fails. An unassessable check makes that trial `inconclusive`. A campaign is `fail` if any valid case fails, otherwise `inconclusive` if any case is inconclusive, otherwise `pass`. Cancellation or evidence-write failure stops further requests and preserves partial results. Callbacks record each completed trial before another starts.

## Evidence and reconstruction

Flow traces gain response headers and a separate sent-request snapshot when the HTTP client supplies one. Prepared request snapshots remain available. Sent metadata includes the actual URL, Host, headers including jar cookies, and the bytes handed to the transport for these raw-request flows; it does not claim to capture TLS or HTTP framing.

`--out` must be a new private directory. Write a versioned `plan.json` before network execution, then a protected `baseline.json` and one case file as each trial completes, and `result.json` for the aggregate outcome. Files use mode 0600 and directories 0700. The recipe contains logical input fingerprints, test-file location, case IDs, and tool/runtime metadata. It does not copy credentials, hook source, or mutation values into the recipe.

Default trace artifacts redact Authorization/Cookie/Set-Cookie and secret-like JSON/query fields; omit opaque bodies while retaining their size and hash. A test may configure additional header names, query keys, and JSON paths under `redact`. Variable values and assertion operands are omitted from normal summaries. `--include-sensitive` explicitly writes full private traces for an operator who needs exact application messages. Redaction is best effort and documented, not a guarantee that every application's sensitive field is recognizable.

`reqfuzzy flow replay --project DIR --run RUN_DIR --case ID --base-url URL --out NEW_DIR` reconstructs the baseline and selected case with fresh sessions. It validates recipe version, test-file containment, case selection, and every current logical input hash before network execution. Changed project/flow/request/script/test inputs cause refusal; a newly edited test is run as a new test instead. The replay target remains explicit.

The CLI plans a conservative maximum request count before execution and refuses plans above `--max-requests` (default 1000). `--delay` spaces request preparation globally, before final signing. A finite sequential plan cannot exceed the declared upper bound. Existing overall/script deadlines still apply. Exit 0 means all checks passed, 3 means a valid invariant violation, 2 means inconclusive/canceled execution, and 1 means configuration/artifact setup failure. JSON output remains a single versioned document without trace secrets.

## Independent acceptance evidence

A local reference API creates a new account/session on login, exposes an initial balance, issues a changing single-use nonce, requires HMAC over the final transfer body, and exposes the resulting balance. Its secure mode rejects a negative amount; its deliberately vulnerable mode accepts it and increases the balance. A reference capture is generated from actual calls to that API. Tests must prove secure rejection still runs downstream verification, the vulnerable mode violates the balance invariant, an expired/invalid session is inconclusive, and every case obtains a fresh nonce/session. Artifact reconstruction must repeat the selected verdict and refuse drift before sending. This is controlled reference evidence, not a claim about an unprovided real-world target.
