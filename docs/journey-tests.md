# Stateful mutation cases, checks, and evidence

`flow compare` shows two executions. `flow test` evaluates reusable cases against explicit application rules. It replays prerequisites for every case, signs after mutation, and can run a verification flow in the same session even when the tested request is rejected.

## Try the reference API

Build `go build -o bin/reqfuzzy ./cmd/reqfuzzy`. Start the independent local reference API:

```sh
go run ./examples/stateful-tests/mock
```

Then run its test definition:

```sh
bin/reqfuzzy flow test --project examples/stateful-tests --base-url http://127.0.0.1:8098 --out .reqfuzzy/runs/secure --json
```

The secure reference rejects negative, missing, null, and text amounts. Verification still reads the balance after each rejection. All checks pass and the command exits 0.

Stop that server and restart it with `--vulnerable-amounts`. Use a new output directory:

```sh
go run ./examples/stateful-tests/mock --vulnerable-amounts
bin/reqfuzzy flow test --project examples/stateful-tests --base-url http://127.0.0.1:8098 --out .reqfuzzy/runs/vulnerable --json
```

The negative case now increases the account balance from 100 to 110. The configured invariant fails and the command exits 3. This demonstrates a known intentional bug in a controlled API; it is not evidence about an unprovided real-world target. The test suite also records a HAR from actual calls to this API and proves import → authored test → verification → evidence → reconstruction.

`--expire-at-transfer` simulates session failure at the tested request. Its response is outside the configured observed statuses, so the result is inconclusive (exit 2), rather than a pass or finding.

## Definition

A version-1 `tests.yaml` file belongs inside the project. `target` names an existing step, location (`json`, `header`, `query`), and path. `cases` supplies unique safe IDs and an action:

| Action | Behavior |
|---|---|
| `set` | Set/add a scalar. JSON preserves number digits and can change types, including null. |
| `remove` | Remove an existing field; no value is allowed. Missing fields are a mutation error. |
| `append` / `prepend` | Combine a string payload with an existing unique string. JSON numbers and repeated headers/query keys are rejected. |

Ambiguous duplicate-key JSON is rejected for structural mutations. Explicit raw Go hooks remain available for deliberate parameter-pollution experiments.

JSON mutation addresses use literal fields and array indices, with escaping for special key characters. SJSON forced-object-key syntax such as `:0` is resolved consistently for mutation and proof. Query selectors, modifiers, and wildcard expressions are rejected as mutation addresses. Each mutation validates its immediate postcondition before sending, so a library no-op cannot silently become a passing case. Array deletion is validated against the complete resulting parent array, accounting for shifted indices. Check selectors remain GJSON expressions.

Target initialization occurs before mutation, so an explicit Host set reaches the server while the selected network origin stays fixed. Host removal and Content-Length/Transfer-Encoding mutations are rejected because the normal HTTP transport manages those fields. A case also checks that the selected mutation survives final hooks and reaches the sent application request. If a refresh/signing hook erases the mutation, the result is inconclusive rather than a misleading pass.

For an intentional opaque body transformation, such as target-specific encryption, set `target.allow_transform: true`. Artifacts then record `mutation_proof: transformed` and the pre-hook mutation stage. The tool cannot automatically prove logical equivalence through arbitrary encryption; use independent downstream checks to establish the effect. Ordinary signing hooks that leave the target field intact need no opt-in.

`observe_statuses` explicitly lists target HTTP responses that may be assessed. An unlisted response such as an expired-session 401 or rate-limited 429 is inconclusive unless the operator deliberately includes it for that test. Prerequisite, transport, hook, or unrelated downstream failures are also inconclusive. Baseline execution and checks must succeed before any mutation case is sent.

`verify: verify.yaml` names a separate flow. It can bind variables declared by the main flow and shares that trial's actor clients and cookies. A baseline and each mutation have separate fresh sessions. If verification needs a variable the rejected request never produced, that trial is inconclusive; use verification requests independent of successful mutation output where possible.

## Checks

Each check has an ID, `phase: flow|verify`, step, selector (`status`, scalar `json` path, or UTF-8 `body`), and operator. Its expected operand comes from exactly one of `value`, `variable`, or `baseline: true`. A baseline operand selects the same step/field in the baseline, helping avoid false differences from unrelated volatile fields.

```yaml
checks:
  - id: no-balance-increase
    phase: verify
    step: balance
    select: json
    path: balance
    op: lte
    variable: initial_balance
```

Operators are `eq`, `ne`, `lt`, `lte`, `gt`, `gte`, `contains`, `not_contains`, and `matches`. Ordered comparisons require numbers and use exact rational arithmetic. Numeric operands are bounded to 4096 characters and exponent magnitude 10000 to keep evaluation finite. Regex checks require a literal string pattern compiled before execution. Missing observations, duplicate-key JSON, incompatible operand types, and unsupported precision are inconclusive.

An assessed case is `pass` when every check passes and `fail` when a configured invariant is violated. If any required check cannot be assessed, that case is inconclusive. Any valid failed case makes the aggregate result fail; otherwise any inconclusive case makes it inconclusive. These are user-defined test verdicts, not a universal automatic vulnerability classification.

## Artifacts and reconstruction

`--out` must name a new directory. It is created with mode 0700; JSON artifacts use mode 0600:

- `plan.json` records the test-file location, case IDs, logical input SHA-256 hashes, target, and runtime/build metadata.
- `baseline.json` and each `<case>.json` record the completed trial, pre-hook mutation/prepared/sent request metadata, response metadata, body sizes/hashes, and check outcomes.
- `result.json` records the aggregate result and interruption status.

Each trial is written before the next begins. A baseline failure, cancellation, or write failure leaves partial evidence and stops the relevant work. Sent metadata includes jar cookies and actual URLs when supplied by the HTTP client, with its internal controls removed. Body tracing observes the actual HTTP RoundTrip request after client middleware, so earlier body inspection does not count as a send. It records up to 16 MiB from the supplied Body. A later replacement, multiple consumed sources, or incomplete/over-limit body is marked unavailable. An unavailable body has no invented hash or size, even in sensitive mode. Prepared-cache snapshots are labeled separately. Body hashes describe the original captured bytes; default JSON views are redacted and reserialized. This is application HTTP evidence, not a TCP/TLS or framing capture.

Default artifacts redact common credential, API-key, and signature headers and secret-like JSON/query keys; non-JSON and ambiguous bodies are omitted while retaining hashes. A configured matching path whose replacement cannot be verified also causes that body to be omitted. Add target-specific policy when needed:

```yaml
redact:
  headers: [X-Customer-Key]
  query_keys: [accountNumber]
  json_paths: [customer.account_number]
```

Automatic redaction is best effort. `--include-sensitive` explicitly stores unredacted headers and exact body bytes as base64 in the private artifacts. Review artifacts before sharing them. Normal stdout/JSON summaries omit raw messages, variables, and assertion operands.

Reconstruct a selected case with fresh authentication and nonces:

```sh
bin/reqfuzzy flow replay --project examples/stateful-tests --base-url http://127.0.0.1:8098 --run .reqfuzzy/runs/vulnerable --case negative --out .reqfuzzy/runs/reproduced --json
```

Replay verifies all logical project, request, flow, test, and referenced script hashes before target traffic. It refuses drift. After editing a test or hook, use a new `flow test` run instead. The target remains explicit so a recorded recipe cannot silently select a host. The recipe does not copy credentials, mutation values, or script source; it requires the original project. Runtime session bytes are expected to change; reconstruction repeats the case and its rules rather than resending stale authenticated messages.

`--max-requests` (default 1000) rejects a plan whose conservative baseline-and-case upper bound is too large. `--delay` spaces request preparation before final signing. Overall and script deadlines still apply. Exit codes: 0 pass, 3 valid invariant violation, 2 inconclusive/canceled execution, 1 configuration or artifact setup error.
