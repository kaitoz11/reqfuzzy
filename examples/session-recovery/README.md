# Signed transfer with session recovery

This local journey uses the existing reference API with one-time transfer expiry. The first transfer returns 401 before changing balance; cookie-authenticated refresh rotates token/signing key and invalidates its old nonce. The journey obtains a new nonce, reapplies the mutation, signs again, and verifies the same account's balance.

Start the API from the repository root:

```sh
go run ./examples/stateful-tests/mock --refresh-once
```

In another terminal:

```sh
go build -o bin/reqfuzzy ./cmd/reqfuzzy
bin/reqfuzzy flow show --project examples/session-recovery
bin/reqfuzzy flow test --project examples/session-recovery --base-url http://127.0.0.1:8098 --out .reqfuzzy/recovered-secure --json
bin/reqfuzzy flow map --project examples/session-recovery --test tests.yaml --out .reqfuzzy/recovery-map.html
```

Secure mode exits 0: negative/missing amounts are rejected after recovery and balance remains 100. Restart the API with `--refresh-once --vulnerable-amounts` to exercise the intentional amount bug, then use a new output directory:

```sh
bin/reqfuzzy flow test --project examples/session-recovery --base-url http://127.0.0.1:8098 --out .reqfuzzy/recovered-vulnerable --json
bin/reqfuzzy flow replay --project examples/session-recovery --base-url http://127.0.0.1:8098 --run .reqfuzzy/recovered-vulnerable --case negative --out .reqfuzzy/recovered-replay --json
```

Both vulnerable run and replay exit 3. Sent amount −10 survives both attempts and the final balance becomes 110. `negative.json` records transfer visits 1/2, first status 401, the `refresh` decision, and mutation proof. Default evidence redacts credentials.

The bound is 7 requests per trial: session 1 + nonce 2 + transfer 2 + refresh 1 + verification 1. Baseline plus two cases therefore plans 21 requests; `--max-requests 20` refuses before traffic. The first account is fresh for each trial and reconstruction.

For persistent expiry, restart with `--refresh-once --expire-at-transfer`. Recovery cannot finish; the baseline reaches its limit, exits 2, and sends no mutation cases. A visit cap bounds work rather than turning an unfinished recovery into success.

The editor supports allowed routes, default next, visit limits, accepted status sets, optional extraction, and extraction status gates. It sends no requests. See [flow-control semantics](../../docs/flow-control.md).
