# Generated payload acceptance

The existing signed session-recovery project now contains reusable numeric and text payload definitions. Its financial library reads `-1`, `0`, and `2` from JSONL and applies exact multiplication to the current amount. Its text definition combines literal file values with the current nonce and base64-encodes the result before signing.

The native CLI run with `payload-tests.yaml` against the local vulnerable reference API returned exit 3: baseline passed, `finance-000001` violated the balance invariant, and the other generated cases passed. Every case retained its source/index metadata, reached transfer visit 2 after refresh, and recorded verified mutation proof. Reconstruction of `finance-000001` returned the same verdict with fresh state. Private artifacts are `.reqfuzzy/payload-delivery-20261106/` and `.reqfuzzy/payload-replay-20261106/`; planned request bounds were 28 and 14.

CLI integration tests additionally prove secure contained library/wordlist loading, generated-case reconstruction, refusal after source-byte drift before traffic, no target/hook execution during planning, and fresh encoded nonce values on each recovery attempt. Typed expansion covers null, booleans, strings, huge integers, ranges, stable IDs, and exact deduplication.

Review regressions reject null encoder declarations and prevent compiled cases from retaining expanded static payload copies. A targeted 1,000-case shared-render reproduction dropped from roughly 210 MiB retained heap before the fix to no measurable additional retained payload heap in review. Aggregate definition and per-file/value limits remain enforced.

Browser checks protect variables referenced only by payload templates while keeping operands out of the map. Go race/vet/floor checks and browser acceptance passed locally; CI remains the integration gate.
