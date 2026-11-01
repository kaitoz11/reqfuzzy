# Session-recovery acceptance

The reference API's `--refresh-once` mode expires the first transfer before changing balance. Cookie-authenticated refresh rotates token/signing key and invalidates the old nonce. The runnable `examples/session-recovery` project follows declared routes to refresh, issue another nonce, reapply the mutation, and sign the new attempt.

| Scenario | Result | Evidence |
|---|---|---|
| Secure API | exit 0 / pass | Negative and missing amounts are rejected after recovery; balance stays 100. |
| Vulnerable API | exit 3 / fail | Both transfer attempts contain −10; statuses 401 then 201; verified proof and balance 110. |
| Reconstructed negative | exit 3 / fail | Fresh session/recovery/nonce repeats the final invariant violation. |
| Permanently expired API | exit 2 / inconclusive | Baseline reaches its visit limit after six requests; no cases are sent. |
| Max requests 20 | configuration refusal | Planned 21-request campaign is rejected before target traffic. |

The integration tests exercise all scenarios through the CLI and actual local HTTP. The built CLI binary also exercised the vulnerable campaign and reconstruction. Private artifacts are under `.reqfuzzy/recovery-delivery-20261101/` and `.reqfuzzy/recovery-delivery-replay-20261101/`. The negative trace records transfer visits 1/2, first route `refresh` from the response hook, second status 201, and `mutation_proof: verified`. The final balance is 110; normal credential redaction remains in effect.

Runner regressions prove self-poll termination/exhaustion, stale optional/provided-output removal, script navigation atomicity, invalid route/limit preflight, and skipped comparison/mutation targets. Campaign regressions prove last/numbered/all observation selection, missing matching baseline occurrences, and refusal when only the second mutation is erased. Status-gated extraction recovers from text error bodies while optional JSON still rejects malformed or duplicate-key data.

Browser acceptance edits visit limits, status sets, defaults/routes, optional fields and extraction gates, round-trips exports through the Go loader, and blocks invalid destinations. Actual per-keystroke typing is covered for both status-list controls.
