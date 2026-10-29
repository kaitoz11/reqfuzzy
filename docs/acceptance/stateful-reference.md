# Stateful reference acceptance evidence

The local acceptance API is independently specified in `internal/reference`: each login creates a fresh account with balance 100; transfer requires an authenticated cookie/token, HMAC over the final body, and an unexpired single-use nonce. Secure mode rejects nonpositive or malformed amounts. Its explicit vulnerable mode accepts a negative amount and increases the balance.

The actual CLI binary was exercised against all three modes, using `examples/stateful-tests` and private run directories:

| Mode | CLI exit | Outcome | Evidence |
|---|---:|---|---|
| Secure | 0 | pass | Four mutation cases rejected; verification still reads balance 100. |
| Vulnerable amounts | 3 | fail | Negative amount -10 survives to the sent message; verification reads balance 110 against initial 100. |
| Replay negative | 3 | fail | Fresh baseline/session/nonce reconstructs the same invariant violation. |
| Expired transfer session | 2 | inconclusive | Baseline target returns an unlisted 401; no mutation cases are sent. |

Artifact inspection checked mode-0600 files, default credential redaction, a captured negative sent body, and the downstream balance. Artifacts remain under ignored `.reqfuzzy/` directories; they are not published as target data. Build provenance records runtime information and a binary digest when readable, even when the Go build omits VCS settings.

The executable integration test `TestActualCapturedJourneyCampaignEvidenceAndReplay` also starts from a HAR recorded through actual HTTP calls to the reference API. It imports the capture, authors the main and verification flows, evaluates secure/vulnerable outcomes, reconstructs a selected case, and rejects a changed hook before traffic. `TestJourneyRequestBudgetRejectsBeforeTraffic` covers the planning cap.

Additional focused regressions protect interpretation rather than just command success:

- Opposite JSON booleans compare as booleans; numeric checks retain exact digits.
- A hook that erases the mutation makes the case inconclusive.
- Forced object keys and array-element deletion share consistent mutation/proof semantics.
- Request-body inspection before middleware replacement is not counted as a send; the actual RoundTrip body is captured.
- Unsupported or no-op configured redactions omit the body instead of leaving the original value.
- Stream/middleware body replacement cannot use a stale request-byte cache as sent evidence.

This is controlled reference acceptance. It proves the implemented operator loop and known failure distinctions, not compatibility with an unprovided real-world application. The broader product goal remains active; see `docs/product-goal.md` for remaining capability and integration gaps.
