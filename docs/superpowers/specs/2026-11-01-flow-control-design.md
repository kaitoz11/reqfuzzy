# Script-controlled, bounded journeys

Extend the existing flow engine, campaign/evidence loop, and visual editor. Existing ordered flows retain one visit per step and their current status/extraction behavior. Go 1.24 and the standing reviewed/passing-CI development integration policy remain requirements.

## Definition and script API

A step may declare `max_visits` (1 by default, explicit range 1–1,000,000), `next` (omitted: next definition; empty string: end), `routes` (additional allowed script destinations, with an empty string permitting stop), and `expect_statuses` (nonempty unique HTTP statuses, mutually exclusive with `expect_status`). All named destinations must exist in the same flow. Extractions may set `on_status: [200]` to run only on chosen statuses, or `optional: true` to leave absent/null JSON scalars or absent cookies unset. JSON must still be valid and unambiguous; wrong types still fail. Status gating supports recovery responses with text/empty bodies without pretending malformed data is JSON. Each visit clears that step's declared outputs before bindings/hooks, preventing stale optional or provided values. Script state outside declared outputs persists normally.

`ctx.flow.step`, `.visit`, and `.limit` identify the current visit in request and response hooks. Response hooks may call `.next("step")` or `.stop()`; the default destination and declared routes are the only choices. The last choice wins. Navigation edits commit only when the synchronous response callback succeeds, alongside existing staged variable edits. Go callbacks can use `flow.CurrentVisit`, `flow.CheckNext`, and `flow.SetNext` with the request context. Navigation is unavailable in request scripts; forward branching can skip requests after an earlier response.

The runner preserves actor clients and current variables across visits, makes a fresh raw request each time, rebinds state, reapplies the selected mutation on every target visit, and signs after mutation. It rejects the next visit before sending when a limit is exhausted. Exhaustion is an execution/control error, never successful completion. A mutation target skipped by routing is an error. Every sent visit records its ordinal and resolved next-step decision/source.

## Campaign and evidence semantics

The maximum requests per trial is the sum of all step visit limits in main and verification flows, independent of the path taken. CLI planning uses checked integer arithmetic and multiplies this bound by baseline plus cases before target traffic. Replay uses the same definitions and fingerprints.

The campaign observes the last target response, verifies mutation survival on every executed target visit, and remains inconclusive for missing targets or control failures. Recoverable intermediate statuses must be accepted by the flow; final statuses still require campaign `observe_statuses`. Baseline status configuration must intersect the observed statuses. All traces retain intermediate responses and decisions.

Checks add `visit` selecting `last` (default), a positive ordinal, or `all`. A baseline operand uses the matching selected ordinal; a missing matching occurrence is inconclusive. All-visit checks assess every executed occurrence and report the selected/worst visit and count assessed; any unassessable observation makes the check inconclusive. Named variable operands continue to use final trial variables. Existing single-visit checks remain equivalent.

## Authoring, example, and proof

CLI summaries, evidence, `flow show`, and the HTML editor expose visits, limits, accepted statuses, and default/script control routes. The editor validates destinations, preserves optional extraction fields and limits on export, and draws branching/backward/self control edges separately from data edges. It keeps existing campaign references valid.

Extend the local signed reference API with one-time expiry and cookie-authenticated refresh that rotates token/key and invalidates the old nonce. Add a runnable recovery project: session → nonce → transfer(401) → refresh → nonce → transfer → verification. Prove refreshed signing, fresh nonces, mutations on both attempts, secure rejection versus vulnerable balance increase, repeatable replay, and a hard limit when recovery never succeeds. Polling tests additionally prove self-routes, termination, and stale optional/provided-output handling. Preserve existing API modes and examples.

Complete focused regressions, the existing race/vet/Go-1.24/build gates, browser control editing, and read-only review before CI/integration. The broader payload/template work remains active.
