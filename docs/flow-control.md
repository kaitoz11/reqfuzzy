# Conditional journeys and bounded repetition

Flows retain ordered execution and one visit per step by default. Declare extra routes and visit limits when a response needs recovery or polling:

```yaml
name: polling
steps:
  - id: poll
    request: poll
    expect_statuses: [200, 202]
    max_visits: 3
    routes: [poll]
    after_response: decide
    extract:
      - {name: result_id, json: id, on_status: [200]}
  - id: read
    request: read
    bind:
      - {location: query, path: id, variable: result_id}
```

`hooks/decide.js`:

```javascript
function afterResponse(ctx) {
  if (ctx.response.status === 202) ctx.flow.next("poll");
}
```

A ready response falls through to `read`. A third pending response requests a fourth visit, which fails before another request is sent. Exhaustion is an execution error, never a successful poll.

## Routes and visit limits

- Omitted `next` means the next step in the definition. `next: name` chooses a different default; `next: ""` ends the flow.
- `routes` lists additional destinations a response hook may choose. Include `""` to permit `ctx.flow.stop()` where ending is not already the default.
- `max_visits` is an integer from 1 to 1,000,000 and defaults to 1. Every entered visit counts. Limits belong to one flow run; verification has its own limits.
- `expect_statuses` accepts a nonempty unique list of HTTP codes and is mutually exclusive with `expect_status`. Include recoverable responses such as 401 or 202 if their response hook must run.

All named destinations must exist in the same flow; routes cannot jump between journey and verification. A backward jump retains the actor's current client/jar and variables, creates a fresh request, rebinds current state, reapplies any selected mutation, and signs afterward. The CLI's `--delay` applies on every visit.

Response hooks receive `ctx.flow.step`, `.visit` (one-based), and `.limit`. `ctx.flow.next(name)` selects a declared/default destination; `ctx.flow.stop()` selects an allowed end. The last successful choice wins. A failed synchronous callback discards staged navigation and variable edits. Request hooks receive visit metadata but cannot navigate. Go callbacks can use `flow.CurrentVisit(ctx)`, `flow.CheckNext(ctx, name)`, and `flow.SetNext(ctx, name)`.

Bindings still refer to variables declared earlier in the definition. Branches may skip a producer; a missing runtime value then fails before sending the dependent request. Scripts can update an existing declared variable during recovery, as the session example updates `token` and `signing_key`.

## Conditional extraction and fresh outputs

Use `on_status: [201]` to extract only when that status was received. This supports error responses with text or empty bodies. Use `optional: true` when a field may be absent/null within valid JSON, or a response cookie may be absent. Optional extraction still rejects malformed/duplicate-key JSON, wrong scalar types, and ambiguous cookies.

Each step's declared extraction/provided variables are cleared at the start of every visit. A missing second result therefore cannot reuse a successful first result. A `provides` declaration must be fulfilled again by the current visit; undeclared script state can be retained explicitly through `ctx.vars`.

## Campaigns and evidence

The selected mutation applies on **every executed visit** to its logical target. Proof checks every sent attempt, so a hook restoring only the second attempt makes the case inconclusive. The campaign's target status is the last target response. Intermediate recoverable statuses follow the flow expectations; the final target status must still belong to `observe_statuses`. Missing targets and control errors remain inconclusive. A comparison also refuses a baseline that skipped its target.

Checks choose an occurrence with `visit`:

```yaml
checks:
  - {id: final-status, step: transfer, select: status, op: eq, value: 201, visit: last}
  - {id: first-expiry, step: transfer, select: status, op: eq, value: 401, visit: 1}
  - {id: no-server-error, step: transfer, select: status, op: lt, value: 500, visit: all}
```

The default is `last`, preserving the meaning of existing one-visit checks. A numbered selector chooses that ordinal. `all` checks each executed occurrence; an unassessable observation makes the check inconclusive. Baseline comparisons pair numbered/all visits by ordinal and last visits with each other; a missing matching baseline occurrence is inconclusive. Named-variable operands use final trial variables. Results record the representative visit and `visits_checked`.

The planned request bound is the sum of declared visit limits. Campaign planning adds main and verification bounds and multiplies by baseline plus cases. Comparison planning accounts for both runs. Checked arithmetic and `--max-requests` reject oversized plans before traffic (default 1000). Branching may use fewer requests. Overall/script deadlines remain in effect.

CLI summaries and protected traces retain every sent visit, response, ordinal, resolved next step, and decision source. `flow show` exposes routes, limits, and accepted statuses. The offline editor renders default/script control edges separately from data dependencies and preserves the configuration on export.

Try [session recovery](../examples/session-recovery/README.md) for a signed request that expires, refreshes its token/key, obtains a new nonce, and is re-mutated and re-signed before downstream verification.
