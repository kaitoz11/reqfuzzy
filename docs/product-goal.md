# Product goal and evidence

Goal: turn reqfuzzy into a scriptable tool for testing stateful API journeys.

The operator workflow is capture → infer/edit dependencies → script authentication and request preparation → replay valid state → morph a selected request → verify its effects → retain a repeatable test and evidence. Reqfuzzy is the implementation home; the archived Python kvar proposal is not a second implementation.

This implementation provides HAR import, conservative inference, authored sequential flows, scalar/raw variables, actor cookie isolation, final request hooks, response scripts, a CLI, and local signed-flow examples. PR #12 was merged into `feat/req-fuzzer` after user approval.

The integrated journey-test engine adds reusable mutation cases, exact typed checks, same-session verification after rejection, mutation-survival checks, private/redacted evidence, and fingerprinted reconstruction. Tests record actual HTTP traffic from an independent local reference API, import it, distinguish secure/vulnerable/session-invalid outcomes, reconstruct a case, and refuse input drift. Final code review approved the core fixes, and the actual CLI acceptance outcomes are recorded in [stateful reference evidence](acceptance/stateful-reference.md). PR #13 was retargeted and merged into `feat/req-fuzzer` after PR #12, following user approval.

The user delegated independent application selection. The subsequent [Juice Shop acceptance](acceptance/juice-shop.md) imported actual traffic from a pinned local third-party app and reproduced a negative order total using fresh accounts and dynamically bound IDs. The reusable project is `examples/juice-shop`. This closes the immediate need for an independent acceptance target; an operator-provided capture can be added when available.

PR #14 is merged and extends binding and conservative inference to whole URL segments. The Juice Shop example declares its short numeric IDs explicitly, so the dependency graph shows `add → update` and `login → checkout` without URL-changing hooks. Short or ambiguous IDs still require manual authoring.

PR #15 is merged and adds path-segment mutations and UTF-8 URL-encoded form binding, inference, and mutations. All five locations (`json`, `header`, `query`, `path`, `form`) support set/remove/append/prepend. Static target structure is checked before a campaign baseline or CLI comparison, and proof evaluates the actual sent segment/body, including media type and content encoding for forms. Review approved the final encoding fix; race tests, vet, the CLI build, and Go 1.24/stable CI passed. The development branch includes both slices at merge `624d38e`.

Named cookies extend binding and all four mutation actions to a sixth location, integrated in PR #16 at `ab3ffa1` after review and Go 1.24/stable CI. Response-cookie extraction and HAR response-header preservation support explicit and inferred `Set-Cookie` dependencies. Per-request edits filter the selected name from automatic cookies without mutating stored session state, client defaults, or custom transports; server cookie rotations still update the actor's jar. Proof checks observed named-cookie values, and ambiguous/malformed fields stop or remain unresolved. The signed reference example now declares its short session ID as a cookie dependency; short values still remain outside inference thresholds.

`flow map` adds offline visual authoring: actor lanes, execution order, all six dependency locations, main/verification cross-phase sources, target highlighting, and a step/binding/extraction inspector. Edits validate before export and preserve exact strings through the Go loaders. The browser cannot send requests or write project files. Actual browser checks exercised addition/reordering, cookie extraction drafts, broken campaign references, export/import, hostile labels, and desktop/narrow layouts with zero network requests; the stable CI job includes this coverage.

Integration agreement: the user authorized merging these and future reviewed changes with passing CI into `feat/req-fuzzer`. Continue under that standing approval rather than asking for each subsequent integration.

The complete goal remains unproven. These gaps still matter:

- Third-party acceptance now exists for Juice Shop's checkout API; broader application compatibility remains unproven.
- Mutation coverage needs additional PayInt-style payload/template operations and multipart dependencies/mutations. Path, form, and named cookie capabilities are implemented.
- More flexible flow control and payload/template breadth remain to be proved against realistic journeys. The visual authoring loop is implemented for both the reference and Juice Shop projects. Complete PayInt corpus parity and distributed execution are not prerequisites for the first useful tool.

No completion claim should rely on CI alone. It must demonstrate the operator workflow on an independent reference API with changing tokens/nonces, signing, rejected and accepted mutations, and downstream invariant checks; then validate it on an operator-provided capture when one is available.

Next delivery priority is flow-control and payload/template breadth. Prefer core capability over more acceptance variants for the already demonstrated journeys.
