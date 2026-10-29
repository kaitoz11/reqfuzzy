# Product goal and evidence

Goal: turn reqfuzzy into a scriptable tool for testing stateful API journeys.

The operator workflow is capture → infer/edit dependencies → script authentication and request preparation → replay valid state → morph a selected request → verify its effects → retain a repeatable test and evidence. Reqfuzzy is the implementation home; the archived Python kvar proposal is not a second implementation.

The integrated development branch (`feat/req-fuzzer`) provides HAR import, conservative inference for headers/query/JSON, authored sequential flows, scalar/raw variables, actor cookie isolation, final request hooks, response scripts, a CLI, and local signed-flow examples. PR #12 was merged after user approval.

The integrated journey-test engine adds reusable mutation cases, exact typed checks, same-session verification after rejection, mutation-survival checks, private/redacted evidence, and fingerprinted reconstruction. Tests record actual HTTP traffic from an independent local reference API, import it, distinguish secure/vulnerable/session-invalid outcomes, reconstruct a case, and refuse input drift. Final code review approved the core fixes, and the actual CLI acceptance outcomes are recorded in [stateful reference evidence](acceptance/stateful-reference.md). PR #13 was retargeted and merged into `feat/req-fuzzer` after PR #12, following user approval.

The user delegated independent application selection. The subsequent [Juice Shop acceptance](acceptance/juice-shop.md) imported actual traffic from a pinned local third-party app and reproduced a negative order total using fresh accounts and dynamically bound IDs. The reusable project is `examples/juice-shop`. This closes the immediate need for an independent acceptance target; an operator-provided capture can be added when available.

The path-dependency feature branch extends binding and conservative inference to whole URL segments. The Juice Shop example now declares its short numeric IDs explicitly, so the dependency graph shows `add → update` and `login → checkout` without URL-changing hooks. Short or ambiguous IDs still require manual authoring. This feature remains separate from the integrated development branch until its change is merged.

The complete goal remains unproven. These gaps still matter:

- Third-party acceptance now exists for Juice Shop's checkout API; broader application compatibility remains unproven.
- Mutation coverage needs additional PayInt-style operations and request locations. Path bindings and inference are implemented on their feature branch; path-targeted mutations and cookie/form/multipart dependencies remain outside current coverage.
- A visual dependency view and more flexible flow control remain to be proved against realistic captured journeys. A visual editor, complete PayInt corpus parity, and distributed execution are not prerequisites for the first useful tool.

No completion claim should rely on CI alone. It must demonstrate the operator workflow on an independent reference API with changing tokens/nonces, signing, rejected and accepted mutations, and downstream invariant checks; then validate it on an operator-provided capture when one is available.

Next delivery priority is core capability rather than more acceptance variants: deliver explicit path dependencies, expand request mutation locations, then expose inferred and authored dependencies in a visual view. The existing CLI/journey slices are integrated.
