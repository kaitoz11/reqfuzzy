# Product goal and evidence

Goal: turn reqfuzzy into a scriptable tool for testing stateful API journeys.

The operator workflow is capture → infer/edit dependencies → script authentication and request preparation → replay valid state → morph a selected request → verify its effects → retain a repeatable test and evidence. Reqfuzzy is the implementation home; the archived Python kvar proposal is not a second implementation.

The current implementation proves HAR import, conservative inference for headers/query/JSON, authored sequential flows, scalar/raw variables, actor cookie isolation, final request hooks, response scripts, a CLI, and local signed-flow examples. PR #12 is still a draft, so the CLI implementation is available on its feature branch rather than the integrated development branch.

The next feature branch adds reusable mutation cases, exact typed checks, same-session verification after rejection, mutation-survival checks, private/redacted evidence, and fingerprinted reconstruction. Tests record actual HTTP traffic from an independent local reference API, import it, distinguish secure/vulnerable/session-invalid outcomes, reconstruct a case, and refuse input drift. These features require final review and delivery before they count as completed product evidence.

The complete goal remains unproven. These gaps still matter:

- The new invariant/case/evidence loop still needs final review, operator documentation, integration, and validation on an operator-provided real-world capture. Controlled reference evidence alone does not establish compatibility with an unprovided application.
- Mutation coverage needs additional PayInt-style operations and request locations; current inference deliberately excludes path, cookie, form, and multipart dependencies.
- A visual dependency view and more flexible flow control remain to be proved against realistic captured journeys. A visual editor, complete PayInt corpus parity, and distributed execution are not prerequisites for the first useful tool.

No completion claim should rely on CI alone. It must demonstrate the operator workflow on an independent reference API with changing tokens/nonces, signing, rejected and accepted mutations, and downstream invariant checks; then validate it on an operator-provided capture when one is available.
