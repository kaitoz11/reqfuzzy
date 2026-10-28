# Product goal and evidence

Goal: turn reqfuzzy into a scriptable tool for testing stateful API journeys.

The operator workflow is capture → infer/edit dependencies → script authentication and request preparation → replay valid state → morph a selected request → verify its effects → retain a repeatable test and evidence. Reqfuzzy is the implementation home; the archived Python kvar proposal is not a second implementation.

The current implementation proves HAR import, conservative inference for headers/query/JSON, authored sequential flows, scalar/raw variables, actor cookie isolation, final request hooks, response scripts, a CLI, and a local signed-flow example. PR #12 is still a draft, so that implementation is available on its feature branch rather than the integrated development branch.

The complete goal remains unproven. These gaps still matter:

- Response hashes expose differences but do not evaluate business or security invariants. Invalid authentication or a broken prerequisite must remain distinguishable from a finding.
- Single mutations need to become reusable cases that rerun prerequisites and verify downstream state even when the tested request is rejected.
- Evidence needs actual sent HTTP metadata, protected artifacts, input fingerprints, and a way to reconstruct a case with fresh session state.
- Mutation coverage needs additional PayInt-style operations and request locations; current inference deliberately excludes path, cookie, form, and multipart dependencies.
- A visual dependency view and more flexible flow control remain to be proved against realistic captured journeys. A visual editor, complete PayInt corpus parity, and distributed execution are not prerequisites for the first useful tool.

No completion claim should rely on CI alone. It must demonstrate the operator workflow on an independent reference API with changing tokens/nonces, signing, rejected and accepted mutations, and downstream invariant checks; then validate it on an operator-provided capture when one is available.
