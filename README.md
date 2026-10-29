# reqfuzzy

Reqfuzzy is a Go tool for testing stateful API journeys. Import captured requests, review their data dependencies, add JavaScript request/response hooks, and compare a changed request with a fresh baseline journey.

This repository is the implementation home for the PayInt rework. `payintv3` supplies behavior and payload references; the earlier separate Python kvar proposal is historical. Active development is on `feat/req-fuzzer` while the work is integrated into `main`.

Build with Go 1.24 or newer:

```sh
go build -o bin/reqfuzzy ./cmd/reqfuzzy
```

Try the complete local example. Start its API in one terminal:

```sh
go run ./examples/scripted-flow/mock
```

Then inspect and compare the scripted flow in another:

```sh
bin/reqfuzzy flow show --project examples/scripted-flow
bin/reqfuzzy flow run --project examples/scripted-flow --base-url http://127.0.0.1:8099
bin/reqfuzzy flow compare --project examples/scripted-flow --base-url http://127.0.0.1:8099 --step create --location json --path amount --value 99 --json
```

The example obtains a fresh token, signs the final request body, and reads back the changed amount. Comparisons report response hashes and execution outcomes; they do not automatically classify a difference as a vulnerability.

- [CLI commands and projects](docs/cli.md)
- [JavaScript request and response hooks](docs/script-hooks.md)
- [Stateful mutation tests and reproducible evidence](docs/journey-tests.md)
- [HAR import and flow inference](docs/har-flow-inference.md)
- [Flow model and Go API](docs/flow-mutation.md)
- [Binding and mutation locations](docs/request-locations.md)

Reusable test cases can set, remove, append, and prepend values, run downstream verification, evaluate explicit invariants, and record protected evidence for reconstruction. Start with the [stateful reference example](docs/journey-tests.md) to see secure rejection, an intentional balance bug, and invalid-session handling.

Current inference covers JSON response scalars passed into path segments, headers, query values, JSON bodies, and URL-encoded form fields, including Bearer tokens. Short or ambiguous IDs can be bound explicitly. All five locations support set/remove/append/prepend mutations. The [Juice Shop checkout example](examples/juice-shop/README.md) demonstrates fresh accounts, dynamic path IDs, quantity mutation, persisted-order checks, and reconstruction against a pinned local application.

Cookie/multipart inference, broader payload/template support, flexible flow control, and a visual dependency view remain separate increments.
