# Scriptable reqfuzzy command line

Status: approved next slice after the user authorized script hooks and a minimal CLI.

## Project direction

`github.com/kaitoz11/reqfuzzy` is the implementation home. Its Go packages are the engine; `cmd/reqfuzzy` is a thin operator interface. PayInt supplies behavior and payload references. The former separate Python kvar proposal is historical.

## User workflow

Build with `go build -o bin/reqfuzzy ./cmd/reqfuzzy`.

1. `reqfuzzy import --out .reqfuzzy/demo capture.har` writes a new project with `project.yaml`, `flow.yaml`, `links.json`, `requests/`, and `hooks/`.
2. `reqfuzzy flow show --project .reqfuzzy/demo` shows the current edited steps and variable edges. `--json` produces one versioned JSON document.
3. `reqfuzzy flow run --project .reqfuzzy/demo --base-url http://localhost:8080` replays the flow.
4. `reqfuzzy flow compare --project .reqfuzzy/demo --base-url http://localhost:8080 --step create --location json --path amount --value 99` replays baseline and one mutation, including final signing hooks.

Import is offline. A multi-origin HAR requires `--origin` to select one HTTP origin. Import requires a new output directory and stages the complete project before renaming it into place, preserving existing operator edits. Project request paths are relative and must remain inside the project. Replay requires an explicit HTTP(S) base URL and uses it for the Host header too. CLI output summarizes statuses and response hashes; it omits bodies, headers, and variable values.

## JavaScript hook contract

Use an embedded Goja runtime pinned to a revision compatible with the existing Go 1.24 module. Scripts are synchronous JavaScript, without Node.js modules, filesystem, network, or process APIs. A fresh VM runs each invocation. A default one-second deadline includes top-level evaluation and the callback; context cancellation interrupts execution. The deadline is configurable with `--script-timeout`.

Named hooks resolve to `hooks/<name>.js`. Hook names contain only ASCII letters, digits, `_`, and `-`. Compile and check all referenced callbacks before the runner sends requests. A script defines `function beforeSend(ctx) { ... }`, `function afterResponse(ctx) { ... }`, or both. Promise-returning hooks are rejected.

`ctx.request` in `beforeSend` has mutable `method`, relative `url`, and UTF-8 `body`, plus `getHeader(name)`, `setHeader(name, value)`, and `removeHeader(name)`. Header setters replace case variants. Changes apply only after successful execution and validation. A malformed request, timeout, or exception prevents send. Binary bodies remain available through the Go API but cannot enter the text-oriented JS hook.

`ctx.response` in `afterResponse` has `status`, UTF-8 `body`, and `getHeader(name)`. Both callbacks access `ctx.vars.get(name)`, `set(name, scalar)`, `getRaw(name)`, and `setRaw(name, jsonScalarText)`. Missing variables and invalid/non-scalar values throw. `get` refuses unsafe JS numeric conversions; `getRaw` and `setRaw` preserve arbitrary-precision JSON numbers. Variable updates are staged and committed only when the callback succeeds. This initial runtime supplies `crypto.sha256(text)`, `crypto.hmacSha256(key, text)`, and `encoding.base64Encode/base64Decode`.

## Flow changes

Add optional `after_response` and `provides` to a step. `provides` declares variables a response script supplies, so validation can resolve later bindings before network execution. A declaration requires `after_response`; names cannot duplicate extracted or earlier variables. After the status check, the runner performs YAML extraction, invokes the response script, verifies declared variables exist as scalars, and records them in the step trace. Undeclared script variables may be used inside scripts but cannot satisfy later YAML references.

Order: fresh request → bindings → chosen mutation → global preparation → named before hook → send → status check → YAML extraction → after hook → declared-value check → next step. The global preparation callback lets the CLI align the Host with the explicit target before a script signs it.

Add an exported constructor for a set-value mutation using the runner's existing header/query/JSON replacement semantics. JSON mutation values are validated raw JSON scalars so large IDs are not rounded.

## CLI contract

Use the standard flag package and keep command behavior in `internal/cli.Run(args, stdout, stderr) int` for local integration tests. Exit 0 means execution succeeded, including a comparison with different results; 1 means argument/project/import failure; 2 means flow or script execution failure. JSON mode emits exactly one document with `format_version: 1`, a command name, a summary result, and an optional structured error. The CLI does not claim a response difference is a vulnerability.

Project manifest version 1 records the selected origin and named relative request paths. The flow is always loaded from the project's current `flow.yaml`. Script errors identify script, callback, and runner step. `--timeout` bounds the complete run; `--script-timeout` bounds each invocation. Missing/invalid scripts fail before target requests.

## Acceptance

- Import a captured three-step flow, inspect its edges, edit it to use response and request scripts, run it, and compare an amount mutation through the actual command handler against `httptest`.
- A response script provides a token for the next step; a before script signs the body after mutation; baseline and mutated downstream hashes differ.
- Throwing and nonterminating scripts prevent the affected send and return a partial summary with exit 2.
- Large JSON numbers survive raw variable operations; unsafe Number conversions fail explicitly.
- A malformed manifest, escaped request/hook path, invalid header, or existing import directory is rejected without overwriting operator files.
- `go test -race ./...`, `go vet ./...`, and the CLI build pass. Existing Go APIs and YAML files remain compatible.
