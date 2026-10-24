# reqfuzzy flow mutation slice

**Status:** approved for the first implementation milestone on 2026-10-24

## Purpose

An operator can replay a named sequence of captured HTTP requests, carry values from one response into later requests, change one chosen request, and inspect the effect at that step and downstream. The sequence is the unit of execution. This milestone establishes the executable format that later traffic import and flow inference will produce.

## Scope and example

The first slice runs through the Go API with a YAML flow file. A local example will execute `create session -> create item -> read item`, extract the session token and item ID, and bind them into later requests. A comparison runs that flow twice from fresh client sessions: once unchanged and once with a caller-provided mutation on `create item`. A registered hook sees the fully bound and mutated request immediately before send, so it can calculate a signature or transform a body. The result includes both runs and their step traces.

Captured traffic inference, a visual editor, a CLI, the PayInt template corpus, and multiple mutation campaigns are later milestones. They will consume this flow format and runner rather than define a second execution model.

## Flow file

YAML is decoded with `yaml.v3` into `Flow`. The first schema version has this shape:

```yaml
name: item-journey
steps:
  - id: login
    request: login
    actor: default
    expect_status: 200
    extract:
      - name: token
        json: token
  - id: create
    request: create
    actor: default
    bind:
      - location: header
        path: Authorization
        variable: token
    before_send: sign
    expect_status: 201
    extract:
      - name: item_id
        json: id
  - id: read
    request: read
    actor: default
    bind:
      - location: query
        path: id
        variable: item_id
    expect_status: 200
```

- `name` and `steps` are required. A flow contains at least one step. Step IDs are unique and execute in file order.
- `request` names an entry already registered in `attacker.RequestStore`. A missing name fails the run before sending that step.
- `actor` selects a client by name; omission means `default`. A client factory supplies a new client per actor for each run, and steps for one actor share its cookie jar within that run.
- `extract` reads one scalar JSON value from the response with `gjson` path syntax. A missing path, JSON object, or array fails the step. The extracted value keeps its JSON type and raw number representation. Variable names are unique within a flow; a duplicate is rejected before execution.
- `bind` refers to an earlier extracted variable. `location` is `header`, `query`, or `json`. `path` is the header name, query key, or `sjson` path. Missing variables and invalid locations fail before send. JSON binding preserves the extracted JSON type; header and query binding use its string form.
- A `json` binding requires an existing valid JSON request body. It fails before send when the body is plain or malformed text.
- `expect_status`, when set, requires that exact HTTP status. An unmet expectation stops the run and names the step. A step without it accepts any HTTP status for subsequent extraction.
- `before_send` names a Go callback registered by the caller. An unknown name fails before send. The hook receives the current request and run variables and may alter the request; hook errors stop the run.

The loader validates syntax, duplicate IDs, and variable references. The runner validates request names, actor clients, and hook names before network execution. YAML does not execute arbitrary code or resolve files itself.

## Execution contract

`pkg/attacker/flow` owns the flow types, YAML loader, validation, runner, and comparison result. It imports `pkg/attacker`; the existing `attacker` package does not import `flow`.

```go
type ClientFactory func(actor string) (*attacker.HClient, error)
type BeforeSend func(request attacker.Request, variables Variables) error
type Mutation func(request attacker.Request, variables Variables) error

type Runner struct {
    Store         *attacker.RequestStore
    NewClient     ClientFactory
    BeforeSend    map[string]BeforeSend
}

func LoadYAML(data []byte) (Flow, error)
func (r Runner) Run(ctx context.Context, flow Flow, mutation *StepMutation) (RunResult, error)
func (r Runner) Compare(ctx context.Context, flow Flow, mutation StepMutation) (ComparisonResult, error)
```

`StepMutation` has a `StepID` and `Apply Mutation`. The mutation callback receives the variables extracted by preceding steps. `Run` constructs a new client for each actor when first used, loads each named raw request, and creates a fresh request object. Each step applies bindings, then the optional mutation, then `before_send`, then sends the request. It checks the expected status and extracts variables before proceeding. A mutation applies exactly once at its matching step. An unknown mutation step ID fails validation before any network call. The final hook always sees the mutation.

`Compare` performs an unchanged run followed by a mutated run. It calls `NewClient` again for every actor in the second run, so cookies and client state do not cross runs. Business data on the target may still persist; each run must create its own resources or the flow author must provide cleanup. The comparison reports the two outcomes without claiming that a difference is a vulnerability.

The runner executes steps sequentially. It calls `Request.SetContext(ctx)` so cancellation interrupts an in-flight send. There is no parallel request execution in this slice.

## Results and evidence

`RunResult` contains flow name, ordered `StepResult` entries, final variables, and any failed step ID. Each step result includes actor, request name, a snapshot of the fully prepared request (method, URL, query, headers, body), response status, response body, and the variables extracted there. `ComparisonResult` contains `Baseline` and `Mutated` run results plus the mutation step ID. A baseline error prevents the mutated run. A mutated-run error leaves the completed baseline and partial mutated trace in the returned result. Results remain in memory; callers decide how to redact and persist sensitive headers, cookies, and bodies. The runner does not print credentials or results.

The run returns a typed error for invalid flows, missing requests or variables, hook/mutation failure, transport failure, extraction failure, and unmet status. Errors include the step ID. A failed run returns its completed traces alongside the error.

## Existing code boundaries

- `attacker.RequestStore` remains the source of named raw requests. The runner calls its existing lookup method; each execution adapts the cached parsed request into a new mutable request.
- `attacker.HClient` remains the HTTP transport and cookie owner. It adds `NewRequestFromParsed(*rawreq.ParsedRawRequest) (attacker.Request, error)`, which calls the existing adapter without exposing the underlying `req` client.
- The raw request parser must retain multiline bodies. Its current scanner reads only the first body line, which would corrupt captured JSON before the flow runner sees it. The parser fix is part of this slice.
- Existing `FuzzerClient` remains unchanged. The comparison runner uses the same callback style for mutation, then later fuzzing work can schedule many `StepMutation` values through it.

## Verification

- A local `httptest` API drives the three-step example. It confirms response-to-request binding, cookie continuity within one run, and fresh clients across the two runs.
- The mutated create request reaches the server with a changed field, and the final hook observes that changed field before signing it.
- A JSON number extracted from a response remains a number in a later JSON body, including a value above JavaScript's exact integer range.
- Malformed flows and missing variables fail before an affected request is sent; status and transport failures return the completed trace.
- A multiline raw request body survives parsing and sending.
- `go test ./...` passes without contacting an external target.
