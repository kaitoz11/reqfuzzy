# Flow Mutation Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replay a named API flow, carry response values into later requests, mutate one step, and compare baseline and mutated runs.

**Architecture:** Add an isolated `pkg/attacker/flow` package that consumes the existing request store and HTTP client. YAML describes ordered steps, extraction, bindings, and named hooks; Go callbacks supply target-specific transformations and the mutation. Both comparison runs use fresh actor clients and return in-memory traces.

**Tech Stack:** Go 1.24; existing `req/v3`, `gjson`, `sjson`, and `yaml.v3`; standard `httptest` for integration tests.

**Spec:** `docs/superpowers/specs/2026-10-24-flow-mutation-slice-design.md`

## Global Constraints

- Keep `pkg/attacker/flow` dependent on `pkg/attacker`; `pkg/attacker` must not import `flow`.
- Preserve the existing checkout's uncommitted `main.go`; work only in this linked worktree.
- Every comparison run creates fresh clients per actor; steps for one actor share one client within that run.
- Bind variables, then apply the chosen mutation, then run `before_send`, then send.
- Never contact an external target in tests; use `httptest`.
- Keep full request and response traces in memory; do not print or persist credentials.

---

### Task 1: Preserve raw request bodies

**Files:**
- Modify: `pkg/attacker/rawreq/parser.go`
- Test: `pkg/attacker/rawreq/parser_test.go`

**Interfaces:**
- Consumes: `ParseRawRequest([]byte, ...Options) (*ParsedRawRequest, error)`.
- Produces: the same function with `Body` containing every byte after the first blank line, including line breaks and binary bytes.

- [ ] **Step 1: Write a failing body-fidelity test.** Add a test with `raw := []byte("POST /items HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\n\r\n{\n  \"name\": \"a\"\n}\n")`; assert `string(parsed.Body) == "{\n  \"name\": \"a\"\n}\n"` and `parsed.BodyType == rawreq.Json`. Add a second case with `[]byte{0, 10, 255}` after the separator and assert byte equality.
- [ ] **Step 2: Verify red.** Run `go test ./pkg/attacker/rawreq -run TestParseMultilineBody -count=1`; expect the new test to fail because only the first body line is returned.
- [ ] **Step 3: Implement the minimal parser change.** Split the input once at `\r\n\r\n` or `\n\n`; scan only the header portion; copy the remaining bytes directly into `Body`. Preserve the current request-line, header blacklist, and JSON detection behavior. Use `bytes.Index` and `bytes.Clone` so the body is independent of the caller's input buffer.
- [ ] **Step 4: Verify green and existing parser behavior.** Run `go test ./pkg/attacker/rawreq -count=1` and `go test ./...`.
- [ ] **Step 5: Commit.** `git add pkg/attacker/rawreq/parser.go pkg/attacker/rawreq/parser_test.go && git -c commit.gpgsign=false commit -m "fix: preserve complete raw request bodies"`.

### Task 2: Define and validate the flow file

**Files:**
- Create: `pkg/attacker/flow/model.go`
- Create: `pkg/attacker/flow/load.go`
- Test: `pkg/attacker/flow/load_test.go`

**Interfaces:**
- Consumes: YAML bytes.
- Produces: `Flow`, `Step`, `Binding`, `Extraction`, `Variables`, `Value`, `LoadYAML([]byte) (Flow, error)`, and `Validate(Flow) error`.

- [ ] **Step 1: Write failing loader tests.** Use the spec's three-step YAML example. Assert exact decoded step IDs, the default actor `default`, and the order of bindings. Add table cases for duplicate step IDs, duplicate variable names, a binding to a variable not extracted in an earlier step, an unsupported binding location, and an empty flow; assert each returns an error naming the bad step or field.
- [ ] **Step 2: Verify red.** Run `go test ./pkg/attacker/flow -run 'TestLoad|TestValidate' -count=1`; expect undefined `LoadYAML` or types.
- [ ] **Step 3: Implement the model.** Use these public shapes, with YAML tags matching the spec:

```go
type Flow struct { Name string `yaml:"name"`; Steps []Step `yaml:"steps"` }
type Step struct { ID string `yaml:"id"`; Request string `yaml:"request"`; Actor string `yaml:"actor"`; Bind []Binding `yaml:"bind"`; Extract []Extraction `yaml:"extract"`; BeforeSend string `yaml:"before_send"`; ExpectStatus *int `yaml:"expect_status"` }
type Binding struct { Location string `yaml:"location"`; Path string `yaml:"path"`; Variable string `yaml:"variable"` }
type Extraction struct { Name string `yaml:"name"`; JSONPath string `yaml:"json"` }
type Value struct { RawJSON []byte; Text string }
type Variables map[string]Value
```

- [ ] **Step 4: Implement strict load and validation.** `LoadYAML` uses `yaml.NewDecoder(bytes.NewReader(data))`, `KnownFields(true)`, and rejects a second document. `Validate` checks required names, unique step IDs and extracted names, earlier-only variable references, supported locations (`header`, `query`, `json`), nonempty paths, and HTTP status range 100–599. Set omitted actor to `default` when loading or validating a copy.
- [ ] **Step 5: Verify green.** Run `go test ./pkg/attacker/flow -count=1` and `go test ./...`.
- [ ] **Step 6: Commit.** `git add pkg/attacker/flow && git -c commit.gpgsign=false commit -m "feat: define validated API flow files"`.

### Task 3: Execute a flow with bindings, hooks, and traces

**Files:**
- Modify: `pkg/attacker/client.go`
- Create: `pkg/attacker/flow/runner.go`
- Create: `pkg/attacker/flow/result.go`
- Test: `pkg/attacker/flow/runner_test.go`

**Interfaces:**
- Consumes: `Flow`, `attacker.RequestStore`, `ClientFactory`, named `BeforeSend` hooks.
- Produces: `HClient.NewRequestFromParsed(*rawreq.ParsedRawRequest) (attacker.Request, error)` and `Runner.Run(context.Context, Flow, *StepMutation) (RunResult, error)`.

- [ ] **Step 1: Write a failing local integration test.** An `httptest` server handles `/login` (sets a cookie and returns `{"token":"abc"}`), `/create` (requires that cookie and `Authorization: abc`, reads a JSON body, returns `{"id":9007199254740993}`), and `/read` (requires `id=9007199254740993`). Register three raw request files in `RequestStore`, load the example YAML, run it with `req.C().SetBaseURL(server.URL)` in the client factory, and assert three ordered step results plus a successful final query. Assert the hook observes a bound request.
- [ ] **Step 2: Verify red.** Run `go test ./pkg/attacker/flow -run TestRunnerCarriesState -count=1`; expect missing `Runner` or `Run`.
- [ ] **Step 3: Add the adapter boundary.** In `client.go`, implement `NewRequestFromParsed` by calling the existing `FromParsedRawRequestAdapter(c.httpClient, parsed)` and wrapping the result as `attacker.Request`.
- [ ] **Step 4: Add runner and result types.** Use `ClientFactory func(string) (*attacker.HClient,error)`, `BeforeSend func(attacker.Request, Variables) error`, `Mutation func(attacker.Request, Variables) error`, and `StepMutation{StepID string, Apply Mutation}`. `RunResult` holds `FlowName`, `Steps`, `Variables`, `FailedStepID`. A `StepResult` holds `StepID`, `Actor`, `RequestName`, `RequestSnapshot`, `StatusCode`, `ResponseBody`, `Extracted`. A request snapshot copies `Method`, `RawURL`, `QueryParams`, `Headers`, and `Body` after the hook. Return `*StepError{Kind ErrorKind, StepID string, Err error}` for runtime failures, with `Unwrap() error` for callers to inspect the cause.
- [ ] **Step 5: Implement the execution order.** Validate the flow and all request/hook names before creating a client. For each step, get its actor client, create a fresh request, bind header/query/JSON values, apply the matching mutation, run the named hook, call `SetContext(ctx)`, snapshot the request, send, check `expect_status`, then extract scalar values with `gjson.GetBytes`. Use `sjson.SetRawBytes` for JSON bindings so the large ID stays numeric. Append a step trace before returning any status or extraction error.
- [ ] **Step 6: Add focused failure tests.** A missing JSON path, bad status, unknown request/hook, canceled context, and a hook error each fail with the step ID; assert the affected request was not sent where validation or a pre-send hook fails. A transport error returns completed preceding traces.
- [ ] **Step 7: Verify green.** Run `go test ./pkg/attacker/flow -count=1`, `go test ./...`, and `go test -race ./pkg/attacker/flow`.
- [ ] **Step 8: Commit.** `git add pkg/attacker/client.go pkg/attacker/flow && git -c commit.gpgsign=false commit -m "feat: replay stateful API flows"`.

### Task 4: Compare baseline and one mutated journey

**Files:**
- Modify: `pkg/attacker/flow/runner.go`
- Modify: `pkg/attacker/flow/result.go`
- Test: `pkg/attacker/flow/compare_test.go`

**Interfaces:**
- Consumes: `Runner.Run` and `StepMutation` from Task 3.
- Produces: `Runner.Compare(context.Context, Flow, StepMutation) (ComparisonResult, error)`.

- [ ] **Step 1: Write a failing comparison test.** Use a local server where `/login` creates a fresh session, `/create` stores a JSON `amount`, and `/read` returns it. The mutation changes `amount` from 10 to 99. A named hook computes an `X-Body-Signature` from the final body. Assert that both runs have three steps, each uses a distinct session, the server received signed bodies for 10 and 99, and the final read responses differ accordingly.
- [ ] **Step 2: Verify red.** Run `go test ./pkg/attacker/flow -run TestCompare -count=1`; expect missing `Compare`.
- [ ] **Step 3: Implement comparison.** Validate the mutation step ID before network access, call `Run(ctx, flow, nil)` then `Run(ctx, flow, &mutation)`, and return both results. If the baseline fails, return its partial result and do not run the mutation. If the mutation fails, return the completed baseline plus its partial trace.
- [ ] **Step 4: Add one failure test.** Make the second run's `/create` return 409 and assert `ComparisonResult.Baseline` is complete, `Mutated.FailedStepID == "create"`, and no `/read` is sent in the second run.
- [ ] **Step 5: Verify green and race safety.** Run `go test ./pkg/attacker/flow -count=1`, `go test -race ./...`, and `go vet ./...`.
- [ ] **Step 6: Commit.** `git add pkg/attacker/flow && git -c commit.gpgsign=false commit -m "feat: compare mutated API journeys"`.

### Task 5: Document the runnable slice

**Files:**
- Create: `docs/flow-mutation.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: public API implemented by Tasks 1–4.
- Produces: one copyable Go example and the matching YAML flow, using only a local test server or placeholder host.

- [ ] **Step 1: Document setup and execution.** Show `RequestStore.RegisterRequestFilePath`, `flow.LoadYAML`, `Runner{Store,NewClient,BeforeSend}`, `StepMutation`, and `Compare`. State that a flow with raw request files but no responses can be authored manually; automatic inference will require response-bearing captures.
- [ ] **Step 2: Review API names against compiled code.** Run `go test ./...` and `go vet ./...`; ensure every identifier in the Go example is exported and spelled exactly as implemented.
- [ ] **Step 3: Commit.** `git add README.md docs/flow-mutation.md && git -c commit.gpgsign=false commit -m "docs: show stateful flow mutation workflow"`.

## Final verification

- [ ] Run `gofmt` on changed Go files and verify `git diff --check`.
- [ ] Run fresh `go test -race ./...` and `go vet ./...`.
- [ ] Check `git status -sb`, the worktree's commit list, and the original checkout's `main.go` diff.
- [ ] Compare each acceptance criterion in the spec to a test, compiled example, or documented limitation before claiming the milestone complete.
