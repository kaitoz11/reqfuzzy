# HAR Flow Inference Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Import a HAR 1.2 capture into stable raw requests and suggest an editable flow that the existing runner can execute.

**Architecture:** `pkg/attacker/capture` parses HAR entries, materializes request files, and infers response-to-later-request links. It depends on the existing `flow` package; a small additive `Binding.Prefix` change supports Bearer headers. Inference returns metadata separately from strict executable flow YAML.

**Tech Stack:** Go 1.24 standard library, existing `gjson`, `sjson`, `yaml.v3`, `req/v3`, and `httptest`.

**Spec:** `docs/superpowers/specs/2026-10-28-har-flow-inference-design.md`

## Global Constraints

- No network traffic from HAR parsing, request materialization, or inference.
- Preserve HAR entry order and response value JSON types; use `json.Decoder.UseNumber`.
- Generated request filenames must be stable, bounded, and safe; output files use mode `0600`.
- Do not include captured secret values in link metadata or logs.
- Suggestions are drafts; only `flow.Runner` can execute them when explicitly called.
- Keep the original `reqfuzzy` checkout and draft PR #10 unchanged; work on `feat/har-flow-inference`.

---

### Task 1: Bearer-capable flow bindings

**Files:**
- Modify: `pkg/attacker/flow/model.go`, `load.go`, `runner.go`
- Test: `pkg/attacker/flow/load_test.go`, `runner_test.go`

**Interfaces:**
- Add `Prefix string \`yaml:"prefix,omitempty"\`` to `flow.Binding`.
- `header` and `query` use `Prefix + Value.Text`; `json` rejects a nonempty prefix.

- [x] Add a failing loader/runner test with a response token `token-12345`, an existing `Authorization: Bearer stale`, and a later binding `{location: header, path: Authorization, variable: token, prefix: "Bearer "}`. Assert the server receives exactly `Bearer token-12345` once.
- [x] Run `go test ./pkg/attacker/flow -run TestBearerBinding -count=1`; confirm failure due to missing prefix behavior.
- [x] Add the field, validate the location rule, and apply the prefix after extracting the value while retaining case-insensitive header replacement.
- [x] Run `go test ./pkg/attacker/flow -count=1` and `go test ./...`; commit as `feat: support prefixed flow bindings`.

### Task 2: Parse and materialize HAR requests

**Files:**
- Create: `pkg/attacker/capture/har.go`, `request.go`, `write.go`
- Test: `pkg/attacker/capture/har_test.go`, `write_test.go`
- Create: `.gitignore` with `.reqfuzzy/`

**Interfaces:**
- `ParseHAR(data []byte) (Capture, error)` returns ordered `Exchange` values with deterministic names, raw request bytes, response status/body, and body-presence flag.
- `(Capture).WriteRequests(directory string) (map[string]string, error)` writes files idempotently.

- [x] Write a failing test for a three-entry HAR 1.2 document. The first response is base64 encoded JSON, one request has multiline JSON `postData.text`, and one has repeated query keys. Assert entry names/order, raw request line/body, decoded response, and `rawreq.ParseRawRequest` compatibility.
- [x] Run `go test ./pkg/attacker/capture -run TestParseHAR -count=1`; confirm the missing package/API failure.
- [x] Implement strict HAR decoding with UTF-8 BOM handling, required method/URL, `http`/`https` restriction, ordered header serialization, Host insertion, framing-header removal, postData text, URL-encoded params-only fallback, base64 response content, and entry-numbered errors.
- [x] Add failing tests for invalid version, malformed URL/header, unsupported multipart params-only request, invalid base64, and missing response text; implement the smallest error handling that makes them pass.
- [x] Write a failing `WriteRequests` test: first write creates mode-0600 files, second write keeps identical bytes, and a conflicting file is not overwritten. Assert generated names contain no path separators. Implement and add `.reqfuzzy/` to `.gitignore`.
- [x] Run `go test ./pkg/attacker/capture -count=1` and `go test ./...`; commit as `feat: import HAR requests offline`.

### Task 3: Infer response-to-request bindings

**Files:**
- Create: `pkg/attacker/capture/infer.go`, `json_paths.go`
- Test: `pkg/attacker/capture/infer_test.go`

**Interfaces:**
- `SuggestFlow(c Capture) (Suggestion, error)` returns a `flow.Flow` and `[]Link` metadata without raw matched values.
- `(Suggestion).YAML() ([]byte, error)` emits only the runnable flow schema.

- [x] Write a failing three-entry test: login response token appears as a later Bearer header; create response `9007199254740993` appears in confirmation JSON. Assert two links with source/destination paths, prefix and confidence; assert the generated YAML loads through `flow.LoadYAML` and preserves the large number as a JSON binding.
- [x] Run `go test ./pkg/attacker/capture -run TestSuggestFlow -count=1`; confirm the missing inference API failure.
- [x] Implement deterministic JSON leaf traversal, candidate filtering, exact query/header/JSON matches, Bearer-prefix matching, unique-prior-source rule, stable extraction names, and link metadata. Use `json.Number` to avoid float precision loss.
- [x] Add failing tests for missing response body, ambiguous prior values, short/common values, and nested or array JSON paths. Implement only the behavior those tests require.
- [x] Run `go test ./pkg/attacker/capture -count=1` and `go test ./...`; commit as `feat: suggest executable flows from HAR`.

### Task 4: Prove the offline-to-runner handoff and document it

**Files:**
- Test: `pkg/attacker/capture/integration_test.go`
- Create: `docs/har-flow-inference.md`
- Modify: `README.md`

**Interfaces:**
- `ParseHAR` → `WriteRequests` → `SuggestFlow` → `Suggestion.YAML` → `flow.LoadYAML` → `flow.Runner.Run`.

- [x] Build an `httptest` login → create → confirm API and a matching HAR fixture. Import to `t.TempDir()`, register returned request paths, load the suggested YAML, and run it. Assert the server receives the current Bearer token and exact numeric transaction ID, while import/inference itself sends zero requests.
- [x] Run `go test ./pkg/attacker/capture -run TestHARToRunner -count=1`; it passed on the first run because the parser, writer, suggester, and runner already composed correctly.
- [x] Document accepted HAR fields, generated filenames, ignored Git directory, review steps, and the current inference boundaries. Provide a copyable Go API example that writes YAML with mode `0600` and does not execute it automatically.
- [x] Run `go test -race ./... -count=1`, `go vet ./...`, compile the documented example, and check `git diff --check`; commit as `docs: show HAR-to-flow workflow`.

## Final verification

- [x] Review the diff against the spec; check every acceptance item against a test or documented boundary.
- [x] Run fresh `go test -race ./... -count=1` and `go vet ./...` on the final commit.
- [x] Confirm the original `reqfuzzy` checkout and draft flow PR are unchanged.

## Execution note

The local HAR-to-runner integration test passed on its first run. The milestone needed no integration-specific production fix after its component tests. Review fixes subsequently added MIME validation, safe path escaping, duplicate-key and repeated-field exclusions, and UTF-8 validation.
